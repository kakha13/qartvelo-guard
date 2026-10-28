<?php
/**
 * AJAX endpoints used by the dashboard, reports page and wizard.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Every endpoint: action "wpcybersec_<name>", nonce "wpcybersec_ajax"
 * (field _ajax_nonce), capability Admin::cap() (manage_options, or
 * manage_network_options on multisite). Responses use
 * wp_send_json_success( data ) / wp_send_json_error( { message } ).
 *
 *   scan_start   mode=incremental|full|baseline, malware=0|1  -> scan status + { requested, attached, notice }
 *                (attached = true when another scan was already running and is returned instead)
 *   scan_tick                                                  -> scan status
 *   scan_status                                                -> scan status
 *   scan_cancel                                                -> scan status
 *   item_action  do=<action>, id=<int>[, risk_ok=1]            -> { item (match snippets redacted), counts, message }
 *   bulk_action  do=<action>, ids[]=<int>[, risk_ok=1]         -> { done, errors, counts }
 *                (approve / ignore of an item flagged high or critical needs risk_ok=1, which the
 *                Reports page sends after its confirmation dialog; error code "confirm" otherwise)
 *   clean_images                                               -> { ids, count, more } pending uploads "Allow all clean images" may approve
 *   allow_clean  ids[]=<int> (at most ALLOW_CLEAN_MAX)          -> { done, approved, skipped, errors, remaining, counts }
 *                approves the ids that are still clean images, one by one, until the time budget
 *                is used; the browser sends "remaining" again
 *   counts                                                     -> counts
 *   unlock       minutes=<int>                                 -> { unlocked_until }
 *   lock                                                       -> { unlocked_until: 0 }
 *   diff_summary id=<int>                                      -> Diff::summary() { mode, added, removed, base_label, text }
 *   clamav_enable                                              -> { message } (turns on "Also scan uploads with ClamAV" when ClamAV is ready)
 */
class Ajax {

	const NONCE = 'wpcybersec_ajax';

	/** Job states in which the scan still needs ticks. */
	const RUNNING = array( 'enumerating', 'processing', 'finishing' );

	/**
	 * Seconds after the last browser tick before cron takes over a scan that was
	 * started here (for example when the tab is closed).
	 */
	const CRON_TAKEOVER = 90;

	/** Most ids one allow_clean request accepts. */
	const ALLOW_CLEAN_MAX = 50;

	/** Most pending uploads clean_images looks at. */
	const CLEAN_SCAN_MAX = 5000;

	public function register() {
		$endpoints = array( 'scan_start', 'scan_tick', 'scan_status', 'scan_cancel', 'item_action', 'bulk_action', 'counts', 'unlock', 'lock', 'diff_summary', 'clamav_enable', 'clean_images', 'allow_clean' );
		foreach ( $endpoints as $endpoint ) {
			add_action( 'wp_ajax_wpcybersec_' . $endpoint, array( $this, $endpoint ) );
		}
	}

	/**
	 * Nonce + capability gate.
	 */
	private function guard() {
		if ( ! check_ajax_referer( self::NONCE, '_ajax_nonce', false ) ) {
			wp_send_json_error( array( 'message' => __( 'Your session expired. Reload the page and try again.', 'qartvelo-guard' ) ), 403 );
		}
		if ( ! Admin\Admin::can() ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'qartvelo-guard' ) ), 403 );
		}
	}

	/**
	 * @param string $key     Request key.
	 * @param string $default Default.
	 * @return string
	 */
	private function param( $key, $default = '' ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
		return isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : $default;
	}

	public function scan_start() {
		$this->guard();
		$mode = $this->param( 'mode', 'incremental' );
		if ( ! in_array( $mode, array( 'incremental', 'full', 'baseline' ), true ) ) {
			$mode = 'incremental';
		}
		$job    = wpcybersec()->scan_job;
		$before = $job->status();
		$opts   = array(
			'mode'    => $mode,
			'malware' => '1' === $this->param( 'malware', '1' ),
			'trigger' => $this->param( 'trigger', 'manual' ),
		);
		$db     = $this->param( 'database', '' );
		if ( '' !== $db ) {
			// "Scan database" option; without it full and baseline scans include the database.
			$opts['database'] = '1' === $db;
		}
		$id = $job->start( $opts );
		if ( is_wp_error( $id ) ) {
			wp_send_json_error( array( 'message' => $id->get_error_message() ) );
		}
		$status = $job->status();
		$this->keep_alive( $status );

		// Scan_Job::start() returns the id of a scan that is already running instead of starting a new one.
		$attached            = isset( $before['state'], $before['id'] ) && in_array( (string) $before['state'], self::RUNNING, true ) && (string) $before['id'] === (string) $id;
		$status['requested'] = $mode;
		$status['attached']  = $attached;
		$status['notice']    = '';
		if ( $attached && (string) $status['mode'] !== $mode ) {
			$status['notice'] = sprintf(
				/* translators: 1: mode of the scan that is running, 2: mode of the scan that was asked for */
				__( 'A %1$s scan is already running, so the %2$s scan could not start yet. Showing the running scan instead.', 'qartvelo-guard' ),
				self::mode_label( (string) $status['mode'] ),
				self::mode_label( $mode )
			);
		}
		wp_send_json_success( $status );
	}

	public function scan_tick() {
		$this->guard();
		$budget = (float) wpcybersec()->settings->get( 'tick_seconds', 15 );
		$status = wpcybersec()->scan_job->tick( min( 20.0, max( 3.0, $budget ) ) );
		$this->keep_alive( $status );
		wp_send_json_success( $status );
	}

	/**
	 * Keeps one cron tick queued about CRON_TAKEOVER seconds ahead while a scan
	 * runs, so a scan driven from the browser carries on in the background
	 * (File_Monitor handles the hook and chains further ticks) when the page is
	 * closed. While the browser keeps ticking, the event keeps moving forward and
	 * never fires, so the browser and cron do not tick at the same time.
	 *
	 * @param array $status Scan status.
	 */
	private function keep_alive( array $status ) {
		if ( ! in_array( isset( $status['state'] ) ? (string) $status['state'] : '', self::RUNNING, true ) ) {
			return;
		}
		$hook = File_Monitor::TICK_HOOK;
		$next = Network::next_scheduled( $hook );
		// Rewriting the cron option on every tick is wasteful: only move the event when it is getting close.
		if ( $next && ( $next - time() ) > self::CRON_TAKEOVER / 2 ) {
			return;
		}
		if ( $next ) {
			Network::unschedule_event( $next, $hook );
		}
		Network::schedule_single( time() + self::CRON_TAKEOVER, $hook );
	}

	/**
	 * @param string $mode incremental | full | baseline.
	 * @return string Human name of a scan mode.
	 */
	private static function mode_label( $mode ) {
		switch ( $mode ) {
			case 'baseline':
				return __( 'baseline', 'qartvelo-guard' );
			case 'full':
				return __( 'full malware', 'qartvelo-guard' );
			default:
				return __( 'quick', 'qartvelo-guard' );
		}
	}

	public function scan_status() {
		$this->guard();
		wp_send_json_success( wpcybersec()->scan_job->status() );
	}

	public function scan_cancel() {
		$this->guard();
		wpcybersec()->scan_job->cancel();
		// Nothing left to continue in the background.
		Network::clear_hook( File_Monitor::TICK_HOOK );
		wp_send_json_success( wpcybersec()->scan_job->status() );
	}

	public function item_action() {
		$this->guard();
		$action = $this->param( 'do' );
		$id     = (int) $this->param( 'id', '0' );
		$this->require_risk_confirm( $action, array( $id ) );
		$result = wpcybersec()->decisions->apply( $action, $id );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		$item = wpcybersec()->store->item_get( $id );
		// Extra instructions for the admin (for example "upload the plugin ZIP again"); empty when there are none.
		$message = ( 'approve' === $action && $item && ! empty( $item['details']['approval_note'] ) ) ? (string) $item['details']['approval_note'] : '';
		wp_send_json_success(
			array(
				'item'      => $item ? self::public_item( $item ) : $item,
				'available' => $item ? Decisions::available( $item ) : array(),
				'counts'    => wpcybersec()->store->counts(),
				'message'   => $message,
			)
		);
	}

	/**
	 * An item as sent to the browser: the malware match snippets (excerpts of
	 * the file, which may hold a password) are redacted like on the page.
	 *
	 * @param array $item Item.
	 * @return array
	 */
	private static function public_item( array $item ) {
		if ( empty( $item['details']['hits'] ) || ! is_array( $item['details']['hits'] ) ) {
			return $item;
		}
		$name = basename( (string) $item['path'] );
		foreach ( $item['details']['hits'] as $k => $hit ) {
			if ( is_array( $hit ) && isset( $hit['snippet'] ) ) {
				$item['details']['hits'][ $k ]['snippet'] = Diff::redact_snippet( (string) $hit['snippet'], ! empty( $hit['file'] ) ? basename( (string) $hit['file'] ) : $name );
			}
		}
		return $item;
	}

	public function bulk_action() {
		$this->guard();
		$action = $this->param( 'do' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
		$ids    = isset( $_POST['ids'] ) ? array_map( 'intval', (array) wp_unslash( $_POST['ids'] ) ) : array();
		if ( count( $ids ) > Admin\Admin::MAX_BULK ) {
			/* translators: %s: number of items */
			wp_send_json_error( array( 'message' => sprintf( __( 'Select at most %s items at a time.', 'qartvelo-guard' ), number_format_i18n( Admin\Admin::MAX_BULK ) ) ) );
		}
		$this->require_risk_confirm( $action, $ids );
		$result = wpcybersec()->decisions->bulk( $action, $ids );
		$result['counts'] = wpcybersec()->store->counts();
		wp_send_json_success( $result );
	}

	/**
	 * Allowing (or marking safe) an item flagged high or critical needs the
	 * confirmation of the Reports page dialog (risk_ok=1); answers with error
	 * code "confirm" otherwise. WP-CLI and Decisions themselves are not
	 * affected.
	 *
	 * @param string $action Decision.
	 * @param int[]  $ids    Item ids.
	 */
	private function require_risk_confirm( $action, array $ids ) {
		if ( ! in_array( $action, array( 'approve', 'ignore' ), true ) || '1' === $this->param( 'risk_ok' ) ) {
			return;
		}
		$risky = Admin\Admin::risky_items( $ids );
		if ( ! $risky ) {
			return;
		}
		$text = Admin\Admin::risk_confirm_text( $risky[0] );
		wp_send_json_error(
			array(
				'code'    => 'confirm',
				'message' => $text['verdict'] . '. ' . __( 'Confirm on the Reports page before allowing a file flagged high or critical.', 'qartvelo-guard' ),
			)
		);
	}

	/**
	 * Pending uploads that "Allow all clean images" may approve (verified
	 * images without any finding, see Upload_Gate::is_clean_image()).
	 */
	public function clean_images() {
		$this->guard();
		$gate  = wpcybersec()->upload_gate;
		$store = wpcybersec()->store;
		$start = microtime( true );
		$ids   = array();
		$more  = false;
		$page  = 1;
		$seen  = 0;
		do {
			$result = $store->items_query(
				array(
					'type'     => Store::TYPE_UPLOAD,
					'status'   => Store::STATUS_PENDING,
					'orderby'  => 'id',
					'order'    => 'ASC',
					'per_page' => 200,
					'page'     => $page,
				)
			);
			$rows = isset( $result['rows'] ) ? (array) $result['rows'] : array();
			foreach ( $rows as $item ) {
				++$seen;
				if ( $gate->is_clean_image( $item ) ) {
					$ids[] = (int) $item['id'];
				}
			}
			++$page;
			if ( $seen >= self::CLEAN_SCAN_MAX || microtime( true ) - $start > 10.0 ) {
				$more = count( $rows ) >= 200;
				break;
			}
		} while ( count( $rows ) >= 200 );
		wp_send_json_success(
			array(
				'ids'   => $ids,
				'count' => count( $ids ),
				'more'  => $more,
			)
		);
	}

	/**
	 * Approves clean images in batches (each is imported into the Media
	 * Library like a single Allow). Every id is checked again here, so the
	 * list from clean_images() cannot be stretched to anything else.
	 */
	public function allow_clean() {
		$this->guard();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
		$ids      = isset( $_POST['ids'] ) ? array_slice( array_values( array_unique( array_filter( array_map( 'intval', (array) wp_unslash( $_POST['ids'] ) ) ) ) ), 0, self::ALLOW_CLEAN_MAX ) : array();
		$plugin   = wpcybersec();
		$budget   = self::allow_budget();
		$start    = microtime( true );
		$done     = 0;
		$skip     = 0;
		$errors   = array();
		$approved = array();
		$left     = $ids;
		foreach ( $ids as $id ) {
			if ( $done + $skip + count( $errors ) > 0 && microtime( true ) - $start > $budget ) {
				break;
			}
			array_shift( $left );
			$item = $plugin->store->item_get( $id );
			if ( ! $item || ! $plugin->upload_gate->is_clean_image( $item ) ) {
				++$skip;
				continue;
			}
			$result = $plugin->decisions->bulk( 'approve', array( $id ) );
			if ( ! empty( $result['done'] ) ) {
				++$done;
				$approved[] = $id;
			}
			if ( ! empty( $result['errors'] ) ) {
				$errors = array_merge( $errors, array_map( 'strval', (array) $result['errors'] ) );
			}
		}
		wp_send_json_success(
			array(
				'done'      => $done,
				'approved'  => $approved,
				'skipped'   => $skip,
				'errors'    => array_slice( $errors, 0, 20 ),
				'remaining' => array_values( $left ),
				'counts'    => $plugin->store->counts(),
			)
		);
	}

	/**
	 * Seconds one allow_clean request may spend on imports: well inside
	 * max_execution_time (thumbnails of a large photo take seconds).
	 *
	 * @return float
	 */
	private static function allow_budget() {
		$max = (int) ini_get( 'max_execution_time' );
		if ( $max <= 0 ) {
			return 15.0;
		}
		return max( 2.0, min( 15.0, $max / 3 ) );
	}

	public function counts() {
		$this->guard();
		wp_send_json_success( wpcybersec()->store->counts() );
	}

	/**
	 * "+N -M lines vs ..." for the expandable details of one report (computed
	 * only when the details are opened; never downloads anything).
	 */
	public function diff_summary() {
		$this->guard();
		$id   = (int) $this->param( 'id', '0' );
		$item = $id > 0 ? wpcybersec()->store->item_get( $id ) : null;
		if ( ! $item ) {
			wp_send_json_error( array( 'message' => __( 'Item not found.', 'qartvelo-guard' ) ) );
		}
		try {
			wp_send_json_success( Diff::summary( $item ) );
		} catch ( \Throwable $e ) {
			wp_send_json_error( array( 'message' => __( 'The changes could not be compared.', 'qartvelo-guard' ) ) );
		}
	}

	public function unlock() {
		$this->guard();
		if ( Install_Gate::mods_disallowed() ) {
			// DISALLOW_FILE_MODS in wp-config.php blocks installs and updates whatever the lock says.
			wp_send_json_error( array( 'message' => __( 'File changes cannot be unlocked: wp-config.php sets DISALLOW_FILE_MODS, so WordPress allows no plugin, theme or core installs and updates. Remove that line to install or update.', 'qartvelo-guard' ) ) );
		}
		$minutes = (int) $this->param( 'minutes', (string) wpcybersec()->settings->get( 'unlock_minutes', 15 ) );
		wpcybersec()->install_gate->unlock( $minutes );
		wp_send_json_success( array( 'unlocked_until' => wpcybersec()->install_gate->unlocked_until() ) );
	}

	public function lock() {
		$this->guard();
		wpcybersec()->install_gate->lock();
		wp_send_json_success( array( 'unlocked_until' => 0 ) );
	}

	/**
	 * One-click "Turn on ClamAV for uploads" (Settings, Dashboard, wizard).
	 */
	public function clamav_enable() {
		$this->guard();
		$scanner = wpcybersec()->scanner;
		if ( ! $scanner || ! method_exists( $scanner, 'clamav_available' ) || ! $scanner->clamav_available() ) {
			wp_send_json_error( array( 'message' => __( 'ClamAV is not ready on this server, so it was not turned on. Settings > Advanced > Antivirus engines shows what is missing.', 'qartvelo-guard' ) ) );
		}
		wpcybersec()->settings->update( array( 'clamav_enabled' => true ) );
		$info    = $scanner->clamav_info();
		$message = ! empty( $info['daemon'] )
			? __( 'ClamAV is on: it now checks every upload, and whole-site scans use it too.', 'qartvelo-guard' )
			: __( 'ClamAV is on: it now checks every upload.', 'qartvelo-guard' );
		wpcybersec()->logger->log( 'clamav_enabled', $message );
		wp_send_json_success( array( 'message' => $message ) );
	}
}
