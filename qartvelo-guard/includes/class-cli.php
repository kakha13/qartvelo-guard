<?php
/**
 * WP-CLI commands: wp wpcybersec <subcommand>.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Scan the site, review held files and manage Qartvelo Guard.
 *
 * ## EXAMPLES
 *
 *     # Show what is protected and what waits for a decision.
 *     $ wp wpcybersec status
 *
 *     # Run a quick scan of new and changed files.
 *     $ wp wpcybersec scan
 *
 *     # Approve two held uploads.
 *     $ wp wpcybersec approve 12 13
 */
class Cli {

	/**
	 * Registers the command (called by Plugin::boot() when WP-CLI runs).
	 */
	public static function register() {
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command(
			'wpcybersec',
			__CLASS__,
			array( 'shortdesc' => 'Scan the site, review held files and manage Qartvelo Guard.' )
		);
		// The WP-CLI variant of the real cron jobs runs "wp cron event run" every
		// 5 minutes: that proves real cron as well as bin/cron.php does.
		\WP_CLI::add_hook( 'after_invoke:cron event run', array( __CLASS__, 'record_cron_run' ) );
	}

	/**
	 * Records that real cron runs (network option wpcybersec_cli_cron_at, also
	 * written by bin/cron.php), so Settings > Advanced > Real cron shows "Real cron
	 * last ran" and offers to switch off visitor-triggered cron. Only for runs
	 * without a terminal or with --quiet (how crontab lines run): a command typed
	 * once by hand proves nothing about a cron job.
	 */
	public static function record_cron_run() {
		$quiet = class_exists( '\WP_CLI' ) && \WP_CLI::get_config( 'quiet' );
		$tty   = function_exists( 'posix_isatty' ) && defined( 'STDOUT' ) && @posix_isatty( STDOUT ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $quiet || ! $tty ) {
			Network::update_option( 'wpcybersec_cli_cron_at', time(), false );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Helpers (private, so WP-CLI does not expose them as subcommands)    */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $name Service name.
	 * @return object Service; exits with an error when the module is missing.
	 */
	private function service( $name ) {
		$service = Sysadmin_Tools::service( $name );
		if ( ! $service ) {
			/* translators: %s: module name */
			\WP_CLI::error( sprintf( __( 'The %s module is not available.', 'qartvelo-guard' ), $name ) );
		}
		return $service;
	}

	/**
	 * @param array  $assoc_args Arguments.
	 * @param string $key        Key.
	 * @param mixed  $default    Default.
	 * @return mixed
	 */
	private function flag( array $assoc_args, $key, $default = null ) {
		if ( function_exists( '\WP_CLI\Utils\get_flag_value' ) ) {
			return \WP_CLI\Utils\get_flag_value( $assoc_args, $key, $default );
		}
		return isset( $assoc_args[ $key ] ) ? $assoc_args[ $key ] : $default;
	}

	/**
	 * @param string $format Format.
	 * @param array  $rows   Rows.
	 * @param array  $fields Columns.
	 */
	private function output( $format, array $rows, array $fields ) {
		if ( 'count' === $format ) {
			\WP_CLI::line( (string) count( $rows ) );
			return;
		}
		if ( 'ids' === $format ) {
			\WP_CLI::line( implode( ' ', array_column( $rows, 'id' ) ) );
			return;
		}
		\WP_CLI\Utils\format_items( $format, $rows, $fields );
	}

	/**
	 * @param int $timestamp Unix time.
	 * @return string Local date and time.
	 */
	private function when( $timestamp ) {
		$timestamp = (int) $timestamp;
		if ( $timestamp <= 0 ) {
			return '-';
		}
		return wp_date( 'Y-m-d H:i:s', $timestamp );
	}

	/**
	 * @param array $status Scan status.
	 * @return bool
	 */
	private function is_running( $status ) {
		return is_array( $status ) && isset( $status['state'] ) && in_array( $status['state'], array( 'enumerating', 'processing', 'finishing' ), true );
	}

	/* ------------------------------------------------------------------ */
	/* status                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Shows the protection settings, what waits for a decision, the last scan and the early guard.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec status
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function status( $args, $assoc_args ) {
		unset( $args );
		$settings = $this->service( 'settings' );
		$s        = $settings->all();
		$store    = Sysadmin_Tools::service( 'store' );
		$counts   = $store ? $store->counts() : array();
		$last     = Sysadmin_Tools::call( 'scan_job', 'last_result', array(), array() );
		$current  = Sysadmin_Tools::call( 'scan_job', 'status', array(), array() );
		$guard    = Sysadmin_Tools::call( 'guard_manager', 'status', array(), null );
		$until    = (int) Sysadmin_Tools::call( 'install_gate', 'unlocked_until', array(), 0 );

		$rows = array(
			array( 'setting' => 'protection_level', 'value' => $s['protection_level'] ),
			array( 'setting' => 'upload_mode', 'value' => $s['upload_mode'] ),
			array( 'setting' => 'upload_bypass_roles', 'value' => $s['upload_bypass_roles'] ? implode( ', ', $s['upload_bypass_roles'] ) : '-' ),
			array( 'setting' => 'install_mode', 'value' => $s['install_mode'] ),
			array( 'setting' => 'file_mode', 'value' => $s['file_mode'] ),
			array( 'setting' => 'scan_schedule', 'value' => $s['scan_schedule'] ),
			array( 'setting' => 'notify_mode', 'value' => $s['notify_mode'] . ' (' . implode( ', ', $settings->recipients() ) . ')' ),
			array( 'setting' => 'freeze_mods', 'value' => $s['freeze_mods'] ? ( $until > time() ? 'on, unlocked until ' . $this->when( $until ) : 'on, locked' ) : 'off' ),
			array( 'setting' => 'wizard_completed', 'value' => $s['wizard_completed'] ? 'yes' : 'no' ),
			array( 'setting' => 'pending_approvals', 'value' => isset( $counts['pending'] ) ? (int) $counts['pending'] : 0 ),
			array( 'setting' => 'open_threats', 'value' => isset( $counts['threats'] ) ? (int) $counts['threats'] : 0 ),
			array( 'setting' => 'in_quarantine', 'value' => isset( $counts['quarantined'] ) ? (int) $counts['quarantined'] : 0 ),
			array( 'setting' => 'files_monitored', 'value' => $store ? (int) $store->manifest_count() : 0 ),
			array( 'setting' => 'baseline', 'value' => (int) Network::get_option( 'wpcybersec_baseline_at', 0 ) > 0 ? 'recorded ' . $this->when( (int) Network::get_option( 'wpcybersec_baseline_at', 0 ) ) : 'none yet (the next whole-site scan records it)' ),
			array( 'setting' => 'allowlist_entries', 'value' => (int) Sysadmin_Tools::call( 'allowlist', 'count', array(), 0 ) ),
			array( 'setting' => 'scan_root', 'value' => Paths::scan_root() ),
			array( 'setting' => 'data_dir', 'value' => $settings && Sysadmin_Tools::service( 'storage' ) ? Sysadmin_Tools::service( 'storage' )->data_dir() : '-' ),
		);

		if ( $this->is_running( $current ) ) {
			$rows[] = array(
				'setting' => 'scan_running',
				'value'   => sprintf( '%s, %d of %d files', $current['mode'], (int) $current['files_done'], (int) $current['files_total'] ),
			);
		}
		if ( is_array( $last ) && ! empty( $last['finished_at'] ) ) {
			$rows[] = array(
				'setting' => 'last_scan',
				'value'   => sprintf(
					'%s %s at %s: %d files, %d new, %d modified, %d threats',
					isset( $last['mode'] ) ? $last['mode'] : '',
					isset( $last['state'] ) ? $last['state'] : '',
					$this->when( $last['finished_at'] ),
					isset( $last['files_total'] ) ? (int) $last['files_total'] : 0,
					isset( $last['new'] ) ? (int) $last['new'] : 0,
					isset( $last['modified'] ) ? (int) $last['modified'] : 0,
					isset( $last['threats'] ) ? (int) $last['threats'] : 0
				),
			);
		} else {
			$rows[] = array(
				'setting' => 'last_scan',
				'value'   => 'never',
			);
		}
		if ( is_array( $guard ) ) {
			$rows[] = array(
				'setting' => 'early_guard',
				'value'   => ! empty( $guard['installed'] ) ? 'installed' . ( ! empty( $guard['prepend'] ) ? ', prepend ' . $guard['prepend'] : ', auto_prepend_file not set for this SAPI' ) : 'not installed',
			);
		}
		$this->output( $this->flag( $assoc_args, 'format', 'table' ), $rows, array( 'setting', 'value' ) );
	}

	/* ------------------------------------------------------------------ */
	/* scan                                                                */
	/* ------------------------------------------------------------------ */

	/**
	 * Runs a scan to completion.
	 *
	 * Without options, only new and changed files are checked (quick). If a scan
	 * is already running, this command waits for it and reports its result.
	 *
	 * ## OPTIONS
	 *
	 * [--full]
	 * : Also re-check unchanged files for malware.
	 *
	 * [--baseline]
	 * : Trust every current file (rebuild the fingerprint baseline). Files with malware are still reported as threats.
	 *
	 * [--malware]
	 * : Check files for malware signatures. On by default; use --no-malware to only detect new and changed files.
	 *
	 * [--database]
	 * : Also scan the database (options and posts) for injected code. On by default for --full and --baseline; use --no-database to skip it, or --database to add it to a quick scan.
	 *
	 * [--isolated]
	 * : Not available here: a scan where other plugins and the theme cannot run has to start before WordPress loads them. Use the standalone runner instead: php wp-content/plugins/qartvelo-guard/bin/cron.php --isolated [--full]
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec scan
	 *     $ wp wpcybersec scan --full
	 *     $ wp wpcybersec scan --baseline --no-malware
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function scan( $args, $assoc_args ) {
		unset( $args );
		if ( isset( $assoc_args['isolated'] ) ) {
			\WP_CLI::error(
				sprintf(
					/* translators: %s: command */
					__( 'WP-CLI has already loaded the active plugins and the theme, so this scan cannot isolate them. Run the isolated scan with the standalone runner: %s', 'qartvelo-guard' ),
					Sysadmin_Tools::php_command() . ' ' . Sysadmin_Tools::shell_arg( WPCYBERSEC_DIR . 'bin/cron.php' ) . ' --isolated --full --wp=' . Sysadmin_Tools::shell_arg( untrailingslashit( ABSPATH ) ) . ( is_multisite() ? ' --url=' . Sysadmin_Tools::shell_arg( network_home_url( '/' ) ) : '' )
				)
			);
		}
		$job      = $this->service( 'scan_job' );
		$full     = (bool) $this->flag( $assoc_args, 'full', false );
		$baseline = (bool) $this->flag( $assoc_args, 'baseline', false );
		$malware  = (bool) $this->flag( $assoc_args, 'malware', true );
		if ( $full && $baseline ) {
			\WP_CLI::error( __( 'Use either --full or --baseline, not both.', 'qartvelo-guard' ) );
		}
		$mode = $baseline ? 'baseline' : ( $full ? 'full' : 'incremental' );

		$opts = array(
			'mode'    => $mode,
			'malware' => $malware,
			'trigger' => 'cli',
		);
		if ( isset( $assoc_args['database'] ) ) {
			$opts['database'] = (bool) $this->flag( $assoc_args, 'database', false );
		}
		$id = $job->start( $opts );
		if ( is_wp_error( $id ) ) {
			\WP_CLI::error( $id->get_error_message() );
		}
		$status = $job->status();
		if ( is_array( $status ) && isset( $status['mode'] ) && $status['mode'] !== $mode && $this->is_running( $status ) ) {
			/* translators: %s: scan mode */
			\WP_CLI::warning( sprintf( __( 'Another scan (%s) is already running. Waiting for it to finish; run this command again afterwards.', 'qartvelo-guard' ), $status['mode'] ) );
		}

		$bar      = null;
		$done     = 0;
		$last_log = 0;
		$progress = function ( $status ) use ( &$bar, &$done, &$last_log ) {
			if ( ! is_array( $status ) || empty( $status['state'] ) ) {
				return;
			}
			if ( 'enumerating' === $status['state'] && time() - $last_log >= 5 ) {
				$last_log = time();
				/* translators: %s: number of files */
				\WP_CLI::log( sprintf( __( 'Listing files: %s found so far', 'qartvelo-guard' ), number_format_i18n( (int) $status['files_total'] ) ) );
			}
			if ( 'processing' === $status['state'] && (int) $status['files_total'] > 0 ) {
				if ( null === $bar ) {
					$bar  = \WP_CLI\Utils\make_progress_bar( __( 'Checking files', 'qartvelo-guard' ), (int) $status['files_total'] );
					$done = 0;
				}
				$delta = (int) $status['files_done'] - $done;
				if ( $delta > 0 ) {
					$bar->tick( $delta );
					$done += $delta;
				}
			}
		};

		if ( method_exists( $job, 'run_to_completion' ) ) {
			$final = $job->run_to_completion( $progress );
		} else {
			$settings = Sysadmin_Tools::service( 'settings' );
			$budget   = $settings ? (float) $settings->get( 'tick_seconds', 15 ) : 15.0;
			$final    = $job->status();
			while ( $this->is_running( $final ) ) {
				$final = $job->tick( $budget );
				$progress( $final );
			}
		}
		if ( $bar ) {
			$bar->finish();
		}
		if ( ! is_array( $final ) || empty( $final['state'] ) ) {
			$final = $job->status();
		}

		$state = isset( $final['state'] ) ? $final['state'] : 'unknown';
		if ( 'unknown' !== $state ) {
			self::record_cron_run(); // The WP-CLI cron lines run "wp wpcybersec scan --quiet", like bin/cron.php any run counts.
		}
		if ( 'failed' === $state ) {
			/* translators: %s: error message */
			\WP_CLI::error( sprintf( __( 'Scan failed: %s', 'qartvelo-guard' ), isset( $final['message'] ) ? $final['message'] : '' ) );
		}
		if ( 'cancelled' === $state ) {
			\WP_CLI::error( __( 'Scan was cancelled.', 'qartvelo-guard' ) );
		}

		$summary = array();
		foreach ( array( 'files_total', 'new', 'modified', 'deleted', 'threats', 'quarantined', 'skipped' ) as $key ) {
			$summary[] = array(
				'result' => $key,
				'count'  => isset( $final[ $key ] ) ? (int) $final[ $key ] : 0,
			);
		}
		\WP_CLI\Utils\format_items( 'table', $summary, array( 'result', 'count' ) );

		$threats = isset( $final['threats'] ) ? (int) $final['threats'] : 0;
		if ( $threats > 0 ) {
			/* translators: %d: number of threats */
			\WP_CLI::warning( sprintf( _n( '%d possible threat found. Review it with: wp wpcybersec pending --type=threat', '%d possible threats found. Review them with: wp wpcybersec pending --type=threat', $threats, 'qartvelo-guard' ), $threats ) );
			return;
		}
		\WP_CLI::success( __( 'Scan complete.', 'qartvelo-guard' ) );
	}

	/* ------------------------------------------------------------------ */
	/* report                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Creates the security report (one self-contained HTML file).
	 *
	 * It holds the scan results, open items with their code, settings,
	 * environment checks and recent activity. Secret values are hidden and
	 * email addresses shortened, so it is safe to send to a developer.
	 *
	 * ## OPTIONS
	 *
	 * [--file=<path>]
	 * : Write the report to this file. Without it, the HTML is printed (redirect it to a file).
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec report --file=/tmp/security-report.html
	 *     $ wp wpcybersec report > report.html
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function report( $args, $assoc_args ) {
		unset( $args );
		$html = ( new Site_Report() )->build();
		$file = (string) $this->flag( $assoc_args, 'file', '' );
		if ( '' === $file ) {
			\WP_CLI::line( $html );
			return;
		}
		if ( is_dir( $file ) ) {
			$file = trailingslashit( $file ) . Site_Report::filename();
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- CLI output file chosen by the operator.
		if ( false === @file_put_contents( $file, $html ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			/* translators: %s: file path */
			\WP_CLI::error( sprintf( __( 'Could not write %s.', 'qartvelo-guard' ), $file ) );
		}
		@chmod( $file, 0600 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_chmod
		wpcybersec()->logger->log( 'report_downloaded', __( 'Created the security report with WP-CLI.', 'qartvelo-guard' ) );
		/* translators: 1: file path, 2: size */
		\WP_CLI::success( sprintf( __( 'Report written to %1$s (%2$s).', 'qartvelo-guard' ), $file, size_format( strlen( $html ), 1 ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* core-reinstall                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Replaces WordPress core (wp-admin, wp-includes and the core files in the WordPress folder) with the verified official files of the installed version.
	 *
	 * Downloads the no-content package from wordpress.org, checks every file
	 * against the official checksums, then swaps core with maintenance mode on.
	 * When the site does not answer afterwards, the old core is put back. The
	 * old core is kept as a backup for 7 days (Dashboard > Restore the previous
	 * core). wp-config.php, wp-content and every other file stay as they are.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Do not ask for confirmation before the swap.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec core-reinstall
	 *     $ wp wpcybersec core-reinstall --yes
	 *
	 * @subcommand core-reinstall
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function core_reinstall( $args, $assoc_args ) {
		unset( $args );
		$repair = $this->service( 'core_repair' );
		$damage = $repair->damage();
		/* translators: 1: number of files, 2: changed, 3: threats, 4: extra, 5: missing */
		\WP_CLI::log( sprintf( __( 'Core files affected: %1$s (%2$s changed, %3$s threats, %4$s extra files in wp-admin or wp-includes, %5$s missing).', 'qartvelo-guard' ), $damage['total'], $damage['modified'], $damage['threats'], $damage['unknown'], $damage['missing'] ) );

		$state = $repair->start();
		while ( ! is_wp_error( $state ) && isset( $state['step'] ) && in_array( $state['step'], array( 'download', 'extract', 'verify' ), true ) ) {
			$public = Core_Repair::public_state( $state );
			\WP_CLI::log( $public['label'] . ' (' . $public['percent'] . '%)' );
			$state = $repair->tick();
		}
		if ( is_wp_error( $state ) ) {
			\WP_CLI::error( $state->get_error_message() );
		}
		if ( ! isset( $state['step'] ) || 'ready' !== $state['step'] ) {
			\WP_CLI::error( isset( $state['message'] ) && '' !== $state['message'] ? $state['message'] : __( 'The package could not be prepared.', 'qartvelo-guard' ) );
		}
		$confirm = Core_Repair::confirm_text( $state );
		\WP_CLI::log( $confirm['text'] );
		\WP_CLI::log( $confirm['verdict'] );
		if ( ! $this->flag( $assoc_args, 'yes', false ) ) {
			// WP_CLI::confirm() exits on "no"; the verified package must be cleaned up first.
			fwrite( STDOUT, $confirm['title'] . ' [y/n] ' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- interactive CLI prompt.
			$answer = strtolower( trim( (string) fgets( STDIN ) ) );
			if ( 'y' !== $answer && 'yes' !== $answer ) {
				$repair->cancel();
				\WP_CLI::log( __( 'Cancelled. Nothing was changed.', 'qartvelo-guard' ) );
				return;
			}
		}
		$state = $repair->swap();
		while ( ! is_wp_error( $state ) && isset( $state['step'] ) && 'finish' === $state['step'] ) {
			$state = $repair->tick();
		}
		if ( is_wp_error( $state ) ) {
			\WP_CLI::error( $state->get_error_message() );
		}
		if ( ! isset( $state['step'] ) || 'done' !== $state['step'] ) {
			\WP_CLI::error( isset( $state['message'] ) ? (string) $state['message'] : __( 'The reinstall did not finish.', 'qartvelo-guard' ) );
		}
		$repair->dismiss();
		\WP_CLI::success( (string) $state['message'] );
		foreach ( Core_Repair::after_steps() as $step ) {
			\WP_CLI::log( '- ' . $step['text'] . ( ! empty( $step['code'] ) ? ' ' . $step['code'] : '' ) );
		}
		$job = $this->service( 'scan_job' );
		if ( $this->is_running( $job->status() ) ) {
			\WP_CLI::log( __( 'Running the quick scan...', 'qartvelo-guard' ) );
			$final = $job->run_to_completion();
			if ( is_array( $final ) && ! empty( $final['message'] ) ) {
				\WP_CLI::log( (string) $final['message'] );
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/* pending / approve / deny                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Lists items waiting for a decision (held uploads and installs, unknown files, threats).
	 *
	 * ## OPTIONS
	 *
	 * [--type=<type>]
	 * : Only items of this type.
	 * ---
	 * default: all
	 * options:
	 *   - all
	 *   - upload
	 *   - install
	 *   - file
	 *   - threat
	 *   - user
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 *   - ids
	 *   - count
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec pending
	 *     $ wp wpcybersec pending --type=threat --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function pending( $args, $assoc_args ) {
		unset( $args );
		$store = $this->service( 'store' );
		$type  = (string) $this->flag( $assoc_args, 'type', 'all' );
		$types = 'all' === $type ? array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL, Store::TYPE_FILE, Store::TYPE_THREAT, Store::TYPE_USER ) : array( $type );

		$rows = array();
		$page = 1;
		do {
			$result = $store->items_query(
				array(
					'type'     => $types,
					'status'   => Store::STATUS_PENDING,
					'orderby'  => 'id',
					'order'    => 'ASC',
					'per_page' => 500,
					'page'     => $page,
				)
			);
			foreach ( $result['rows'] as $item ) {
				$rows[] = array(
					'id'       => (int) $item['id'],
					'type'     => $item['type'],
					'severity' => Store::severity_label( $item['severity'] ),
					'path'     => Store::TYPE_USER === $item['type']
						? sprintf( '%s (user #%d)', User_Watch::item_login( $item ), User_Watch::item_user_id( $item ) )
						: $item['path'],
					'size'     => $item['size'] ? size_format( (int) $item['size'] ) : '-',
					'source'   => $item['source'],
					'held'     => '' !== (string) $item['quarantine_path'] ? 'yes' : 'no',
					'sha256'   => $item['sha256'],
					'created'  => $item['created_at'] . ' UTC',
				);
			}
			++$page;
		} while ( count( $result['rows'] ) === 500 );

		$format = (string) $this->flag( $assoc_args, 'format', 'table' );
		if ( ! $rows && 'table' === $format ) {
			\WP_CLI::success( __( 'Nothing is waiting for a decision.', 'qartvelo-guard' ) );
			return;
		}
		$fields = 'table' === $format ? array( 'id', 'type', 'severity', 'path', 'size', 'source', 'held', 'created' ) : array( 'id', 'type', 'severity', 'path', 'size', 'source', 'held', 'sha256', 'created' );
		$this->output( $format, $rows, $fields );
	}

	/**
	 * Approves held items. The file's SHA-256 is remembered, so the same file is never held again.
	 *
	 * For threats this marks the file as safe.
	 *
	 * ## OPTIONS
	 *
	 * <id>...
	 * : One or more item IDs (see wp wpcybersec pending).
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec approve 12 13
	 *
	 * @param array $args       Item ids.
	 * @param array $assoc_args Associative arguments.
	 */
	public function approve( $args, $assoc_args ) {
		$this->decide( 'approve', $args, $assoc_args );
	}

	/**
	 * Denies held items.
	 *
	 * Held uploads and installs are rejected and their held copy is deleted.
	 * Unknown files and threats that are still in place are moved to quarantine.
	 *
	 * ## OPTIONS
	 *
	 * <id>...
	 * : One or more item IDs (see wp wpcybersec pending).
	 *
	 * [--delete]
	 * : Permanently delete file and threat items instead (also files already in quarantine).
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec deny 14
	 *     $ wp wpcybersec deny 15 --delete
	 *
	 * @param array $args       Item ids.
	 * @param array $assoc_args Associative arguments.
	 */
	public function deny( $args, $assoc_args ) {
		$this->decide( 'deny', $args, $assoc_args );
	}

	/**
	 * Replaces changed WordPress core files with the official copy of the installed version.
	 *
	 * The current file is kept as a copy, so the change can still be viewed on the Reports page.
	 *
	 * ## OPTIONS
	 *
	 * <id>...
	 * : One or more item IDs of changed core files (see wp wpcybersec threats).
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec restore-official 24
	 *
	 * @subcommand restore-official
	 *
	 * @param array $args       Item ids.
	 * @param array $assoc_args Associative arguments.
	 */
	public function restore_official( $args, $assoc_args ) {
		unset( $assoc_args );
		$store     = $this->service( 'store' );
		$decisions = $this->service( 'decisions' );
		$failed    = 0;
		foreach ( $args as $raw ) {
			$id   = (int) $raw;
			$item = $id > 0 ? $store->item_get( $id ) : null;
			if ( ! $item ) {
				/* translators: %s: item id */
				\WP_CLI::warning( sprintf( __( 'Item #%s not found.', 'qartvelo-guard' ), $raw ) );
				++$failed;
				continue;
			}
			if ( ! in_array( 'restore_official', Decisions::available( $item ), true ) ) {
				/* translators: %d: item id */
				\WP_CLI::warning( sprintf( __( 'Item #%d has no official copy to restore (only changed WordPress core files have one).', 'qartvelo-guard' ), $id ) );
				++$failed;
				continue;
			}
			$result = $decisions->apply( 'restore_official', $id );
			if ( is_wp_error( $result ) ) {
				/* translators: 1: item id, 2: error message */
				\WP_CLI::warning( sprintf( __( 'Item #%1$d: %2$s', 'qartvelo-guard' ), $id, $result->get_error_message() ) );
				++$failed;
				continue;
			}
			/* translators: 1: item id, 2: path */
			\WP_CLI::log( sprintf( __( 'Item #%1$d: the official file is back (%2$s).', 'qartvelo-guard' ), $id, $item['path'] ) );
		}
		if ( $failed ) {
			/* translators: 1: failed items, 2: all items */
			\WP_CLI::error( sprintf( __( '%1$d of %2$d items could not be processed.', 'qartvelo-guard' ), $failed, count( $args ) ) );
		}
		\WP_CLI::success( __( 'Done.', 'qartvelo-guard' ) );
	}

	/**
	 * @param string $verb       approve | deny.
	 * @param array  $ids        Ids.
	 * @param array  $assoc_args Arguments.
	 */
	private function decide( $verb, array $ids, array $assoc_args ) {
		$store     = $this->service( 'store' );
		$decisions = $this->service( 'decisions' );
		$delete    = (bool) $this->flag( $assoc_args, 'delete', false );
		$failed    = 0;

		foreach ( $ids as $raw ) {
			$id   = (int) $raw;
			$item = $id > 0 ? $store->item_get( $id ) : null;
			if ( ! $item ) {
				/* translators: %s: item id */
				\WP_CLI::warning( sprintf( __( 'Item #%s not found.', 'qartvelo-guard' ), $raw ) );
				++$failed;
				continue;
			}
			$available = Decisions::available( $item );
			$action    = '';
			if ( 'approve' === $verb ) {
				if ( in_array( 'approve', $available, true ) ) {
					$action = 'approve';
				} elseif ( in_array( 'ignore', $available, true ) ) {
					$action = 'ignore';
				}
			} elseif ( $delete && in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) {
				$action = in_array( 'delete', $available, true ) ? 'delete' : '';
			} elseif ( in_array( 'deny', $available, true ) ) {
				$action = 'deny';
			} elseif ( in_array( 'quarantine', $available, true ) ) {
				$action = 'quarantine';
			}

			if ( '' === $action ) {
				if ( 'deny' === $verb && ! $delete && '' !== (string) $item['quarantine_path'] ) {
					/* translators: %d: item id */
					\WP_CLI::warning( sprintf( __( 'Item #%d is already in quarantine. Use --delete to delete it permanently.', 'qartvelo-guard' ), $id ) );
				} elseif ( 'deny' === $verb && Store::STATUS_PENDING === $item['status'] && in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) {
					// A critical WordPress file: never quarantined or deleted.
					\WP_CLI::warning( in_array( 'restore_official', $available, true )
						/* translators: 1: item id, 2: item id */
						? sprintf( __( 'Item #%1$d is a critical WordPress file: it cannot be quarantined or deleted. Use `wp wpcybersec restore-official %2$d` to replace it with the official copy, or `approve` to mark it safe.', 'qartvelo-guard' ), $id, $id )
						/* translators: %d: item id */
						: sprintf( __( 'Item #%d is a critical WordPress file: it cannot be quarantined or deleted. Restore it from a backup, or `approve` to mark it safe.', 'qartvelo-guard' ), $id ) );
				} else {
					/* translators: 1: item id, 2: status, 3: verb */
					\WP_CLI::warning( sprintf( __( 'Item #%1$d is %2$s and cannot be %3$s.', 'qartvelo-guard' ), $id, $item['status'], 'approve' === $verb ? __( 'approved', 'qartvelo-guard' ) : __( 'denied', 'qartvelo-guard' ) ) );
				}
				++$failed;
				continue;
			}

			$result = $decisions->apply( $action, $id );
			if ( is_wp_error( $result ) ) {
				/* translators: 1: item id, 2: error message */
				\WP_CLI::warning( sprintf( __( 'Item #%1$d: %2$s', 'qartvelo-guard' ), $id, $result->get_error_message() ) );
				++$failed;
				continue;
			}
			/* translators: 1: item id, 2: action, 3: path */
			\WP_CLI::log( sprintf( __( 'Item #%1$d: %2$s done (%3$s).', 'qartvelo-guard' ), $id, $action, $item['path'] ) );
		}

		if ( $failed ) {
			/* translators: 1: failed items, 2: all items */
			\WP_CLI::error( sprintf( __( '%1$d of %2$d items could not be processed.', 'qartvelo-guard' ), $failed, count( $ids ) ) );
		}
		\WP_CLI::success( __( 'Done.', 'qartvelo-guard' ) );
	}

	/* ------------------------------------------------------------------ */
	/* allowlist                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Lists, adds or removes allowlist entries.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : What to do.
	 * ---
	 * default: list
	 * options:
	 *   - list
	 *   - add
	 *   - remove
	 * ---
	 *
	 * [<value>]
	 * : SHA-256 hash to add, or entry ID to remove.
	 *
	 * [--label=<label>]
	 * : Label for a new entry, usually the file name.
	 *
	 * [--exec]
	 * : Also allow these bytes under an executable name (.php, .phtml, .htaccess...). Without it the hash
	 * only passes for non-executable files such as images, PDFs and ZIP files.
	 *
	 * [--format=<format>]
	 * : Output format for list.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 *   - ids
	 *   - count
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec allowlist list
	 *     $ wp wpcybersec allowlist add 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae --label=logo.svg
	 *     $ wp wpcybersec allowlist add 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --label=helper.php --exec
	 *     $ wp wpcybersec allowlist remove 12
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function allowlist( $args, $assoc_args ) {
		$allowlist = $this->service( 'allowlist' );
		$action    = isset( $args[0] ) ? $args[0] : 'list';
		$value     = isset( $args[1] ) ? trim( (string) $args[1] ) : '';

		if ( 'list' === $action ) {
			$rows = array();
			$page = 1;
			do {
				$result = $allowlist->query(
					array(
						'per_page' => 500,
						'page'     => $page,
					)
				);
				foreach ( $result['rows'] as $row ) {
					$rows[] = array(
						'id'      => (int) $row['id'],
						'kind'    => $row['kind'],
						'value'   => $row['value'],
						'label'   => $row['label'],
						'created' => $row['created_at'] . ' UTC',
					);
				}
				++$page;
			} while ( count( $result['rows'] ) === 500 );
			$this->output( (string) $this->flag( $assoc_args, 'format', 'table' ), $rows, array( 'id', 'kind', 'value', 'label', 'created' ) );
			return;
		}

		if ( 'add' === $action ) {
			if ( ! preg_match( '/^[a-f0-9]{64}$/i', $value ) ) {
				\WP_CLI::error( __( 'Give a SHA-256 hash (64 hexadecimal characters). Get one with: sha256sum <file>', 'qartvelo-guard' ) );
			}
			$label = (string) $this->flag( $assoc_args, 'label', '' );
			$exec  = (bool) $this->flag( $assoc_args, 'exec', false );
			$id    = $allowlist->allow_hash( strtolower( $value ), $label, __( 'Added with WP-CLI', 'qartvelo-guard' ), $exec );
			if ( ! $id ) {
				\WP_CLI::error( __( 'The hash could not be added.', 'qartvelo-guard' ) );
			}
			Sysadmin_Tools::call(
				'logger',
				'log',
				array(
					'allowlist_added',
					sprintf( 'Allowlisted %s with WP-CLI%s.', $label ? $label : $value, $exec ? ' (executable names too)' : '' ),
					array(
						'sha256'     => strtolower( $value ),
						'executable' => $exec,
					),
				)
			);
			if ( $exec ) {
				/* translators: %d: entry id */
				\WP_CLI::success( sprintf( __( 'Allowed. Files with this content will not be held again, including under executable names such as .php (entry #%d).', 'qartvelo-guard' ), $id ) );
			} else {
				/* translators: %d: entry id */
				\WP_CLI::success( sprintf( __( 'Allowed. Files with this content will not be held again under non-executable names (entry #%d). Add --exec to also allow it as a .php or other executable file.', 'qartvelo-guard' ), $id ) );
			}
			return;
		}

		if ( 'remove' === $action ) {
			$id = (int) $value;
			if ( $id <= 0 ) {
				\WP_CLI::error( __( 'Give the entry ID to remove (see wp wpcybersec allowlist list).', 'qartvelo-guard' ) );
			}
			if ( ! $allowlist->remove( $id ) ) {
				/* translators: %d: entry id */
				\WP_CLI::error( sprintf( __( 'Entry #%d not found.', 'qartvelo-guard' ), $id ) );
			}
			/* translators: %d: entry id */
			\WP_CLI::success( sprintf( __( 'Removed entry #%d.', 'qartvelo-guard' ), $id ) );
			return;
		}

		\WP_CLI::error( __( 'Unknown action. Use list, add or remove.', 'qartvelo-guard' ) );
	}

	/* ------------------------------------------------------------------ */
	/* guard                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * Installs, removes or shows the early upload guard (auto_prepend_file).
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : What to do.
	 * ---
	 * default: status
	 * options:
	 *   - install
	 *   - uninstall
	 *   - status
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format for status.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec guard install
	 *     $ wp wpcybersec guard status
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function guard( $args, $assoc_args ) {
		$manager = $this->service( 'guard_manager' );
		$action  = isset( $args[0] ) ? $args[0] : 'status';

		if ( 'status' === $action ) {
			$status = method_exists( $manager, 'status' ) ? $manager->status() : array();
			$rows   = array();
			foreach ( (array) $status as $key => $value ) {
				if ( is_bool( $value ) ) {
					$value = $value ? 'yes' : 'no';
				} elseif ( null === $value || '' === $value ) {
					$value = '-';
				} elseif ( ! is_scalar( $value ) ) {
					$value = wp_json_encode( $value );
				}
				$rows[] = array(
					'key'   => $key,
					'value' => $value,
				);
			}
			$rows[] = array(
				'key'   => 'note',
				'value' => 'WP-CLI runs PHP CLI, which usually has its own auto_prepend_file setting; "active" refers to this CLI process.',
			);
			$this->output( (string) $this->flag( $assoc_args, 'format', 'table' ), $rows, array( 'key', 'value' ) );
			return;
		}

		if ( ! in_array( $action, array( 'install', 'uninstall' ), true ) || ! method_exists( $manager, $action ) ) {
			\WP_CLI::error( __( 'Unknown action. Use install, uninstall or status.', 'qartvelo-guard' ) );
		}
		$result = call_user_func( array( $manager, $action ) );
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}
		if ( false === $result ) {
			\WP_CLI::error( __( 'The action did not complete. Check the permissions of the WordPress folder and the data folder.', 'qartvelo-guard' ) );
		}
		if ( 'install' === $action ) {
			$snippets = method_exists( $manager, 'snippets' ) ? (array) $manager->snippets() : array();
			\WP_CLI::success( __( 'Early guard installed. Point auto_prepend_file at the bootstrap with one of these:', 'qartvelo-guard' ) );
			foreach ( $snippets as $snippet ) {
				if ( is_array( $snippet ) && ! empty( $snippet['code'] ) ) {
					\WP_CLI::log( '' );
					\WP_CLI::log( '# ' . ( isset( $snippet['label'] ) ? $snippet['label'] : '' ) . ( ! empty( $snippet['file'] ) ? ' (' . $snippet['file'] . ')' : '' ) );
					\WP_CLI::log( (string) $snippet['code'] );
				}
			}
			return;
		}
		\WP_CLI::success( __( 'Early guard switched off. Remove auto_prepend_file from the PHP configuration if you added it there.', 'qartvelo-guard' ) );
	}

	/* ------------------------------------------------------------------ */
	/* unlock / lock                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Allows plugin, theme and core changes for a while when freeze mode is on.
	 *
	 * ## OPTIONS
	 *
	 * [--minutes=<minutes>]
	 * : How long. Defaults to the "Unlock for" setting.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec unlock --minutes=30
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function unlock( $args, $assoc_args ) {
		unset( $args );
		$gate     = $this->service( 'install_gate' );
		$settings = $this->service( 'settings' );
		$given    = $this->flag( $assoc_args, 'minutes', null );
		if ( null !== $given && ( ! is_numeric( $given ) || (string) (int) $given !== trim( (string) $given ) || (int) $given < 1 || (int) $given > 1440 ) ) {
			\WP_CLI::error( __( 'Give --minutes as a whole number between 1 and 1440.', 'qartvelo-guard' ) );
		}
		$minutes  = null === $given ? (int) $settings->get( 'unlock_minutes', 15 ) : (int) $given;
		$minutes  = max( 1, min( 1440, $minutes ) );
		if ( Install_Gate::mods_disallowed() ) {
			\WP_CLI::error( __( 'Installs and updates are disabled by the site config (DISALLOW_FILE_MODS in wp-config.php), so there is nothing to unlock.', 'qartvelo-guard' ) );
		}
		$gate->unlock( $minutes );
		$until = method_exists( $gate, 'unlocked_until' ) ? (int) $gate->unlocked_until() : time() + $minutes * MINUTE_IN_SECONDS;
		if ( ! $settings->get( 'freeze_mods', false ) ) {
			\WP_CLI::warning( __( 'Freeze mode is off, so changes are allowed anyway.', 'qartvelo-guard' ) );
		}
		/* translators: %s: date and time */
		\WP_CLI::success( sprintf( __( 'Plugin, theme and core changes are allowed until %s.', 'qartvelo-guard' ), $this->when( $until ) ) );
	}

	/**
	 * Ends an unlock early.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp wpcybersec lock
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function lock( $args, $assoc_args ) {
		unset( $args, $assoc_args );
		$gate = $this->service( 'install_gate' );
		$gate->lock();
		\WP_CLI::success( __( 'Locked. Plugin, theme and core changes are blocked again while freeze mode is on.', 'qartvelo-guard' ) );
	}
}
