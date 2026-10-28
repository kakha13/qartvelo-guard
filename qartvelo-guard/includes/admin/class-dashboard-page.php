<?php
/**
 * Dashboard page: status at a glance, scans, protections and recent activity.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Settings;
use WPCyberSecurity\Store;

defined( 'ABSPATH' ) || exit;

/**
 * Renders the "Qartvelo Guard > Dashboard" screen. Every call into another
 * module goes through Admin::call() so a missing or failing module degrades
 * to "unavailable" instead of breaking the page.
 */
class Dashboard_Page {

	/** @var array Settings merged over defaults. */
	private $s = array();

	/** @var array { pending, threats, quarantined } */
	private $counts = array();

	/** @var array Last finished scan (Scan_Job::last_result()). */
	private $last = array();

	/** @var array Current scan job status. */
	private $job = array();

	/** @var int Trusted manifest rows. */
	private $trusted = 0;

	/**
	 * @var int Unix time the last whole-site baseline finished (0 = never). Other
	 * modules add trusted manifest rows before any baseline exists, so the row
	 * count cannot tell whether one was recorded.
	 */
	private $baseline_at = 0;

	/**
	 * Prints the page.
	 */
	public function render() {
		if ( ! Admin::can() ) {
			wp_die( esc_html__( 'You are not allowed to view this page.', 'qartvelo-guard' ) );
		}
		$this->load();

		echo '<div class="wrap wpcs-wrap wpcs-dashboard" data-wpcs-dashboard>';

		$actions  = '<button type="button" class="button button-primary" data-wpcs-scan data-mode="incremental" data-malware="1">'
			. '<span class="dashicons dashicons-search" aria-hidden="true"></span> ' . esc_html__( 'Run quick scan', 'qartvelo-guard' ) . '</button>';
		$actions .= '<button type="button" class="button" data-wpcs-scan data-mode="full" data-malware="1">'
			. esc_html__( 'Full malware scan', 'qartvelo-guard' ) . '</button>';
		$actions .= '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS ) ) . '">' . esc_html__( 'Reports', 'qartvelo-guard' ) . '</a>';
		$actions .= Admin::report_button();

		Admin::header(
			__( 'Qartvelo Guard', 'qartvelo-guard' ),
			/* translators: %s: site name */
			sprintf( __( 'Malware scanning, upload approval and file integrity for %s', 'qartvelo-guard' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			$actions
		);

		Core_Repair_Card::render( 'dashboard' );
		$this->render_setup_cta();
		$this->render_alerts();
		$this->render_stats();

		echo '<div class="wpcs-dash-cols">';
		echo '<div class="wpcs-stack">';
		$this->render_scan_card();
		$this->render_activity_card();
		echo '</div>';
		echo '<div class="wpcs-stack">';
		$this->render_protection_card();
		$this->render_help_card();
		echo '</div>';
		echo '</div>';

		echo '</div>';
	}

	/**
	 * Loads everything the page needs once.
	 */
	private function load() {
		$defaults = class_exists( '\WPCyberSecurity\Settings' ) ? Settings::defaults() : array();
		$saved    = Admin::call( 'settings', 'all', array(), array() );
		$this->s  = array_merge( $defaults, is_array( $saved ) ? $saved : array() );

		// The small states this page shows are stored without autoload: one query for all of them.
		\WPCyberSecurity\Network::prime_options(
			array(
				'wpcybersec_last_scan',
				'wpcybersec_job',
				'wpcybersec_baseline_at',
				'wpcybersec_core_reinstall',
				'wpcybersec_core_backups',
				'wpcybersec_trusted_admins',
				'wpcybersec_db_scan',
				'wpcybersec_guard_ping_result',
				'wpcybersec_clamav_selftest',
				'wpcybersec_clamav_slow_uploads',
				'wpcybersec_guard_installed',
				'wpcybersec_hosting',
				'wpcybersec_fix_failures',
			)
		);
		$this->counts  = Admin::counts();
		$last          = Admin::call( 'scan_job', 'last_result', array(), array() );
		$this->last    = is_array( $last ) ? $last : array();
		$job           = Admin::call( 'scan_job', 'status', array(), array() );
		$this->job     = is_array( $job ) ? $job : array();
		$this->trusted     = (int) Admin::call( 'store', 'manifest_count', array(), 0 ); // Every fingerprinted file, as the CLI, the report and the wizard count it.
		$this->baseline_at = (int) \WPCyberSecurity\Network::get_option( 'wpcybersec_baseline_at', 0 );
	}

	/**
	 * @param string $key     Setting.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	private function opt( $key, $default = null ) {
		return array_key_exists( $key, $this->s ) ? $this->s[ $key ] : $default;
	}

	/* ------------------------------------------------------------------ */

	/**
	 * Prominent card while the wizard has not been completed.
	 */
	private function render_setup_cta() {
		if ( $this->opt( 'wizard_completed', false ) ) {
			return;
		}
		?>
		<div class="wpcs-card wpcs-card--accent wpcs-setup-cta">
			<div class="wpcs-setup-cta__icon" aria-hidden="true"><span class="dashicons dashicons-admin-tools"></span></div>
			<div class="wpcs-setup-cta__body">
				<h2><?php esc_html_e( 'Finish setting up your protection', 'qartvelo-guard' ); ?></h2>
				<p><?php esc_html_e( 'Uploads and installs are already held with safe defaults. The setup wizard tailors protection to this site and records the files you trust today, so only real changes are reported later.', 'qartvelo-guard' ); ?></p>
				<ul class="wpcs-setup-cta__list">
					<li><span class="dashicons dashicons-yes" aria-hidden="true"></span><?php esc_html_e( 'Choose a protection level', 'qartvelo-guard' ); ?></li>
					<li><span class="dashicons dashicons-yes" aria-hidden="true"></span><?php esc_html_e( 'Record a trusted baseline of your files', 'qartvelo-guard' ); ?></li>
					<li><span class="dashicons dashicons-yes" aria-hidden="true"></span><?php esc_html_e( 'Decide who receives security alerts', 'qartvelo-guard' ); ?></li>
				</ul>
			</div>
			<div class="wpcs-setup-cta__action">
				<a class="button button-primary button-hero" href="<?php echo esc_url( Admin::page_url( Admin::PAGE_WIZARD ) ); ?>"><?php esc_html_e( 'Start the setup wizard', 'qartvelo-guard' ); ?></a>
				<span class="wpcs-sub"><?php esc_html_e( 'Takes about 3 minutes', 'qartvelo-guard' ); ?></span>
			</div>
		</div>
		<?php
	}

	/**
	 * Urgent banners: threats waiting, tampered allowlist.
	 */
	private function render_alerts() {
		if ( $this->counts['threats'] > 0 ) {
			echo '<div class="wpcs-notice wpcs-notice--bad wpcs-dash-alert"><span class="dashicons dashicons-warning" aria-hidden="true"></span><div><p><strong>';
			echo esc_html(
				sprintf(
					/* translators: %s: number of threats */
					_n( '%s possible threat was found on this site.', '%s possible threats were found on this site.', $this->counts['threats'], 'qartvelo-guard' ),
					number_format_i18n( $this->counts['threats'] )
				)
			);
			echo '</strong></p><p>' . esc_html__( 'Review each file: quarantine it if you do not recognize it, or mark it safe if it is a false positive.', 'qartvelo-guard' ) . '</p></div>';
			echo '<a class="button wpcs-dash-alert__btn" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'threats' ) ) ) . '">' . esc_html__( 'Review threats', 'qartvelo-guard' ) . '</a></div>';
		}

		if ( false === Admin::call( 'allowlist', 'verify_integrity', array(), null ) ) {
			echo '<div class="wpcs-notice wpcs-notice--bad wpcs-dash-alert"><span class="dashicons dashicons-shield" aria-hidden="true"></span><div><p><strong>'
				. esc_html__( 'The allowlist was changed outside the plugin.', 'qartvelo-guard' )
				. '</strong></p><p>' . esc_html__( 'Its tamper checksum no longer matches. Someone with database access may have approved files. Check the allowlist and remove entries you do not recognize.', 'qartvelo-guard' ) . '</p></div>'
				. '<a class="button wpcs-dash-alert__btn" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'allowlist' ) ) ) . '">' . esc_html__( 'Check the allowlist', 'qartvelo-guard' ) . '</a></div>';
		}
	}

	/* ------------------------------------------------------------------ */
	/* Status cards                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Six status cards.
	 */
	private function render_stats() {
		echo '<div class="wpcs-stats">';

		// Protection level.
		$level  = (string) $this->opt( 'protection_level', 'balanced' );
		$levels = array(
			'strict'   => __( 'Strict', 'qartvelo-guard' ),
			'balanced' => __( 'Balanced', 'qartvelo-guard' ),
			'relaxed'  => __( 'Relaxed', 'qartvelo-guard' ),
			'custom'   => __( 'Custom', 'qartvelo-guard' ),
		);
		$weak = 'off' === $this->opt( 'upload_mode' ) && 'off' === $this->opt( 'install_mode' );
		$this->stat(
			$weak ? 'warn' : 'ok',
			'shield-alt',
			isset( $levels[ $level ] ) ? $levels[ $level ] : ucfirst( $level ),
			__( 'Protection level', 'qartvelo-guard' ),
			esc_html( $this->protection_summary() ),
			'',
			'wpcs-stat__value--text'
		);

		// Waiting for approval.
		$pending = $this->counts['pending'];
		$this->stat(
			$pending > 0 ? 'warn' : 'ok',
			'clock',
			number_format_i18n( $pending ),
			__( 'Waiting for approval', 'qartvelo-guard' ),
			$pending > 0
				? '<a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'pending' ) ) ) . '">' . esc_html__( 'Review on Reports', 'qartvelo-guard' ) . ' &rarr;</a>'
				: esc_html__( 'Nothing is waiting for you.', 'qartvelo-guard' ),
			'pending'
		);

		// Threats.
		$threats = $this->counts['threats'];
		$this->stat(
			$threats > 0 ? 'bad' : 'ok',
			$threats > 0 ? 'warning' : 'yes-alt',
			number_format_i18n( $threats ),
			__( 'Threats', 'qartvelo-guard' ),
			$threats > 0
				? '<a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'threats' ) ) ) . '">' . esc_html__( 'Review threats', 'qartvelo-guard' ) . ' &rarr;</a>'
				: esc_html__( 'No malware found in the last scans.', 'qartvelo-guard' ),
			'threats'
		);

		// Quarantine.
		$held = $this->counts['quarantined'];
		$this->stat(
			'info',
			'lock',
			number_format_i18n( $held ),
			__( 'In quarantine', 'qartvelo-guard' ),
			$held > 0
				? '<a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'quarantine' ) ) ) . '">' . esc_html__( 'See the held files', 'qartvelo-guard' ) . ' &rarr;</a>'
				: esc_html__( 'No files are held right now.', 'qartvelo-guard' ),
			'quarantined'
		);

		// Files monitored.
		$this->stat(
			$this->baseline_at > 0 ? 'info' : 'warn',
			'media-code',
			number_format_i18n( $this->trusted ),
			__( 'Files monitored', 'qartvelo-guard' ),
			$this->baseline_at > 0
				/* translators: %s: relative time such as "3 days ago" */
				? esc_html( sprintf( __( 'Files with a fingerprint. Baseline recorded %s.', 'qartvelo-guard' ), Admin::ago( $this->baseline_at ) ) )
				: esc_html__( 'No baseline yet. Run the setup wizard or rebuild the baseline.', 'qartvelo-guard' )
		);

		// Last scan.
		$this->render_last_scan_stat();

		echo '</div>';
	}

	/**
	 * One status card.
	 *
	 * @param string $tone        ok | warn | bad | info.
	 * @param string $icon        Dashicon name without prefix.
	 * @param string $value       Main value (plain text).
	 * @param string $label       Label (plain text).
	 * @param string $meta_html   Escaped meta HTML.
	 * @param string $count_key   data-wpcs-count key for live updates ('' for none).
	 * @param string $value_class Extra class for the value.
	 */
	private function stat( $tone, $icon, $value, $label, $meta_html = '', $count_key = '', $value_class = '' ) {
		echo '<div class="wpcs-card wpcs-stat-card wpcs-stat-card--' . esc_attr( $tone ) . '"><div class="wpcs-stat wpcs-stat--' . esc_attr( $tone ) . '">';
		echo '<div class="wpcs-stat__icon" aria-hidden="true"><span class="dashicons dashicons-' . esc_attr( $icon ) . '"></span></div>';
		echo '<div class="wpcs-stat__body">';
		echo '<div class="wpcs-stat__value ' . esc_attr( $value_class ) . '"' . ( $count_key ? ' data-wpcs-count="' . esc_attr( $count_key ) . '"' : '' ) . '>' . esc_html( $value ) . '</div>';
		echo '<div class="wpcs-stat__label">' . esc_html( $label ) . '</div>';
		if ( '' !== $meta_html ) {
			echo '<div class="wpcs-stat__meta">' . wp_kses_post( $meta_html ) . '</div>';
		}
		echo '</div></div></div>';
	}

	/**
	 * "Last scan" card.
	 */
	private function render_last_scan_stat() {
		$finished = $this->last_time();
		if ( ! $finished ) {
			if ( $this->baseline_at > 0 ) {
				$cta = '<button type="button" class="button button-small" data-wpcs-scan data-mode="incremental" data-malware="1">' . esc_html__( 'Run the first scan', 'qartvelo-guard' ) . '</button>';
			} else {
				$cta = '<a class="button button-small" href="' . esc_url( Admin::page_url( Admin::PAGE_WIZARD ) ) . '">' . esc_html__( 'Create a baseline in the wizard', 'qartvelo-guard' ) . '</a>';
			}
			$this->stat_raw( 'warn', 'search', __( 'Never', 'qartvelo-guard' ), __( 'Last scan', 'qartvelo-guard' ), $cta );
			return;
		}

		$state   = isset( $this->last['state'] ) ? (string) $this->last['state'] : 'done';
		$threats = isset( $this->last['threats'] ) ? (int) $this->last['threats'] : 0;
		$tone    = 'ok';
		if ( 'failed' === $state || $threats > 0 ) {
			$tone = 'bad';
		} elseif ( 'cancelled' === $state || time() - $finished > 3 * DAY_IN_SECONDS ) {
			$tone = 'warn';
		}
		$mode = $this->mode_label( isset( $this->last['mode'] ) ? $this->last['mode'] : '' );
		$meta = $mode . ' - ' . $this->result_summary( $this->last );
		if ( 'ok' === $tone && $this->counts['threats'] > 0 ) {
			// The last run found nothing new, but earlier findings are still open.
			$tone  = 'warn';
			$meta .= ' ' . sprintf(
				/* translators: %s: number of threats */
				_n( '%s threat still waits on Reports.', '%s threats still wait on Reports.', $this->counts['threats'], 'qartvelo-guard' ),
				number_format_i18n( $this->counts['threats'] )
			);
		}
		$this->stat( $tone, 'search', Admin::ago( $finished ), __( 'Last scan', 'qartvelo-guard' ), esc_html( $meta ), '', 'wpcs-stat__value--text' );
	}

	/**
	 * Stat card whose meta contains a button (allowed through a narrow kses list).
	 *
	 * @param string $tone      Tone.
	 * @param string $icon      Icon.
	 * @param string $value     Value.
	 * @param string $label     Label.
	 * @param string $meta_html Meta HTML built with escaping.
	 */
	private function stat_raw( $tone, $icon, $value, $label, $meta_html ) {
		echo '<div class="wpcs-card wpcs-stat-card wpcs-stat-card--' . esc_attr( $tone ) . '"><div class="wpcs-stat wpcs-stat--' . esc_attr( $tone ) . '">';
		echo '<div class="wpcs-stat__icon" aria-hidden="true"><span class="dashicons dashicons-' . esc_attr( $icon ) . '"></span></div>';
		echo '<div class="wpcs-stat__body">';
		echo '<div class="wpcs-stat__value wpcs-stat__value--text">' . esc_html( $value ) . '</div>';
		echo '<div class="wpcs-stat__label">' . esc_html( $label ) . '</div>';
		echo '<div class="wpcs-stat__meta">' . wp_kses(
			$meta_html,
			array(
				'a'      => array( 'class' => true, 'href' => true ),
				'button' => array( 'class' => true, 'type' => true, 'data-wpcs-scan' => true, 'data-mode' => true, 'data-malware' => true, 'data-confirm' => true ),
			)
		) . '</div>';
		echo '</div></div></div>';
	}

	/**
	 * One-line summary of the active protections.
	 *
	 * @return string
	 */
	private function protection_summary() {
		$parts   = array();
		$uploads = array(
			'hold_all'   => __( 'All uploads held', 'qartvelo-guard' ),
			'hold_risky' => __( 'Risky uploads held', 'qartvelo-guard' ),
			'scan_only'  => __( 'Uploads scanned', 'qartvelo-guard' ),
			'off'        => __( 'Uploads not checked', 'qartvelo-guard' ),
		);
		$mode    = (string) $this->opt( 'upload_mode', 'hold_all' );
		$parts[] = isset( $uploads[ $mode ] ) ? $uploads[ $mode ] : $uploads['hold_all'];
		$parts[] = 'hold' === $this->opt( 'install_mode' ) ? __( 'new plugins and themes held', 'qartvelo-guard' ) : __( 'installs not held', 'qartvelo-guard' );
		if ( 'quarantine_exec' === $this->opt( 'file_mode' ) ) {
			$parts[] = __( 'unknown scripts quarantined', 'qartvelo-guard' );
		}
		$schedule = (string) $this->opt( 'scan_schedule', 'twicedaily' );
		$parts[]  = 'off' === $schedule
			? __( 'no scheduled scans', 'qartvelo-guard' )
			/* translators: %s: schedule such as "twice daily" */
			: sprintf( __( 'scans %s', 'qartvelo-guard' ), strtolower( $this->schedule_label( $schedule ) ) );
		return implode( ', ', $parts ) . '.';
	}

	/* ------------------------------------------------------------------ */
	/* Scan card                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Scan buttons, progress and last result.
	 */
	private function render_scan_card() {
		$running  = $this->is_running( $this->job );
		$baseline = __( 'Rebuild the baseline? Every file on the server right now is trusted exactly as it is, and only later changes are reported. Do this only when you know the site is clean, for example right after a fresh install or a cleanup. Files with malware are still reported as threats.', 'qartvelo-guard' );
		$no_base  = $this->baseline_at < 1;
		?>
		<div class="wpcs-card wpcs-scan-card">
			<h2 class="wpcs-card__title"><span class="dashicons dashicons-search" aria-hidden="true"></span><?php esc_html_e( 'Scan your site', 'qartvelo-guard' ); ?></h2>
			<p class="wpcs-card__desc"><?php esc_html_e( 'Scans compare every file with your trusted baseline and check new or changed files for malware. You can keep working while a scan runs.', 'qartvelo-guard' ); ?></p>

			<?php if ( $no_base ) : ?>
				<div class="wpcs-notice wpcs-notice--warn">
					<span class="dashicons dashicons-info-outline" aria-hidden="true"></span>
					<div><p><?php esc_html_e( 'There is no baseline yet. Create one first (setup wizard or "Rebuild baseline"), otherwise every existing file is reported as new.', 'qartvelo-guard' ); ?></p></div>
				</div>
			<?php endif; ?>

			<div class="wpcs-scan-modes">
				<div class="wpcs-scan-mode">
					<strong><?php esc_html_e( 'Quick scan', 'qartvelo-guard' ); ?></strong>
					<span class="wpcs-sub"><?php esc_html_e( 'New and changed files since the last scan. Usually takes seconds.', 'qartvelo-guard' ); ?></span>
					<button type="button" class="button <?php echo $no_base ? '' : 'button-primary'; ?>" data-wpcs-scan data-mode="incremental" data-malware="1"><?php esc_html_e( 'Run quick scan', 'qartvelo-guard' ); ?></button>
				</div>
				<div class="wpcs-scan-mode">
					<strong><?php esc_html_e( 'Full malware scan', 'qartvelo-guard' ); ?></strong>
					<span class="wpcs-sub"><?php esc_html_e( 'Reads every file again and checks it against all malware signatures.', 'qartvelo-guard' ); ?></span>
					<button type="button" class="button" data-wpcs-scan data-mode="full" data-malware="1"><?php esc_html_e( 'Run full scan', 'qartvelo-guard' ); ?></button>
				</div>
				<div class="wpcs-scan-mode">
					<strong><?php esc_html_e( 'Rebuild baseline', 'qartvelo-guard' ); ?></strong>
					<span class="wpcs-sub"><?php esc_html_e( 'Trusts every current file as the new known-good state.', 'qartvelo-guard' ); ?></span>
					<button type="button" class="button <?php echo esc_attr( $no_base ? 'button-primary' : '' ); ?>" data-wpcs-scan data-mode="baseline" data-malware="1" data-confirm="<?php echo esc_attr( $baseline ); ?>"><?php esc_html_e( 'Rebuild baseline', 'qartvelo-guard' ); ?></button>
				</div>
			</div>

			<?php $this->render_progress( $running ); ?>

			<?php $this->render_last_scan_details(); ?>
		</div>
		<?php
	}

	/**
	 * Progress block driven by core.js (auto attaches to a running scan).
	 *
	 * @param bool $running Whether a scan is running right now.
	 */
	private function render_progress( $running ) {
		$pct  = $running && isset( $this->job['percent'] ) ? max( 0, min( 100, (float) $this->job['percent'] ) ) : 0;
		$text = $running ? __( 'Scan in progress...', 'qartvelo-guard' ) : '';
		?>
		<div id="wpcs-scan-progress" class="wpcs-progress <?php echo $running ? '' : 'wpcs-hidden'; ?>" data-wpcs-progress-auto aria-live="polite">
			<div class="wpcs-progress__track"><div class="wpcs-progress__bar" style="width:<?php echo esc_attr( (string) $pct ); ?>%"></div></div>
			<div class="wpcs-progress__label"><span class="wpcs-progress__text"><?php echo esc_html( $text ); ?></span><span class="wpcs-progress__current"></span></div>
		</div>
		<?php
	}

	/**
	 * Numbers from the last finished scan.
	 */
	private function render_last_scan_details() {
		$finished = $this->last_time();
		echo '<div class="wpcs-last-scan">';
		if ( ! $finished ) {
			echo '<p class="wpcs-muted">' . esc_html__( 'No scan has finished yet. Results appear here after the first scan.', 'qartvelo-guard' ) . '</p></div>';
			return;
		}
		$last    = $this->last;
		$state   = isset( $last['state'] ) ? (string) $last['state'] : 'done';
		$started = isset( $last['started_at'] ) ? (int) $last['started_at'] : 0;
		$ended   = isset( $last['finished_at'] ) ? (int) $last['finished_at'] : 0;

		$heading = sprintf(
			/* translators: 1: scan type, 2: relative time, 3: how it was started */
			__( '%1$s finished %2$s, %3$s', 'qartvelo-guard' ),
			$this->mode_label( isset( $last['mode'] ) ? $last['mode'] : '' ),
			Admin::ago( $finished ),
			$this->trigger_label( isset( $last['trigger'] ) ? $last['trigger'] : '' )
		);
		echo '<div class="wpcs-last-scan__head"><strong>' . esc_html__( 'Last scan', 'qartvelo-guard' ) . '</strong> <span class="wpcs-muted" title="' . esc_attr( Admin::datetime( $finished ) ) . '">' . esc_html( $heading ) . '</span></div>';

		if ( 'failed' === $state || 'cancelled' === $state ) {
			$msg = 'failed' === $state ? __( 'The scan failed.', 'qartvelo-guard' ) : __( 'The scan was cancelled before it finished.', 'qartvelo-guard' );
			if ( ! empty( $last['message'] ) ) {
				$msg .= ' ' . (string) $last['message'];
			}
			echo '<div class="wpcs-notice ' . ( 'failed' === $state ? 'wpcs-notice--bad' : 'wpcs-notice--warn' ) . '"><span class="dashicons dashicons-warning" aria-hidden="true"></span><div><p>' . esc_html( $msg ) . '</p></div></div>';
		}

		$checked = isset( $last['files_done'] ) && (int) $last['files_done'] > 0 ? (int) $last['files_done'] : ( isset( $last['files_total'] ) ? (int) $last['files_total'] : 0 );
		$cells   = array(
			array( __( 'Files checked', 'qartvelo-guard' ), number_format_i18n( $checked ), '' ),
			array( __( 'New', 'qartvelo-guard' ), number_format_i18n( isset( $last['new'] ) ? (int) $last['new'] : 0 ), ! empty( $last['new'] ) ? 'is-warn' : '' ),
			array( __( 'Modified', 'qartvelo-guard' ), number_format_i18n( isset( $last['modified'] ) ? (int) $last['modified'] : 0 ), ! empty( $last['modified'] ) ? 'is-warn' : '' ),
			array( __( 'Deleted', 'qartvelo-guard' ), number_format_i18n( isset( $last['deleted'] ) ? (int) $last['deleted'] : 0 ), '' ),
			array( __( 'Threats', 'qartvelo-guard' ), number_format_i18n( isset( $last['threats'] ) ? (int) $last['threats'] : 0 ), ! empty( $last['threats'] ) ? 'is-bad' : 'is-ok' ),
			array( __( 'Duration', 'qartvelo-guard' ), $this->duration( $started, $ended ), '' ),
		);
		echo '<dl class="wpcs-kv">';
		foreach ( $cells as $cell ) {
			echo '<div class="wpcs-kv__item ' . esc_attr( $cell[2] ) . '"><dt>' . esc_html( $cell[0] ) . '</dt><dd>' . esc_html( $cell[1] ) . '</dd></div>';
		}
		echo '</dl>';

		if ( ! empty( $last['new'] ) || ! empty( $last['modified'] ) || ! empty( $last['threats'] ) ) {
			echo '<p class="wpcs-last-scan__foot"><a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => ! empty( $last['threats'] ) ? 'threats' : 'pending' ) ) ) . '">' . esc_html__( 'See what was found on the Reports page', 'qartvelo-guard' ) . ' &rarr;</a></p>';
		}
		echo '</div>';
	}

	/* ------------------------------------------------------------------ */
	/* Protection overview                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * List of active protections with on/off badges.
	 */
	private function render_protection_card() {
		echo '<div class="wpcs-card wpcs-protection-card">';
		echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>' . esc_html__( 'Protection overview', 'qartvelo-guard' ) . '</h2>';
		echo '<ul class="wpcs-plist">';

		// Uploads.
		$upload_modes = array(
			'hold_all'   => array( __( 'Hold all', 'qartvelo-guard' ), 'ok', __( 'Every new upload waits for your approval unless it was allowed before.', 'qartvelo-guard' ) ),
			'hold_risky' => array( __( 'Risky only', 'qartvelo-guard' ), 'info', __( 'Scripts, archives, SVG, HTML and disguised files wait for approval.', 'qartvelo-guard' ) ),
			'scan_only'  => array( __( 'Scan only', 'qartvelo-guard' ), 'medium', __( 'Only uploads that contain malware are held.', 'qartvelo-guard' ) ),
			'off'        => array( __( 'Off', 'qartvelo-guard' ), 'muted', __( 'Uploads are not checked.', 'qartvelo-guard' ) ),
		);
		$mode = (string) $this->opt( 'upload_mode', 'hold_all' );
		$row  = isset( $upload_modes[ $mode ] ) ? $upload_modes[ $mode ] : $upload_modes['hold_all'];
		$this->prow( 'upload', __( 'Upload holding', 'qartvelo-guard' ), $row[2], $row[0], $row[1] );

		// Installs.
		if ( 'hold' === $this->opt( 'install_mode', 'hold' ) ) {
			$desc = $this->opt( 'hold_updates', false )
				? __( 'New plugins, themes and their updates wait for approval.', 'qartvelo-guard' )
				: __( 'New plugins and themes wait for approval. Updates of installed ones pass.', 'qartvelo-guard' );
			$this->prow( 'admin-plugins', __( 'Install holding', 'qartvelo-guard' ), $desc, __( 'On', 'qartvelo-guard' ), 'ok' );
		} else {
			$this->prow( 'admin-plugins', __( 'Install holding', 'qartvelo-guard' ), __( 'Plugins and themes install without approval.', 'qartvelo-guard' ), __( 'Off', 'qartvelo-guard' ), 'muted' );
		}

		// File monitor.
		$file_modes = array(
			'quarantine_exec' => array( __( 'Quarantine', 'qartvelo-guard' ), 'ok', __( 'Unknown new scripts are moved to quarantine until you allow them.', 'qartvelo-guard' ) ),
			'report'          => array( __( 'Report', 'qartvelo-guard' ), 'info', __( 'New and changed files are listed for your review and stay in place.', 'qartvelo-guard' ) ),
			'off'             => array( __( 'Off', 'qartvelo-guard' ), 'muted', __( 'New files are not reported. Malware is still detected.', 'qartvelo-guard' ) ),
		);
		$fmode = (string) $this->opt( 'file_mode', 'report' );
		$row   = isset( $file_modes[ $fmode ] ) ? $file_modes[ $fmode ] : $file_modes['report'];
		$this->prow( 'media-code', __( 'File monitor', 'qartvelo-guard' ), $row[2], $row[0], $row[1] );

		// Administrator watch.
		$this->admin_watch_row();

		// Database scan.
		$this->database_row();

		// Scheduled scans.
		$this->schedule_row();

		// Early guard.
		$this->guard_row();

		// ClamAV and Linux Malware Detect.
		$this->antivirus_row();

		// Freeze lock.
		$this->freeze_row();

		// Alerts.
		$notify = (string) $this->opt( 'notify_mode', 'instant' );
		$recips = Admin::call( 'settings', 'recipients', array(), array() );
		$recips = is_array( $recips ) ? array_slice( $recips, 0, 3 ) : array();
		/* translators: %s: email addresses */
		$to = $recips ? sprintf( __( 'Sent to %s.', 'qartvelo-guard' ), implode( ', ', $recips ) ) : '';
		if ( 'instant' === $notify ) {
			$this->prow( 'email-alt', __( 'Email alerts', 'qartvelo-guard' ), trim( __( 'Instant email when something is held or found.', 'qartvelo-guard' ) . ' ' . $to ), __( 'Instant', 'qartvelo-guard' ), 'ok' );
		} elseif ( 'digest' === $notify ) {
			$this->prow( 'email-alt', __( 'Email alerts', 'qartvelo-guard' ), trim( __( 'One summary email per day.', 'qartvelo-guard' ) . ' ' . $to ), __( 'Daily digest', 'qartvelo-guard' ), 'info' );
		} else {
			$this->prow( 'email-alt', __( 'Email alerts', 'qartvelo-guard' ), __( 'Nobody is told when uploads are held or threats are found.', 'qartvelo-guard' ), __( 'Off', 'qartvelo-guard' ), 'medium' );
		}

		// Allowlist.
		$allow_count = (int) Admin::call( 'allowlist', 'count', array(), 0 );
		$link        = '<a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'allowlist' ) ) ) . '">' . esc_html__( 'View', 'qartvelo-guard' ) . '</a>';
		$this->prow(
			'yes-alt',
			__( 'Allowlist', 'qartvelo-guard' ),
			__( 'Files and installs you allowed once are never held again.', 'qartvelo-guard' ),
			sprintf(
				/* translators: %s: number of entries */
				_n( '%s entry', '%s entries', $allow_count, 'qartvelo-guard' ),
				number_format_i18n( $allow_count )
			),
			'info',
			$link
		);

		// Tamper checksum.
		$integrity = Admin::call( 'allowlist', 'verify_integrity', array(), null );
		if ( true === $integrity ) {
			$this->prow( 'privacy', __( 'Tamper checksum', 'qartvelo-guard' ), __( 'The allowlist matches its signed checksum.', 'qartvelo-guard' ), __( 'Intact', 'qartvelo-guard' ), 'ok' );
		} elseif ( false === $integrity ) {
			$this->prow( 'privacy', __( 'Tamper checksum', 'qartvelo-guard' ), __( 'The allowlist was changed outside the plugin. Review it now.', 'qartvelo-guard' ), __( 'Changed', 'qartvelo-guard' ), 'critical' );
		} else {
			$this->prow( 'privacy', __( 'Tamper checksum', 'qartvelo-guard' ), __( 'Optional. Define WPCYBERSEC_HMAC_KEY in wp-config.php to detect database edits of the allowlist.', 'qartvelo-guard' ), __( 'Not set up', 'qartvelo-guard' ), 'muted' );
		}

		// Steps that need someone with server access.
		$this->developer_row();

		echo '</ul>';
		echo '<p class="wpcs-protection-card__foot"><a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_SETTINGS ) ) . '"><span class="dashicons dashicons-admin-generic" aria-hidden="true"></span> ' . esc_html__( 'Change settings', 'qartvelo-guard' ) . '</a></p>';
		echo '</div>';
	}

	/**
	 * One protection row.
	 *
	 * @param string $icon        Dashicon name.
	 * @param string $title       Title.
	 * @param string $desc        Description.
	 * @param string $badge       Badge text.
	 * @param string $tone        Badge tone (ok, info, medium, high, critical, muted, pending).
	 * @param string $action_html Escaped extra HTML (link or button).
	 */
	private function prow( $icon, $title, $desc, $badge, $tone, $action_html = '' ) {
		echo '<li class="wpcs-plist__row">';
		echo '<span class="wpcs-plist__icon wpcs-plist__icon--' . esc_attr( $tone ) . '" aria-hidden="true"><span class="dashicons dashicons-' . esc_attr( $icon ) . '"></span></span>';
		echo '<div class="wpcs-plist__text"><strong>' . esc_html( $title ) . '</strong><span class="wpcs-sub">' . esc_html( $desc ) . '</span></div>';
		echo '<div class="wpcs-plist__state"><span class="wpcs-badge wpcs-badge--' . esc_attr( $tone ) . '">' . esc_html( $badge ) . '</span>';
		if ( '' !== $action_html ) {
			echo wp_kses(
				$action_html,
				array(
					'a'      => array( 'href' => true, 'class' => true ),
					'button' => array( 'type' => true, 'class' => true, 'data-wpcs-freeze' => true, 'data-minutes' => true, 'data-wpcs-clamav-enable' => true ),
				)
			);
		}
		echo '</div></li>';
	}

	/**
	 * Administrator watch row: trusted administrators and accounts waiting.
	 */
	private function admin_watch_row() {
		$title = __( 'Administrator watch', 'qartvelo-guard' );
		if ( ! Admin::service( 'user_watch' ) ) {
			$this->prow( 'admin-users', $title, __( 'The administrator watch module is not available.', 'qartvelo-guard' ), __( 'Unavailable', 'qartvelo-guard' ), 'muted' );
			return;
		}
		$trusted = Admin::call( 'user_watch', 'trusted_ids', array(), array() );
		$trusted = is_array( $trusted ) ? count( $trusted ) : 0;
		$waiting = (int) Admin::call(
			'store',
			'items_count',
			array(
				array(
					'type'   => Store::TYPE_USER,
					'status' => Store::STATUS_PENDING,
				),
			),
			0
		);
		$badge = sprintf(
			/* translators: %s: number of administrators */
			_n( '%s trusted admin', '%s trusted admins', $trusted, 'qartvelo-guard' ),
			number_format_i18n( $trusted )
		);
		if ( $waiting > 0 ) {
			$link = '<a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'pending', 'type' => Store::TYPE_USER ) ) ) . '">' . esc_html__( 'Review', 'qartvelo-guard' ) . '</a>';
			$desc = sprintf(
				/* translators: %s: number of accounts */
				_n( '%s new administrator account is waiting for your review.', '%s new administrator accounts are waiting for your review.', $waiting, 'qartvelo-guard' ),
				number_format_i18n( $waiting )
			) . ' ' . sprintf(
				/* translators: %s: number of administrators */
				_n( '%s administrator is trusted.', '%s administrators are trusted.', $trusted, 'qartvelo-guard' ),
				number_format_i18n( $trusted )
			);
			// The badge names the problem, not the trusted count.
			$badge = sprintf(
				/* translators: %s: number of accounts */
				_n( '%s waiting', '%s waiting', $waiting, 'qartvelo-guard' ),
				number_format_i18n( $waiting )
			);
			$this->prow( 'admin-users', $title, $desc, $badge, 'high', $link );
			return;
		}
		$this->prow( 'admin-users', $title, __( 'New administrator accounts are reported at once and checked again by every scan.', 'qartvelo-guard' ), $badge, 'ok' );
	}

	/**
	 * Database scan row: when options and posts were last checked.
	 */
	private function database_row() {
		$title = __( 'Database scan', 'qartvelo-guard' );
		$last  = Admin::call( 'db_scanner', 'last_run', array(), array() );
		$last  = is_array( $last ) ? $last : array();
		$at    = isset( $last['finished_at'] ) ? (int) $last['finished_at'] : 0;
		if ( ! $at ) {
			$this->prow( 'database', $title, __( 'Options, widgets and posts are checked for injected code by full and baseline scans, and once a day by scheduled scans.', 'qartvelo-guard' ), __( 'Not run yet', 'qartvelo-guard' ), 'medium' );
			return;
		}
		$found = isset( $last['findings'] ) ? (int) $last['findings'] : 0;
		$desc  = sprintf(
			/* translators: 1: date and time, 2: options checked, 3: posts checked */
			__( 'Last run %1$s: %2$s options and %3$s posts checked.', 'qartvelo-guard' ),
			Admin::datetime( $at ),
			number_format_i18n( isset( $last['options_total'] ) ? (int) $last['options_total'] : 0 ),
			number_format_i18n( isset( $last['posts_total'] ) ? (int) $last['posts_total'] : 0 )
		);
		if ( $found > 0 ) {
			$link = '<a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'threats' ) ) ) . '">' . esc_html__( 'Review', 'qartvelo-guard' ) . '</a>';
			$this->prow(
				'database',
				$title,
				$desc,
				sprintf(
					/* translators: %s: number of findings */
					_n( '%s finding', '%s findings', $found, 'qartvelo-guard' ),
					number_format_i18n( $found )
				),
				'high',
				$link
			);
			return;
		}
		$this->prow( 'database', $title, $desc, Admin::ago( $at ), 'ok' );
	}

	/**
	 * Scheduled scans row.
	 */
	private function schedule_row() {
		$schedule = (string) $this->opt( 'scan_schedule', 'twicedaily' );
		if ( 'off' === $schedule ) {
			$this->prow( 'calendar-alt', __( 'Scheduled scans', 'qartvelo-guard' ), __( 'Scans only run when you start them.', 'qartvelo-guard' ), __( 'Off', 'qartvelo-guard' ), 'medium' );
			return;
		}
		$next = (int) \WPCyberSecurity\Network::next_scheduled( 'wpcybersec_scheduled_scan' );
		if ( $next ) {
			$desc = sprintf(
				/* translators: 1: date and time, 2: relative time */
				__( 'Next run: %1$s (%2$s).', 'qartvelo-guard' ),
				Admin::datetime( $next ),
				$next <= time() ? __( 'due now', 'qartvelo-guard' ) : Admin::ago( $next )
			);
			if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
				$desc .= ' ' . __( 'WP-Cron is disabled, so a server cron job must run it.', 'qartvelo-guard' );
			}
			$this->prow( 'calendar-alt', __( 'Scheduled scans', 'qartvelo-guard' ), $desc, $this->schedule_label( $schedule ), 'ok' );
		} else {
			$this->prow( 'calendar-alt', __( 'Scheduled scans', 'qartvelo-guard' ), __( 'Not scheduled yet. It is set up on the next page load; if it stays like this, check that WP-Cron runs.', 'qartvelo-guard' ), $this->schedule_label( $schedule ), 'medium' );
		}
	}

	/**
	 * Early upload guard row.
	 */
	private function guard_row() {
		$title    = __( 'Early upload guard', 'qartvelo-guard' );
		$settings = '<a href="' . esc_url( Admin::page_url( Admin::PAGE_SETTINGS, array( 'tab' => 'advanced', 'section' => 'guard' ) ) . '#wpcs-guard' ) . '">' . esc_html__( 'Set up', 'qartvelo-guard' ) . '</a>';

		if ( ! Admin::service( 'guard_manager' ) ) {
			$this->prow( 'shield', $title, __( 'The guard module is not available.', 'qartvelo-guard' ), __( 'Unavailable', 'qartvelo-guard' ), 'muted' );
			return;
		}
		$manager = Admin::service( 'guard_manager' );
		if ( method_exists( $manager, 'maybe_reping' ) && ! $manager::request_can_tell() ) {
			// This request cannot see the guard (development server): a short live test at most every 6 hours.
			$manager->maybe_reping( 3 );
		}
		$status = Admin::call( 'guard_manager', 'status', array(), array() );
		$status = is_array( $status ) ? $status : array();
		$live   = method_exists( $manager, 'live_state' ) ? $manager->live_state( $status ) : array( 'state' => ! empty( $status['active'] ) ? 'active' : '' );

		if ( 'active' === $live['state'] || 'confirmed' === $live['state'] ) {
			$desc = __( 'Holds uploads sent to any PHP script on the server, before WordPress loads.', 'qartvelo-guard' );
			if ( 'confirmed' === $live['state'] ) {
				$desc .= ' ' . __( 'This page cannot see it by itself, so the last live test tells.', 'qartvelo-guard' );
			}
			$this->prow( 'shield', $title, $desc, 'confirmed' === $live['state'] ? $live['label'] : __( 'Active', 'qartvelo-guard' ), 'ok' );
		} elseif ( ! empty( $status['installed'] ) ) {
			$desc = ! empty( $status['conflict'] )
				/* translators: %s: file path */
				? sprintf( __( 'Installed, but PHP prepends another file (%s). See Advanced settings.', 'qartvelo-guard' ), (string) $status['conflict'] )
				: __( 'Installed, but PHP does not load it yet (auto_prepend_file). Server changes can take a few minutes.', 'qartvelo-guard' );
			$this->prow( 'shield', $title, $desc, __( 'Not running', 'qartvelo-guard' ), 'medium', $settings );
		} else {
			$this->prow( 'shield', $title, __( 'Optional, for system administrators. Also holds uploads sent to PHP scripts outside WordPress.', 'qartvelo-guard' ), __( 'Off', 'qartvelo-guard' ), 'muted', $settings );
		}
	}

	/**
	 * Antivirus engines row: ClamAV state and whether maldet is installed.
	 */
	private function antivirus_row() {
		$title = __( 'Antivirus engines', 'qartvelo-guard' );
		$av    = Admin::call( 'sysadmin', 'antivirus_status', array(), null );
		if ( ! is_array( $av ) ) {
			return;
		}
		$clam   = $av['clamav'];
		$maldet = $av['maldet'];
		$link   = '<a href="' . esc_url( Admin::page_url( Admin::PAGE_SETTINGS, array( 'tab' => 'advanced', 'section' => 'antivirus' ) ) . '#wpcs-antivirus' ) . '">' . esc_html__( 'Set up', 'qartvelo-guard' ) . '</a>';
		/* translators: %s: ClamAV state, for example "Ready, not in use" */
		$parts = array( sprintf( __( 'ClamAV: %s.', 'qartvelo-guard' ), $clam['label'] ) );
		if ( '' !== $maldet['binary'] ) {
			$parts[] = __( 'Linux Malware Detect: installed.', 'qartvelo-guard' );
		} elseif ( ! empty( $maldet['hidden'] ) ) {
			$parts[] = __( 'Linux Malware Detect: unknown (hosting hides it).', 'qartvelo-guard' );
		} elseif ( $maldet['supported'] ) {
			$parts[] = __( 'Linux Malware Detect: not installed.', 'qartvelo-guard' );
		}
		if ( 'ready_off' === $clam['state'] ) {
			$button = '<button type="button" class="button button-small" data-wpcs-clamav-enable>' . esc_html__( 'Turn on', 'qartvelo-guard' ) . '</button>';
			$this->prow( 'sos', $title, implode( ' ', $parts ) . ' ' . __( 'A second opinion on every upload; it finds more but does not block attacks.', 'qartvelo-guard' ), __( 'Not in use', 'qartvelo-guard' ), 'medium', $button );
			return;
		}
		if ( in_array( $clam['state'], array( 'uploads', 'uploads_scans' ), true ) ) {
			$badge = 'uploads_scans' === $clam['state'] ? __( 'Uploads and scans', 'qartvelo-guard' ) : __( 'Uploads', 'qartvelo-guard' );
			$this->prow( 'sos', $title, implode( ' ', $parts ), $badge, 'ok' );
			return;
		}
		if ( 'broken' === $clam['state'] || 'slow' === $clam['state'] ) {
			// The self-test failed, or only a clamscan works that is too slow for uploads.
			$this->prow( 'sos', $title, implode( ' ', $parts ) . ( ! empty( $clam['hint'] ) ? ' ' . $clam['hint'] . ( ! empty( $clam['hint_code'] ) ? ' ' . $clam['hint_code'] : '' ) : '' ), 'broken' === $clam['state'] ? __( 'Not working', 'qartvelo-guard' ) : __( 'Slow', 'qartvelo-guard' ), 'broken' === $clam['state'] ? 'high' : 'medium', $link );
			return;
		}
		$this->prow( 'sos', $title, implode( ' ', $parts ) . ' ' . __( 'Optional: they know many more existing infections, but do not block attacks.', 'qartvelo-guard' ), 'blocked' === $clam['state'] ? __( 'Cannot run', 'qartvelo-guard' ) : ( ! empty( $clam['hidden'] ) ? __( 'Unknown', 'qartvelo-guard' ) : __( 'Not installed', 'qartvelo-guard' ) ), 'muted', $link );
	}

	/**
	 * Developer instructions row, only while something needs server access.
	 */
	private function developer_row() {
		$count = (int) Admin::call( 'developer', 'count', array(), 0 );
		if ( $count < 1 ) {
			return;
		}
		$link = '<a href="' . esc_url( Admin::page_url( Admin::PAGE_SETTINGS, array( 'tab' => 'advanced', 'section' => 'developer' ) ) . '#wpcs-developer' ) . '">' . esc_html__( 'View', 'qartvelo-guard' ) . '</a>';
		$this->prow(
			'clipboard',
			__( 'Developer instructions', 'qartvelo-guard' ),
			__( 'Steps the plugin could not do from here. Send them to someone with server access (SSH, SFTP or the hosting panel).', 'qartvelo-guard' ),
			/* translators: %s: number of steps */
			sprintf( _n( '%s step', '%s steps', $count, 'qartvelo-guard' ), number_format_i18n( $count ) ),
			'info',
			$link
		);
	}

	/**
	 * Freeze lock row with unlock / lock buttons.
	 */
	private function freeze_row() {
		$title   = __( 'Freeze lock', 'qartvelo-guard' );
		$can_ajx = Admin::service( 'install_gate' ) && method_exists( Admin::service( 'install_gate' ), 'unlock' );
		if ( ! $this->opt( 'freeze_mods', false ) ) {
			$link = '<a href="' . esc_url( Admin::page_url( Admin::PAGE_SETTINGS, array( 'tab' => 'advanced', 'section' => 'freeze' ) ) . '#wpcs-freeze' ) . '">' . esc_html__( 'Set up', 'qartvelo-guard' ) . '</a>';
			$this->prow( 'lock', $title, __( 'Optional. Blocks every plugin, theme and core file change until you unlock it for a few minutes.', 'qartvelo-guard' ), __( 'Off', 'qartvelo-guard' ), 'muted', $link );
			return;
		}
		if ( \WPCyberSecurity\Install_Gate::mods_disallowed() ) {
			// DISALLOW_FILE_MODS: WordPress itself refuses every change, so there is nothing to unlock.
			$this->prow( 'lock', $title, __( 'Installs and updates are disabled by the site config (DISALLOW_FILE_MODS in wp-config.php), so the freeze lock cannot be unlocked here. Remove that line to update from the dashboard.', 'qartvelo-guard' ), __( 'Disabled by site config', 'qartvelo-guard' ), 'ok' );
			return;
		}
		$until   = (int) Admin::call( 'install_gate', 'unlocked_until', array(), 0 );
		$minutes = max( 1, (int) $this->opt( 'unlock_minutes', 15 ) );
		if ( $until > time() ) {
			$desc   = sprintf(
				/* translators: 1: time, 2: relative time */
				__( 'File changes are allowed until %1$s (%2$s).', 'qartvelo-guard' ),
				wp_date( get_option( 'time_format' ), $until ),
				Admin::ago( $until )
			);
			$button = $can_ajx ? '<button type="button" class="button button-small" data-wpcs-freeze="lock">' . esc_html__( 'Lock now', 'qartvelo-guard' ) . '</button>' : '';
			$this->prow( 'unlock', $title, $desc, __( 'Unlocked', 'qartvelo-guard' ), 'medium', $button );
		} else {
			$button = $can_ajx
				? '<button type="button" class="button button-small" data-wpcs-freeze="unlock" data-minutes="' . esc_attr( (string) $minutes ) . '">'
					/* translators: %s: number of minutes */
					. esc_html( sprintf( __( 'Unlock for %s min', 'qartvelo-guard' ), number_format_i18n( $minutes ) ) ) . '</button>'
				: '';
			$this->prow( 'lock', $title, __( 'Plugin, theme and core files cannot be changed. Unlock briefly to install or update.', 'qartvelo-guard' ), __( 'Locked', 'qartvelo-guard' ), 'ok', $button );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Activity and help                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Last 8 log rows.
	 */
	private function render_activity_card() {
		$log  = Admin::call( 'store', 'log_query', array( array( 'per_page' => 8 ) ), array() );
		$rows = is_array( $log ) && ! empty( $log['rows'] ) ? (array) $log['rows'] : array();

		echo '<div class="wpcs-card wpcs-activity-card">';
		echo '<div class="wpcs-card__head"><h2 class="wpcs-card__title"><span class="dashicons dashicons-backup" aria-hidden="true"></span>' . esc_html__( 'Recent activity', 'qartvelo-guard' ) . '</h2>';
		if ( $rows ) {
			echo '<a class="wpcs-card__link" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'activity' ) ) ) . '">' . esc_html__( 'View all', 'qartvelo-guard' ) . ' &rarr;</a>';
		}
		echo '</div>';

		if ( ! $rows ) {
			echo '<div class="wpcs-empty wpcs-empty--compact"><span class="dashicons dashicons-backup" aria-hidden="true"></span><h3>' . esc_html__( 'No activity yet', 'qartvelo-guard' ) . '</h3><p>' . esc_html__( 'Held uploads, decisions and scans are recorded here.', 'qartvelo-guard' ) . '</p></div>';
			echo '</div>';
			return;
		}

		echo '<ul class="wpcs-activity">';
		foreach ( $rows as $row ) {
			$meta = Admin::event_meta( isset( $row['event'] ) ? $row['event'] : '' );
			$ts   = Admin::utc_ts( isset( $row['created_at'] ) ? $row['created_at'] : '' );
			$user = Admin::user_name( isset( $row['user_id'] ) ? $row['user_id'] : 0 );
			$by   = array( Admin::ago( $ts ) );
			if ( '' !== $user ) {
				/* translators: %s: user display name */
				$by[] = sprintf( __( 'by %s', 'qartvelo-guard' ), $user );
			}
			echo '<li class="wpcs-activity__row">';
			echo '<span class="wpcs-activity__icon wpcs-activity__icon--' . esc_attr( $meta['tone'] ) . '" aria-hidden="true"><span class="dashicons dashicons-' . esc_attr( $meta['icon'] ) . '"></span></span>';
			echo '<div class="wpcs-activity__text"><span class="wpcs-activity__msg">' . esc_html( isset( $row['message'] ) ? (string) $row['message'] : '' ) . '</span>';
			echo '<span class="wpcs-sub" title="' . esc_attr( Admin::datetime( $ts ) ) . '">' . esc_html( $meta['label'] . ' - ' . implode( ' ', $by ) ) . '</span></div>';
			echo '</li>';
		}
		echo '</ul></div>';
	}

	/**
	 * Short explanation of the approval model.
	 */
	private function render_help_card() {
		?>
		<div class="wpcs-card wpcs-help-card">
			<h2 class="wpcs-card__title"><span class="dashicons dashicons-lightbulb" aria-hidden="true"></span><?php esc_html_e( 'How approvals work', 'qartvelo-guard' ); ?></h2>
			<ol class="wpcs-steps-list">
				<li><strong><?php esc_html_e( 'Held', 'qartvelo-guard' ); ?></strong> <?php esc_html_e( 'New uploads, installs and unknown files wait in a locked quarantine folder where they cannot run.', 'qartvelo-guard' ); ?></li>
				<li><strong><?php esc_html_e( 'Reviewed', 'qartvelo-guard' ); ?></strong> <?php esc_html_e( 'You see who sent it, from where, and what the malware scan found.', 'qartvelo-guard' ); ?></li>
				<li><strong><?php esc_html_e( 'Allowed once, allowed always', 'qartvelo-guard' ); ?></strong> <?php esc_html_e( 'Allowing remembers the file\'s SHA-256 fingerprint, so the same file is never held again.', 'qartvelo-guard' ); ?></li>
			</ol>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array $status Job status.
	 * @return bool
	 */
	private function is_running( array $status ) {
		return isset( $status['state'] ) && in_array( $status['state'], array( 'enumerating', 'processing', 'finishing' ), true );
	}

	/**
	 * Unix time of the last finished scan, 0 when none.
	 *
	 * @return int
	 */
	private function last_time() {
		if ( empty( $this->last ) ) {
			return 0;
		}
		if ( ! empty( $this->last['finished_at'] ) ) {
			return (int) $this->last['finished_at'];
		}
		return ! empty( $this->last['started_at'] ) ? (int) $this->last['started_at'] : 0;
	}

	/**
	 * @param string $mode Scan mode.
	 * @return string
	 */
	private function mode_label( $mode ) {
		$labels = array(
			'incremental' => __( 'Quick scan', 'qartvelo-guard' ),
			'full'        => __( 'Full malware scan', 'qartvelo-guard' ),
			'baseline'    => __( 'Baseline scan', 'qartvelo-guard' ),
		);
		return isset( $labels[ $mode ] ) ? $labels[ $mode ] : __( 'Scan', 'qartvelo-guard' );
	}

	/**
	 * @param string $trigger Trigger.
	 * @return string
	 */
	private function trigger_label( $trigger ) {
		$labels = array(
			'manual' => __( 'started manually', 'qartvelo-guard' ),
			'cron'   => __( 'scheduled', 'qartvelo-guard' ),
			'cli'    => __( 'started from the command line', 'qartvelo-guard' ),
			'wizard' => __( 'started by the setup wizard', 'qartvelo-guard' ),
			'update' => __( 'after an update', 'qartvelo-guard' ),
		);
		return isset( $labels[ $trigger ] ) ? $labels[ $trigger ] : __( 'started manually', 'qartvelo-guard' );
	}

	/**
	 * @param string $schedule Schedule key.
	 * @return string
	 */
	private function schedule_label( $schedule ) {
		$labels = array(
			'hourly'     => __( 'Hourly', 'qartvelo-guard' ),
			'twicedaily' => __( 'Twice daily', 'qartvelo-guard' ),
			'daily'      => __( 'Daily', 'qartvelo-guard' ),
			'weekly'     => __( 'Weekly', 'qartvelo-guard' ),
			'off'        => __( 'Off', 'qartvelo-guard' ),
		);
		return isset( $labels[ $schedule ] ) ? $labels[ $schedule ] : ucfirst( (string) $schedule );
	}

	/**
	 * "2 threats, 5 new files" style summary.
	 *
	 * @param array $status Scan status.
	 * @return string
	 */
	private function result_summary( array $status ) {
		$state = isset( $status['state'] ) ? (string) $status['state'] : 'done';
		if ( 'failed' === $state ) {
			return __( 'failed', 'qartvelo-guard' );
		}
		if ( 'cancelled' === $state ) {
			return __( 'cancelled', 'qartvelo-guard' );
		}
		$parts   = array();
		$threats = isset( $status['threats'] ) ? (int) $status['threats'] : 0;
		$new     = isset( $status['new'] ) ? (int) $status['new'] : 0;
		$changed = isset( $status['modified'] ) ? (int) $status['modified'] : 0;
		if ( $threats ) {
			/* translators: %s: number */
			$parts[] = sprintf( _n( '%s threat', '%s threats', $threats, 'qartvelo-guard' ), number_format_i18n( $threats ) );
		}
		if ( $new ) {
			/* translators: %s: number */
			$parts[] = sprintf( _n( '%s new file', '%s new files', $new, 'qartvelo-guard' ), number_format_i18n( $new ) );
		}
		if ( $changed ) {
			/* translators: %s: number */
			$parts[] = sprintf( _n( '%s modified', '%s modified', $changed, 'qartvelo-guard' ), number_format_i18n( $changed ) );
		}
		if ( $parts ) {
			return implode( ', ', $parts );
		}
		// A quick scan only looks at what changed since the last one.
		return 'incremental' === ( isset( $status['mode'] ) ? (string) $status['mode'] : '' ) ? __( 'no new problems found', 'qartvelo-guard' ) : __( 'no problems found', 'qartvelo-guard' );
	}

	/**
	 * Human duration between two unix times.
	 *
	 * @param int $start Start.
	 * @param int $end   End.
	 * @return string
	 */
	private function duration( $start, $end ) {
		if ( $start <= 0 || $end <= 0 || $end < $start ) {
			return '-';
		}
		$seconds = $end - $start;
		if ( $seconds < 60 ) {
			/* translators: %s: number of seconds */
			return sprintf( _n( '%s second', '%s seconds', max( 1, $seconds ), 'qartvelo-guard' ), number_format_i18n( max( 1, $seconds ) ) );
		}
		return human_time_diff( $start, $end );
	}
}
