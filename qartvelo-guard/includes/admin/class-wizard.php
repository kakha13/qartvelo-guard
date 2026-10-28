<?php
/**
 * Setup wizard for site owners.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Settings;
use WPCyberSecurity\Sysadmin_Tools;

defined( 'ABSPATH' ) || exit;

/**
 * Seven short steps: welcome, environment check, protection level, baseline
 * scan, alerts, server hardening (optional) and a summary. Every step posts to
 * admin-post "wpcybersec_wizard" (handled by Sysadmin_Tools).
 */
class Wizard {

	/**
	 * @return array step => label
	 */
	public static function steps() {
		return array(
			'welcome'       => __( 'Welcome', 'qartvelo-guard' ),
			'environment'   => __( 'Environment', 'qartvelo-guard' ),
			'protection'    => __( 'Protection', 'qartvelo-guard' ),
			'baseline'      => __( 'Baseline scan', 'qartvelo-guard' ),
			'notifications' => __( 'Alerts', 'qartvelo-guard' ),
			'hardening'     => __( 'Server', 'qartvelo-guard' ),
			'done'          => __( 'Done', 'qartvelo-guard' ),
		);
	}

	/**
	 * @param string $step Step.
	 * @param array  $args Extra query args.
	 * @return string
	 */
	public static function url( $step = '', array $args = array() ) {
		return Sysadmin_Tools::wizard_url( $step, $args );
	}

	/**
	 * @return Sysadmin_Tools
	 */
	private function tools() {
		$tools = Sysadmin_Tools::service( 'sysadmin' );
		return $tools instanceof Sysadmin_Tools ? $tools : new Sysadmin_Tools();
	}

	/**
	 * @return array Current settings (defaults when the service is missing).
	 */
	private function settings() {
		$settings = Sysadmin_Tools::service( 'settings' );
		return $settings ? $settings->all() : Settings::defaults();
	}

	/**
	 * @return string Current step key.
	 */
	private function current_step() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigation only.
		$step = isset( $_GET['step'] ) ? sanitize_key( wp_unslash( $_GET['step'] ) ) : 'welcome';
		$steps = self::steps();
		return isset( $steps[ $step ] ) ? $step : 'welcome';
	}

	/**
	 * Renders the wizard page.
	 */
	public function render() {
		if ( ! Admin::can() ) {
			wp_die( esc_html__( 'You are not allowed to access this page.', 'qartvelo-guard' ) );
		}
		$steps = self::steps();
		$keys  = array_keys( $steps );
		$step  = $this->current_step();
		$index = (int) array_search( $step, $keys, true );

		$exit = '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_DASHBOARD ) ) . '">' . esc_html__( 'Exit setup', 'qartvelo-guard' ) . '</a>';
		?>
		<div class="wrap wpcs-wrap wpcs-wizard">
			<?php
			Settings_Page::page_header(
				__( 'Setup wizard', 'qartvelo-guard' ),
				/* translators: 1: step number, 2: number of steps, 3: step name */
				sprintf( __( 'Step %1$d of %2$d: %3$s', 'qartvelo-guard' ), $index + 1, count( $keys ), $steps[ $step ] ),
				$exit
			);
			$this->render_progress( $steps, $index );
			Settings_Page::render_flash();

			if ( 'done' === $step ) {
				echo '<div class="wpcs-card wpcs-wizard__card wpcs-wizard__card--done">';
				$this->safe_render( 'render_done' );
				echo '</div>';
			} else {
				?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpcs-wizard__form" id="wpcs-wizard-form" data-step="<?php echo esc_attr( $step ); ?>">
					<input type="hidden" name="action" value="wpcybersec_wizard">
					<input type="hidden" name="step" value="<?php echo esc_attr( $step ); ?>">
					<?php wp_nonce_field( 'wpcybersec_wizard' ); ?>
					<button type="submit" name="wpcs_nav" value="next" class="wpcs-default-submit" tabindex="-1" aria-hidden="true"><?php esc_html_e( 'Continue', 'qartvelo-guard' ); ?></button>
					<div class="wpcs-card wpcs-wizard__card wpcs-wizard__card--<?php echo esc_attr( $step ); ?>">
						<?php $this->safe_render( 'render_' . $step ); ?>
						<?php $this->render_footer( $step, $keys, $index ); ?>
					</div>
				</form>
				<?php
			}
			?>
		</div>
		<?php
	}

	/**
	 * Runs a step renderer and turns unexpected errors into a notice instead of a fatal error.
	 *
	 * @param string $method Method name.
	 */
	private function safe_render( $method ) {
		if ( ! method_exists( $this, $method ) ) {
			return;
		}
		try {
			$this->$method();
		} catch ( \Throwable $e ) {
			Settings_Page::notice(
				/* translators: %s: error message */
				sprintf( __( 'This step could not be shown completely: %s', 'qartvelo-guard' ), $e->getMessage() ),
				'bad'
			);
		}
	}

	/**
	 * Progress indicator.
	 *
	 * @param array $steps Steps.
	 * @param int   $index Current index.
	 */
	private function render_progress( array $steps, $index ) {
		echo '<ol class="wpcs-steps" aria-label="' . esc_attr__( 'Setup progress', 'qartvelo-guard' ) . '">';
		$i = 0;
		foreach ( $steps as $key => $label ) {
			$class = $i < $index ? 'is-done' : ( $i === $index ? 'is-current' : '' );
			echo '<li class="' . esc_attr( $class ) . '"' . ( $i === $index ? ' aria-current="step"' : '' ) . '>';
			if ( $i < $index ) {
				echo '<a href="' . esc_url( self::url( $key ) ) . '">' . esc_html( $label ) . '</a>';
			} else {
				echo esc_html( $label );
			}
			echo '</li>';
			++$i;
		}
		echo '</ol>';
	}

	/**
	 * Back / Skip / Continue bar.
	 *
	 * @param string $step  Step.
	 * @param array  $keys  Step keys.
	 * @param int    $index Current index.
	 */
	private function render_footer( $step, array $keys, $index ) {
		$config = array(
			'welcome'       => array( false, '', __( 'Let\'s start', 'qartvelo-guard' ) ),
			'environment'   => array( true, '', __( 'Continue', 'qartvelo-guard' ) ),
			'protection'    => array( true, __( 'Keep current settings', 'qartvelo-guard' ), __( 'Save and continue', 'qartvelo-guard' ) ),
			'baseline'      => array( true, __( 'Skip for now', 'qartvelo-guard' ), __( 'Continue', 'qartvelo-guard' ) ),
			'notifications' => array( true, __( 'Skip', 'qartvelo-guard' ), __( 'Save and continue', 'qartvelo-guard' ) ),
			'hardening'     => array( true, __( 'Skip', 'qartvelo-guard' ), __( 'Finish setup', 'qartvelo-guard' ) ),
		);
		if ( ! isset( $config[ $step ] ) ) {
			return;
		}
		list( $back, $skip, $next ) = $config[ $step ];
		?>
		<div class="wpcs-wizard__footer">
			<?php if ( $back && $index > 0 ) : ?>
				<a class="button button-large wpcs-wizard__back" href="<?php echo esc_url( self::url( $keys[ $index - 1 ] ) ); ?>">
					<span class="dashicons dashicons-arrow-left-alt2" aria-hidden="true"></span><?php esc_html_e( 'Back', 'qartvelo-guard' ); ?>
				</a>
			<?php elseif ( 'welcome' === $step ) : ?>
				<a class="wpcs-wizard__later" href="<?php echo esc_url( Admin::page_url( Admin::PAGE_DASHBOARD ) ); ?>"><?php esc_html_e( 'I will do this later', 'qartvelo-guard' ); ?></a>
			<?php endif; ?>
			<span class="wpcs-spacer"></span>
			<?php if ( $skip ) : ?>
				<button type="submit" name="wpcs_nav" value="skip" class="button button-link wpcs-wizard__skip" formnovalidate><?php echo esc_html( $skip ); ?></button>
			<?php endif; ?>
			<button type="submit" name="wpcs_nav" value="next" class="button button-primary button-large wpcs-wizard__next" data-wpcs-continue>
				<?php echo esc_html( $next ); ?><span class="dashicons dashicons-arrow-right-alt2" aria-hidden="true"></span>
			</button>
		</div>
		<?php
	}

	/**
	 * Step heading.
	 *
	 * @param string $icon  Dashicon name without prefix.
	 * @param string $title Title.
	 * @param string $lead  Intro text.
	 */
	private function heading( $icon, $title, $lead = '' ) {
		?>
		<div class="wpcs-wizard__head">
			<span class="wpcs-wizard__icon"><span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>" aria-hidden="true"></span></span>
			<div>
				<h2 class="wpcs-wizard__title"><?php echo esc_html( $title ); ?></h2>
				<?php if ( $lead ) : ?>
					<p class="wpcs-wizard__lead"><?php echo esc_html( $lead ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Steps                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * Step 1: what the plugin does.
	 */
	private function render_welcome() {
		$features = array(
			array(
				'search',
				__( 'Scans everything', 'qartvelo-guard' ),
				__( 'WordPress core, plugins, themes and uploads are checked for malware, backdoors and changed files. Core files are compared with the official versions.', 'qartvelo-guard' ),
			),
			array(
				'lock',
				__( 'Holds every new upload until you allow it', 'qartvelo-guard' ),
				__( 'New media files and plugin or theme installs wait in a safe quarantine until an administrator approves them on the Reports page. New PHP files that appear on the server are reported for review (the Strict level moves them away too).', 'qartvelo-guard' ),
			),
			array(
				'saved',
				__( 'Allow once, remembered for good', 'qartvelo-guard' ),
				__( 'Each approval stores the file\'s fingerprint. The same file is never held again, wherever it shows up.', 'qartvelo-guard' ),
			),
			array(
				'bell',
				__( 'Alerts you when something needs you', 'qartvelo-guard' ),
				__( 'You get an email (or a Slack or Teams message) when a file is held or a threat is found.', 'qartvelo-guard' ),
			),
		);
		?>
		<div class="wpcs-wizard__hero">
			<span class="wpcs-wizard__hero-icon"><span class="dashicons dashicons-shield" aria-hidden="true"></span></span>
			<h2 class="wpcs-wizard__hero-title"><?php esc_html_e( 'Welcome to Qartvelo Guard', 'qartvelo-guard' ); ?></h2>
			<p class="wpcs-wizard__lead"><?php esc_html_e( 'From now on nothing new is uploaded or installed on your site without your approval. This short setup picks safe settings for you.', 'qartvelo-guard' ); ?></p>
		</div>
		<ul class="wpcs-features">
			<?php foreach ( $features as $feature ) : ?>
				<li>
					<span class="wpcs-features__icon"><span class="dashicons dashicons-<?php echo esc_attr( $feature[0] ); ?>" aria-hidden="true"></span></span>
					<span class="wpcs-features__text">
						<strong><?php echo esc_html( $feature[1] ); ?></strong>
						<span><?php echo esc_html( $feature[2] ); ?></span>
					</span>
				</li>
			<?php endforeach; ?>
		</ul>
		<div class="wpcs-wizard__meta">
			<span><span class="dashicons dashicons-clock" aria-hidden="true"></span><?php esc_html_e( 'Takes about 2 minutes', 'qartvelo-guard' ); ?></span>
			<span><span class="dashicons dashicons-admin-settings" aria-hidden="true"></span><?php esc_html_e( 'Everything can be changed later in Settings', 'qartvelo-guard' ); ?></span>
		</div>
		<?php
	}

	/**
	 * Step 2: environment check.
	 */
	private function render_environment() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read only.
		$fresh  = ! empty( $_GET['recheck'] );
		$checks = $this->tools()->diagnostics( $fresh );

		$counts = array(
			'pass' => 0,
			'warn' => 0,
			'fail' => 0,
			'info' => 0,
		);
		$groups = array(
			'fail' => array(),
			'warn' => array(),
			'pass' => array(),
			'info' => array(),
		);
		foreach ( $checks as $check ) {
			$status = isset( $groups[ $check['status'] ] ) ? $check['status'] : 'info';
			++$counts[ $status ];
			$groups[ $status ][] = $check;
		}

		$this->heading(
			'performance',
			__( 'Environment check', 'qartvelo-guard' ),
			__( 'We looked at how your server is set up. Most recommendations can be fixed right here with one click; the rest come with short step-by-step instructions. Nothing here stops the setup.', 'qartvelo-guard' )
		);
		$this->render_hosting_line( $fresh );
		$attention_checks = array_merge( $groups['fail'], $groups['warn'] );
		$fixable          = Settings_Page::auto_fix_ids( $attention_checks );
		if ( $fixable ) {
			echo '<div class="wpcs-fixall">';
			echo '<div><strong>' . esc_html(
				/* translators: %d: number of items */
				sprintf( _n( '%d item can be fixed for you', '%d items can be fixed for you', count( $fixable ), 'qartvelo-guard' ), count( $fixable ) )
			) . '</strong>';
			echo '<span class="wpcs-sub">' . esc_html__( 'Each fix is tested right away and undone if it would break something.', 'qartvelo-guard' ) . '</span></div>';
			echo '<button type="button" class="button button-primary button-hero" data-wpcs-fix-all="' . esc_attr( implode( ',', $fixable ) ) . '"><span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>' . esc_html__( 'Fix them all', 'qartvelo-guard' ) . '</button>';
			echo '</div>';
		}
		?>
		<div class="wpcs-check-summary">
			<span class="wpcs-badge wpcs-badge--ok"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
				<?php
				/* translators: %d: number of checks */
				echo esc_html( sprintf( _n( '%d passed', '%d passed', $counts['pass'], 'qartvelo-guard' ), $counts['pass'] ) );
				?>
			</span>
			<span class="wpcs-badge wpcs-badge--medium"><span class="dashicons dashicons-warning" aria-hidden="true"></span>
				<?php
				/* translators: %d: number of checks */
				echo esc_html( sprintf( _n( '%d recommendation', '%d recommendations', $counts['warn'], 'qartvelo-guard' ), $counts['warn'] ) );
				?>
			</span>
			<?php if ( $counts['fail'] ) : ?>
				<span class="wpcs-badge wpcs-badge--high"><span class="dashicons dashicons-dismiss" aria-hidden="true"></span>
					<?php
					/* translators: %d: number of checks */
					echo esc_html( sprintf( _n( '%d problem', '%d problems', $counts['fail'], 'qartvelo-guard' ), $counts['fail'] ) );
					?>
				</span>
			<?php endif; ?>
			<span class="wpcs-badge wpcs-badge--info"><span class="dashicons dashicons-info" aria-hidden="true"></span>
				<?php
				/* translators: %d: number of checks */
				echo esc_html( sprintf( _n( '%d for your information', '%d for your information', $counts['info'], 'qartvelo-guard' ), $counts['info'] ) );
				?>
			</span>
			<span class="wpcs-spacer"></span>
			<a class="button button-small" href="<?php echo esc_url( self::url( 'environment', array( 'recheck' => 1 ) ) ); ?>"><span class="dashicons dashicons-update" aria-hidden="true"></span><?php esc_html_e( 'Check again', 'qartvelo-guard' ); ?></a>
		</div>
		<?php
		$attention = array_merge( $groups['fail'], $groups['warn'] );
		$rest      = array_merge( $groups['pass'], $groups['info'] );
		if ( $attention ) {
			Settings_Page::render_checks( $attention, true );
		} else {
			echo '<div class="wpcs-all-good">';
			Settings_Page::notice( __( 'Everything important looks good. The details are below.', 'qartvelo-guard' ), 'ok' );
			echo '</div>';
		}
		if ( $rest ) {
			echo '<details class="wpcs-more-checks"' . ( $attention ? '' : ' open' ) . '><summary>';
			echo esc_html(
				/* translators: %d: number of checks */
				sprintf( _n( '%d passed or informational check', '%d passed or informational checks', count( $rest ), 'qartvelo-guard' ), count( $rest ) )
			);
			echo ' <span class="wpcs-muted">' . esc_html__( 'PHP, cron, server software, plugins and more', 'qartvelo-guard' ) . '</span>';
			echo '</summary>';
			Settings_Page::render_checks( $rest, true );
			echo '</details>';
		}
	}

	/**
	 * "Hosting: CyberPanel (OpenLiteSpeed, lsphp)" with a link to change it:
	 * every by-hand step of the wizard follows that panel.
	 *
	 * @param bool $fresh Detect again.
	 */
	private function render_hosting_line( $fresh = false ) {
		$hosting = Sysadmin_Tools::service( 'hosting' );
		if ( ! $hosting || ! method_exists( $hosting, 'current' ) ) {
			return;
		}
		$info = $hosting->current( $fresh );
		echo '<p class="wpcs-hosting__line wpcs-wizard-hosting" data-wpcs-hosting="' . esc_attr( $info['id'] ) . '"><span class="dashicons dashicons-admin-site-alt3" aria-hidden="true"></span>';
		/* translators: %s: hosting panel with web server and PHP handler */
		echo '<strong>' . esc_html( sprintf( __( 'Hosting: %s', 'qartvelo-guard' ), $hosting->label( $info ) ) ) . '</strong> ';
		echo '<span class="wpcs-muted">' . esc_html( 'unknown' === $info['id'] ? __( 'Steps below are generic.', 'qartvelo-guard' ) : __( 'Steps below follow this panel.', 'qartvelo-guard' ) ) . '</span> ';
		echo '<a href="' . esc_url( \WPCyberSecurity\Hosting::change_url() ) . '">' . esc_html__( 'Change', 'qartvelo-guard' ) . '</a></p>';
	}

	/**
	 * Name of the detected panel when it has its own steps for a task, else ''.
	 *
	 * @param string $task Hosting task.
	 * @return string
	 */
	private static function panel_name( $task ) {
		$hosting = Sysadmin_Tools::service( 'hosting' );
		if ( ! $hosting || ! method_exists( $hosting, 'steps' ) || ! $hosting->steps( $task ) ) {
			return '';
		}
		$info = $hosting->current();
		return (string) $info['name'];
	}

	/**
	 * Step 3: protection level and key toggles.
	 */
	private function render_protection() {
		$s            = $this->settings();
		$level        = $s['protection_level'];
		$hold_admin   = ! in_array( 'administrator', (array) $s['upload_bypass_roles'], true );
		$hold_install = 'hold' === $s['install_mode'];
		$quarantine   = 'quarantine_exec' === $s['file_mode'];

		// A level that differs only in which uploads are held still starts from its card.
		$card = $level;
		if ( 'custom' === $level ) {
			$base = $this->tools()->match_level( array_merge( $s, array( 'upload_mode' => 'hold_all' ) ) );
			$card = 'custom' !== $base ? $base : $level;
		}

		$this->heading(
			'shield',
			__( 'Choose a protection level', 'qartvelo-guard' ),
			__( 'Pick a starting point. Balanced suits most sites; you can fine-tune every setting later.', 'qartvelo-guard' )
		);
		if ( 'custom' === $card ) {
			Settings_Page::notice( __( 'Your settings are currently customized. Pick a level to start from its defaults, or keep your current settings.', 'qartvelo-guard' ), 'info' );
		}
		$this->render_upload_hint( $s );
		echo Settings_Page::level_cards( 'level', $card ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in level_cards().
		?>
		<div class="wpcs-wizard__tune" data-wpcs-level-form="wizard">
			<h3 class="wpcs-wizard__subtitle"><?php esc_html_e( 'Fine-tune', 'qartvelo-guard' ); ?></h3>
			<div class="wpcs-field" data-wpcs-upload-mode>
				<div class="wpcs-field__label"><?php esc_html_e( 'New uploads', 'qartvelo-guard' ); ?></div>
				<div>
				<?php
				echo Settings_Page::radio_list( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in radio_list().
					'upload_mode',
					array(
						'hold_all'   => array( __( 'Hold every upload', 'qartvelo-guard' ), __( 'Every new file waits until an administrator approves it. Safest; best for sites with few uploads.', 'qartvelo-guard' ) ),
						'hold_risky' => array( __( 'Hold only risky uploads (clean images and documents pass after scanning)', 'qartvelo-guard' ), __( 'Risky means: files that can run code (PHP and other script names, double extensions such as photo.php.jpg, .htaccess), archives (ZIP, RAR, 7z, TAR, GZ), SVG, HTML, XML and JavaScript files, files whose content does not match their extension or whose type is unknown, and anything the malware scan flags.', 'qartvelo-guard' ) ),
					),
					in_array( $s['upload_mode'], array( 'hold_all', 'hold_risky' ), true ) ? $s['upload_mode'] : ''
				);
				?>
				<span class="wpcs-field__help"><?php esc_html_e( 'Uploads that look malicious are always held, whichever you choose.', 'qartvelo-guard' ); ?></span>
				</div>
			</div>
			<?php
			Settings_Page::render_toggle_row(
				'hold_admin_uploads',
				$hold_admin,
				__( 'Hold administrators\' own uploads too', 'qartvelo-guard' ),
				__( 'When off, files that administrators upload are still scanned and pass automatically when they are clean.', 'qartvelo-guard' ),
				array( 'data-wpcs-sync' => 'hold_admin_uploads' )
			);
			Settings_Page::render_toggle_row(
				'hold_installs',
				$hold_install,
				__( 'Hold new plugin and theme installs', 'qartvelo-guard' ),
				__( 'New plugins and themes stay in quarantine until you approve them. Updates of installed ones are not held.', 'qartvelo-guard' ),
				array( 'data-wpcs-sync' => 'hold_installs' )
			);
			Settings_Page::render_toggle_row(
				'quarantine_php',
				$quarantine,
				__( 'Move new unknown PHP files to quarantine automatically', 'qartvelo-guard' ),
				__( 'New PHP files that the plugin does not know are moved away until you approve them. When off, they are reported and stay in place.', 'qartvelo-guard' ),
				array( 'data-wpcs-sync' => 'quarantine_php' )
			);
			Settings_Page::notice( __( 'Keep the last option off on development or staging sites where you edit code: every new PHP file you create would be moved away until you approve it.', 'qartvelo-guard' ), 'warn' );
			?>
			<p class="wpcs-custom-hint wpcs-hidden" data-wpcs-custom-hint></p>
		</div>
		<?php
	}

	/**
	 * Busy sites: how many approvals "hold every upload" means, and the
	 * combination that keeps that manageable.
	 *
	 * @param array $s Settings.
	 */
	private function render_upload_hint( array $s ) {
		$tools = $this->tools();
		if ( ! method_exists( $tools, 'upload_activity' ) ) {
			return;
		}
		try {
			$stats = $tools->upload_activity();
		} catch ( \Throwable $e ) {
			return;
		}
		$per_day = isset( $stats['per_day'] ) ? (float) $stats['per_day'] : 0.0;
		if ( $per_day <= Sysadmin_Tools::BUSY_UPLOADS_PER_DAY ) {
			return;
		}
		$n    = number_format_i18n( (int) round( $per_day ) );
		$text = sprintf(
			/* translators: 1: uploads per day, 2: percentage, 3: uploads per day */
			__( 'This site receives about %1$s uploads a day (%2$s%% from users who are not administrators). Holding every upload means approving about %3$s files a day.', 'qartvelo-guard' ),
			$n,
			number_format_i18n( (int) $stats['non_admin_pct'] ),
			$n
		);
		echo '<div class="wpcs-callout wpcs-callout--hint" data-wpcs-upload-hint>';
		echo '<span class="wpcs-callout__icon" aria-hidden="true"><span class="dashicons dashicons-chart-bar"></span></span>';
		echo '<div class="wpcs-callout__text"><strong>' . esc_html( $text ) . '</strong>';
		if ( 'hold_risky' === $s['upload_mode'] && 'hold' === $s['install_mode'] ) {
			echo '<span class="wpcs-sub">' . esc_html__( 'This site already holds only risky uploads and every new plugin and theme, the combination we recommend for busy sites.', 'qartvelo-guard' ) . '</span></div>';
			echo '</div>';
			return;
		}
		echo '<span class="wpcs-sub">' . esc_html__( 'Recommended for this site: Balanced, but hold only risky uploads, and keep holding new plugins and themes. Clean images and documents then pass after the malware scan; anything that could run code still waits for you.', 'qartvelo-guard' ) . '</span></div>';
		echo '<button type="submit" name="wpcs_do" value="recommended_uploads" class="button button-primary" formnovalidate><span class="dashicons dashicons-yes" aria-hidden="true"></span>' . esc_html__( 'Use this', 'qartvelo-guard' ) . '</button>';
		echo '</div>';
	}

	/**
	 * Step 4: baseline scan.
	 */
	private function render_baseline() {
		$store     = Sysadmin_Tools::service( 'store' );
		$scan_job  = Sysadmin_Tools::service( 'scan_job' );
		$count     = ( $store && method_exists( $store, 'manifest_count' ) ) ? (int) $store->manifest_count() : 0;
		$available = $scan_job && method_exists( $scan_job, 'start' );
		// Set by the scan engine when a whole-site baseline finishes. Trusted rows alone
		// prove nothing: approvals and updates add some before any baseline exists.
		$base_at  = (int) \WPCyberSecurity\Network::get_option( 'wpcybersec_baseline_at', 0 );
		$has_base = $base_at > 0;

		$this->heading(
			'database',
			__( 'Fingerprint your current files', 'qartvelo-guard' ),
			__( 'The plugin records a fingerprint (SHA-256) of every file on your site and checks each one for malware. From then on only new or changed files are reported, so you are not asked to approve files that were already there.', 'qartvelo-guard' )
		);
		?>
		<ul class="wpcs-points">
			<li><span class="dashicons dashicons-media-code" aria-hidden="true"></span><?php esc_html_e( 'Covers WordPress core, plugins, themes and uploads.', 'qartvelo-guard' ); ?></li>
			<li><span class="dashicons dashicons-shield" aria-hidden="true"></span><?php esc_html_e( 'Files with known malware are reported as threats instead of being trusted.', 'qartvelo-guard' ); ?></li>
			<li><span class="dashicons dashicons-clock" aria-hidden="true"></span><?php esc_html_e( 'Usually takes 1 to 5 minutes. If you leave this page, the scan continues in the background, more slowly.', 'qartvelo-guard' ); ?></li>
		</ul>
		<?php
		if ( ! $available ) {
			Settings_Page::notice( __( 'The scan engine is not available in this installation, so the baseline cannot be created now. You can skip this step.', 'qartvelo-guard' ), 'bad' );
			return;
		}
		if ( $has_base ) {
			$when    = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $base_at );
			$message = sprintf(
				/* translators: 1: number of files, 2: date */
				__( 'A baseline already exists: %1$s files are fingerprinted (baseline recorded %2$s). You can continue, or run it again to trust the files as they are now.', 'qartvelo-guard' ),
				number_format_i18n( $count ),
				$when
			);
			Settings_Page::notice( $message, 'ok' );
		}
		?>
		<div class="wpcs-scanbox" data-wpcs-baseline-box data-has-baseline="<?php echo $has_base ? '1' : '0'; ?>">
			<div class="wpcs-scanbox__action">
				<?php // Once a baseline exists, Continue is the main action and scanning again is secondary. ?>
				<button type="button" class="<?php echo esc_attr( $has_base ? 'button button-large' : 'button button-primary button-hero' ); ?>" data-wpcs-baseline>
					<span class="dashicons dashicons-<?php echo esc_attr( $has_base ? 'update' : 'search' ); ?>" aria-hidden="true"></span>
					<span data-wpcs-baseline-label><?php echo $has_base ? esc_html__( 'Scan again', 'qartvelo-guard' ) : esc_html__( 'Scan and trust current files', 'qartvelo-guard' ); ?></span>
				</button>
				<span class="wpcs-scanbox__hint wpcs-muted" data-wpcs-baseline-hint<?php echo $has_base ? ' hidden' : ''; ?>><?php esc_html_e( 'Continue unlocks when the scan is done, or skip it for now.', 'qartvelo-guard' ); ?></span>
			</div>
			<div class="wpcs-progress wpcs-hidden" data-wpcs-baseline-progress>
				<div class="wpcs-progress__track"><div class="wpcs-progress__bar"></div></div>
				<div class="wpcs-progress__label"><span class="wpcs-progress__text"></span><span class="wpcs-progress__current"></span></div>
			</div>
			<div class="wpcs-scanbox__result wpcs-hidden" data-wpcs-baseline-result aria-live="polite"></div>
		</div>
		<p class="wpcs-muted wpcs-wizard__note"><?php esc_html_e( 'Tip: the baseline trusts what is on the server right now. If you suspect the site is already infected, look at the threats it reports before you approve anything.', 'qartvelo-guard' ); ?></p>
		<?php
	}

	/**
	 * Step 5: alerts.
	 */
	private function render_notifications() {
		$s      = $this->settings();
		$emails = $s['notify_emails'] ? (array) $s['notify_emails'] : \WPCyberSecurity\Network::default_recipients();

		$this->heading(
			'bell',
			__( 'How should we alert you?', 'qartvelo-guard' ),
			__( 'You will be told when an upload or install is waiting for approval and when a threat is found.', 'qartvelo-guard' )
		);
		?>
		<div class="wpcs-field">
			<div class="wpcs-field__label"><?php esc_html_e( 'Send alerts', 'qartvelo-guard' ); ?></div>
			<div><?php echo Settings_Page::notify_mode_choices( $s['notify_mode'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside. ?></div>
		</div>
		<div class="wpcs-field">
			<label class="wpcs-field__label" for="wpcs-notify-emails"><?php esc_html_e( 'Email recipients', 'qartvelo-guard' ); ?></label>
			<div>
				<textarea id="wpcs-notify-emails" name="notify_emails" rows="3" class="wpcs-textarea-sm" spellcheck="false"><?php echo esc_textarea( implode( "\n", $emails ) ); ?></textarea>
				<span class="wpcs-field__help">
					<?php
					echo esc_html(
						is_multisite()
							/* translators: %s: email addresses */
							? sprintf( __( 'One address per line. Leave empty to use the network admin email and the super admins (%s).', 'qartvelo-guard' ), implode( ', ', \WPCyberSecurity\Network::default_recipients() ) )
							/* translators: %s: email address */
							: sprintf( __( 'One address per line. Leave empty to use the site admin email (%s).', 'qartvelo-guard' ), get_option( 'admin_email' ) )
					);
					?>
				</span>
				<p class="wpcs-inline-actions">
					<button type="submit" name="wpcs_do" value="send_test" class="button" data-wpcs-test-email data-source="#wpcs-notify-emails">
						<span class="dashicons dashicons-email-alt" aria-hidden="true"></span><?php esc_html_e( 'Send test email', 'qartvelo-guard' ); ?>
					</button>
				</p>
			</div>
		</div>
		<div class="wpcs-field">
			<label class="wpcs-field__label" for="wpcs-webhook"><?php esc_html_e( 'Webhook URL', 'qartvelo-guard' ); ?> <span class="wpcs-muted"><?php esc_html_e( '(optional)', 'qartvelo-guard' ); ?></span></label>
			<div>
				<input type="url" id="wpcs-webhook" name="webhook_url" value="<?php echo esc_attr( $s['webhook_url'] ); ?>" placeholder="https://hooks.slack.com/services/..." class="regular-text" autocomplete="off">
				<span class="wpcs-field__help"><?php esc_html_e( 'Also posts a short message to Slack, Discord, Microsoft Teams or any service that accepts incoming webhooks. Must start with https://.', 'qartvelo-guard' ); ?></span>
			</div>
		</div>
		<?php
		// Optional, unchecked unless already chosen; "Skip" saves nothing, so it stays off.
		echo Settings_Page::share_stats_box( ! empty( $s['share_stats'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside.
	}

	/**
	 * Step 6: server hardening for system administrators.
	 */
	private function render_hardening() {
		$tools   = $this->tools();
		$s       = $this->settings();
		$server  = Sysadmin_Tools::server_type();
		$status  = $tools->uploads_htaccess_status();
		$guard   = Sysadmin_Tools::call( 'guard_manager', 'status', array(), null );
		$cron    = $tools->cron_snippets();
		$storage = Sysadmin_Tools::service( 'storage' );
		$in_root = $storage && method_exists( $storage, 'is_in_webroot' ) ? $storage->is_in_webroot( $storage->data_dir() ) : false;

		$this->heading(
			'admin-tools',
			__( 'Server hardening', 'qartvelo-guard' ),
			__( 'These steps add protection at the server level. If you are not sure, skip them: all of them are also in Settings > Advanced.', 'qartvelo-guard' )
		);
		$this->render_hosting_line();
		echo '<p class="wpcs-wizard__audience"><span class="wpcs-badge wpcs-badge--info"><span class="dashicons dashicons-admin-users" aria-hidden="true"></span>' . esc_html__( 'For system administrators - optional', 'qartvelo-guard' ) . '</span></p>';
		?>
		<div class="wpcs-section">
			<div class="wpcs-section__head">
				<span class="dashicons dashicons-upload" aria-hidden="true"></span>
				<h3><?php esc_html_e( 'Block PHP in the uploads folder', 'qartvelo-guard' ); ?></h3>
				<?php if ( 'none' !== $status ) : ?>
					<span class="wpcs-badge wpcs-badge--ok"><?php esc_html_e( 'Done', 'qartvelo-guard' ); ?></span>
				<?php endif; ?>
			</div>
			<p><?php esc_html_e( 'The uploads folder only needs images and documents. Blocking PHP there stops a planted backdoor from running even if it slips through.', 'qartvelo-guard' ); ?></p>
			<?php if ( 'nginx' === $server ) : ?>
				<p class="wpcs-muted"><?php esc_html_e( 'This server runs nginx, which ignores .htaccess files. Add these rules to the server block:', 'qartvelo-guard' ); ?></p>
				<?php echo Settings_Page::code( $tools->nginx_rules() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code(). ?>
			<?php elseif ( 'ours' !== $status ) : ?>
				<button type="submit" name="wpcs_do" value="write_htaccess" class="button">
					<span class="dashicons dashicons-media-text" aria-hidden="true"></span><?php esc_html_e( 'Add the rule to uploads/.htaccess', 'qartvelo-guard' ); ?>
				</button>
				<span class="wpcs-muted wpcs-inline-help"><?php esc_html_e( 'Existing content is kept. If the server rejects the rule, it is removed again automatically.', 'qartvelo-guard' ); ?></span>
			<?php endif; ?>
		</div>

		<div class="wpcs-section">
			<div class="wpcs-section__head">
				<span class="dashicons dashicons-lock" aria-hidden="true"></span>
				<h3><?php esc_html_e( 'Freeze mode', 'qartvelo-guard' ); ?></h3>
			</div>
			<?php
			Settings_Page::render_toggle_row(
				'freeze_mods',
				! empty( $s['freeze_mods'] ),
				__( 'Freeze plugins, themes and WordPress core', 'qartvelo-guard' ),
				__( 'Blocks installing, updating, deleting and editing code from the dashboard until you unlock it for a few minutes in Settings > Advanced. Recommended for finished sites that are updated on a schedule.', 'qartvelo-guard' )
			);
			?>
		</div>

		<div class="wpcs-section">
			<div class="wpcs-section__head">
				<span class="dashicons dashicons-clock" aria-hidden="true"></span>
				<h3><?php esc_html_e( 'Real cron job', 'qartvelo-guard' ); ?></h3>
				<?php $cron_runs = (int) \WPCyberSecurity\Network::get_option( 'wpcybersec_cli_cron_at', 0 ) > time() - 2 * HOUR_IN_SECONDS; ?>
				<?php if ( $cron_runs ) : ?>
					<span class="wpcs-badge wpcs-badge--ok"><?php esc_html_e( 'Running', 'qartvelo-guard' ); ?></span>
				<?php endif; ?>
			</div>
			<p><?php esc_html_e( 'WordPress normally runs scheduled tasks only when someone visits the site. A real cron job makes scans run on time. Cron jobs are set up in your hosting control panel (or with crontab on your own server), so this one cannot be done from here.', 'qartvelo-guard' ); ?></p>
			<?php
			$hardening = Sysadmin_Tools::service( 'hardening' );
			if ( $hardening && method_exists( $hardening, 'manual_steps' ) ) {
				// A real cron job already runs: the steps stay available but folded away.
				$panel_name = self::panel_name( 'cron' );
				/* translators: %s: hosting panel name */
				$where = '' !== $panel_name ? sprintf( __( 'On %s', 'qartvelo-guard' ), $panel_name ) : __( 'In a hosting control panel', 'qartvelo-guard' );
				echo $cron_runs ? '<details class="wpcs-manual"><summary>' . esc_html( $where ) . '</summary>' : '<div class="wpcs-manual wpcs-manual--open"><span class="wpcs-sub wpcs-check__fix">' . esc_html( $where ) . ':</span>';
				Settings_Page::render_steps( $hardening->manual_steps( 'wp_cron' ) );
				echo $cron_runs ? '</details>' : '</div>';
				echo '<details class="wpcs-manual"><summary>' . esc_html__( 'On your own server (crontab)', 'qartvelo-guard' ) . '</summary>';
				echo Settings_Page::code( $cron[0]['code'], $cron[0]['file'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
				echo '</details>';
				if ( $hardening->descriptor( 'disable_wp_cron' ) ) {
					$hardening->render_fix( 'disable_wp_cron' );
				}
			} else {
				echo Settings_Page::code( $cron[0]['code'], $cron[0]['file'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
				echo Settings_Page::code( $cron[2]['code'], $cron[2]['file'], $cron[2]['help'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
			}
			?>
		</div>

		<div class="wpcs-section">
			<div class="wpcs-section__head">
				<span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>
				<h3><?php esc_html_e( 'Early upload guard', 'qartvelo-guard' ); ?></h3>
				<?php
				$live = $this->guard_live( $guard );
				if ( $live ) {
					echo '<span class="wpcs-badge wpcs-badge--' . esc_attr( $live['tone'] ) . '">' . esc_html( $live['label'] ) . '</span>';
				}
				?>
			</div>
			<p><?php esc_html_e( 'Runs before any PHP code through auto_prepend_file and holds files uploaded to ANY script, including old scripts outside WordPress that attackers like to abuse.', 'qartvelo-guard' ); ?></p>
			<?php
			$hardening = Sysadmin_Tools::service( 'hardening' );
			$running   = $live && in_array( $live['state'], array( 'active', 'confirmed' ), true );
			if ( $running || ( is_array( $guard ) && ! empty( $guard['conflict'] ) ) ) {
				echo '<a class="button" href="' . esc_url( Sysadmin_Tools::settings_url( 'advanced', array(), 'wpcs-guard' ) ) . '">' . esc_html__( 'Guard settings', 'qartvelo-guard' ) . '</a>';
			} elseif ( $hardening && method_exists( $hardening, 'render_fix' ) ) {
				// One click: files, the right auto_prepend_file line for this server, a live test, undo on failure.
				$hardening->render_fix( 'guard' );
			} else {
				echo '<a class="button" href="' . esc_url( Sysadmin_Tools::settings_url( 'advanced', array(), 'wpcs-guard' ) ) . '">' . esc_html__( 'Set it up in Settings > Advanced', 'qartvelo-guard' ) . '</a>';
			}
			?>
		</div>

		<?php $this->render_antivirus_section(); ?>

		<div class="wpcs-section">
			<div class="wpcs-section__head">
				<span class="dashicons dashicons-media-code" aria-hidden="true"></span>
				<h3><?php esc_html_e( 'wp-config.php additions', 'qartvelo-guard' ); ?></h3>
			</div>
			<?php
			$hardening = Sysadmin_Tools::service( 'hardening' );
			if ( $in_root ) {
				echo '<p>' . esc_html__( 'Keep quarantined files outside the web root.', 'qartvelo-guard' ) . '</p>';
				if ( $hardening && method_exists( $hardening, 'render_fix' ) ) {
					$hardening->render_fix( 'data_dir' );
				} else {
					$data = $tools->data_dir_snippet();
					echo Settings_Page::code( $data['config'], 'wp-config.php' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
				}
			}
			echo '<p>' . esc_html__( 'A secret key lets the plugin notice when someone edits the allowlist directly in the database.', 'qartvelo-guard' ) . '</p>';
			if ( defined( 'WPCYBERSEC_HMAC_KEY' ) ) {
				echo '<span class="wpcs-badge wpcs-badge--ok">' . esc_html__( 'Key is set in wp-config.php', 'qartvelo-guard' ) . '</span>';
			} elseif ( $hardening && method_exists( $hardening, 'render_fix' ) ) {
				$hardening->render_fix( 'hmac_key' );
			} else {
				echo Settings_Page::code( $tools->hmac_snippet(), 'wp-config.php', __( 'The key was generated just now for you. Store it only in wp-config.php.', 'qartvelo-guard' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
			}
			?>
		</div>
		<?php
		$this->render_developer_link();
	}

	/**
	 * Optional antivirus engines (ClamAV, Linux Malware Detect) on the Server step.
	 */
	private function render_antivirus_section() {
		$av = Sysadmin_Tools::call( 'sysadmin', 'antivirus_status', array(), null );
		if ( ! is_array( $av ) ) {
			return;
		}
		$clam   = $av['clamav'];
		$maldet = $av['maldet'];
		$guide  = Sysadmin_Tools::settings_url( 'advanced', array(), 'wpcs-antivirus' );
		echo '<div class="wpcs-section">';
		echo '<div class="wpcs-section__head"><span class="dashicons dashicons-sos" aria-hidden="true"></span><h3>' . esc_html__( 'Antivirus (optional)', 'qartvelo-guard' ) . '</h3>';
		$short = array(
			'broken' => __( 'Not working', 'qartvelo-guard' ),
			'slow'   => __( 'Works, but slow', 'qartvelo-guard' ),
		);
		echo '<span class="wpcs-badge wpcs-badge--' . esc_attr( $clam['tone'] ) . '">' . esc_html( 'ClamAV: ' . ( isset( $short[ $clam['state'] ] ) ? $short[ $clam['state'] ] : $clam['label'] ) ) . '</span>';
		echo '</div>';
		echo '<p>' . esc_html__( 'ClamAV and Linux Malware Detect know many more existing infections and give every upload a second opinion. They find more, but they do not block attacks.', 'qartvelo-guard' ) . '</p>';
		$facts = array();
		$facts[] = '' !== $clam['binary']
			/* translators: %s: program path */
			? sprintf( __( 'ClamAV found at %s.', 'qartvelo-guard' ), $clam['binary'] )
			: ( ! empty( $clam['hidden'] ) ? __( 'Whether ClamAV is installed is unknown: the hosting hides it.', 'qartvelo-guard' ) : __( 'ClamAV is not installed.', 'qartvelo-guard' ) );
		if ( '' !== $maldet['binary'] ) {
			/* translators: %s: program path */
			$facts[] = sprintf( __( 'Linux Malware Detect found at %s.', 'qartvelo-guard' ), $maldet['binary'] );
		} elseif ( ! empty( $maldet['hidden'] ) ) {
			$facts[] = __( 'Whether Linux Malware Detect is installed is unknown: the hosting hides the folders it is installed in.', 'qartvelo-guard' );
		} elseif ( $maldet['supported'] ) {
			$facts[] = __( 'Linux Malware Detect is not installed.', 'qartvelo-guard' );
		}
		echo '<p class="wpcs-muted">' . esc_html( implode( ' ', $facts ) ) . '</p>';
		if ( 'missing' === $clam['state'] ) {
			// How this hosting panel installs ClamAV; the per-system guide is in Settings > Advanced.
			Settings_Page::render_panel_steps( 'clamav' );
		}
		if ( in_array( $clam['state'], array( 'broken', 'slow' ), true ) || ( 'ready_off' === $clam['state'] && ! empty( $clam['slow_only'] ) ) ) {
			// The self-test failed, or only a clamscan that is too slow for uploads works.
			Settings_Page::notice( $clam['label'] . ( ! empty( $clam['hint'] ) ? ' ' . $clam['hint'] : '' ), 'broken' === $clam['state'] ? 'bad' : 'warn' );
			if ( ! empty( $clam['hint_code'] ) ) {
				echo Settings_Page::code( $clam['hint_code'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
			}
		}
		echo '<p class="wpcs-row">';
		if ( 'ready_off' === $clam['state'] ) {
			echo '<button type="button" class="button button-primary" data-wpcs-clamav-enable><span class="dashicons dashicons-yes" aria-hidden="true"></span>' . esc_html__( 'Turn on ClamAV for uploads', 'qartvelo-guard' ) . '</button>';
			echo '<a href="' . esc_url( $guide ) . '">' . esc_html__( 'Details', 'qartvelo-guard' ) . '</a>';
		} elseif ( in_array( $clam['state'], array( 'uploads', 'uploads_scans', 'slow', 'broken' ), true ) ) {
			echo '<a class="button" href="' . esc_url( $guide ) . '">' . esc_html__( 'Antivirus settings', 'qartvelo-guard' ) . '</a>';
		} else {
			echo '<a class="button" href="' . esc_url( $guide ) . '"><span class="dashicons dashicons-book" aria-hidden="true"></span>' . esc_html__( 'Install guide', 'qartvelo-guard' ) . '</a>';
		}
		echo '</p></div>';
	}

	/**
	 * Link to the developer instructions while something needs server access.
	 */
	private function render_developer_link() {
		$count = (int) Sysadmin_Tools::call( 'developer', 'count', array(), 0 );
		if ( $count < 1 ) {
			return;
		}
		echo '<div class="wpcs-notice wpcs-devnote"><span class="dashicons dashicons-clipboard" aria-hidden="true"></span><p>';
		echo esc_html(
			sprintf(
				/* translators: %d: number of steps */
				_n( '%d step needs someone with server access (SSH, SFTP or the hosting panel).', '%d steps need someone with server access (SSH, SFTP or the hosting panel).', $count, 'qartvelo-guard' ),
				$count
			)
		) . ' ';
		echo '<a href="' . esc_url( Sysadmin_Tools::settings_url( 'advanced', array(), 'wpcs-developer' ) ) . '">' . esc_html__( 'Open the developer instructions', 'qartvelo-guard' ) . '</a>';
		echo '</p></div>';
	}

	/**
	 * Antivirus row of the summary: ClamAV state, plus Linux Malware Detect when it is installed.
	 *
	 * @param array $av Sysadmin_Tools::antivirus_status().
	 * @return string
	 */
	private function antivirus_summary( array $av ) {
		$clam  = $av['clamav'];
		$texts = array(
			'missing'       => ! empty( $clam['hidden'] ) ? __( 'ClamAV: unknown (hosting hides it)', 'qartvelo-guard' ) : __( 'ClamAV: not installed (optional)', 'qartvelo-guard' ),
			'blocked'       => __( 'ClamAV: installed, PHP cannot run it', 'qartvelo-guard' ),
			'broken'        => __( 'ClamAV: installed, not working', 'qartvelo-guard' ),
			'ready_off'     => __( 'ClamAV: ready, not in use', 'qartvelo-guard' ),
			'slow'          => __( 'ClamAV: on, too slow for uploads', 'qartvelo-guard' ),
			'uploads'       => __( 'ClamAV: checks uploads', 'qartvelo-guard' ),
			'uploads_scans' => __( 'ClamAV: checks uploads and scans', 'qartvelo-guard' ),
		);
		$parts = array( isset( $texts[ $clam['state'] ] ) ? $texts[ $clam['state'] ] : 'ClamAV: ' . $clam['label'] );
		if ( ! empty( $av['maldet']['binary'] ) ) {
			$parts[] = __( 'Linux Malware Detect: installed', 'qartvelo-guard' );
		}
		return implode( ', ', $parts );
	}

	/**
	 * @param array $av Sysadmin_Tools::antivirus_status().
	 * @return string Badge tone.
	 */
	private function antivirus_tone( array $av ) {
		$state = $av['clamav']['state'];
		if ( in_array( $state, array( 'uploads', 'uploads_scans' ), true ) ) {
			return 'ok';
		}
		if ( 'broken' === $state ) {
			return 'high';
		}
		return in_array( $state, array( 'ready_off', 'slow', 'blocked' ), true ) ? 'medium' : 'muted';
	}

	/**
	 * What to show for the early guard (Guard_Manager::live_state()).
	 *
	 * @param array|null $status Guard_Manager::status().
	 * @return array|null { state, label, tone }
	 */
	private function guard_live( $status ) {
		if ( ! is_array( $status ) ) {
			return null;
		}
		$manager = Sysadmin_Tools::service( 'guard_manager' );
		if ( $manager && method_exists( $manager, 'live_state' ) ) {
			return $manager->live_state( $status );
		}
		if ( ! empty( $status['active'] ) ) {
			return array(
				'state' => 'active',
				'label' => __( 'Active', 'qartvelo-guard' ),
				'tone'  => 'ok',
			);
		}
		return ! empty( $status['installed'] )
			? array(
				'state' => 'installed',
				'label' => __( 'Installed, not loaded yet', 'qartvelo-guard' ),
				'tone'  => 'medium',
			)
			: array(
				'state' => 'off',
				'label' => __( 'Not installed', 'qartvelo-guard' ),
				'tone'  => 'muted',
			);
	}

	/**
	 * Step 7: summary.
	 */
	private function render_done() {
		$s        = $this->settings();
		$labels   = Settings_Page::labels();
		$store    = Sysadmin_Tools::service( 'store' );
		$count    = ( $store && method_exists( $store, 'manifest_count' ) ) ? (int) $store->manifest_count() : 0;
		$has_base = (int) \WPCyberSecurity\Network::get_option( 'wpcybersec_baseline_at', 0 ) > 0;
		$guard    = Sysadmin_Tools::call( 'guard_manager', 'status', array(), null );
		$settings = Sysadmin_Tools::service( 'settings' );
		$emails   = $settings ? $settings->recipients() : \WPCyberSecurity\Network::default_recipients();

		$level_label = isset( $labels['protection_level'][ $s['protection_level'] ] ) ? $labels['protection_level'][ $s['protection_level'] ] : $s['protection_level'];

		$rows = array(
			array( 'shield', __( 'Protection level', 'qartvelo-guard' ), $level_label, 'ok' ),
			array( 'upload', __( 'New uploads', 'qartvelo-guard' ), $labels['upload_mode'][ $s['upload_mode'] ], 'off' === $s['upload_mode'] ? 'muted' : 'ok' ),
			array(
				'admin-plugins',
				__( 'Plugin and theme installs', 'qartvelo-guard' ),
				'hold' === $s['install_mode'] ? __( 'Held for approval', 'qartvelo-guard' ) : __( 'Not held', 'qartvelo-guard' ),
				'hold' === $s['install_mode'] ? 'ok' : 'muted',
			),
			array( 'media-code', __( 'New unknown PHP files', 'qartvelo-guard' ), $labels['file_mode'][ $s['file_mode'] ], 'off' === $s['file_mode'] ? 'muted' : 'ok' ),
			array( 'search', __( 'Scheduled scans', 'qartvelo-guard' ), $labels['scan_schedule'][ $s['scan_schedule'] ], 'off' === $s['scan_schedule'] ? 'muted' : 'ok' ),
			array(
				'database',
				__( 'Baseline', 'qartvelo-guard' ),
				/* translators: %s: number of files */
				$has_base ? sprintf( __( '%s files fingerprinted', 'qartvelo-guard' ), number_format_i18n( $count ) ) : __( 'Not created yet', 'qartvelo-guard' ),
				$has_base ? 'ok' : 'medium',
			),
			array(
				'email-alt',
				__( 'Alerts', 'qartvelo-guard' ),
				'off' === $s['notify_mode'] ? $labels['notify_mode']['off'] : $labels['notify_mode'][ $s['notify_mode'] ] . ': ' . implode( ', ', $emails ),
				'off' === $s['notify_mode'] ? 'muted' : 'ok',
			),
			array(
				'lock',
				__( 'Freeze mode', 'qartvelo-guard' ),
				! empty( $s['freeze_mods'] ) ? __( 'On', 'qartvelo-guard' ) : __( 'Off', 'qartvelo-guard' ),
				! empty( $s['freeze_mods'] ) ? 'ok' : 'muted',
			),
		);
		$live = $this->guard_live( $guard );
		if ( $live ) {
			$rows[] = array( 'shield-alt', __( 'Early upload guard', 'qartvelo-guard' ), 'off' === $live['state'] ? __( 'Not installed (optional)', 'qartvelo-guard' ) : $live['label'], $live['tone'] );
		}
		$av = Sysadmin_Tools::call( 'sysadmin', 'antivirus_status', array(), null );
		if ( is_array( $av ) ) {
			$rows[] = array( 'sos', __( 'Antivirus', 'qartvelo-guard' ), $this->antivirus_summary( $av ), $this->antivirus_tone( $av ) );
		}
		$alerts_off = 'off' === $s['notify_mode'];
		$counts     = Admin::counts();
		$open       = (int) $counts['threats'] + (int) $counts['pending'];
		if ( $counts['threats'] > 0 ) {
			Settings_Page::notice(
				sprintf(
					/* translators: %s: number of threats */
					_n( 'The baseline scan found %s possible threat. Review it on Reports > Threats before you approve anything.', 'The baseline scan found %s possible threats. Review them on Reports > Threats before you approve anything.', $counts['threats'], 'qartvelo-guard' ),
					number_format_i18n( $counts['threats'] )
				) . ' <a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'threats' ) ) ) . '">' . esc_html__( 'Open the threats', 'qartvelo-guard' ) . '</a>',
				'bad',
				true
			);
		} elseif ( $counts['pending'] > 0 ) {
			Settings_Page::notice(
				sprintf(
					/* translators: %s: number of items */
					_n( '%s item already waits for your decision on the Reports page.', '%s items already wait for your decision on the Reports page.', $counts['pending'], 'qartvelo-guard' ),
					number_format_i18n( $counts['pending'] )
				) . ' <a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS ) ) . '">' . esc_html__( 'Open Reports', 'qartvelo-guard' ) . '</a>',
				'info',
				true
			);
		}
		?>
		<div class="wpcs-wizard__hero wpcs-wizard__hero--done">
			<span class="wpcs-wizard__hero-icon"><span class="dashicons dashicons-<?php echo $open > 0 ? 'flag' : 'yes'; ?>" aria-hidden="true"></span></span>
			<h2 class="wpcs-wizard__hero-title"><?php echo esc_html( $counts['threats'] > 0 ? __( 'Setup is complete: review the threats', 'qartvelo-guard' ) : ( $open > 0 ? __( 'Setup is complete', 'qartvelo-guard' ) : __( 'Your site is protected', 'qartvelo-guard' ) ) ); ?></h2>
			<p class="wpcs-wizard__lead">
				<?php
				echo esc_html(
					$alerts_off
						? __( 'Here is what is active now. When something is held, it appears on the Reports page. Alerts are off, so look there regularly (or turn alerts on in Settings).', 'qartvelo-guard' )
						: __( 'Here is what is active now. When something is held, it appears on the Reports page and you get an alert.', 'qartvelo-guard' )
				);
				?>
			</p>
		</div>
		<ul class="wpcs-summary">
			<?php foreach ( $rows as $row ) : ?>
				<li>
					<span class="dashicons dashicons-<?php echo esc_attr( $row[0] ); ?>" aria-hidden="true"></span>
					<span class="wpcs-summary__label"><?php echo esc_html( $row[1] ); ?></span>
					<span class="wpcs-badge wpcs-badge--<?php echo esc_attr( $row[3] ); ?>"><?php echo esc_html( $row[2] ); ?></span>
				</li>
			<?php endforeach; ?>
		</ul>
		<h3 class="wpcs-wizard__subtitle"><?php esc_html_e( 'What\'s next', 'qartvelo-guard' ); ?></h3>
		<div class="wpcs-next">
			<a class="wpcs-next__item" href="<?php echo esc_url( Admin::page_url( Admin::PAGE_DASHBOARD ) ); ?>">
				<span class="dashicons dashicons-dashboard" aria-hidden="true"></span>
				<strong><?php esc_html_e( 'Dashboard', 'qartvelo-guard' ); ?></strong>
				<span><?php esc_html_e( 'Status at a glance, scans and recent activity.', 'qartvelo-guard' ); ?></span>
			</a>
			<a class="wpcs-next__item" href="<?php echo esc_url( Admin::page_url( Admin::PAGE_REPORTS ) ); ?>">
				<span class="dashicons dashicons-list-view" aria-hidden="true"></span>
				<strong><?php esc_html_e( 'Reports', 'qartvelo-guard' ); ?></strong>
				<span><?php esc_html_e( 'Approve or deny held uploads, installs and files.', 'qartvelo-guard' ); ?></span>
			</a>
			<a class="wpcs-next__item" href="<?php echo esc_url( Sysadmin_Tools::settings_url( 'advanced' ) ); ?>">
				<span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>
				<strong><?php esc_html_e( 'Advanced settings', 'qartvelo-guard' ); ?></strong>
				<span><?php esc_html_e( 'Early guard, real cron, server rules and more.', 'qartvelo-guard' ); ?></span>
			</a>
		</div>
		<div class="wpcs-wizard__footer">
			<a class="button button-large wpcs-wizard__back" href="<?php echo esc_url( self::url( 'hardening' ) ); ?>">
				<span class="dashicons dashicons-arrow-left-alt2" aria-hidden="true"></span><?php esc_html_e( 'Back', 'qartvelo-guard' ); ?>
			</a>
			<span class="wpcs-spacer"></span>
			<a class="button button-primary button-large wpcs-wizard__next" href="<?php echo esc_url( Admin::page_url( Admin::PAGE_DASHBOARD ) ); ?>">
				<?php esc_html_e( 'Go to the Dashboard', 'qartvelo-guard' ); ?><span class="dashicons dashicons-arrow-right-alt2" aria-hidden="true"></span>
			</a>
		</div>
		<?php
	}
}
