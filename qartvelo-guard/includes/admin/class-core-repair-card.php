<?php
/**
 * "WordPress core looks damaged" card on the Dashboard and the Reports tabs.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Core_Repair;

defined( 'ABSPATH' ) || exit;

/**
 * Shows the core damage found by the last scan with the two ways to get a
 * clean core (WordPress reinstalls itself when this server allows it, by hand
 * always) and the outcome of the last reinstall. Behaviour lives in
 * assets/js/core-repair.js.
 */
class Core_Repair_Card {

	/**
	 * Prints the card when there is something to show.
	 *
	 * @param string $context dashboard | reports.
	 * @return bool Whether the damage card (id wpcs-core-card) was printed with its reinstall option.
	 */
	public static function render( $context = 'dashboard' ) {
		$repair = function_exists( 'wpcybersec' ) ? wpcybersec()->core_repair : null;
		if ( ! $repair instanceof Core_Repair ) {
			return false;
		}
		try {
			$result = $repair->last_result();
			$damage = $repair->damage();
			if ( $result ) {
				self::render_result( $result, $damage, $context );
			}
			if ( ! $damage['show'] ) {
				return false;
			}
			self::render_damage( $repair, $damage, $context );
			return $damage['repairable'] > 0;
		} catch ( \Throwable $e ) {
			return false; // Never break the page over this card.
		}
	}

	/**
	 * Outcome of the last reinstall, until it is dismissed.
	 *
	 * @param array  $result  Core_Repair::last_result().
	 * @param array  $damage  damage().
	 * @param string $context dashboard | reports.
	 */
	private static function render_result( array $result, array $damage, $context ) {
		if ( empty( $result['ok'] ) ) {
			echo '<div class="wpcs-notice wpcs-notice--bad wpcs-dash-alert wpcs-core-result" data-wpcs-core-result><span class="dashicons dashicons-warning" aria-hidden="true"></span><div><p><strong>'
				. esc_html__( 'The core reinstall did not complete.', 'qartvelo-guard' ) . '</strong></p><p>' . esc_html( (string) $result['message'] ) . '</p></div>';
			echo '<button type="button" class="button wpcs-dash-alert__btn" data-wpcs-core-dismiss>' . esc_html__( 'Dismiss', 'qartvelo-guard' ) . '</button></div>';
			return;
		}
		echo '<div class="wpcs-notice wpcs-notice--ok wpcs-dash-alert wpcs-core-result" data-wpcs-core-result><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span><div><p><strong>'
			. esc_html__( 'WordPress core was reinstalled.', 'qartvelo-guard' ) . '</strong></p><p>' . esc_html( (string) $result['message'] ) . '</p>';
		// Counted now, not when the reinstall ran: files reviewed since are not named again.
		$extra = Core_Repair::extra_text( (int) $damage['unknown'], $context );
		if ( '' !== $extra ) {
			echo '<p><strong>' . esc_html( $extra ) . '</strong>';
			if ( 'reports' !== $context ) {
				echo ' <a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'threats' ) ) ) . '">' . esc_html__( 'Open Reports', 'qartvelo-guard' ) . '</a>';
			}
			echo '</p>';
		}
		echo '<p>' . esc_html( Core_Repair::after_steps()[0]['text'] ) . ' <code>wp config shuffle-salts</code></p></div>';
		echo '<button type="button" class="button wpcs-dash-alert__btn" data-wpcs-core-dismiss>' . esc_html__( 'Dismiss', 'qartvelo-guard' ) . '</button></div>';
	}

	/**
	 * The damage card with both options.
	 *
	 * @param Core_Repair $repair  Service.
	 * @param array       $damage  damage().
	 * @param string      $context dashboard | reports.
	 */
	private static function render_damage( Core_Repair $repair, array $damage, $context ) {
		$auto = $repair->auto_status();
		echo '<div class="wpcs-card wpcs-card--bad wpcs-core-card" data-wpcs-core id="wpcs-core-card">';
		echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-wordpress" aria-hidden="true"></span>' . esc_html(
			$damage['repairable']
				? sprintf(
					/* translators: %s: number of files */
					_n( 'WordPress core looks damaged: %s core file affected', 'WordPress core looks damaged: %s core files affected', $damage['total'], 'qartvelo-guard' ),
					number_format_i18n( $damage['total'] )
				)
				: sprintf(
					/* translators: %s: number of files */
					_n( '%s file in wp-admin or wp-includes is not part of WordPress', '%s files in wp-admin or wp-includes are not part of WordPress', $damage['unknown'], 'qartvelo-guard' ),
					number_format_i18n( $damage['unknown'] )
				)
		) . '</h2>';

		$lines = array();
		if ( $damage['modified'] ) {
			/* translators: %s: number of files */
			$lines[] = sprintf( _n( '%s core file differs from the official WordPress file', '%s core files differ from the official WordPress files', $damage['modified'], 'qartvelo-guard' ), number_format_i18n( $damage['modified'] ) );
		}
		if ( $damage['threats'] ) {
			/* translators: %s: number of files */
			$lines[] = sprintf( _n( '%s threat in a core file', '%s threats in core files', $damage['threats'], 'qartvelo-guard' ), number_format_i18n( $damage['threats'] ) );
		}
		if ( $damage['unknown'] ) {
			$lines[] = sprintf(
				/* translators: 1: number of files, 2: number of them that can run code */
				_n( '%1$s file in wp-admin or wp-includes that is not part of WordPress (%2$s can run code)', '%1$s files in wp-admin or wp-includes that are not part of WordPress (%2$s can run code)', $damage['unknown'], 'qartvelo-guard' ),
				number_format_i18n( $damage['unknown'] ),
				number_format_i18n( $damage['unknown_exec'] )
			);
		}
		if ( $damage['missing'] ) {
			/* translators: %s: number of files */
			$lines[] = sprintf( _n( '%s core file is missing', '%s core files are missing', $damage['missing'], 'qartvelo-guard' ), number_format_i18n( $damage['missing'] ) );
		}
		echo '<ul class="wpcs-core-card__counts">';
		foreach ( $lines as $line ) {
			echo '<li><span class="dashicons dashicons-arrow-right-alt2" aria-hidden="true"></span>' . esc_html( $line ) . '</li>';
		}
		echo '</ul>';
		if ( $damage['unknown_exec'] ) {
			echo '<p class="wpcs-core-card__warn"><strong>' . esc_html__( 'wp-admin and wp-includes should only ever contain WordPress files. An extra PHP file there is a classic backdoor.', 'qartvelo-guard' ) . '</strong></p>';
		}
		if ( $damage['repairable'] ) {
			// A localized package is the full one: WordPress's updater replaces its own translation files too.
			echo '<p>' . esc_html(
				Core_Repair::is_localized()
					? sprintf(
						/* translators: %s: WordPress version */
						__( 'Reinstalling WordPress core restores every core file from the official package of version %s, which is faster and safer than reviewing changed core files one by one: wp-admin, wp-includes and the core files in the WordPress folder are overwritten with the official ones. wp-config.php, .htaccess, plugins, themes, uploads and the other files you added are not touched.', 'qartvelo-guard' ),
						$damage['version']
					) . ' ' . Core_Repair::languages_text()
					: sprintf(
						/* translators: %s: WordPress version */
						__( 'Reinstalling WordPress core restores every core file from the official package of version %s, which is faster and safer than reviewing changed core files one by one: wp-admin, wp-includes and the core files in the WordPress folder are overwritten with the official ones. wp-config.php, wp-content (plugins, themes, uploads, languages), .htaccess and the other files you added stay as they are.', 'qartvelo-guard' ),
						$damage['version']
					)
			) . '</p>';
		}
		if ( $damage['unknown'] ) {
			echo '<p>' . esc_html(
				'reports' === $context
					? __( 'Reinstalling WordPress core only overwrites WordPress files. It does not remove files that are not part of WordPress: those stay in wp-admin or wp-includes and stay in the list below, where you quarantine or delete them one by one.', 'qartvelo-guard' )
					: __( 'Reinstalling WordPress core only overwrites WordPress files. It does not remove files that are not part of WordPress: those stay in wp-admin or wp-includes and stay in Reports, where you quarantine or delete them one by one.', 'qartvelo-guard' )
			);
			if ( 'reports' !== $context ) {
				echo ' <a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'threats' ) ) ) . '">' . esc_html__( 'Open Reports', 'qartvelo-guard' ) . '</a>';
			}
			echo '</p>';
		}

		echo '<div class="wpcs-core-card__options">';
		if ( $damage['repairable'] ) {
			self::render_reinstall_option( $auto, $damage );
		} else {
			// Only extra files: a reinstall by WordPress changes nothing for them. Replacing the two folders by hand removes them all at once.
			echo '<p class="wpcs-sub">' . esc_html__( 'No WordPress core file is changed or missing, so a reinstall has nothing to restore. When there are too many extra files to review one by one, replacing wp-admin and wp-includes by hand removes all of them at once:', 'qartvelo-guard' ) . '</p>';
		}

		echo '<details class="wpcs-core-option wpcs-core-manual"' . ( $auto['ok'] || ! $damage['repairable'] ? '' : ' open' ) . '>';
		echo '<summary>' . esc_html__( 'Do it by hand, step by step', 'qartvelo-guard' ) . '</summary>';
		$hosting = wpcybersec()->hosting;
		if ( $hosting ) {
			$info = $hosting->current();
			echo '<p class="wpcs-sub"><span class="dashicons dashicons-admin-site-alt3" aria-hidden="true"></span> ' . esc_html( $hosting->label( $info ) ) . ' <a href="' . esc_url( \WPCyberSecurity\Hosting::change_url() ) . '">' . esc_html__( 'Not your hosting?', 'qartvelo-guard' ) . '</a></p>';
		}
		Settings_Page::render_steps( $repair->manual_steps() );
		if ( 'composer' !== Core_Repair::layout() ) {
			echo '<p class="wpcs-core-card__actions">';
			echo '<a class="button" href="' . esc_url( Core_Repair::package_url( $damage['version'] ) ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span> ' . esc_html__( 'Download the package', 'qartvelo-guard' ) . '</a> ';
			echo '<a class="button" href="' . esc_url( \WPCyberSecurity\Developer_Instructions::download_url() ) . '">' . esc_html__( 'Download these steps (.txt)', 'qartvelo-guard' ) . '</a>';
			echo '</p>';
		}
		echo '</details>';
		echo '</div></div>';
	}

	/**
	 * "Let WordPress reinstall its core": the button, or why it cannot be started from here.
	 *
	 * @param array $auto   Core_Repair::auto_status().
	 * @param array $damage damage().
	 */
	private static function render_reinstall_option( array $auto, array $damage ) {
		echo '<div class="wpcs-core-option">';
		echo '<h3>' . esc_html__( 'Let WordPress reinstall its core', 'qartvelo-guard' ) . '</h3>';
		if ( $auto['ok'] ) {
			$confirm = Core_Repair::confirm_text( $damage );
			echo '<p class="wpcs-sub">' . esc_html__( 'Starts the updater that is built into WordPress, the same one as Dashboard > Updates > "Re-install": WordPress downloads the official package of this version from wordpress.org, checks it, switches its maintenance mode on for a moment and overwrites its own files. The plugin itself writes no core file. The changed files are not kept.', 'qartvelo-guard' )
				. ' <a href="' . esc_url( Core_Repair::updates_url() ) . '">' . esc_html__( 'Open Dashboard > Updates instead', 'qartvelo-guard' ) . '</a></p>';
			echo '<p class="wpcs-core-card__actions"><button type="button" class="button button-primary" data-wpcs-core-start'
				. ' data-title="' . esc_attr( $confirm['title'] ) . '" data-verdict="' . esc_attr( $confirm['verdict'] ) . '"'
				. ' data-text="' . esc_attr( $confirm['text'] ) . '" data-confirm-label="' . esc_attr( $confirm['confirm'] ) . '">'
				. '<span class="dashicons dashicons-update" aria-hidden="true"></span> ' . esc_html__( 'Reinstall WordPress core', 'qartvelo-guard' ) . '</button></p>';
			echo '<p class="wpcs-sub wpcs-core-card__status wpcs-hidden" data-wpcs-core-status role="status"></p>';
			self::progress();
		} else {
			echo '<p class="wpcs-sub">' . esc_html__( 'Not available on this site:', 'qartvelo-guard' ) . ' ' . esc_html( $auto['reason'] ) . '</p>';
			if ( 'fs' === $auto['code'] ) {
				echo '<p class="wpcs-core-card__actions"><a class="button button-primary" href="' . esc_url( Core_Repair::updates_url() ) . '">' . esc_html__( 'Open Dashboard > Updates', 'qartvelo-guard' ) . '</a></p>';
			}
		}
		echo '</div>';
	}

	/**
	 * Hidden progress block (same markup as the scan progress): core-repair.js
	 * shows the quick scan in it that follows a reinstall.
	 */
	private static function progress() {
		echo '<div class="wpcs-progress wpcs-hidden" data-wpcs-core-progress>';
		echo '<div class="wpcs-progress__track"><div class="wpcs-progress__bar" style="width:0%"></div></div>';
		echo '<div class="wpcs-progress__label"><span class="wpcs-progress__text"></span><span class="wpcs-progress__current"></span></div>';
		echo '</div>';
	}

	/**
	 * Strings for core-repair.js.
	 *
	 * @return array
	 */
	public static function i18n() {
		return array(
			'working' => __( 'WordPress is reinstalling its core: it downloads the official package and replaces its own files. This can take a minute. Keep this page open.', 'qartvelo-guard' ),
			'timeout' => __( 'The request did not answer. WordPress may still be working: reload this page in a minute to see the result.', 'qartvelo-guard' ),
		);
	}
}
