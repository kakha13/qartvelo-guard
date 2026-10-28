<?php
/**
 * Admin menu, assets, notices, admin bar and admin-post handlers.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Decisions;
use WPCyberSecurity\Installer;
use WPCyberSecurity\Recent_Changes;
use WPCyberSecurity\Site_Report;
use WPCyberSecurity\Store;

defined( 'ABSPATH' ) || exit;

/**
 * Glue for every admin screen of the plugin. Pages:
 *
 *   wpcybersec           Dashboard_Page
 *   wpcybersec-reports   Reports_Page
 *   wpcybersec-settings  Settings_Page (setup module)
 *   wpcybersec-wizard    Wizard (setup module)
 *
 * Other modules can rely on:
 *   Admin::header( $title, $subtitle, $actions_html )   page header partial
 *   Admin::page_url( $page, $args )                     admin URL of a plugin page
 *   Admin::is_plugin_page()                             true on any plugin screen
 *   action wpcybersec_admin_enqueue( $page, $hook )     fires after base + admin assets are enqueued
 *   filter wpcybersec_is_plugin_screen( $bool, $hook )  extend which screens get the assets
 */
class Admin {

	/**
	 * Capability on a single site. On multisite every screen and handler needs
	 * NETWORK_CAP instead (see cap()), because the plugin works on the shared
	 * file system: a site administrator must not be able to change the scan
	 * folder, quarantine or download files of the whole network.
	 */
	const CAP         = 'manage_options';
	const NETWORK_CAP = 'manage_network_options';

	const PAGE_DASHBOARD = 'wpcybersec';
	const PAGE_REPORTS   = 'wpcybersec-reports';
	const PAGE_SETTINGS  = 'wpcybersec-settings';
	const PAGE_WIZARD    = 'wpcybersec-wizard';

	const META_DISMISS_SETUP   = 'wpcybersec_dismiss_setup';

	/** Most items one bulk action may touch (the risk check inspects every one of them). */
	const MAX_BULK = 500;
	const META_DISMISS_PENDING = 'wpcybersec_dismiss_pending';
	const META_DISMISS_STORAGE = 'wpcybersec_dismiss_storage';

	/** User meta: result of the "Move the data" button, shown once on the next page. */
	const META_STORAGE_MOVE = 'wpcybersec_storage_move';

	/** @var array|null Per-request cache of Store::counts(). */
	private static $counts = null;

	/** @var object|null Admin\Settings_Page instance (setup module). */
	private $settings_page = null;

	/** @var object|null Admin\Wizard instance (setup module). */
	private $wizard = null;

	/** @var bool */
	private $admin_bar_registered = false;

	/**
	 * Capability required for every plugin screen, AJAX endpoint and admin-post
	 * handler.
	 *
	 * @return string
	 */
	public static function cap() {
		return is_multisite() ? self::NETWORK_CAP : self::CAP;
	}

	/**
	 * Whether the current user may use the plugin (see cap()).
	 *
	 * @return bool
	 */
	public static function can() {
		return current_user_can( self::cap() );
	}

	/**
	 * Hooks. Runs on plugins_loaded inside is_admin() requests (admin pages,
	 * admin-post.php and admin-ajax.php).
	 */
	public function register() {
		// Setup module pages register their own handlers (admin-post wpcybersec_wizard, wpcybersec_save_settings).
		$this->settings_page = $this->make( __NAMESPACE__ . '\\Settings_Page' );
		$this->wizard        = $this->make( __NAMESPACE__ . '\\Wizard' );
		foreach ( array( $this->settings_page, $this->wizard ) as $page ) {
			if ( is_object( $page ) && method_exists( $page, 'register' ) ) {
				$page->register();
			}
		}

		// Multisite: the screens live in Network Admin only. Site administrators
		// see no plugin menu (their uploads are still held); super admins
		// approve from Network Admin.
		$menu_hook = is_multisite() ? 'network_admin_menu' : 'admin_menu';
		add_action( $menu_hook, array( $this, 'menu' ) );
		add_action( $menu_hook, array( $this, 'menu_bubbles' ), 999 );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_init', array( $this, 'maybe_redirect' ), 1 );
		add_action( 'admin_notices', array( $this, 'notices' ) );
		add_action( 'network_admin_notices', array( $this, 'notices' ) );
		add_filter( 'plugin_action_links_' . WPCYBERSEC_BASENAME, array( $this, 'action_links' ) );
		add_filter( 'network_admin_plugin_action_links_' . WPCYBERSEC_BASENAME, array( $this, 'action_links' ) );
		add_filter( 'removable_query_args', array( $this, 'removable_query_args' ) );

		add_action( 'admin_post_wpcybersec_download', array( $this, 'handle_download' ) );
		add_action( 'admin_post_wpcybersec_preview', array( $this, 'handle_preview' ) );
		add_action( 'admin_post_wpcybersec_allowlist_remove', array( $this, 'handle_allowlist_remove' ) );
		add_action( 'admin_post_wpcybersec_reports_bulk', array( $this, 'handle_reports_bulk' ) );
		add_action( 'admin_post_wpcybersec_dismiss_notice', array( $this, 'handle_dismiss_notice' ) );
		add_action( 'admin_post_wpcybersec_storage_move', array( $this, 'handle_storage_move' ) );
		add_action( 'admin_post_wpcybersec_report', array( $this, 'handle_report' ) );
		add_action( 'admin_post_wpcybersec_recent_report', array( $this, 'handle_recent_report' ) );

		$this->register_admin_bar();
	}

	/**
	 * Admin bar node. Public so the front end can show it too:
	 * ( new Admin\Admin() )->register_admin_bar().
	 */
	public function register_admin_bar() {
		if ( $this->admin_bar_registered ) {
			return;
		}
		$this->admin_bar_registered = true;
		add_action( 'admin_bar_menu', array( $this, 'admin_bar' ), 85 );
		add_action( 'wp_enqueue_scripts', array( $this, 'admin_bar_style' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'admin_bar_style' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Menu                                                                */
	/* ------------------------------------------------------------------ */

	/**
	 * Registers the top level menu and its pages.
	 */
	public function menu() {
		$dashboard = new Dashboard_Page();
		$reports   = new Reports_Page();

		add_menu_page(
			__( 'Qartvelo Guard', 'qartvelo-guard' ),
			// Short on purpose: the full name plus the count bubble does not fit the 160px menu.
			__( 'Guard', 'qartvelo-guard' ),
			self::cap(),
			self::PAGE_DASHBOARD,
			array( $dashboard, 'render' ),
			'dashicons-shield',
			80
		);

		add_submenu_page(
			self::PAGE_DASHBOARD,
			__( 'Security Dashboard', 'qartvelo-guard' ),
			__( 'Dashboard', 'qartvelo-guard' ),
			self::cap(),
			self::PAGE_DASHBOARD,
			array( $dashboard, 'render' )
		);

		add_submenu_page(
			self::PAGE_DASHBOARD,
			__( 'Security Reports', 'qartvelo-guard' ),
			__( 'Reports', 'qartvelo-guard' ),
			self::cap(),
			self::PAGE_REPORTS,
			array( $reports, 'render' )
		);

		add_submenu_page(
			self::PAGE_DASHBOARD,
			__( 'Security Settings', 'qartvelo-guard' ),
			__( 'Settings', 'qartvelo-guard' ),
			self::cap(),
			self::PAGE_SETTINGS,
			$this->page_callback( $this->settings_page, __( 'Settings', 'qartvelo-guard' ) )
		);

		add_submenu_page(
			self::PAGE_DASHBOARD,
			__( 'Security Setup Wizard', 'qartvelo-guard' ),
			__( 'Setup Wizard', 'qartvelo-guard' ),
			self::cap(),
			self::PAGE_WIZARD,
			$this->page_callback( $this->wizard, __( 'Setup Wizard', 'qartvelo-guard' ) )
		);
	}

	/**
	 * Appends count bubbles after the menu is built, so page hook names stay
	 * stable ("cyber-security_page_wpcybersec-reports") whatever the count is.
	 */
	public function menu_bubbles() {
		global $menu, $submenu;
		if ( ! self::can() ) {
			return;
		}
		$counts = self::counts();
		$total  = $counts['pending'] + $counts['threats'];
		if ( $total < 1 ) {
			return;
		}
		$bubble = self::bubble_html( $total );

		if ( is_array( $menu ) ) {
			foreach ( $menu as $key => $item ) {
				if ( isset( $item[2] ) && self::PAGE_DASHBOARD === $item[2] ) {
					$menu[ $key ][0] .= $bubble; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				}
			}
		}
		if ( isset( $submenu[ self::PAGE_DASHBOARD ] ) && is_array( $submenu[ self::PAGE_DASHBOARD ] ) ) {
			foreach ( $submenu[ self::PAGE_DASHBOARD ] as $key => $item ) {
				if ( isset( $item[2] ) && self::PAGE_REPORTS === $item[2] ) {
					$submenu[ self::PAGE_DASHBOARD ][ $key ][0] .= $bubble; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				}
			}
		}
	}

	/**
	 * WordPress' standard "awaiting-mod" count bubble.
	 *
	 * @param int $total Count.
	 * @return string
	 */
	private static function bubble_html( $total ) {
		$total = (int) $total;
		return sprintf(
			' <span class="awaiting-mod wpcs-menu-count count-%1$d"><span class="pending-count" aria-hidden="true">%2$s</span><span class="screen-reader-text">%3$s</span></span>',
			$total,
			esc_html( number_format_i18n( $total ) ),
			esc_html(
				sprintf(
					/* translators: %s: number of items */
					_n( '%s item needs your review', '%s items need your review', $total, 'qartvelo-guard' ),
					number_format_i18n( $total )
				)
			)
		);
	}

	/**
	 * Creates a setup module page object if its class is available.
	 *
	 * @param string $class Fully qualified class name.
	 * @return object|null
	 */
	private function make( $class ) {
		try {
			if ( class_exists( $class ) ) {
				return new $class();
			}
		} catch ( \Throwable $e ) {
			self::debug_log( $e );
		}
		return null;
	}

	/**
	 * @param object|null $page  Page object with render().
	 * @param string      $label Page name for the fallback message.
	 * @return callable
	 */
	private function page_callback( $page, $label ) {
		if ( is_object( $page ) && method_exists( $page, 'render' ) ) {
			return array( $page, 'render' );
		}
		return static function () use ( $label ) {
			self::render_missing( $label );
		};
	}

	/**
	 * Fallback when a page from another module is not installed.
	 *
	 * @param string $label Page name.
	 */
	public static function render_missing( $label ) {
		echo '<div class="wrap wpcs-wrap">';
		self::header( $label );
		echo '<div class="wpcs-notice wpcs-notice--warn"><span class="dashicons dashicons-warning" aria-hidden="true"></span><div><p><strong>'
			. esc_html__( 'This page is not available.', 'qartvelo-guard' )
			. '</strong></p><p>'
			. esc_html__( 'Some plugin files are missing or could not be loaded. Reinstall Qartvelo Guard to restore them. Your settings, approvals and allowlist are kept.', 'qartvelo-guard' )
			. '</p></div></div>';
		echo '<p><a class="button" href="' . esc_url( self::page_url( self::PAGE_DASHBOARD ) ) . '">' . esc_html__( 'Back to the dashboard', 'qartvelo-guard' ) . '</a></p>';
		echo '</div>';
	}

	/* ------------------------------------------------------------------ */
	/* Assets                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Registers shared handles everywhere and enqueues them on plugin screens
	 * (dashboard, reports, settings and wizard).
	 *
	 * @param string $hook Admin page hook suffix.
	 */
	public function enqueue( $hook ) {
		Assets::register();

		if ( ! $this->is_plugin_screen( $hook ) ) {
			return;
		}

		Assets::enqueue();
		wp_enqueue_style( 'wpcybersec-admin', WPCYBERSEC_URL . 'assets/css/admin.css', array( 'wpcybersec-base' ), \WPCyberSecurity\Admin\Assets::ver( 'assets/css/admin.css' ) );
		wp_enqueue_script( 'wpcybersec-admin', WPCYBERSEC_URL . 'assets/js/admin.js', array( 'wpcybersec-core' ), \WPCyberSecurity\Admin\Assets::ver( 'assets/js/admin.js' ), true );
		wp_localize_script(
			'wpcybersec-admin',
			'wpcybersecAdmin',
			array(
				'i18n' => array(
					'details'        => __( 'Details', 'qartvelo-guard' ),
					'hideDetails'    => __( 'Hide details', 'qartvelo-guard' ),
					'chooseAction'   => __( 'Choose a bulk action first.', 'qartvelo-guard' ),
					'chooseItems'    => __( 'Select at least one item.', 'qartvelo-guard' ),
					'confirmDeleteOne' => __( 'Delete the selected item permanently? Its held copy or live file is removed and this cannot be undone.', 'qartvelo-guard' ),
					/* translators: %s: number of items */
					'confirmDelete'    => __( 'Delete %s items permanently? Held copies and live files are removed and this cannot be undone.', 'qartvelo-guard' ),
					'confirmDenyOne'   => __( 'Deny the selected item? Its held copy is deleted.', 'qartvelo-guard' ),
					/* translators: %s: number of items */
					'confirmDeny'      => __( 'Deny %s items? Their held copies are deleted.', 'qartvelo-guard' ),
					'bulkDoneOne'      => __( '1 item updated.', 'qartvelo-guard' ),
					/* translators: %s: number of items */
					'bulkDone'         => __( '%s items updated.', 'qartvelo-guard' ),
					'bulkFailedOne'    => __( '1 item could not be changed:', 'qartvelo-guard' ),
					/* translators: %s: number of items */
					'bulkFailed'       => __( '%s items could not be changed:', 'qartvelo-guard' ),
					'working'        => __( 'Working...', 'qartvelo-guard' ),
					'comparing'      => __( 'Comparing...', 'qartvelo-guard' ),
					'unlocked'       => __( 'File changes unlocked. Install or update what you need, then lock again.', 'qartvelo-guard' ),
					'locked'         => __( 'File changes locked.', 'qartvelo-guard' ),
					'refreshing'     => __( 'Scan finished. Refreshing the dashboard...', 'qartvelo-guard' ),
					/* translators: %s: number of items */
					'menuCount'      => __( '%s items need your review', 'qartvelo-guard' ),
					'cancel'           => __( 'Cancel', 'qartvelo-guard' ),
					'riskAllowYes'     => __( 'Allow anyway', 'qartvelo-guard' ),
					'riskSafeYes'      => __( 'Mark safe anyway', 'qartvelo-guard' ),
					'riskBulkAllowOne' => __( 'Allow 1 risky item anyway?', 'qartvelo-guard' ),
					/* translators: %s: number of items */
					'riskBulkAllow'    => __( 'Allow %s risky items anyway?', 'qartvelo-guard' ),
					'riskBulkSafeOne'  => __( 'Mark 1 risky item as safe anyway?', 'qartvelo-guard' ),
					/* translators: %s: number of items */
					'riskBulkSafe'     => __( 'Mark %s risky items as safe anyway?', 'qartvelo-guard' ),
					/* translators: 1: number of risky items, 2: number of selected items */
					'riskBulkVerdict'  => __( '%1$s of the %2$s selected items were flagged high or critical.', 'qartvelo-guard' ),
					'cleanTitleOne'    => __( 'Allow 1 clean image?', 'qartvelo-guard' ),
					/* translators: %s: number of images */
					'cleanTitle'       => __( 'Allow %s clean images?', 'qartvelo-guard' ),
					'cleanYesOne'      => __( 'Allow 1 image', 'qartvelo-guard' ),
					/* translators: %s: number of images */
					'cleanYes'         => __( 'Allow %s images', 'qartvelo-guard' ),
					'cleanText'        => __( 'Only uploads with no findings whose content was verified as a JPEG, PNG, GIF or WebP image are included. Each one is added to the Media Library and its fingerprint is remembered, like a single Allow.', 'qartvelo-guard' ),
					'cleanMore'        => __( 'This is the first part of a long list; run it again afterwards for the rest.', 'qartvelo-guard' ),
					'cleanNone'        => __( 'No clean images are waiting. Images with findings, and files that are not verified JPEG, PNG, GIF or WebP images, are left for you to review one by one.', 'qartvelo-guard' ),
					/* translators: 1: images done, 2: images in total */
					'cleanProgress'    => __( '%1$s of %2$s images done', 'qartvelo-guard' ),
					'cleanDoneOne'     => __( '1 image was allowed and added to the Media Library.', 'qartvelo-guard' ),
					/* translators: %s: number of images */
					'cleanDone'        => __( '%s images were allowed and added to the Media Library.', 'qartvelo-guard' ),
				),
			)
		);

		$page = self::current_page();
		if ( in_array( $page, array( self::PAGE_DASHBOARD, self::PAGE_REPORTS ), true ) ) {
			wp_enqueue_script( 'wpcybersec-core-repair', WPCYBERSEC_URL . 'assets/js/core-repair.js', array( 'wpcybersec-core' ), \WPCyberSecurity\Admin\Assets::ver( 'assets/js/core-repair.js' ), true );
			wp_localize_script( 'wpcybersec-core-repair', 'wpcybersecCore', array( 'i18n' => Core_Repair_Card::i18n() ) );
		}

		/**
		 * Fires after the base, core and admin assets are enqueued on a plugin screen.
		 * The setup module can enqueue setup.css / setup.js here.
		 *
		 * @param string $page Current plugin page slug (wpcybersec, wpcybersec-reports, ...).
		 * @param string $hook Admin page hook suffix.
		 */
		do_action( 'wpcybersec_admin_enqueue', self::current_page(), $hook );
	}

	/**
	 * @param string $hook Admin page hook suffix.
	 * @return bool
	 */
	private function is_plugin_screen( $hook ) {
		$is = ( false !== strpos( (string) $hook, 'wpcybersec' ) ) || self::is_plugin_page();

		/**
		 * Filters whether the shared plugin assets load on this screen.
		 *
		 * @param bool   $is   Whether this is a plugin screen.
		 * @param string $hook Admin page hook suffix.
		 */
		return (bool) apply_filters( 'wpcybersec_is_plugin_screen', $is, $hook );
	}

	/**
	 * @return string Current plugin page slug, '' when not on a plugin page.
	 */
	public static function current_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		return 0 === strpos( $page, 'wpcybersec' ) ? $page : '';
	}

	/**
	 * @return bool True on any of the plugin's admin pages.
	 */
	public static function is_plugin_page() {
		return is_admin() && '' !== self::current_page();
	}

	/* ------------------------------------------------------------------ */
	/* Page header and shared helpers                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Prints the page header used by every plugin page.
	 *
	 * @param string $title        Page title (plain text).
	 * @param string $subtitle     Short description (plain text).
	 * @param string $actions_html Buttons/links, already escaped by the caller (filtered through wp_kses).
	 */
	public static function header( $title, $subtitle = '', $actions_html = '' ) {
		echo '<div class="wpcs-header">';
		echo '<div class="wpcs-header__icon" aria-hidden="true"><span class="dashicons dashicons-shield"></span></div>';
		echo '<div class="wpcs-header__text"><h1>' . esc_html( $title ) . '</h1>';
		if ( '' !== (string) $subtitle ) {
			echo '<p>' . esc_html( $subtitle ) . '</p>';
		}
		echo '</div>';
		if ( '' !== trim( (string) $actions_html ) ) {
			echo '<div class="wpcs-header__actions">' . wp_kses( $actions_html, self::allowed_header_html() ) . '</div>';
		}
		echo '</div>';
		// WordPress moves admin notices after this marker instead of into the header.
		echo '<hr class="wp-header-end">';
	}

	/**
	 * Tags allowed in header actions.
	 *
	 * @return array
	 */
	private static function allowed_header_html() {
		$common = array(
			'class'            => true,
			'id'               => true,
			'title'            => true,
			'role'             => true,
			'aria-label'       => true,
			'aria-hidden'      => true,
			'aria-expanded'    => true,
			'aria-controls'    => true,
			'aria-describedby' => true,
			'data-*'           => true,
		);
		$allowed = array(
			'a'      => array_merge( $common, array( 'href' => true, 'target' => true, 'rel' => true ) ),
			'button' => array_merge( $common, array( 'type' => true, 'name' => true, 'value' => true, 'disabled' => true, 'form' => true ) ),
			'span'   => $common,
			'strong' => $common,
			'em'     => $common,
			'form'   => array_merge( $common, array( 'action' => true, 'method' => true ) ),
			'input'  => array_merge( $common, array( 'type' => true, 'name' => true, 'value' => true, 'checked' => true, 'disabled' => true, 'form' => true ) ),
			'select' => array_merge( $common, array( 'name' => true, 'disabled' => true, 'form' => true ) ),
			'option' => array_merge( $common, array( 'value' => true, 'selected' => true ) ),
		);

		/**
		 * Filters the HTML allowed in page header actions.
		 *
		 * @param array $allowed wp_kses allowed tags.
		 */
		return apply_filters( 'wpcybersec_header_allowed_html', $allowed );
	}

	/**
	 * Admin URL of a plugin page.
	 *
	 * @param string $page Page slug (wpcybersec, wpcybersec-reports, ...).
	 * @param array  $args Extra query args (raw values, encoded here).
	 * @return string Unescaped URL.
	 */
	public static function page_url( $page, $args = array() ) {
		$query = array( 'page' => sanitize_key( $page ) );
		foreach ( (array) $args as $key => $value ) {
			if ( null === $value || '' === $value || false === $value ) {
				continue;
			}
			$query[ sanitize_key( $key ) ] = rawurlencode( (string) $value );
		}
		return add_query_arg( $query, self::admin_page_base() );
	}

	/**
	 * admin.php of the screen that holds the plugin pages: Network Admin on
	 * multisite (also the action of the pages' GET filter forms).
	 *
	 * @return string Unescaped URL.
	 */
	public static function admin_page_base() {
		return \WPCyberSecurity\Network::admin_url( 'admin.php' );
	}

	/**
	 * Store::counts() with a per-request cache and zero fallback.
	 *
	 * @param bool $fresh Bypass the cache.
	 * @return array { pending, threats, quarantined }
	 */
	public static function counts( $fresh = false ) {
		if ( null === self::$counts || $fresh ) {
			$counts       = self::call( 'store', 'counts', array(), array() );
			$counts       = is_array( $counts ) ? $counts : array();
			self::$counts = array(
				'pending'     => isset( $counts['pending'] ) ? (int) $counts['pending'] : 0,
				'threats'     => isset( $counts['threats'] ) ? (int) $counts['threats'] : 0,
				'quarantined' => isset( $counts['quarantined'] ) ? (int) $counts['quarantined'] : 0,
			);
		}
		return self::$counts;
	}

	/**
	 * A service from the container, or null when it is missing.
	 *
	 * @param string $name Property name on wpcybersec().
	 * @return object|null
	 */
	public static function service( $name ) {
		if ( ! function_exists( 'wpcybersec' ) ) {
			return null;
		}
		$plugin = wpcybersec();
		return ( isset( $plugin->$name ) && is_object( $plugin->$name ) ) ? $plugin->$name : null;
	}

	/**
	 * Calls a service method defensively: a missing module or an exception
	 * returns $default instead of breaking the admin screen.
	 *
	 * @param string $service Service name.
	 * @param string $method  Method name.
	 * @param array  $args    Arguments.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public static function call( $service, $method, array $args = array(), $default = null ) {
		$object = self::service( $service );
		if ( ! $object || ! method_exists( $object, $method ) ) {
			return $default;
		}
		try {
			return call_user_func_array( array( $object, $method ), $args );
		} catch ( \Throwable $e ) {
			self::debug_log( $e );
			return $default;
		}
	}

	/**
	 * @param string $key     Setting.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public static function setting( $key, $default = null ) {
		return self::call( 'settings', 'get', array( $key, $default ), $default );
	}

	/**
	 * @param \Throwable $e Error.
	 */
	public static function debug_log( $e ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && $e instanceof \Throwable ) {
			error_log( 'Qartvelo Guard admin: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		}
	}

	/**
	 * UTC "Y-m-d H:i:s" to a unix timestamp (0 when empty).
	 *
	 * @param string $utc Datetime.
	 * @return int
	 */
	public static function utc_ts( $utc ) {
		$utc = (string) $utc;
		if ( '' === $utc || 0 === strpos( $utc, '0000-00-00' ) ) {
			return 0;
		}
		$ts = strtotime( $utc . ' UTC' );
		return $ts ? (int) $ts : 0;
	}

	/**
	 * "3 hours ago" / "in 2 hours".
	 *
	 * @param int $ts Unix timestamp.
	 * @return string
	 */
	public static function ago( $ts ) {
		$ts = (int) $ts;
		if ( $ts <= 0 ) {
			return '';
		}
		$now = time();
		if ( $ts > $now + 60 ) {
			/* translators: %s: time span such as "2 hours" */
			return sprintf( __( 'in %s', 'qartvelo-guard' ), human_time_diff( $now, $ts ) );
		}
		if ( $now - $ts < 60 ) {
			return __( 'just now', 'qartvelo-guard' );
		}
		/* translators: %s: time span such as "2 hours" */
		return sprintf( __( '%s ago', 'qartvelo-guard' ), human_time_diff( $ts, $now ) );
	}

	/**
	 * Site-local date and time.
	 *
	 * @param int $ts Unix timestamp.
	 * @return string
	 */
	public static function datetime( $ts ) {
		$ts = (int) $ts;
		if ( $ts <= 0 ) {
			return '';
		}
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts );
	}

	/**
	 * Display name of a user, cached.
	 *
	 * @param int $user_id User id.
	 * @return string '' when the user does not exist.
	 */
	public static function user_name( $user_id ) {
		static $cache = array();
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return '';
		}
		if ( ! isset( $cache[ $user_id ] ) ) {
			$user              = get_userdata( $user_id );
			$cache[ $user_id ] = $user ? (string) $user->display_name : '';
		}
		return $cache[ $user_id ];
	}

	/**
	 * Status badge HTML for an item status.
	 *
	 * @param string $status Item status.
	 * @return string
	 */
	public static function status_badge( $status ) {
		$map = array(
			Store::STATUS_PENDING     => array( __( 'Waiting', 'qartvelo-guard' ), 'pending' ),
			Store::STATUS_APPROVED    => array( __( 'Approved', 'qartvelo-guard' ), 'ok' ),
			Store::STATUS_DENIED      => array( __( 'Denied', 'qartvelo-guard' ), 'muted' ),
			Store::STATUS_IGNORED     => array( __( 'Marked safe', 'qartvelo-guard' ), 'ok' ),
			Store::STATUS_QUARANTINED => array( __( 'Quarantined', 'qartvelo-guard' ), 'medium' ),
			Store::STATUS_RESTORED    => array( __( 'Restored', 'qartvelo-guard' ), 'info' ),
			Store::STATUS_DELETED     => array( __( 'Deleted', 'qartvelo-guard' ), 'muted' ),
			Store::STATUS_RESOLVED    => array( __( 'Resolved', 'qartvelo-guard' ), 'muted' ),
		);
		$entry = isset( $map[ $status ] ) ? $map[ $status ] : array( ucfirst( (string) $status ), 'muted' );
		return '<span class="wpcs-badge wpcs-badge--' . esc_attr( $entry[1] ) . '">' . esc_html( $entry[0] ) . '</span>';
	}

	/**
	 * Severity badge HTML.
	 *
	 * @param int $severity 0-3.
	 * @return string
	 */
	public static function severity_badge( $severity ) {
		$severity = max( 0, min( 3, (int) $severity ) );
		$classes  = array( 'info', 'medium', 'high', 'critical' );
		return '<span class="wpcs-badge wpcs-badge--' . esc_attr( $classes[ $severity ] ) . '">' . esc_html( Store::severity_label( $severity ) ) . '</span>';
	}

	/**
	 * Icon, tone and readable label for an activity log event.
	 *
	 * @param string $event Event machine name.
	 * @return array { icon, tone, label }
	 */
	public static function event_meta( $event ) {
		$event = (string) $event;
		$rules = array(
			array( array( 'decision_failed', '_failed', 'error' ), 'dismiss', 'bad' ),
			array( array( 'threat', 'malware', 'tamper' ), 'warning', 'bad' ),
			array( array( 'deleted', 'purged' ), 'trash', 'muted' ),
			array( array( 'denied', 'blocked' ), 'dismiss', 'muted' ),
			array( array( 'allowlist_removed' ), 'minus', 'muted' ),
			array( array( 'approved', 'ignored', 'allowlist', 'trusted' ), 'yes-alt', 'ok' ),
			array( array( 'quarantine' ), 'lock', 'medium' ),
			array( array( 'restored' ), 'undo', 'info' ),
			array( array( 'download' ), 'download', 'info' ),
			array( array( 'unlock' ), 'unlock', 'medium' ),
			array( array( 'lock', 'freeze' ), 'lock', 'info' ),
			array( array( 'upload' ), 'upload', 'pending' ),
			array( array( 'install', 'update' ), 'admin-plugins', 'pending' ),
			array( array( 'guard' ), 'shield', 'info' ),
			array( array( 'scan', 'baseline' ), 'search', 'info' ),
			array( array( 'notif', 'email', 'digest', 'webhook' ), 'email-alt', 'info' ),
			array( array( 'setting', 'wizard', 'setup' ), 'admin-generic', 'info' ),
			array( array( 'file' ), 'media-code', 'pending' ),
		);
		$icon = 'info-outline';
		$tone = 'info';
		foreach ( $rules as $rule ) {
			foreach ( $rule[0] as $needle ) {
				if ( false !== strpos( $event, $needle ) ) {
					$icon = $rule[1];
					$tone = $rule[2];
					break 2;
				}
			}
		}
		$label = ucfirst( trim( str_replace( array( '_', '-' ), ' ', $event ) ) );
		return array(
			'icon'  => $icon,
			'tone'  => $tone,
			'label' => '' !== $label ? $label : __( 'Event', 'qartvelo-guard' ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* Activation redirect                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * Opens the setup wizard once right after activation.
	 */
	public function maybe_redirect() {
		if ( ! \WPCyberSecurity\Network::get_option( Installer::REDIRECT_OPTION ) ) {
			return;
		}
		if ( wp_doing_ajax() || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'IFRAME_REQUEST' ) && IFRAME_REQUEST ) ) {
			return; // Keep the flag for the next normal page load.
		}
		global $pagenow;
		if ( 'admin-post.php' === $pagenow || ! self::can() ) {
			return;
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'GET' !== $method ) {
			return;
		}

		// Multisite: the wizard is a Network Admin page; keep the flag for the next Network Admin page load.
		if ( is_multisite() && ! is_network_admin() ) {
			return;
		}

		\WPCyberSecurity\Network::delete_option( Installer::REDIRECT_OPTION );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only flag set by WordPress.
		if ( isset( $_GET['activate-multi'] ) ) {
			return;
		}
		if ( self::setting( 'wizard_completed', false ) || self::PAGE_WIZARD === self::current_page() ) {
			return;
		}
		wp_safe_redirect( self::page_url( self::PAGE_WIZARD ) );
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Notices                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Setup and pending-approval notices on screens outside the plugin.
	 */
	public function notices() {
		if ( ! self::can() ) {
			return;
		}
		$this->print_storage_notice();
		if ( self::is_plugin_page() || is_network_admin() ) {
			return;
		}
		$user_id = get_current_user_id();

		if ( ! self::setting( 'wizard_completed', false ) ) {
			$until = (int) get_user_meta( $user_id, self::META_DISMISS_SETUP, true );
			if ( $until < time() ) {
				$this->print_setup_notice();
			}
		}

		$counts = self::counts();
		$total  = $counts['pending'] + $counts['threats'];
		if ( $total > 0 ) {
			$newest    = self::newest_open_item_id();
			$dismissed = (int) get_user_meta( $user_id, self::META_DISMISS_PENDING, true );
			if ( $newest > $dismissed ) {
				$this->print_pending_notice( $counts );
			}
		}
	}

	/**
	 * Data folder problem (not writable, fallback folder in use), on the
	 * plugin's pages and the dashboard. Checking here also covers "on
	 * settings load": the state is checked again on every such page.
	 */
	private function print_storage_notice() {
		global $pagenow;
		if ( ! self::is_plugin_page() && 'index.php' !== $pagenow ) {
			return;
		}
		$storage = self::service( 'storage' );
		if ( ! is_object( $storage ) || ! method_exists( $storage, 'check' ) ) {
			return;
		}
		$user_id = get_current_user_id();
		// User meta of the current user is already in the request cache (a transient cost a query on every page).
		$result = get_user_meta( $user_id, self::META_STORAGE_MOVE, true );
		if ( is_array( $result ) && isset( $result['ok'], $result['message'] ) ) {
			delete_user_meta( $user_id, self::META_STORAGE_MOVE );
		}
		if ( is_array( $result ) && isset( $result['ok'], $result['message'] ) && ( empty( $result['until'] ) || (int) $result['until'] > time() ) ) {
			echo '<div class="notice ' . esc_attr( $result['ok'] ? 'notice-success' : 'notice-error' ) . ' is-dismissible wpcs-admin-notice"><p>' . esc_html( (string) $result['message'] ) . '</p></div>';
		}
		try {
			$status  = $storage->check();
			$problem = $storage->problem( $status );
		} catch ( \Throwable $e ) {
			self::debug_log( $e );
			return;
		}
		if ( ! $problem ) {
			return;
		}
		if ( (string) get_user_meta( $user_id, self::META_DISMISS_STORAGE, true ) === self::storage_key( $status ) ) {
			return;
		}
		$can_move = 'fallback' === $status['state'] && ! empty( $status['primary_ok'] ) && ! is_multisite() && ! ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR );
		?>
		<div class="notice <?php echo esc_attr( 'error' === $problem['level'] ? 'notice-error' : 'notice-warning' ); ?> wpcs-admin-notice">
			<p>
				<strong><?php echo esc_html( $problem['title'] ); ?></strong><br>
				<?php echo esc_html( $problem['text'] ); ?>
			</p>
			<p><?php echo esc_html( $problem['fix'] ); ?></p>
			<?php if ( '' !== $problem['code'] ) : ?>
				<p><code><?php echo esc_html( $problem['code'] ); ?></code></p>
			<?php endif; ?>
			<p>
				<?php if ( $can_move ) : ?>
					<a class="button button-primary" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wpcybersec_storage_move' ), 'wpcybersec_storage_move' ) ); ?>">
						<?php
						/* translators: %s: folder path */
						echo esc_html( sprintf( __( 'Move the data to %s', 'qartvelo-guard' ), $status['primary'] ) );
						?>
					</a>
				<?php endif; ?>
				<a class="button-link" style="margin-left:8px" href="<?php echo esc_url( self::dismiss_url( 'storage' ) ); ?>"><?php esc_html_e( 'Hide until this changes', 'qartvelo-guard' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Identifies a storage state, so a hidden notice comes back when it changes.
	 *
	 * @param array $status Storage::status().
	 * @return string
	 */
	private static function storage_key( array $status ) {
		return md5( $status['state'] . '|' . $status['dir'] . '|' . ( empty( $status['primary_ok'] ) ? '0' : '1' ) );
	}

	/**
	 * Moves the data from the fallback folder back to the configured one.
	 */
	public function handle_storage_move() {
		$this->require_cap();
		check_admin_referer( 'wpcybersec_storage_move' );
		$storage  = self::service( 'storage' );
		$hardener = self::service( 'hardening' );
		$result   = new \WP_Error( 'wpcybersec_storage', __( 'The data folder could not be moved.', 'qartvelo-guard' ) );
		if ( is_object( $storage ) && is_object( $hardener ) && method_exists( $hardener, 'move_data_dir' ) ) {
			$status = $storage->check();
			if ( 'fallback' === $status['state'] && ! empty( $status['primary_ok'] ) ) {
				$result = $hardener->move_data_dir( $status['primary'] );
			} else {
				$result = __( 'Nothing to move: the data is already in the configured folder.', 'qartvelo-guard' );
			}
			\WPCyberSecurity\Storage::reset();
		}
		update_user_meta(
			get_current_user_id(),
			self::META_STORAGE_MOVE,
			array(
				'ok'      => ! is_wp_error( $result ),
				'message' => is_wp_error( $result ) ? $result->get_error_message() : ( is_string( $result ) ? $result : __( 'Moved.', 'qartvelo-guard' ) ),
				'until'   => time() + 5 * MINUTE_IN_SECONDS,
			)
		);
		$this->redirect_back( self::page_url( self::PAGE_DASHBOARD ), array() );
	}

	/**
	 * "Finish setting up" notice.
	 */
	private function print_setup_notice() {
		?>
		<div class="notice notice-info wpcs-admin-notice">
			<p>
				<strong><?php esc_html_e( 'Finish setting up Qartvelo Guard', 'qartvelo-guard' ); ?></strong><br>
				<?php esc_html_e( 'The setup wizard picks a protection level, records a trusted baseline of your files and sets up alerts. It takes about three minutes.', 'qartvelo-guard' ); ?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( self::page_url( self::PAGE_WIZARD ) ); ?>"><?php esc_html_e( 'Start the setup wizard', 'qartvelo-guard' ); ?></a>
				<a class="button-link" style="margin-left:8px" href="<?php echo esc_url( self::dismiss_url( 'setup' ) ); ?>"><?php esc_html_e( 'Remind me in 3 days', 'qartvelo-guard' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * "N items are waiting for your approval" notice.
	 *
	 * @param array $counts Counts.
	 */
	private function print_pending_notice( array $counts ) {
		$lines = array();
		if ( $counts['pending'] > 0 ) {
			$lines[] = sprintf(
				/* translators: %s: number of items */
				_n( '%s upload, install, file or account is waiting for your approval.', '%s uploads, installs, files or accounts are waiting for your approval.', $counts['pending'], 'qartvelo-guard' ),
				number_format_i18n( $counts['pending'] )
			);
		}
		if ( $counts['threats'] > 0 ) {
			$lines[] = sprintf(
				/* translators: %s: number of threats */
				_n( '%s possible threat needs your attention.', '%s possible threats need your attention.', $counts['threats'], 'qartvelo-guard' ),
				number_format_i18n( $counts['threats'] )
			);
		}
		$tab   = $counts['pending'] > 0 ? 'pending' : 'threats';
		$class = $counts['threats'] > 0 ? 'notice-error' : 'notice-warning';
		?>
		<div class="notice <?php echo esc_attr( $class ); ?> wpcs-admin-notice">
			<p>
				<strong><?php esc_html_e( 'Qartvelo Guard:', 'qartvelo-guard' ); ?></strong>
				<?php echo esc_html( implode( ' ', $lines ) ); ?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( self::page_url( self::PAGE_REPORTS, array( 'tab' => $tab ) ) ); ?>"><?php esc_html_e( 'Review now', 'qartvelo-guard' ); ?></a>
				<a class="button-link" style="margin-left:8px" href="<?php echo esc_url( self::dismiss_url( 'pending' ) ); ?>"><?php esc_html_e( 'Hide until something new arrives', 'qartvelo-guard' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * @param string $which setup | pending | storage.
	 * @return string
	 */
	private static function dismiss_url( $which ) {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => 'wpcybersec_dismiss_notice',
					'notice' => $which,
				),
				admin_url( 'admin-post.php' )
			),
			'wpcybersec_dismiss_' . $which
		);
	}

	/**
	 * Highest id among open items (used to re-show a dismissed notice when new items arrive).
	 *
	 * @return int
	 */
	private static function newest_open_item_id() {
		// Cached with the counts (Store::counts()), so the notice costs no query.
		return (int) self::call( 'store', 'newest_open_id', array(), 0 );
	}

	/* ------------------------------------------------------------------ */
	/* Admin bar                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * @param \WP_Admin_Bar $bar Admin bar.
	 */
	public function admin_bar( $bar ) {
		if ( ! is_object( $bar ) || ! is_admin_bar_showing() || ! self::can() ) {
			return;
		}
		$counts = self::counts();
		$total  = $counts['pending'] + $counts['threats'];
		if ( $total < 1 ) {
			return;
		}
		$title = '<span class="ab-icon" aria-hidden="true"></span>'
			. '<span class="ab-label">' . esc_html__( 'Qartvelo Guard', 'qartvelo-guard' ) . '</span>'
			. '<span class="wpcs-ab-count" aria-hidden="true">' . esc_html( number_format_i18n( $total ) ) . '</span>'
			. '<span class="screen-reader-text">' . esc_html(
				sprintf(
					/* translators: %s: number of items */
					_n( '%s item needs your review', '%s items need your review', $total, 'qartvelo-guard' ),
					number_format_i18n( $total )
				)
			) . '</span>';

		$bar->add_node(
			array(
				'id'    => 'wpcybersec',
				'title' => $title,
				'href'  => self::page_url( self::PAGE_REPORTS, array( 'tab' => $counts['pending'] > 0 ? 'pending' : 'threats' ) ),
				'meta'  => array( 'class' => $counts['threats'] > 0 ? 'wpcs-ab-threats' : '' ),
			)
		);
		if ( $counts['pending'] > 0 ) {
			$bar->add_node(
				array(
					'parent' => 'wpcybersec',
					'id'     => 'wpcybersec-pending',
					'title'  => esc_html(
						sprintf(
							/* translators: %s: number of items */
							_n( '%s waiting for approval', '%s waiting for approval', $counts['pending'], 'qartvelo-guard' ),
							number_format_i18n( $counts['pending'] )
						)
					),
					'href'   => self::page_url( self::PAGE_REPORTS, array( 'tab' => 'pending' ) ),
				)
			);
		}
		if ( $counts['threats'] > 0 ) {
			$bar->add_node(
				array(
					'parent' => 'wpcybersec',
					'id'     => 'wpcybersec-threats',
					'title'  => esc_html(
						sprintf(
							/* translators: %s: number of threats */
							_n( '%s possible threat', '%s possible threats', $counts['threats'], 'qartvelo-guard' ),
							number_format_i18n( $counts['threats'] )
						)
					),
					'href'   => self::page_url( self::PAGE_REPORTS, array( 'tab' => 'threats' ) ),
				)
			);
		}
		$bar->add_node(
			array(
				'parent' => 'wpcybersec',
				'id'     => 'wpcybersec-dashboard',
				'title'  => esc_html__( 'Security dashboard', 'qartvelo-guard' ),
				'href'   => self::page_url( self::PAGE_DASHBOARD ),
			)
		);
	}

	/**
	 * Small inline style for the admin bar node (front end and admin).
	 */
	public function admin_bar_style() {
		if ( ! is_admin_bar_showing() || ! self::can() || ! wp_style_is( 'admin-bar', 'registered' ) ) {
			return;
		}
		$counts = self::counts();
		if ( $counts['pending'] + $counts['threats'] < 1 ) {
			return;
		}
		$css = '#wpadminbar #wp-admin-bar-wpcybersec .ab-icon:before{content:"\f332";top:2px}'
			. '#wpadminbar #wp-admin-bar-wpcybersec .wpcs-ab-count{display:inline-block;min-width:18px;height:18px;margin-left:6px;padding:0 5px;border-radius:9px;background:#d63638;color:#fff;font-size:11px;line-height:18px;text-align:center;vertical-align:middle;box-sizing:border-box}'
			. '#wpadminbar #wp-admin-bar-wpcybersec:not(.wpcs-ab-threats) .wpcs-ab-count{background:#dba617;color:#1d2327}'
			. '@media screen and (max-width:782px){#wpadminbar #wp-admin-bar-wpcybersec{display:block}#wpadminbar #wp-admin-bar-wpcybersec .ab-label{display:none}#wpadminbar #wp-admin-bar-wpcybersec .ab-icon:before{top:0}}';
		wp_add_inline_style( 'admin-bar', $css );
	}

	/* ------------------------------------------------------------------ */
	/* Plugins screen                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array $links Action links.
	 * @return array
	 */
	public function action_links( $links ) {
		if ( ! self::can() ) {
			return $links;
		}
		$own = array(
			'wpcybersec-settings' => '<a href="' . esc_url( self::page_url( self::PAGE_SETTINGS ) ) . '">' . esc_html__( 'Settings', 'qartvelo-guard' ) . '</a>',
			'wpcybersec-setup'    => '<a href="' . esc_url( self::page_url( self::PAGE_WIZARD ) ) . '">' . esc_html__( 'Setup', 'qartvelo-guard' ) . '</a>',
			'wpcybersec-reports'  => '<a href="' . esc_url( self::page_url( self::PAGE_REPORTS ) ) . '">' . esc_html__( 'Reports', 'qartvelo-guard' ) . '</a>',
		);
		return array_merge( $own, (array) $links );
	}

	/**
	 * Result args stripped from the address bar after display.
	 *
	 * @param array $args Args.
	 * @return array
	 */
	public function removable_query_args( $args ) {
		return array_merge( (array) $args, array( 'wpcs_msg', 'wpcs_done', 'wpcs_failed' ) );
	}

	/* ------------------------------------------------------------------ */
	/* admin-post handlers                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * Common capability gate for handlers.
	 */
	private function require_cap() {
		if ( ! self::can() ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'qartvelo-guard' ), esc_html__( 'Forbidden', 'qartvelo-guard' ), array( 'response' => 403, 'back_link' => true ) );
		}
	}

	/**
	 * Streams a held (quarantined) copy so an administrator can inspect it.
	 */
	public function handle_download() {
		$this->require_cap();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified right below.
		$id = isset( $_GET['id'] ) ? absint( wp_unslash( $_GET['id'] ) ) : 0;
		check_admin_referer( 'wpcybersec_download_' . $id );

		$item = $id ? self::call( 'store', 'item_get', array( $id ) ) : null;
		if ( ! is_array( $item ) || '' === (string) $item['quarantine_path'] ) {
			wp_die( esc_html__( 'This file is no longer held, so there is nothing to download.', 'qartvelo-guard' ), esc_html__( 'Not found', 'qartvelo-guard' ), array( 'response' => 404, 'back_link' => true ) );
		}
		$quarantine = self::service( 'quarantine' );
		if ( ! $quarantine || ! method_exists( $quarantine, 'stream' ) ) {
			wp_die( esc_html__( 'Quarantine storage is not available.', 'qartvelo-guard' ), '', array( 'response' => 500, 'back_link' => true ) );
		}
		self::call(
			'logger',
			'log',
			array(
				'item_downloaded',
				/* translators: %s: file name or path */
				sprintf( __( 'Downloaded the held copy of %s for inspection.', 'qartvelo-guard' ), $item['path'] ),
				array( 'item_id' => (int) $item['id'] ),
			)
		);
		// Validates that the path is inside the quarantine folder, sends the file and exits.
		$quarantine->stream( $item );
		exit;
	}

	/**
	 * Address of the image preview of a held upload (admin-post with a nonce
	 * bound to the item and the user's session).
	 *
	 * @param int $id Item id.
	 * @return string Unescaped URL.
	 */
	public static function preview_url( $id ) {
		$id = (int) $id;
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => 'wpcybersec_preview',
					'id'     => $id,
				),
				admin_url( 'admin-post.php' )
			),
			'wpcybersec_preview_' . $id
		);
	}

	/**
	 * Streams the held copy of an upload as an image, for the thumbnails and
	 * the preview on the Reports page. Only after Upload_Gate::image_preview()
	 * verified that the copy really is the raster image its name says
	 * (getimagesize() and finfo), and never for uploads flagged high or
	 * critical. The response cannot run anything even if a browser tried to
	 * read it as a document: nosniff, a sandbox CSP that allows nothing, and
	 * an inline image disposition.
	 */
	public function handle_preview() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- verified right below.
		$id    = isset( $_GET['id'] ) ? absint( wp_unslash( $_GET['id'] ) ) : 0;
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_key( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		// phpcs:enable
		if ( ! self::can() || ! $id || ! wp_verify_nonce( $nonce, 'wpcybersec_preview_' . $id ) ) {
			self::preview_refused( 403 );
		}
		$item = self::call( 'store', 'item_get', array( $id ) );
		$gate = self::service( 'upload_gate' );
		if ( ! is_array( $item ) || ! is_object( $gate ) || ! method_exists( $gate, 'image_preview' ) ) {
			self::preview_refused( 404 );
		}
		$preview = $gate->image_preview( $item );
		if ( empty( $preview['ok'] ) ) {
			self::preview_refused( 'missing' === $preview['reason'] ? 404 : 403 );
		}
		$size = @filesize( $preview['path'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size ) {
			self::preview_refused( 404 );
		}
		foreach ( array( 'Expires', 'Pragma', 'Last-Modified' ) as $header ) {
			header_remove( $header );
		}
		header( 'Content-Type: ' . $preview['mime'] );
		header( 'Content-Length: ' . (int) $size );
		header( 'Content-Disposition: inline; filename="preview.' . $preview['ext'] . '"' );
		header( 'X-Content-Type-Options: nosniff' );
		header( "Content-Security-Policy: default-src 'none'; sandbox" );
		header( 'Cross-Origin-Resource-Policy: same-origin' );
		header( 'Cache-Control: private, max-age=600' );
		header( 'Referrer-Policy: no-referrer' );
		readfile( $preview['path'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- streams a verified image from the quarantine folder.
		exit;
	}

	/**
	 * Ends a refused preview request without an HTML page (it is loaded as an image).
	 *
	 * @param int $code HTTP status.
	 */
	private static function preview_refused( $code ) {
		status_header( (int) $code );
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Cache-Control: no-store, private' );
		exit;
	}

	/**
	 * Highest severity of an item (its own or its worst match).
	 *
	 * @param array $item Item.
	 * @return int 0-3.
	 */
	public static function risk_level( array $item ) {
		return \WPCyberSecurity\Upload_Gate::risk_level( $item );
	}

	/**
	 * Whether allowing (or marking safe) this item must be confirmed first:
	 * flagged high or critical. Administrator accounts have their own
	 * decision (trust the account) and are not covered.
	 *
	 * @param array $item Item.
	 * @return bool
	 */
	public static function needs_risk_confirm( array $item ) {
		return isset( $item['type'] ) && Store::TYPE_USER !== $item['type'] && self::risk_level( $item ) >= Store::SEV_HIGH;
	}

	/**
	 * Name of the worst finding of an item ("PHP code hidden in an image file").
	 *
	 * @param array $item Item.
	 * @return string
	 */
	public static function risk_verdict( array $item ) {
		$best  = '';
		$level = -1;
		$hits  = isset( $item['details']['hits'] ) && is_array( $item['details']['hits'] ) ? $item['details']['hits'] : array();
		foreach ( $hits as $hit ) {
			if ( ! is_array( $hit ) ) {
				continue;
			}
			$sev = isset( $hit['severity'] ) ? (int) $hit['severity'] : 0;
			if ( $sev > $level ) {
				$level = $sev;
				$best  = ! empty( $hit['title'] ) ? (string) $hit['title'] : ( ! empty( $hit['sig'] ) ? (string) $hit['sig'] : '' );
			}
		}
		if ( '' !== $best ) {
			return $best;
		}
		$checksum = isset( $item['details']['checksum'] ) ? (string) $item['details']['checksum'] : '';
		if ( 'mismatch' === $checksum ) {
			return __( 'Differs from the official WordPress.org file', 'qartvelo-guard' );
		}
		return __( 'Flagged by the scanner', 'qartvelo-guard' );
	}

	/**
	 * Text of the confirmation before allowing (or marking safe) a risky item.
	 *
	 * @param array  $item   Item.
	 * @param string $action approve | ignore.
	 * @return array { title, verdict, text, confirm }
	 */
	public static function risk_confirm_text( array $item, $action = 'approve' ) {
		$name    = Store::TYPE_INSTALL === $item['type'] && ! empty( $item['details']['name'] ) ? (string) $item['details']['name'] : wp_basename( (string) $item['path'] );
		$verdict = sprintf(
			/* translators: 1: severity (Critical, High), 2: finding, e.g. "PHP code hidden in an image file" */
			__( '%1$s: %2$s', 'qartvelo-guard' ),
			Store::severity_label( self::risk_level( $item ) ),
			self::risk_verdict( $item )
		);
		if ( 'ignore' === $action ) {
			return array(
				/* translators: %s: file name */
				'title'   => sprintf( __( 'Mark %s as safe anyway?', 'qartvelo-guard' ), $name ),
				'verdict' => $verdict,
				'text'    => __( 'Marking it safe remembers its SHA-256 fingerprint for good: this exact content is never reported again. Only continue if you know it and are sure the finding is a false positive.', 'qartvelo-guard' ),
				'confirm' => __( 'Mark safe anyway', 'qartvelo-guard' ),
			);
		}
		return array(
			/* translators: %s: file name */
			'title'   => sprintf( __( 'Allow %s anyway?', 'qartvelo-guard' ), $name ),
			'verdict' => $verdict,
			'text'    => __( 'Allowing it remembers its SHA-256 fingerprint for good: this exact file is never held or reported again, wherever it appears on the site. Only continue if you know the file and trust where it came from.', 'qartvelo-guard' ),
			'confirm' => __( 'Allow anyway', 'qartvelo-guard' ),
		);
	}

	/**
	 * Removes one allowlist entry.
	 */
	public function handle_allowlist_remove() {
		$this->require_cap();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified right below.
		$id = isset( $_GET['entry'] ) ? absint( wp_unslash( $_GET['entry'] ) ) : 0;
		check_admin_referer( 'wpcybersec_allowlist_remove_' . $id );

		$removed = $id ? (bool) self::call( 'allowlist', 'remove', array( $id ), false ) : false;
		$this->redirect_back(
			self::page_url( self::PAGE_REPORTS, array( 'tab' => 'allowlist' ) ),
			array( 'wpcs_msg' => $removed ? 'allowlist_removed' : 'allowlist_missing' )
		);
	}

	/**
	 * Non-JS fallback for the reports table: bulk form and single action buttons.
	 */
	public function handle_reports_bulk() {
		$this->require_cap();
		check_admin_referer( 'wpcybersec_reports_bulk' );

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified above.
		$action = '';
		$ids    = array();
		$single = isset( $_POST['wpcs_single'] ) ? sanitize_text_field( wp_unslash( $_POST['wpcs_single'] ) ) : '';
		if ( '' !== $single && preg_match( '/^([a-z_]+):(\d+)$/', $single, $m ) ) { // restore_official has an underscore.
			$action = $m[1];
			$ids    = array( (int) $m[2] );
		} else {
			$action = isset( $_POST['bulk_action'] ) ? sanitize_key( wp_unslash( $_POST['bulk_action'] ) ) : '';
			$ids    = isset( $_POST['ids'] ) ? array_map( 'absint', (array) wp_unslash( $_POST['ids'] ) ) : array();
		}
		$tab = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : 'pending';
		// phpcs:enable

		$ids      = array_values( array_unique( array_filter( $ids ) ) );
		$fallback = self::page_url( self::PAGE_REPORTS, array( 'tab' => $tab ) );

		if ( ! in_array( $action, Decisions::ACTIONS, true ) ) {
			$this->redirect_back( $fallback, array( 'wpcs_msg' => 'no_action' ) );
		}
		if ( ! $ids ) {
			$this->redirect_back( $fallback, array( 'wpcs_msg' => 'no_items' ) );
		}

		if ( count( $ids ) > self::MAX_BULK ) {
			$this->redirect_back( $fallback, array( 'wpcs_msg' => 'too_many' ) );
		}

		// Allowing something flagged high or critical is confirmed first (the
		// Reports page asks in a dialog; without JavaScript this page asks).
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above.
		if ( in_array( $action, array( 'approve', 'ignore' ), true ) && empty( $_POST['wpcs_risk_ok'] ) ) {
			$risky = self::risky_items( $ids );
			if ( $risky ) {
				$this->confirm_risky_page( $action, $ids, $risky, $tab );
			}
		}

		$result = self::call( 'decisions', 'bulk', array( $action, $ids ), null );
		if ( ! is_array( $result ) ) {
			$this->redirect_back( $fallback, array( 'wpcs_msg' => 'failed' ) );
		}
		$errors = isset( $result['errors'] ) ? array_slice( array_map( 'strval', (array) $result['errors'] ), 0, 20 ) : array();
		if ( $errors ) {
			set_transient( 'wpcybersec_bulk_errors_' . get_current_user_id(), $errors, 5 * MINUTE_IN_SECONDS );
		}
		$this->redirect_back(
			$fallback,
			array(
				'wpcs_msg'    => 'bulk',
				'wpcs_done'   => isset( $result['done'] ) ? (int) $result['done'] : 0,
				'wpcs_failed' => count( $errors ),
			)
		);
	}

	/**
	 * Items among $ids that need a confirmation before they are allowed.
	 *
	 * @param int[] $ids Item ids.
	 * @return array[] Items.
	 */
	public static function risky_items( array $ids ) {
		$out = array();
		// Every id the action will touch is inspected (the callers cap a request at MAX_BULK ids).
		foreach ( array_values( array_unique( array_map( 'intval', $ids ) ) ) as $id ) {
			$item = $id > 0 ? self::call( 'store', 'item_get', array( $id ) ) : null;
			if ( is_array( $item ) && self::needs_risk_confirm( $item ) ) {
				$out[] = $item;
			}
		}
		return $out;
	}

	/**
	 * Confirmation page of the no-JavaScript path before allowing items that
	 * were flagged high or critical. Posts the same request again with
	 * wpcs_risk_ok, or goes back.
	 *
	 * @param string  $action approve | ignore.
	 * @param int[]   $ids    Every selected id.
	 * @param array[] $risky  The risky items among them.
	 * @param string  $tab    Reports tab to return to.
	 */
	private function confirm_risky_page( $action, array $ids, array $risky, $tab ) {
		$first = self::risk_confirm_text( $risky[0], $action );
		$html  = '<h1>' . esc_html( 1 === count( $risky ) ? $first['title'] : sprintf(
			/* translators: %s: number of items */
			'ignore' === $action ? __( 'Mark %s risky items as safe anyway?', 'qartvelo-guard' ) : __( 'Allow %s risky items anyway?', 'qartvelo-guard' ),
			number_format_i18n( count( $risky ) )
		) ) . '</h1><ul>';
		foreach ( array_slice( $risky, 0, 20 ) as $item ) {
			$text  = self::risk_confirm_text( $item, $action );
			$html .= '<li><strong>' . esc_html( wp_basename( (string) $item['path'] ) ) . '</strong>: ' . esc_html( $text['verdict'] ) . '</li>';
		}
		$html .= '</ul><p>' . esc_html( $first['text'] ) . '</p>';
		$html .= '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		$html .= '<input type="hidden" name="action" value="wpcybersec_reports_bulk">';
		$html .= '<input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce( 'wpcybersec_reports_bulk' ) ) . '">';
		$html .= '<input type="hidden" name="tab" value="' . esc_attr( $tab ) . '">';
		$html .= '<input type="hidden" name="bulk_action" value="' . esc_attr( $action ) . '">';
		$html .= '<input type="hidden" name="wpcs_risk_ok" value="1">';
		foreach ( $ids as $id ) {
			$html .= '<input type="hidden" name="ids[]" value="' . esc_attr( (string) (int) $id ) . '">';
		}
		$html .= '<p><a class="button button-primary" href="' . esc_url( self::page_url( self::PAGE_REPORTS, array( 'tab' => $tab ) ) ) . '">' . esc_html__( 'Cancel', 'qartvelo-guard' ) . '</a> ';
		$html .= '<button type="submit" class="button">' . esc_html( $first['confirm'] ) . '</button></p></form>';
		wp_die( $html, esc_html__( 'Confirm', 'qartvelo-guard' ), array( 'response' => 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built with escaping above.
	}

	/**
	 * Address of the "Download report" button (admin-post with a nonce).
	 *
	 * @return string Unescaped URL.
	 */
	public static function report_url() {
		return wp_nonce_url( add_query_arg( 'action', 'wpcybersec_report', admin_url( 'admin-post.php' ) ), 'wpcybersec_report' );
	}

	/**
	 * "Download report" header button.
	 *
	 * @return string Escaped HTML.
	 */
	public static function report_button() {
		return '<a class="button" href="' . esc_url( self::report_url() ) . '" title="' . esc_attr__( 'One HTML file with the scan results, open items and recent activity, safe to send to your developer (secrets are hidden)', 'qartvelo-guard' ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span> ' . esc_html__( 'Download report', 'qartvelo-guard' ) . '</a>';
	}

	/**
	 * Sends the security report as an HTML attachment.
	 */
	public function handle_report() {
		$this->require_cap();
		check_admin_referer( 'wpcybersec_report' );

		try {
			$report = new Site_Report();
			$html   = $report->build();
		} catch ( \Throwable $e ) {
			self::debug_log( $e );
			wp_die( esc_html__( 'The report could not be created. Try again in a moment.', 'qartvelo-guard' ), '', array( 'response' => 500, 'back_link' => true ) );
		}
		self::call( 'logger', 'log', array( 'report_downloaded', __( 'Downloaded the security report.', 'qartvelo-guard' ) ) );

		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . Site_Report::filename() . '"' );
		header( 'Content-Length: ' . strlen( $html ) );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Cache-Control: no-store, private' );
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built escaped by Site_Report.
		exit;
	}

	/**
	 * Reports > Recent changes > "Report for review": a pending file item.
	 */
	public function handle_recent_report() {
		$this->require_cap();
		check_admin_referer( 'wpcybersec_recent_report' );
		// Not sanitized as text (that would change file names); Recent_Changes::resolve() accepts only an exact manifest path inside the scan root.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- verified above / validated in resolve().
		$rel = isset( $_POST['path'] ) && is_string( $_POST['path'] ) ? substr( (string) wp_unslash( $_POST['path'] ), 0, 4096 ) : '';

		$id = Recent_Changes::report( $rel );
		if ( is_wp_error( $id ) ) {
			wp_die( esc_html( $id->get_error_message() ), esc_html__( 'Not found', 'qartvelo-guard' ), array( 'response' => 404, 'back_link' => true ) );
		}
		self::$counts = null;
		wp_safe_redirect(
			self::page_url(
				self::PAGE_REPORTS,
				array(
					'view' => 'changes',
					'item' => (int) $id,
					'from' => 'pending',
				)
			)
		);
		exit;
	}

	/**
	 * Hides a notice: setup for 3 days, pending until a newer item arrives.
	 */
	public function handle_dismiss_notice() {
		$this->require_cap();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified right below.
		$which = isset( $_GET['notice'] ) ? sanitize_key( wp_unslash( $_GET['notice'] ) ) : '';
		check_admin_referer( 'wpcybersec_dismiss_' . $which );

		$user_id = get_current_user_id();
		if ( 'setup' === $which ) {
			// A site with a baseline is protected without the wizard: dismissed for
			// good then. Without one the reminder returns in three days.
			$baseline = (int) \WPCyberSecurity\Network::get_option( 'wpcybersec_baseline_at', 0 );
			update_user_meta( $user_id, self::META_DISMISS_SETUP, $baseline > 0 ? PHP_INT_MAX : time() + 3 * DAY_IN_SECONDS );
		} elseif ( 'pending' === $which ) {
			update_user_meta( $user_id, self::META_DISMISS_PENDING, self::newest_open_item_id() );
		} elseif ( 'storage' === $which ) {
			$storage = self::service( 'storage' );
			if ( is_object( $storage ) && method_exists( $storage, 'status' ) ) {
				update_user_meta( $user_id, self::META_DISMISS_STORAGE, self::storage_key( $storage->status() ) );
			}
		}
		$this->redirect_back( admin_url(), array() );
	}

	/**
	 * Redirects to the referring admin page (or $fallback) with result args, then exits.
	 *
	 * @param string $fallback URL used when there is no valid referer.
	 * @param array  $args     Query args to add.
	 */
	private function redirect_back( $fallback, array $args ) {
		$target     = (string) wp_get_referer();
		$admin_path = (string) wp_parse_url( admin_url(), PHP_URL_PATH );
		$is_admin   = '' !== $target && ( 0 === strpos( $target, admin_url() ) || ( '' !== $admin_path && 0 === strpos( $target, $admin_path ) ) );
		if ( ! $is_admin || false !== strpos( $target, 'admin-post.php' ) ) {
			$target = $fallback;
		}
		$target = remove_query_arg( array( 'wpcs_msg', 'wpcs_done', 'wpcs_failed' ), $target );
		if ( $args ) {
			$target = add_query_arg( array_map( 'rawurlencode', array_map( 'strval', $args ) ), $target );
		}
		wp_safe_redirect( $target );
		exit;
	}
}
