<?php
/**
 * System administrator tools: environment diagnostics, server snippets and the
 * admin-post handlers used by the setup wizard and the settings page.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * The setup module hooks into WordPress only through register(). Everything
 * else is plain methods that the wizard, the settings page and WP-CLI call.
 */
class Sysadmin_Tools {

	/** Marker used for the uploads .htaccess block. */
	const MARKER = 'Qartvelo Guard';

	/** The same marker in versions before 1.1.0 (CyberGate Security); still recognised. */
	const LEGACY_MARKER = 'CyberGate Security';

	/** Extensions nginx_uploads_rule() refuses to serve from uploads (regex alternation). */
	const UPLOADS_EXEC_PATTERN = 'php[0-9]?|phtml|phar|pht|phps|inc';

	/** Admin page slugs owned by the setup module. */
	const WIZARD_PAGE   = 'wpcybersec-wizard';
	const SETTINGS_PAGE = 'wpcybersec-settings';

	/** Transient holding the results of the live web probes. */
	const PROBE_TRANSIENT = 'wpcybersec_probes';

	/** Per-user transient prefix for one-time notices shown after a redirect. */
	const FLASH_PREFIX = 'wpcybersec_flash_';

	/** PHP versions below this one no longer receive security fixes. */
	const PHP_SUPPORTED = '8.2';

	/**
	 * Preset keys that do not decide the protection level: changing how alerts
	 * are delivered does not turn a level into "custom".
	 */
	const LEVEL_IGNORE = array( 'notify_mode' );

	/** Wizard quick actions that may be posted with wpcs_do. */
	const WIZARD_ACTIONS = array( 'write_htaccess', 'probe', 'send_test', 'recommended_uploads' );

	/** Average uploads a day above which holding every upload means a lot of approvals. */
	const BUSY_UPLOADS_PER_DAY = 15;

	/**
	 * Hooks: assets for the wizard and settings page, admin-post handlers and
	 * the test email AJAX endpoint.
	 */
	public function register() {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ), 20 );
		add_action( 'in_admin_header', array( $this, 'quiet_wizard_notices' ), 1 );
		add_filter( 'admin_body_class', array( $this, 'body_class' ) );

		$handlers = array( 'wizard', 'save_settings', 'guard', 'export', 'import', 'write_htaccess', 'test_email', 'snapshots_clear', 'cgav' );
		foreach ( $handlers as $handler ) {
			add_action( 'admin_post_wpcybersec_' . $handler, array( $this, 'handle_' . $handler ) );
		}
		add_action( 'wp_ajax_wpcybersec_test_email', array( $this, 'ajax_test_email' ) );
		// Runs before Ajax::clamav_enable(): "Turn on ClamAV" tests ClamAV first.
		add_action( 'wp_ajax_wpcybersec_clamav_enable', array( $this, 'ajax_clamav_precheck' ), 1 );
		add_action( 'wpcybersec_settings_updated', array( $this, 'forget_baseline_on_root_change' ), 10, 2 );
	}

	/**
	 * Fingerprints are stored relative to the scan folder, so after the folder
	 * changes (settings page, import, WP-CLI) the old baseline matches nothing.
	 * Forgetting it makes the next whole-site scan record a new baseline instead
	 * of reporting (or, in strict mode, quarantining) every file as new.
	 *
	 * @param array $new New settings.
	 * @param array $old Previous settings.
	 */
	public function forget_baseline_on_root_change( $new, $old ) {
		$new = (array) $new;
		$old = (array) $old;
		foreach ( array( 'scan_root', 'scan_root_custom' ) as $key ) {
			$before = isset( $old[ $key ] ) ? (string) $old[ $key ] : '';
			$after  = isset( $new[ $key ] ) ? (string) $new[ $key ] : '';
			if ( $before !== $after ) {
				Network::delete_option( 'wpcybersec_baseline_at' );
				return;
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/* Assets and screen tweaks                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * @return string The current ?page= value.
	 */
	public static function current_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read only.
		return isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
	}

	/**
	 * @param string $hook_suffix Admin page hook.
	 * @return bool Whether this is the wizard or the settings page.
	 */
	private static function is_setup_screen( $hook_suffix ) {
		$page = self::current_page();
		if ( in_array( $page, array( self::WIZARD_PAGE, self::SETTINGS_PAGE ), true ) ) {
			return true;
		}
		$hook_suffix = (string) $hook_suffix;
		return false !== strpos( $hook_suffix, self::WIZARD_PAGE ) || false !== strpos( $hook_suffix, self::SETTINGS_PAGE );
	}

	/**
	 * Enqueues setup.css and setup.js on the wizard and the settings page.
	 *
	 * @param string $hook_suffix Admin page hook.
	 */
	public function enqueue( $hook_suffix ) {
		if ( ! self::is_setup_screen( $hook_suffix ) ) {
			return;
		}

		if ( class_exists( '\WPCyberSecurity\Admin\Assets' ) ) {
			if ( ! wp_script_is( 'wpcybersec-core', 'registered' ) ) {
				Admin\Assets::register();
			}
			Admin\Assets::enqueue();
		}

		$css_deps = wp_style_is( 'wpcybersec-base', 'registered' ) ? array( 'wpcybersec-base' ) : array( 'dashicons' );
		$js_deps  = wp_script_is( 'wpcybersec-core', 'registered' ) ? array( 'wpcybersec-core' ) : array();

		wp_enqueue_style( 'wpcybersec-setup', WPCYBERSEC_URL . 'assets/css/setup.css', $css_deps, \WPCyberSecurity\Admin\Assets::ver( 'assets/css/setup.css' ) );
		wp_enqueue_script( 'wpcybersec-setup', WPCYBERSEC_URL . 'assets/js/setup.js', $js_deps, \WPCyberSecurity\Admin\Assets::ver( 'assets/js/setup.js' ), true );
		wp_localize_script(
			'wpcybersec-setup',
			'wpcybersecSetup',
			array(
				'presets'    => Settings::presets(),
				'levels'     => array(
					'strict'   => __( 'Strict', 'qartvelo-guard' ),
					'balanced' => __( 'Balanced', 'qartvelo-guard' ),
					'relaxed'  => __( 'Relaxed', 'qartvelo-guard' ),
				),
				'threatsUrl' => Network::admin_url( 'admin.php?page=wpcybersec-reports&tab=threats' ),
				'i18n'       => array(
					'starting'       => __( 'Starting the scan...', 'qartvelo-guard' ),
					'waitOther'      => __( 'Another scan is running. The baseline scan starts as soon as it finishes.', 'qartvelo-guard' ),
					/* translators: %s: number of files */
					'fingerprinted'  => __( '%s files fingerprinted and trusted.', 'qartvelo-guard' ),
					/* translators: %s: number of threats */
					'threatsFound'   => __( '%s possible threats found. They were not trusted; review them on the Reports page.', 'qartvelo-guard' ),
					'threatsLink'    => __( 'Review threats', 'qartvelo-guard' ),
					'noThreats'      => __( 'No known malware was found.', 'qartvelo-guard' ),
					/* translators: %s: error message */
					'scanFailed'     => __( 'The scan stopped: %s', 'qartvelo-guard' ),
					'scanCancelled'  => __( 'The scan was cancelled. You can start it again.', 'qartvelo-guard' ),
					'runAgain'       => __( 'Run the scan again', 'qartvelo-guard' ),
					'scanAgain'      => __( 'Scan again', 'qartvelo-guard' ),
					'listing'        => __( 'Listing files...', 'qartvelo-guard' ),
					/* translators: %s: number of files */
					'listingCount'   => __( 'Listing files - %s files found so far', 'qartvelo-guard' ),
					'leaving'        => __( 'A scan is running. If you leave, it continues in the background, more slowly.', 'qartvelo-guard' ),
					'sending'        => __( 'Sending...', 'qartvelo-guard' ),
					/* translators: %s: time */
					'unlockedUntil'  => __( 'Unlocked until %s', 'qartvelo-guard' ),
					'locked'         => __( 'Locked', 'qartvelo-guard' ),
					/* translators: %s: number of minutes */
					'unlockFor'      => __( 'Unlock for %s minutes', 'qartvelo-guard' ),
					/* translators: %s: number of minutes (always 1) */
					'unlockFor1'     => __( 'Unlock for %s minute', 'qartvelo-guard' ),
					'unlockedToast'  => __( 'Changes are allowed for a few minutes.', 'qartvelo-guard' ),
					'lockedToast'    => __( 'Locked again.', 'qartvelo-guard' ),
					/* translators: %s: protection level name */
					'customHint'     => __( 'Your choices differ from the %s preset, so the level is saved as Custom.', 'qartvelo-guard' ),
					'customNoLevel'  => __( 'Your choices do not match a preset, so the level is saved as Custom.', 'qartvelo-guard' ),
				),
			)
		);
	}

	/**
	 * Removes notices of other plugins from the wizard so it stays focused.
	 */
	public function quiet_wizard_notices() {
		if ( self::WIZARD_PAGE !== self::current_page() ) {
			return;
		}
		remove_all_actions( 'admin_notices' );
		remove_all_actions( 'all_admin_notices' );
		remove_all_actions( 'network_admin_notices' );
		remove_all_actions( 'user_admin_notices' );
	}

	/**
	 * @param string $classes Body classes.
	 * @return string
	 */
	public function body_class( $classes ) {
		$page = self::current_page();
		if ( self::WIZARD_PAGE === $page ) {
			$classes .= ' wpcs-wizard-screen';
		} elseif ( self::SETTINGS_PAGE === $page ) {
			$classes .= ' wpcs-settings-screen';
		}
		return $classes;
	}

	/* ------------------------------------------------------------------ */
	/* Small helpers                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * A service from the container, or null when that module is missing.
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
	 * Calls a method of another module without ever fataling.
	 *
	 * @param string $service Service name.
	 * @param string $method  Method.
	 * @param array  $args    Arguments.
	 * @param mixed  $default Returned when the module or method is missing or throws.
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
			return $default;
		}
	}

	/**
	 * Writes an activity log entry when the logger exists.
	 *
	 * @param string $event   Event.
	 * @param string $message Message.
	 * @param array  $context Context.
	 */
	private static function log( $event, $message, array $context = array() ) {
		self::call( 'logger', 'log', array( $event, $message, $context ) );
	}

	/**
	 * Queues a notice for the next page view of the current user.
	 *
	 * @param string $message Plain text.
	 * @param string $type    ok | warn | bad | info.
	 */
	public static function flash( $message, $type = 'ok' ) {
		$key   = self::FLASH_PREFIX . get_current_user_id();
		$queue = get_transient( $key );
		$queue = is_array( $queue ) ? $queue : array();
		$queue[] = array(
			'message' => (string) $message,
			'type'    => in_array( $type, array( 'ok', 'warn', 'bad', 'info' ), true ) ? $type : 'info',
		);
		set_transient( $key, $queue, 5 * MINUTE_IN_SECONDS );
	}

	/**
	 * Returns and clears queued notices.
	 *
	 * @return array[] Each { message, type }.
	 */
	public static function take_flash() {
		$key   = self::FLASH_PREFIX . get_current_user_id();
		$queue = get_transient( $key );
		if ( false !== $queue ) {
			delete_transient( $key );
		}
		return is_array( $queue ) ? $queue : array();
	}

	/**
	 * @param string $tab  general | advanced.
	 * @param array  $args Extra query args.
	 * @param string $hash Optional fragment without "#".
	 * @return string
	 */
	public static function settings_url( $tab = 'general', array $args = array(), $hash = '' ) {
		// Advanced is split into sections shown one at a time: open the one the fragment points to.
		if ( 'advanced' === $tab && ! isset( $args['section'] ) && 0 === strpos( (string) $hash, 'wpcs-' ) ) {
			$args['section'] = substr( (string) $hash, 5 );
		}
		$url = add_query_arg( array_merge( array( 'page' => self::SETTINGS_PAGE, 'tab' => $tab ), $args ), Network::admin_url( 'admin.php' ) );
		return $url . ( $hash ? '#' . $hash : '' );
	}

	/**
	 * @param string $step Step key.
	 * @param array  $args Extra query args.
	 * @return string
	 */
	public static function wizard_url( $step = '', array $args = array() ) {
		$query = array( 'page' => self::WIZARD_PAGE );
		if ( $step ) {
			$query['step'] = $step;
		}
		return add_query_arg( array_merge( $query, $args ), Network::admin_url( 'admin.php' ) );
	}

	/**
	 * Same rule as Admin::can(): manage_options, or manage_network_options on
	 * multisite, because these tools change files shared by the whole network.
	 *
	 * @return bool
	 */
	public static function user_can_manage() {
		if ( class_exists( '\WPCyberSecurity\Admin\Admin' ) ) {
			return Admin\Admin::can();
		}
		return current_user_can( is_multisite() ? 'manage_network_options' : 'manage_options' );
	}

	/**
	 * Capability and nonce gate for admin-post handlers. Dies on failure.
	 *
	 * @param string $nonce_action Nonce action.
	 */
	private function check_request( $nonce_action ) {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'qartvelo-guard' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce_action );
	}

	/**
	 * Redirects (only to this site) and exits.
	 *
	 * @param string $url Target.
	 */
	private function redirect( $url ) {
		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Redirects to the referring admin page, or the fallback.
	 *
	 * @param string $fallback Fallback URL.
	 */
	private function redirect_back( $fallback ) {
		$referer = wp_get_referer();
		$this->redirect( $referer ? $referer : $fallback );
	}

	/**
	 * Splits a textarea or comma list into trimmed, non-empty strings.
	 *
	 * @param mixed $raw String or array.
	 * @return string[]
	 */
	public static function parse_list( $raw ) {
		if ( is_array( $raw ) ) {
			$items = $raw;
		} else {
			$items = preg_split( '/[\r\n,;]+/', (string) $raw );
		}
		$out = array();
		foreach ( (array) $items as $item ) {
			$item = trim( sanitize_text_field( (string) $item ) );
			if ( '' !== $item ) {
				$out[] = $item;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Quotes a value for a POSIX shell only when needed, so snippets stay readable.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	public static function shell_arg( $value ) {
		$value = (string) $value;
		if ( '' !== $value && preg_match( '#^[A-Za-z0-9_@%+=:,./-]+$#', $value ) ) {
			return $value;
		}
		return "'" . str_replace( "'", "'\\''", $value ) . "'";
	}

	/**
	 * Server type from SERVER_SOFTWARE.
	 *
	 * @return string apache | litespeed | nginx | iis | unknown.
	 */
	public static function server_type() {
		$soft = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		if ( false !== strpos( $soft, 'litespeed' ) ) {
			return 'litespeed';
		}
		if ( false !== strpos( $soft, 'nginx' ) || false !== strpos( $soft, 'openresty' ) ) {
			return 'nginx';
		}
		if ( false !== strpos( $soft, 'apache' ) ) {
			return 'apache';
		}
		if ( false !== strpos( $soft, 'iis' ) ) {
			return 'iis';
		}
		return 'unknown';
	}

	/**
	 * PHP CLI binary for cron snippets: PHP_BINARY when it looks like a CLI
	 * binary, a CLI binary next to php-fpm, lsphp (LiteSpeed, CyberPanel:
	 * /usr/local/lsws/lsphpXX/bin/lsphp next to bin/php) or php-cgi when one
	 * exists, php-cgi itself when that is all there is, else "php".
	 *
	 * @param string|null $bin Binary to map (default: PHP_BINARY).
	 * @return string
	 */
	public static function php_binary( $bin = null ) {
		$bin  = null !== $bin ? wp_normalize_path( (string) $bin ) : ( defined( 'PHP_BINARY' ) ? wp_normalize_path( (string) PHP_BINARY ) : '' );
		$base = strtolower( basename( $bin ) );
		if ( '' !== $bin && preg_match( '/^php(\d+(\.\d+)*)?(-cli)?(\.exe)?$/', $base ) ) {
			return self::stable_binary( $bin );
		}
		if ( '' !== $bin && preg_match( '/^(?:php-?fpm|lsphp|php-?cgi)([\d.]*)(\.exe)?$/', $base, $m ) ) {
			$ver        = $m[1];
			$candidates = array(
				dirname( $bin ) . '/php' . $ver,
				dirname( $bin ) . '/php',
				dirname( dirname( $bin ) ) . '/bin/php' . $ver,
				dirname( dirname( $bin ) ) . '/bin/php',
				'/usr/bin/php' . $ver,
				'/usr/local/bin/php' . $ver,
			);
			// lsphp74 / lsphp81 folders: the matching CLI version.
			if ( preg_match( '#/lsphp(\d)(\d+)/#', $bin, $v ) ) {
				$candidates[] = '/usr/bin/php' . $v[1] . '.' . $v[2];
			}
			$candidates[] = '/usr/bin/php';
			$candidates[] = '/usr/local/bin/php';
			foreach ( array_unique( $candidates ) as $candidate ) {
				if ( self::path_allowed( $candidate ) && @is_file( $candidate ) && @is_executable( $candidate ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					return self::stable_binary( $candidate );
				}
			}
			// LiteSpeed always ships the CLI next to lsphp (lsphpXX/bin/php). When
			// open_basedir hides that folder (CyberPanel's open_basedir protection),
			// it cannot be checked, but it is still the right binary.
			if ( 0 === strpos( $base, 'lsphp' ) && ! self::path_allowed( dirname( $bin ) . '/php' ) ) {
				return dirname( $bin ) . '/php';
			}
			// php-cgi works too (bin/cron.php accepts it from a shell): better than a "php" that may not exist.
			if ( 0 === strpos( $base, 'php-cgi' ) || 0 === strpos( $base, 'phpcgi' ) ) {
				return self::stable_binary( $bin );
			}
		}
		return 'php';
	}

	/**
	 * Shell command that starts PHP for bin/cron.php: the binary, plus -q for
	 * php-cgi (hides the HTTP headers it prints).
	 *
	 * @return string Shell-quoted.
	 */
	public static function php_command() {
		$bin = self::php_binary();
		$cmd = self::shell_arg( $bin );
		if ( preg_match( '/^php-?cgi/i', basename( $bin ) ) ) {
			$cmd .= ' -q';
		}
		return $cmd;
	}

	/**
	 * How snippets start WP-CLI. "wp" runs with the server's default "php",
	 * which can be another PHP version than the site's: on CyberPanel and
	 * OpenLiteSpeed /usr/bin/php may be 8.1 while the site runs lsphp83, and
	 * the composer platform_check of other plugins then stops WP-CLI with a
	 * fatal error. So when this site's PHP (php_binary()) is not the default
	 * php, the command names it: "/usr/local/lsws/lsphp83/bin/php /usr/local/bin/wp".
	 *
	 * @param string|null $bin PHP binary of the site (default: php_binary()).
	 * @return string Shell text, already quoted.
	 */
	public static function wp_cli( $bin = null ) {
		$bin = null !== $bin ? wp_normalize_path( (string) $bin ) : self::php_binary();
		// php-cgi cannot run the wp program; "php" means nothing better is known.
		if ( '' === $bin || 'php' === $bin || preg_match( '/^php-?cgi/i', basename( $bin ) ) || self::is_default_php( $bin ) ) {
			return 'wp';
		}
		$wp = self::wp_cli_path();
		return self::shell_arg( $bin ) . ' ' . ( '' !== $wp ? self::shell_arg( $wp ) : '"$(command -v wp)"' );
	}

	/**
	 * Whether $bin is the PHP that a plain "php" starts in a shell or cron
	 * (the first php in /usr/local/bin, /usr/bin, /bin, links resolved).
	 *
	 * @param string $bin PHP binary.
	 * @return bool False when it cannot be told (then naming the binary is the safe choice).
	 */
	public static function is_default_php( $bin ) {
		$real = self::path_allowed( $bin ) ? @realpath( $bin ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $real ) {
			return false;
		}
		foreach ( array( '/usr/local/bin/php', '/usr/bin/php', '/bin/php' ) as $default ) {
			if ( ! self::path_allowed( $default ) || ! @is_file( $default ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			$target = @realpath( $default ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $target && wp_normalize_path( $target ) === wp_normalize_path( $real );
		}
		return false;
	}

	/**
	 * Where the wp program is installed ('' when not found here).
	 *
	 * @return string
	 */
	public static function wp_cli_path() {
		foreach ( array( '/usr/local/bin/wp', '/usr/bin/wp', '/usr/local/bin/wp-cli', '/usr/local/bin/wp-cli.phar', '/usr/bin/wp-cli' ) as $candidate ) {
			if ( self::path_allowed( $candidate ) && @is_file( $candidate ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return $candidate;
			}
		}
		return '';
	}

	/**
	 * Short name of this site for server-wide files that several sites of one
	 * server may each add (fapolicyd rules, the inotify watcher): the host with
	 * dots as dashes, so two sites never overwrite each other's file.
	 *
	 * @return string
	 */
	public static function site_slug() {
		$host = sanitize_title( (string) wp_parse_url( Network::home_url(), PHP_URL_HOST ) );
		$path = trim( (string) wp_parse_url( Network::home_url(), PHP_URL_PATH ), '/' );
		if ( '' !== $path ) {
			$host .= '-' . sanitize_title( str_replace( '/', '-', $path ) );
		}
		return '' !== $host ? $host : 'site';
	}

	/**
	 * " --url=<network address>" for bin/cron.php on multisite (WordPress cannot
	 * pick the site without it), '' on single sites.
	 *
	 * @return string Leading space included.
	 */
	public static function cron_url_arg() {
		return is_multisite() ? ' --url=' . self::shell_arg( network_home_url( '/' ) ) : '';
	}

	/**
	 * Homebrew keeps binaries in versioned Cellar folders that disappear on
	 * upgrade; prefer the stable "opt" link of the same formula.
	 *
	 * @param string $bin Binary path.
	 * @return string
	 */
	private static function stable_binary( $bin ) {
		if ( preg_match( '#^(.*)/Cellar/([^/]+)/[^/]+/bin/([^/]+)$#', $bin, $m ) ) {
			$link = $m[1] . '/opt/' . $m[2] . '/bin/' . $m[3];
			if ( @is_file( $link ) && @is_executable( $link ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return $link;
			}
		}
		return $bin;
	}

	/**
	 * @return string ABSPATH without trailing slash, normalized.
	 */
	private static function abspath() {
		return untrailingslashit( wp_normalize_path( ABSPATH ) );
	}

	/**
	 * Location of wp-config.php (WordPress also allows one folder up).
	 *
	 * @return string Empty when not found.
	 */
	public static function wp_config_path() {
		$here   = self::abspath() . '/wp-config.php';
		$parent = dirname( self::abspath() ) . '/wp-config.php';
		if ( @is_file( $here ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $here;
		}
		if ( @is_file( $parent ) && ! @is_file( dirname( self::abspath() ) . '/wp-settings.php' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $parent;
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/* Diagnostics                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Environment checks for the wizard and the advanced settings.
	 *
	 * @param bool $fresh True to ignore cached live probe results.
	 * @return array[] Each { id, label, status pass|warn|fail|info, detail, fix, code, actions[] }.
	 */
	public function diagnostics( $fresh = false ) {
		$methods = array(
			'check_php',
			'check_wordpress',
			'check_https',
			'check_data_dir',
			'check_quarantine_web',
			'check_uploads_php',
			'check_cron',
			'check_prepend',
			'check_exec',
			'check_open_basedir',
			'check_zip',
			'check_wp_config',
			'check_world_writable',
			'check_file_edit',
			'check_hosting',
			'check_server',
			'check_plugins',
			'check_security_plugins',
		);
		$checks = array();
		foreach ( $methods as $method ) {
			try {
				$check = $this->$method( $fresh );
			} catch ( \Throwable $e ) {
				$check = array(
					'id'     => $method,
					'label'  => $method,
					'status' => 'info',
					/* translators: %s: error message */
					'detail' => sprintf( __( 'This check could not run: %s', 'qartvelo-guard' ), $e->getMessage() ),
				);
			}
			if ( $check ) {
				$checks[] = array_merge(
					array(
						'id'      => '',
						'label'   => '',
						'status'  => 'info',
						'detail'  => '',
						'fix'     => '',
						'code'    => '',
						'actions' => array(),
					),
					$check
				);
			}
		}

		/**
		 * Filters the environment checks.
		 *
		 * @param array[] $checks Checks.
		 */
		return apply_filters( 'wpcybersec_diagnostics', $checks );
	}

	/**
	 * @return array
	 */
	private function check_php() {
		$version = PHP_VERSION;
		$check   = array(
			'id'    => 'php_version',
			'label' => __( 'PHP version', 'qartvelo-guard' ),
		);
		if ( version_compare( $version, self::PHP_SUPPORTED, '>=' ) ) {
			$check['status'] = 'pass';
			/* translators: %s: PHP version */
			$check['detail'] = sprintf( __( 'PHP %s receives security fixes.', 'qartvelo-guard' ), $version );
		} else {
			$check['status'] = 'warn';
			/* translators: %s: PHP version */
			$check['detail'] = sprintf( __( 'PHP %s no longer receives security fixes.', 'qartvelo-guard' ), $version );
			/* translators: %s: PHP version */
			$check['fix'] = sprintf( __( 'Ask your host to switch this site to PHP %s or newer.', 'qartvelo-guard' ), self::PHP_SUPPORTED );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_wordpress() {
		$version = get_bloginfo( 'version' );
		$check   = array(
			'id'     => 'wp_version',
			'label'  => __( 'WordPress version', 'qartvelo-guard' ),
			'status' => 'pass',
			/* translators: %s: WordPress version */
			'detail' => sprintf( __( 'WordPress %s is up to date.', 'qartvelo-guard' ), $version ),
		);
		if ( ! function_exists( 'get_core_updates' ) && is_readable( ABSPATH . 'wp-admin/includes/update.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( function_exists( 'get_core_updates' ) ) {
			$updates = get_core_updates( array( 'dismissed' => false ) );
			foreach ( (array) $updates as $update ) {
				if ( is_object( $update ) && isset( $update->response, $update->current ) && 'upgrade' === $update->response ) {
					$check['status'] = 'warn';
					/* translators: 1: available version, 2: installed version */
					$check['detail'] = sprintf( __( 'WordPress %1$s is available. This site runs %2$s.', 'qartvelo-guard' ), $update->current, $version );
					$check['fix']    = __( 'Update from Dashboard > Updates. Security fixes ship in every release.', 'qartvelo-guard' );
					break;
				}
			}
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_https() {
		$https = is_ssl() || 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
		return array(
			'id'     => 'https',
			'label'  => __( 'HTTPS', 'qartvelo-guard' ),
			'status' => $https ? 'pass' : 'warn',
			'detail' => $https
				? __( 'The site is served over HTTPS.', 'qartvelo-guard' )
				: __( 'The site does not use HTTPS, so logins and cookies travel unencrypted.', 'qartvelo-guard' ),
			'fix'    => $https ? '' : __( 'Install a TLS certificate (most hosts offer a free one) and change the site address to https:// in Settings > General.', 'qartvelo-guard' ),
		);
	}

	/**
	 * @return array
	 */
	private function check_data_dir() {
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$dir     = $storage->data_dir();
		$check   = array(
			'id'    => 'data_dir',
			'label' => __( 'Data folder', 'qartvelo-guard' ),
		);
		$problem = method_exists( $storage, 'check' ) ? $storage->problem( $storage->check() ) : null;
		$dir     = $storage->data_dir();
		if ( $problem ) {
			$check['status'] = 'error' === $problem['level'] ? 'fail' : 'warn';
			$check['detail'] = $problem['text'];
			$check['fix']    = $problem['fix'];
			if ( '' !== $problem['code'] ) {
				$check['code'] = $problem['code'];
			}
			return $check;
		}
		if ( ! is_dir( $dir ) ) {
			$storage->ensure();
		}
		if ( ! is_dir( $dir ) || ! wp_is_writable( $dir ) ) {
			$check['status'] = 'fail';
			/* translators: %s: folder path */
			$check['detail'] = sprintf( __( '%s does not exist or is not writable. Held files cannot be stored.', 'qartvelo-guard' ), $dir );
			$check['fix']    = __( 'Make the folder writable by the web server user, for example: chown www-data and chmod 750.', 'qartvelo-guard' );
			return $check;
		}
		if ( $storage->is_in_webroot( $dir ) ) {
			$check['status'] = 'warn';
			/* translators: %s: folder path */
			$check['detail'] = sprintf( __( '%s is writable but inside the web root. Held files have random .bin names and deny rules, but a folder outside the web root is safer.', 'qartvelo-guard' ), $dir );
			$check['fix']    = __( 'For system administrators: move it outside the web root with this line in wp-config.php.', 'qartvelo-guard' );
			$snippet         = $this->data_dir_snippet();
			$check['code']   = $snippet['config'];
			return $check;
		}
		$check['status'] = 'pass';
		/* translators: %s: folder path */
		$check['detail'] = sprintf( __( '%s is writable and outside the web root.', 'qartvelo-guard' ), $dir );
		return $check;
	}

	/**
	 * @param bool $fresh Ignore the cached probe.
	 * @return array
	 */
	private function check_quarantine_web( $fresh = false ) {
		$check = array(
			'id'    => 'quarantine_web',
			'label' => __( 'Quarantine is not reachable from the web', 'qartvelo-guard' ),
		);
		$probe = $this->probe_quarantine_web( $fresh );
		switch ( $probe['result'] ) {
			case 'outside':
				$check['status'] = 'pass';
				$check['detail'] = __( 'The data folder is outside the web root.', 'qartvelo-guard' );
				break;
			case 'blocked':
				$check['status'] = 'pass';
				/* translators: %d: HTTP status code */
				$check['detail'] = sprintf( __( 'A test file in the quarantine folder could not be downloaded (HTTP %d).', 'qartvelo-guard' ), $probe['code'] );
				break;
			case 'reachable':
				$check['status'] = 'warn';
				$check['detail'] = __( 'A test file in the quarantine folder could be downloaded. The server ignores the .htaccess deny rules (typical for nginx). Held files cannot run, and the data folder has a random name, so only someone who knows its exact address could download a file. The rule below closes the folder completely.', 'qartvelo-guard' );
				$check['fix']    = __( 'Add this rule to the nginx server block, or move the data folder outside the web root.', 'qartvelo-guard' );
				$check['code']   = $this->nginx_data_rule();
				break;
			default:
				$check['status'] = 'info';
				$check['detail'] = $probe['message'] ? $probe['message'] : __( 'Could not test web access automatically.', 'qartvelo-guard' );
				$check['actions'] = array( 'probe' );
		}
		return $check;
	}

	/**
	 * @param bool $fresh Ignore cached probe results (live probe only runs on request).
	 * @return array
	 */
	private function check_uploads_php( $fresh = false ) {
		unset( $fresh ); // The live PHP probe only runs when the administrator asks for it.
		$check  = array(
			'id'    => 'uploads_php',
			'label' => __( 'Uploads folder blocks PHP', 'qartvelo-guard' ),
		);
		$server = self::server_type();
		$cached = $this->cached_probe( 'uploads_php' );

		if ( $cached && 'executed' === $cached['result'] ) {
			$check['status'] = 'fail';
			$check['detail'] = __( 'Live test: a PHP file placed in the uploads folder was executed. A backdoor uploaded there would run.', 'qartvelo-guard' );
			if ( 'nginx' === $server ) {
				$check['fix']  = __( 'Add this rule to the nginx server block, then run the test again.', 'qartvelo-guard' );
				$check['code'] = self::nginx_uploads_rule();
			} else {
				$check['fix']     = __( 'Write the blocking rule to uploads/.htaccess, then run the test again.', 'qartvelo-guard' );
				$check['actions'] = array( 'write_htaccess', 'probe' );
			}
			return $check;
		}
		if ( $cached && 'blocked' === $cached['result'] ) {
			$check['status'] = 'pass';
			if ( $cached['code'] ) {
				/* translators: %d: HTTP status code */
				$check['detail'] = sprintf( __( 'Live test: PHP files in the uploads folder do not run (HTTP %d).', 'qartvelo-guard' ), $cached['code'] );
			} else {
				$check['detail'] = __( 'Live test: PHP files in the uploads folder do not run.', 'qartvelo-guard' );
			}
			return $check;
		}

		$status = $this->uploads_htaccess_status();
		if ( 'litespeed' === $server && 'openlitespeed' === Guard_Manager::litespeed_edition() ) {
			// OpenLiteSpeed only reads rewrite rules from .htaccess: a deny block proves nothing there.
			$check['status']  = 'info';
			$check['detail']  = __( 'This server runs OpenLiteSpeed, which reads only rewrite rules from .htaccess files, so a rule in uploads/.htaccess may not stop PHP. Run the live test to see whether PHP runs in uploads.', 'qartvelo-guard' );
			$check['fix']     = __( 'If it does: in WebAdmin open Virtual Hosts > this site > Context and add a context that denies access to .php files in the uploads folder, or ask your host.', 'qartvelo-guard' );
			$check['actions'] = array( 'probe' );
			return $check;
		}
		if ( in_array( $server, array( 'apache', 'litespeed' ), true ) ) {
			if ( 'ours' === $status ) {
				$check['status'] = 'pass';
				$check['detail'] = __( 'Blocked by the Qartvelo Guard rules in uploads/.htaccess.', 'qartvelo-guard' );
			} elseif ( 'other' === $status ) {
				$check['status'] = 'pass';
				$check['detail'] = __( 'uploads/.htaccess contains rules that block PHP.', 'qartvelo-guard' );
			} else {
				$check['status']  = 'warn';
				$check['detail']  = __( 'No rule in uploads/.htaccess stops PHP files from running there. A file dropped in uploads by a vulnerable plugin could run.', 'qartvelo-guard' );
				$check['fix']     = __( 'Let the plugin add the rule (existing content is kept, and the change is undone if images stop loading), or run a live test first.', 'qartvelo-guard' );
				$check['actions'] = array( 'write_htaccess', 'probe' );
			}
			return $check;
		}
		if ( 'nginx' === $server ) {
			$check['status']  = 'info';
			$check['detail']  = __( 'nginx does not read .htaccess files, so the blocking rule must be in the server configuration.', 'qartvelo-guard' );
			$check['fix']     = __( 'Make sure the server block contains a rule like this one, then run a live test.', 'qartvelo-guard' );
			$check['code']    = self::nginx_uploads_rule();
			$check['actions'] = array( 'probe' );
			return $check;
		}
		$check['status']  = 'info';
		$check['detail']  = __( 'Unknown web server. Run a live test to see whether PHP runs in the uploads folder.', 'qartvelo-guard' );
		$check['actions'] = array( 'probe' );
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_cron() {
		$disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		$next     = Network::next_scheduled( 'wpcybersec_scheduled_scan' );
		$check    = array(
			'id'    => 'wp_cron',
			'label' => __( 'Scheduled tasks (cron)', 'qartvelo-guard' ),
		);
		$snippets = $this->cron_snippets();
		if ( $next && $next < time() - HOUR_IN_SECONDS ) {
			$check['status'] = 'warn';
			/* translators: %s: time span, e.g. "3 hours" */
			$check['detail'] = sprintf( __( 'Scheduled tasks are late: the last scheduled scan was due %s ago, so cron is not running.', 'qartvelo-guard' ), human_time_diff( $next ) );
			$check['fix']    = __( 'Add a real cron job on the server:', 'qartvelo-guard' );
			$check['code']   = $snippets[0]['code'];
		} elseif ( $disabled ) {
			$check['status'] = 'pass';
			$check['detail'] = __( 'WP-Cron is disabled and tasks run on time, so a real cron job is in place.', 'qartvelo-guard' );
		} else {
			$check['status'] = 'info';
			$check['detail'] = __( 'WP-Cron runs when people visit the site. On quiet sites scheduled scans can start late.', 'qartvelo-guard' );
			$check['fix']    = __( 'Recommended for system administrators: a real cron job (all variants are in Settings > Advanced).', 'qartvelo-guard' );
			$check['code']   = $snippets[0]['code'];
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_prepend() {
		$prepend   = trim( (string) ini_get( 'auto_prepend_file' ) );
		$bootstrap = (string) self::call( 'guard_manager', 'bootstrap_path', array(), ABSPATH . 'wpcybersec-guard.php' );
		$check     = array(
			'id'    => 'auto_prepend_file',
			'label' => __( 'auto_prepend_file', 'qartvelo-guard' ),
		);
		$manager = self::service( 'guard_manager' );
		if ( ( '' === $prepend || 'none' === strtolower( $prepend ) ) && $manager && method_exists( $manager, 'live_state' ) ) {
			$live = $manager->live_state();
			if ( 'confirmed' === $live['state'] ) {
				// WP-CLI, cron or a development server: this PHP does not read .user.ini or .htaccess.
				$check['status'] = 'pass';
				$check['detail'] = $live['label'];
				return $check;
			}
		}
		if ( '' === $prepend || 'none' === strtolower( $prepend ) ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'Not set. The optional early upload guard is not active.', 'qartvelo-guard' );
			$check['fix']    = __( 'System administrators can install the early guard in Settings > Advanced. It also holds uploads sent to PHP files outside WordPress.', 'qartvelo-guard' );
			return $check;
		}
		$real_prepend   = @realpath( $prepend ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$real_bootstrap = @realpath( $bootstrap ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ( $real_prepend && $real_bootstrap && $real_prepend === $real_bootstrap ) || wp_normalize_path( $prepend ) === wp_normalize_path( $bootstrap ) ) {
			$check['status'] = 'pass';
			$check['detail'] = __( 'The early upload guard is active.', 'qartvelo-guard' );
			return $check;
		}
		$other = Guard_Manager::other_site_root( $prepend );
		if ( '' !== $other ) {
			$check['status'] = 'fail';
			/* translators: 1: prepend file, 2: folder of the other site */
			$check['detail'] = sprintf( __( 'PHP runs %1$s before every request, a file of another WordPress site (%2$s). This site depends on that site and runs its code with its settings, usually a leftover from copying a site.', 'qartvelo-guard' ), $prepend, $other );
			$check['fix']    = __( 'Remove that auto_prepend_file line (.user.ini or .htaccess in this site\'s folder, the hosting panel\'s PHP settings, or the web server\'s settings for this site) and restart PHP. If this site uses Wordfence, run Wordfence > Firewall > Optimize the Wordfence Firewall again so it creates this site\'s own file. Then install the early guard.', 'qartvelo-guard' );
			$gm              = self::service( 'guard_manager' );
			if ( $gm && method_exists( $gm, 'foreign_prepend_hint' ) ) {
				$where         = $gm->foreign_prepend_hint();
				$check['fix'] .= ' ' . $where['text'];
				$check['code'] = $where['code'];
				$check['detail'] .= ' ' . __( 'It can also be set in the server-wide php.ini.', 'qartvelo-guard' ) . ' ' . $where['note'];
			}
			return $check;
		}
		$check['status'] = 'info';
		if ( false !== stripos( $prepend, 'wordfence-waf' ) ) {
			/* translators: %s: file path */
			$check['detail'] = sprintf( __( 'Used by the Wordfence firewall (%s).', 'qartvelo-guard' ), $prepend );
			$check['fix']    = __( 'Both can run: the early guard bootstrap can include the Wordfence file. See Settings > Advanced > Early upload guard.', 'qartvelo-guard' );
		} else {
			/* translators: %s: file path */
			$check['detail'] = sprintf( __( 'Already used by another file: %s', 'qartvelo-guard' ), $prepend );
			$check['fix']    = __( 'Only one auto_prepend_file can be set. Check what that file does before you install the early guard.', 'qartvelo-guard' );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_exec() {
		$parts = array();
		foreach ( array( 'exec', 'proc_open', 'shell_exec' ) as $function ) {
			$parts[] = sprintf(
				'%1$s(): %2$s',
				$function,
				self::function_available( $function ) ? __( 'available', 'qartvelo-guard' ) : __( 'disabled', 'qartvelo-guard' )
			);
		}
		$clam   = $this->clamav_detect();
		$detail = implode( ', ', $parts ) . '. ';
		$detail .= $clam
			/* translators: %s: binary path */
			? sprintf( __( 'ClamAV found at %s.', 'qartvelo-guard' ), $clam )
			: __( 'ClamAV not found.', 'qartvelo-guard' );
		$check = array(
			'id'     => 'exec',
			'label'  => __( 'Command execution and ClamAV', 'qartvelo-guard' ),
			'status' => 'info',
			'detail' => $detail,
		);
		$maldet  = self::maldet_detect();
		if ( '' !== $maldet ) {
			/* translators: %s: binary path */
			$detail .= ' ' . sprintf( __( 'Linux Malware Detect found at %s.', 'qartvelo-guard' ), $maldet );
		} else {
			$detail .= ' ' . ( self::maldet_hidden()
				? __( 'Linux Malware Detect (maldet): unknown, the hosting hides the folders it is installed in (open_basedir).', 'qartvelo-guard' )
				: __( 'Linux Malware Detect (maldet) not found.', 'qartvelo-guard' ) );
		}
		$check['detail'] = $detail;

		$settings = self::service( 'settings' );
		$av       = $clam ? $this->antivirus_status()['clamav'] : null;
		if ( $av && 'broken' === $av['state'] ) {
			// Installed, but the self-test failed: say why instead of "turn it on".
			$check['detail'] .= ' ' . $av['label'];
			$check['fix']     = $av['hint'];
			$check['code']    = $av['hint_code'];
		} elseif ( $clam && self::function_available( 'exec' ) && $settings && ! $settings->get( 'clamav_enabled', false ) ) {
			$check['fix'] = __( 'Turn on ClamAV in Settings > Advanced > Antivirus engines for a second opinion on uploads.', 'qartvelo-guard' );
		} elseif ( ! $clam || '' === $maldet ) {
			$check['fix'] = __( 'Optional. ClamAV and Linux Malware Detect know many more existing infections (web shells, phishing kits, infected uploads) and are a good second opinion, but they do not block attacks. With root access (VPS or dedicated server): install ClamAV and Linux Malware Detect (maldet). Without root (shared hosting): run the malware scanner of your hosting panel, for example cPanel Virus Scanner or Imunify360.', 'qartvelo-guard' );
		}
		return $check;
	}

	/**
	 * Linux Malware Detect binary: a standard install place, or "maldet" in PATH.
	 *
	 * @return string Path, '' when not found.
	 */
	public static function maldet_detect() {
		foreach ( self::maldet_candidates() as $bin ) {
			if ( self::path_allowed( $bin ) && @is_file( $bin ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return wp_normalize_path( $bin );
			}
		}
		return '';
	}

	/**
	 * Places Linux Malware Detect is installed in: the standard ones and
	 * "maldet" in every PATH folder.
	 *
	 * @return string[]
	 */
	private static function maldet_candidates() {
		$candidates = array( '/usr/local/maldetect/maldet', '/usr/local/sbin/maldet', '/usr/sbin/maldet', '/usr/bin/maldet', '/usr/local/bin/maldet' );
		$path       = (string) getenv( 'PATH' );
		foreach ( '' !== $path ? explode( PATH_SEPARATOR, $path ) : array() as $dir ) {
			$dir = trim( $dir );
			if ( '' !== $dir && '/' === $dir[0] ) {
				$candidates[] = rtrim( $dir, '/' ) . '/maldet';
			}
		}
		return array_values( array_unique( $candidates ) );
	}

	/**
	 * Whether PHP cannot tell if Linux Malware Detect is installed:
	 * open_basedir hides one of the places it is installed in (like
	 * clamav_hidden() for ClamAV).
	 *
	 * @return bool
	 */
	public static function maldet_hidden() {
		if ( '' !== self::maldet_detect() ) {
			return false;
		}
		foreach ( self::maldet_candidates() as $candidate ) {
			if ( ! self::path_allowed( $candidate ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Status of the antivirus engines for the settings card, the Dashboard
	 * and the wizard.
	 *
	 * clamav.state:
	 *   missing        no ClamAV binary found
	 *   blocked        installed, but PHP may not run programs
	 *   broken         installed, but no binary passed the self-test (label says why)
	 *   ready_off      ready to scan, "Also scan uploads with ClamAV" is off
	 *   slow           on, but only a slow clamscan works, so uploads skip it while someone waits
	 *   uploads        scans uploads (no background service: whole-site scans skip it)
	 *   uploads_scans  scans uploads and whole-site scans (clamd running)
	 *
	 * The self-test (Scanner::clamav_selftest()) scans the EICAR test file with
	 * every installed binary. Admin pages run it once when there is no result
	 * yet; afterwards it is refreshed in the background, by "Check again" and
	 * when a ClamAV setting changes.
	 *
	 * @return array { clamav: { state, label, tone, binary, exec, daemon, enabled, hint, hint_code, error, kind, daemon_ms, scan_ms, slow_only, tested, tested_at, bins }, maldet: { supported, binary, version, linked (bool|null), monitor (inotifywait found; null without maldet), label, tone } }
	 */
	public function antivirus_status() {
		$binary   = $this->clamav_detect();
		$exec     = self::function_available( 'exec' ) || self::function_available( 'proc_open' );
		$scanner  = self::service( 'scanner' );
		$info     = self::call( 'scanner', 'clamav_info', array(), array() );
		$info     = is_array( $info ) ? $info : array();
		if ( is_admin() && $scanner && method_exists( $scanner, 'clamav_selftest' ) && ! empty( $info['installed'] ) && empty( $info['tested'] ) ) {
			// First look at a site with ClamAV (or other binaries now): test it once, then use the cached result.
			$scanner->clamav_selftest( true );
			$info = (array) $scanner->clamav_info();
		}
		$ready    = ! empty( $info['available'] );
		$daemon   = $ready && ! empty( $info['daemon'] );
		$settings = self::service( 'settings' );
		$enabled  = $settings ? (bool) $settings->get( 'clamav_enabled', false ) : false;
		$test     = isset( $info['selftest'] ) && is_array( $info['selftest'] ) ? $info['selftest'] : null;
		$d_ms     = isset( $info['daemon_ms'] ) ? $info['daemon_ms'] : null;
		$s_ms     = isset( $info['scan_ms'] ) ? $info['scan_ms'] : null;
		$slow     = ! empty( $info['slow_only'] );
		$forced   = (bool) Network::get_option( Scanner::FORCE_SLOW_OPTION, false );
		$kind     = '';
		$error    = isset( $info['error'] ) ? (string) $info['error'] : '';
		if ( $test ) {
			foreach ( $test['bins'] as $row ) {
				if ( empty( $row['ok'] ) && '' !== (string) $row['kind'] ) {
					$kind = (string) $row['kind'];
					break;
				}
			}
		}
		$speed = '';
		if ( null !== $d_ms ) {
			/* translators: %s: time per file, for example "45 ms" */
			$speed = sprintf( __( 'background service, about %s per file', 'qartvelo-guard' ), self::duration_ms( $d_ms ) );
		} elseif ( null !== $s_ms ) {
			/* translators: %s: time per upload, for example "6.6 s" */
			$speed = sprintf( __( 'about %s per upload', 'qartvelo-guard' ), self::duration_ms( $s_ms ) );
		}

		$hidden = false;
		$hint   = '';
		$code   = '';
		if ( '' === $binary && empty( $info['installed'] ) ) {
			$state  = 'missing';
			$hidden = self::clamav_hidden();
			$label  = $hidden ? __( 'Unknown (hosting hides it)', 'qartvelo-guard' ) : __( 'Not installed', 'qartvelo-guard' );
			$tone   = 'muted';
		} elseif ( ! $exec || empty( $info['installed'] ) ) {
			$state = 'blocked';
			$label = $exec ? __( 'Installed, cannot run', 'qartvelo-guard' ) : __( 'Installed, PHP cannot run it', 'qartvelo-guard' );
			$tone  = 'medium';
		} elseif ( ! $ready ) {
			$state = 'broken';
			/* translators: %s: error message */
			$label = '' !== $error ? sprintf( __( 'Installed, not working: %s', 'qartvelo-guard' ), $error ) : __( 'Installed, not working', 'qartvelo-guard' );
			$tone  = 'high';
			list( $hint, $code ) = self::clamav_fix_hint( $kind );
		} elseif ( $slow ) {
			$state = $enabled ? ( $forced ? 'uploads' : 'slow' ) : 'ready_off';
			/* translators: %s: time per upload, for example "6.6 s" */
			$label = sprintf( __( 'Works, but slow: no background service (about %s per upload)', 'qartvelo-guard' ), self::duration_ms( $s_ms ) );
			$tone  = $enabled && $forced ? 'ok' : 'medium';
			$hint  = $forced
				? __( 'Uploads wait for clamscan because "Also use the slow clamscan for uploads" is on. Start clamd for fast scans:', 'qartvelo-guard' )
				: __( 'Uploads are not scanned with it while someone waits; held uploads the early guard imports by cron are. Start clamd for fast scans:', 'qartvelo-guard' );
			$code  = self::clamd_start_command();
			if ( 'not_running' !== $kind && '' !== $kind ) {
				list( $hint, $code ) = self::clamav_fix_hint( $kind );
			}
		} elseif ( ! $enabled ) {
			$state = 'ready_off';
			$label = '' !== $speed
				/* translators: %s: speed, for example "background service, about 45 ms per file" */
				? sprintf( __( 'Ready (%s)', 'qartvelo-guard' ), $speed )
				: __( 'Ready, not in use', 'qartvelo-guard' );
			$tone  = 'medium';
		} elseif ( $daemon ) {
			$state = 'uploads_scans';
			$label = '' !== $speed
				/* translators: %s: speed, for example "background service, about 45 ms per file" */
				? sprintf( __( 'In use for uploads and scans (%s)', 'qartvelo-guard' ), $speed )
				: __( 'In use for uploads and scans', 'qartvelo-guard' );
			$tone  = 'ok';
		} else {
			$state = 'uploads';
			$label = '' !== $speed
				/* translators: %s: speed, for example "about 1.2 s per upload" */
				? sprintf( __( 'In use for uploads (%s)', 'qartvelo-guard' ), $speed )
				: __( 'In use for uploads', 'qartvelo-guard' );
			$tone  = 'ok';
		}
		if ( ! $daemon && '' === $hint && in_array( $state, array( 'uploads', 'ready_off' ), true ) ) {
			$hint = __( 'Start clamd so whole-site scans can use ClamAV too:', 'qartvelo-guard' );
			$code = self::clamd_start_command();
		}
		$clam_info = array(
			'error'     => $error,
			'kind'      => $kind,
			'hint'      => $hint,
			'hint_code' => $code,
			'daemon_ms' => $d_ms,
			'scan_ms'   => $s_ms,
			'slow_only' => $slow,
			'forced'    => $forced,
			'tested'    => null !== $test,
			'tested_at' => $test ? (int) $test['at'] : 0,
			'bins'      => $test ? $test['bins'] : array(),
		);

		$maldet    = self::maldet_detect();
		$supported = 'Linux' === PHP_OS_FAMILY;
		$version   = '';
		$linked    = null;
		if ( '' !== $maldet ) {
			$real = @realpath( $maldet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$home = ( $real && @is_dir( dirname( $real ) . '/sigs' ) ) ? dirname( $real ) : '/usr/local/maldetect'; // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$file = $home . '/sigs/maldet.sigs.ver';
			if ( @is_readable( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$raw     = (string) @file_get_contents( $file, false, null, 0, 64 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				$version = preg_replace( '/[^0-9A-Za-z._-]/', '', (string) strtok( $raw . "\n", "\n" ) );
			}
			// maldet copies its signatures (rfxn.*) into ClamAV's database folder when it is linked.
			$seen = false;
			foreach ( array( '/var/lib/clamav', '/var/clamav', '/usr/local/share/clamav', '/usr/share/clamav', '/usr/local/var/lib/clamav', '/opt/homebrew/var/lib/clamav' ) as $db ) {
				if ( ! @is_dir( $db ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					continue;
				}
				$seen = true;
				foreach ( array( 'rfxn.ndb', 'rfxn.hdb', 'rfxn.yara' ) as $sig ) {
					if ( @is_file( $db . '/' . $sig ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
						$linked = true;
						break 2;
					}
				}
			}
			if ( null === $linked && $seen ) {
				$linked = false;
			}
		}
		$monitor  = '' !== $maldet ? self::inotifywait_installed() : null;
		$m_hidden = $supported && '' === $maldet && self::maldet_hidden();
		if ( '' !== $maldet && ! $monitor ) {
			$m_label = __( 'Installed, real-time monitor unavailable', 'qartvelo-guard' );
			$m_tone  = 'medium';
		} elseif ( '' !== $maldet ) {
			$m_label = __( 'Installed', 'qartvelo-guard' );
			$m_tone  = 'ok';
		} elseif ( $m_hidden ) {
			$m_label = __( 'Unknown (hosting hides it)', 'qartvelo-guard' );
			$m_tone  = 'muted';
		} elseif ( $supported ) {
			$m_label = __( 'Not installed', 'qartvelo-guard' );
			$m_tone  = 'muted';
		} else {
			$m_label = __( 'Linux only', 'qartvelo-guard' );
			$m_tone  = 'muted';
		}

		return array(
			'clamav' => array(
				'state'   => $state,
				'label'   => $label,
				'tone'    => $tone,
				'binary'  => ! empty( $info['binary'] ) ? wp_normalize_path( (string) $info['binary'] ) : $binary,
				'exec'    => $exec,
				'daemon'  => $daemon,
				'enabled' => $enabled,
				// state "missing" while open_basedir or disabled exec() hides the answer.
				'hidden'  => $hidden,
			) + $clam_info,
			'maldet' => array(
				'supported' => $supported,
				'binary'    => $maldet,
				'version'   => $version,
				'linked'    => $linked,
				'monitor'   => $monitor,
				'label'     => $m_label,
				'tone'      => $m_tone,
				// Not found while open_basedir hides where it would be installed.
				'hidden'    => $m_hidden,
			),
		);
	}

	/**
	 * @return array
	 */
	private function check_open_basedir() {
		$value = trim( (string) ini_get( 'open_basedir' ) );
		if ( '' === $value ) {
			return array(
				'id'     => 'open_basedir',
				'label'  => __( 'open_basedir', 'qartvelo-guard' ),
				'status' => 'info',
				'detail' => __( 'Not set. PHP can read every folder the web server user can read.', 'qartvelo-guard' ),
			);
		}
		$check = array(
			'id'     => 'open_basedir',
			'label'  => __( 'open_basedir', 'qartvelo-guard' ),
			'status' => 'pass',
			/* translators: %s: list of folders */
			'detail' => sprintf( __( 'PHP is restricted to: %s', 'qartvelo-guard' ), $value ),
		);
		$parent = dirname( self::abspath() );
		if ( ! @is_readable( $parent ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$check['status'] = 'info';
			$check['fix']    = __( 'The folder above WordPress cannot be read, so the "parent folder" scan scope is not available.', 'qartvelo-guard' );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_zip() {
		$ok = class_exists( 'ZipArchive' );
		return array(
			'id'     => 'zip',
			'label'  => __( 'ZipArchive', 'qartvelo-guard' ),
			'status' => $ok ? 'pass' : 'warn',
			'detail' => $ok
				? __( 'Plugin and theme ZIP files can be inspected before you approve them.', 'qartvelo-guard' )
				: __( 'The PHP zip extension is missing, so plugin and theme ZIP files cannot be inspected before approval.', 'qartvelo-guard' ),
			'fix'    => $ok ? '' : __( 'Ask your host to enable the PHP zip extension.', 'qartvelo-guard' ),
		);
	}

	/**
	 * @return array
	 */
	private function check_wp_config() {
		$file  = self::wp_config_path();
		$check = array(
			'id'    => 'wp_config_perms',
			'label' => __( 'wp-config.php permissions', 'qartvelo-guard' ),
		);
		if ( '' === $file ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'wp-config.php was not found in the usual places.', 'qartvelo-guard' );
			return $check;
		}
		if ( '\\' === DIRECTORY_SEPARATOR ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'File permissions cannot be checked on Windows servers.', 'qartvelo-guard' );
			return $check;
		}
		$perms = @fileperms( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $perms ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'The permissions of wp-config.php could not be read.', 'qartvelo-guard' );
			return $check;
		}
		$mode = substr( sprintf( '%o', $perms ), -4 );
		$cmd  = 'chmod 640 ' . self::shell_arg( $file );
		if ( $perms & 0002 ) {
			$check['status'] = 'fail';
			/* translators: %s: permission bits, e.g. 0666 */
			$check['detail'] = sprintf( __( 'wp-config.php is writable by every user on the server (%s).', 'qartvelo-guard' ), $mode );
			$check['fix']    = __( 'Restrict it (use 600 when PHP runs as the file owner):', 'qartvelo-guard' );
			$check['code']   = $cmd;
		} elseif ( $perms & 0004 ) {
			$check['status'] = 'warn';
			/* translators: %s: permission bits, e.g. 0644 */
			$check['detail'] = sprintf( __( 'wp-config.php is readable by every user on the server (%s). It holds the database password.', 'qartvelo-guard' ), $mode );
			$check['fix']    = __( 'Restrict it (use 600 when PHP runs as the file owner):', 'qartvelo-guard' );
			$check['code']   = $cmd;
		} else {
			$check['status'] = 'pass';
			/* translators: %s: permission bits, e.g. 0640 */
			$check['detail'] = sprintf( __( 'Not readable by other users (%s).', 'qartvelo-guard' ), $mode );
		}
		return $check;
	}

	/**
	 * Code folders and files that every user of the server may write (mode
	 * o+w): any other account, a hacked site next door or a service user can
	 * then plant code that this site runs. wp-config.php has its own check.
	 *
	 * @return array
	 */
	private function check_world_writable() {
		$check = array(
			'id'    => 'world_writable',
			'label' => __( 'Code folders other users can write to', 'qartvelo-guard' ),
		);
		$scan = self::world_writable_scan();
		if ( null === $scan ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'File permissions cannot be checked on Windows servers.', 'qartvelo-guard' );
			return $check;
		}
		if ( ! $scan['checked'] ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'The code folders could not be checked here (open_basedir hides them).', 'qartvelo-guard' );
			return $check;
		}
		if ( ! $scan['paths'] ) {
			$check['status'] = 'pass';
			/* translators: %s: number of folders and files */
			$check['detail'] = sprintf( __( 'No code folder can be written by every user of the server (%s folders and files checked).', 'qartvelo-guard' ), number_format_i18n( $scan['checked'] ) );
			return $check;
		}
		$count           = count( $scan['paths'] );
		$check['status'] = 'fail';
		$check['detail'] = sprintf(
			/* translators: 1: number of folders and files, 2: example paths */
			_n(
				'%1$s folder or file of the site\'s code can be written by every user of the server (mode o+w): %2$s. Any other account or service on the server can put code there that this site then runs.',
				'%1$s folders and files of the site\'s code can be written by every user of the server (mode o+w), for example %2$s. Any other account or service on the server can put code there that this site then runs.',
				$count,
				'qartvelo-guard'
			),
			number_format_i18n( $count ) . ( $scan['truncated'] ? '+' : '' ),
			implode( ', ', array_map( array( __CLASS__, 'display_path' ), array_slice( $scan['paths'], 0, 3 ) ) )
		);
		$check['signals'] = array_map( array( __CLASS__, 'display_path' ), array_slice( $scan['paths'], 0, 20 ) );
		$check['fix']     = __( 'Remove write access for other users (it changes nothing for the owner and the web server):', 'qartvelo-guard' );
		$check['code']    = self::world_writable_command( $scan['roots'] );
		return $check;
	}

	/**
	 * The folders world_writable_scan() looks at: { path, children }.
	 * children = also the entries one level below (the WordPress folder, wp-content,
	 * plugin and theme folders).
	 *
	 * @return array[]
	 */
	public static function world_writable_roots() {
		$abs    = self::abspath();
		$themes = function_exists( 'get_theme_root' ) ? (string) get_theme_root() : WP_CONTENT_DIR . '/themes';
		$roots  = array(
			array( WPCYBERSEC_DIR, false ),
			// wp-content and the WordPress folder with one level of entries: languages
			// (PHP translation files since 6.5), upgrade, uploads and backup folders, and
			// another WordPress install in a subfolder. Removing the write bit for other
			// users is safe for all of them: the owner (PHP on per-site hosting) keeps it.
			array( WP_CONTENT_DIR, true ),
			array( WP_PLUGIN_DIR, true ),
			array( $themes, true ),
			array( defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins', false ),
			array( $abs, true ),
			array( $abs . '/wp-admin', false ),
			array( $abs . '/' . WPINC, false ),
		);
		$out  = array();
		$seen = array();
		foreach ( $roots as $root ) {
			$path = untrailingslashit( wp_normalize_path( (string) $root[0] ) );
			if ( '' === $path || isset( $seen[ $path ] ) ) {
				continue;
			}
			$seen[ $path ] = true;
			$out[]         = array(
				'path'     => $path,
				'children' => (bool) $root[1],
			);
		}
		return $out;
	}

	/**
	 * Finds code folders and files with the write bit for other users: each
	 * folder of world_writable_roots() itself, plus one level of entries in the
	 * plugin and theme folders. Never follows symlinks (lstat), never looks
	 * outside open_basedir, stops after $cap entries.
	 *
	 * @param int $cap Entries looked at, at most.
	 * @return array|null { paths: string[], roots: string[] (folders with a finding), checked, truncated }; null on Windows.
	 */
	public static function world_writable_scan( $cap = 500 ) {
		if ( '\\' === DIRECTORY_SEPARATOR ) {
			return null;
		}
		$result = array(
			'paths'     => array(),
			'roots'     => array(),
			'checked'   => 0,
			'truncated' => false,
		);
		$add = static function ( $path, $root ) use ( &$result ) {
			if ( ! in_array( $path, $result['paths'], true ) ) {
				$result['paths'][] = $path;
			}
			if ( ! in_array( $root, $result['roots'], true ) ) {
				$result['roots'][] = $root;
			}
		};
		foreach ( self::world_writable_roots() as $root ) {
			$dir = $root['path'];
			if ( $result['checked'] >= $cap ) {
				$result['truncated'] = true;
				break;
			}
			$mode = self::lmode( $dir );
			if ( null === $mode || 0120000 === ( $mode & 0170000 ) ) {
				continue; // Missing, hidden by open_basedir, or a symlink: never followed.
			}
			++$result['checked'];
			if ( $mode & 0002 ) {
				$add( $dir, $dir );
			}
			if ( ! $root['children'] || 0040000 !== ( $mode & 0170000 ) ) {
				continue;
			}
			$handle = @opendir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! $handle ) {
				continue;
			}
			while ( false !== ( $entry = readdir( $handle ) ) ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				if ( $result['checked'] >= $cap ) {
					$result['truncated'] = true;
					break;
				}
				$path = $dir . '/' . $entry;
				$mode = self::lmode( $path );
				if ( null === $mode || 0120000 === ( $mode & 0170000 ) ) {
					continue;
				}
				++$result['checked'];
				if ( $mode & 0002 ) {
					$add( $path, $dir );
				}
			}
			closedir( $handle );
		}
		return $result;
	}

	/**
	 * Mode of a path itself (a symlink is not followed), null when it cannot be read.
	 *
	 * @param string $path Path.
	 * @return int|null
	 */
	private static function lmode( $path ) {
		if ( ! self::path_allowed( $path ) ) {
			return null;
		}
		$stat = @lstat( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return is_array( $stat ) && isset( $stat['mode'] ) ? (int) $stat['mode'] : null;
	}

	/**
	 * The safe shell command that removes the write bit for other users below
	 * these folders (symlinks are skipped, nothing else changes).
	 *
	 * @param string[] $roots Folders.
	 * @return string
	 */
	public static function world_writable_command( array $roots ) {
		$lines = array();
		foreach ( $roots as $root ) {
			foreach ( $roots as $other ) {
				if ( $other !== $root && 0 === strpos( $root . '/', rtrim( $other, '/' ) . '/' ) ) {
					continue 2; // find walks $other recursively, which covers this folder.
				}
			}
			$lines[] = 'find ' . self::shell_arg( $root ) . ' -perm -o+w -not -type l -exec chmod o-w {} +';
		}
		return implode( "\n", $lines );
	}

	/**
	 * A path for messages: relative to the WordPress folder when inside it.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	public static function display_path( $path ) {
		$abs  = self::abspath();
		$path = wp_normalize_path( (string) $path );
		if ( $path === $abs ) {
			return $abs . '/';
		}
		return 0 === strpos( $path, $abs . '/' ) ? substr( $path, strlen( $abs ) + 1 ) : $path;
	}

	/**
	 * @return array
	 */
	private function check_file_edit() {
		$off = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		return array(
			'id'     => 'file_edit',
			'label'  => __( 'Theme and plugin file editor', 'qartvelo-guard' ),
			'status' => $off ? 'pass' : 'warn',
			'detail' => $off
				? __( 'The built-in code editor is disabled.', 'qartvelo-guard' )
				: __( 'The built-in code editor is enabled. Anyone who steals an administrator login can use it to plant code.', 'qartvelo-guard' ),
			'fix'    => $off ? '' : __( 'Add this line to wp-config.php:', 'qartvelo-guard' ),
			'code'   => $off ? '' : "define( 'DISALLOW_FILE_EDIT', true );",
		);
	}

	/**
	 * Hosting panel the instructions follow (Hosting::current()).
	 *
	 * @param bool $fresh Detect again.
	 * @return array|null
	 */
	private function check_hosting( $fresh = false ) {
		$hosting = self::service( 'hosting' );
		if ( ! $hosting || ! method_exists( $hosting, 'current' ) ) {
			return null;
		}
		$info = $hosting->current( $fresh );
		return array(
			'id'      => 'hosting',
			'label'   => __( 'Hosting', 'qartvelo-guard' ),
			'status'  => 'info',
			'detail'  => $hosting->label( $info ) . '. ' . $hosting->confidence_text( $info ),
			'signals' => isset( $info['signals'] ) ? (array) $info['signals'] : array(),
			'link'    => array(
				'url'   => Hosting::change_url(),
				'label' => __( 'Change the hosting panel', 'qartvelo-guard' ),
			),
		);
	}

	/**
	 * @return array
	 */
	private function check_server() {
		$soft  = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '';
		$type  = self::server_type();
		$names = array(
			'apache'    => 'Apache',
			'litespeed' => 'LiteSpeed',
			'nginx'     => 'nginx',
			'iis'       => 'IIS',
			'unknown'   => __( 'Unknown', 'qartvelo-guard' ),
		);
		$check = array(
			'id'     => 'server',
			'label'  => __( 'Web server', 'qartvelo-guard' ),
			'status' => 'info',
			/* translators: 1: server name, 2: PHP SAPI */
			'detail' => sprintf( __( '%1$s, PHP runs as %2$s.', 'qartvelo-guard' ), $soft ? $soft : $names[ $type ], PHP_SAPI ),
		);
		if ( 'nginx' === $type ) {
			$check['fix'] = __( 'nginx ignores .htaccess files. Copy the nginx rules from Settings > Advanced into the server configuration.', 'qartvelo-guard' );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all      = get_plugins();
		$active   = (array) get_option( 'active_plugins', array() );
		$network  = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		$active   = array_unique( array_merge( $active, $network ) );
		$total    = count( $all );
		$on       = count( array_intersect( array_keys( $all ), $active ) );
		$inactive = max( 0, $total - $on );
		$check    = array(
			'id'     => 'plugins',
			'label'  => __( 'Installed plugins', 'qartvelo-guard' ),
			'status' => 'info',
			/* translators: 1: installed plugins, 2: active plugins */
			'detail' => sprintf( _n( '%1$d plugin installed, %2$d active.', '%1$d plugins installed, %2$d active.', $total, 'qartvelo-guard' ), $total, $on ),
		);
		if ( $inactive > 0 ) {
			$check['fix'] = __( 'Delete inactive plugins you do not need: their files stay on the server and can still be attacked.', 'qartvelo-guard' );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_security_plugins() {
		$known  = array(
			'wordfence'                          => 'Wordfence',
			'sucuri-scanner'                     => 'Sucuri Security',
			'better-wp-security'                 => 'Solid Security (iThemes)',
			'ithemes-security-pro'               => 'Solid Security Pro',
			'all-in-one-wp-security-and-firewall' => 'All-In-One Security (AIOS)',
			'wp-simple-firewall'                 => 'Shield Security',
			'malcare-security'                   => 'MalCare',
			'defender-security'                  => 'Defender',
			'ninjafirewall'                      => 'NinjaFirewall',
		);
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		$found = array();
		foreach ( $active as $basename ) {
			$folder = strtok( (string) $basename, '/' );
			if ( isset( $known[ $folder ] ) ) {
				$found[ $folder ] = $known[ $folder ];
			}
		}
		$check = array(
			'id'     => 'security_plugins',
			'label'  => __( 'Other security plugins', 'qartvelo-guard' ),
			'status' => 'info',
		);
		if ( $found ) {
			/* translators: %s: plugin names */
			$check['detail'] = sprintf( __( 'Active: %s. They can run side by side with Qartvelo Guard.', 'qartvelo-guard' ), implode( ', ', $found ) );
			$check['fix']    = __( 'If both scan uploads, uploading can take a little longer. Avoid two plugins changing the same .htaccess rules.', 'qartvelo-guard' );
		} else {
			$check['detail'] = __( 'None detected.', 'qartvelo-guard' );
		}
		return $check;
	}

	/**
	 * @param string $function Function name.
	 * @return bool
	 */
	public static function function_available( $function ) {
		if ( ! function_exists( $function ) ) {
			return false;
		}
		$disabled = array_map( 'trim', explode( ',', strtolower( (string) ini_get( 'disable_functions' ) ) ) );
		return ! in_array( strtolower( $function ), $disabled, true );
	}

	/**
	 * "45 ms" below a second, else "6.6 s".
	 *
	 * @param int|null $ms Milliseconds.
	 * @return string
	 */
	public static function duration_ms( $ms ) {
		$ms = max( 0, (int) $ms );
		if ( $ms < 1000 ) {
			/* translators: %s: number of milliseconds */
			return sprintf( __( '%s ms', 'qartvelo-guard' ), number_format_i18n( max( 1, $ms ) ) );
		}
		/* translators: %s: number of seconds */
		return sprintf( __( '%s s', 'qartvelo-guard' ), number_format_i18n( $ms / 1000, 1 ) );
	}

	/**
	 * Command that starts the ClamAV background service on this server.
	 *
	 * @return string
	 */
	public static function clamd_start_command() {
		if ( @is_dir( '/usr/local/cpanel' ) && self::path_allowed( '/usr/local/cpanel' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return '/scripts/restartsrv_clamd';
		}
		switch ( Admin\Clamav_Guide::platform() ) {
			case 'macos':
				return 'brew services start clamav';
			case 'rhel':
				return 'sudo systemctl enable --now clamd@scan';
			case 'debian':
				return 'sudo systemctl enable --now clamav-daemon';
		}
		return '\\' === DIRECTORY_SEPARATOR ? 'sc start clamd' : 'sudo systemctl enable --now clamav-daemon';
	}

	/**
	 * What to do about a failed ClamAV self-test.
	 *
	 * @param string $kind Scanner error kind (socket, not_running, config, nodb, nodetect, timeout, other).
	 * @return array [ text, command ]
	 */
	public static function clamav_fix_hint( $kind ) {
		$platform = Admin\Clamav_Guide::platform();
		switch ( $kind ) {
			case 'socket':
				$user = function_exists( 'posix_getpwuid' ) && function_exists( 'posix_geteuid' ) ? @posix_getpwuid( posix_geteuid() ) : null; // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$user = is_array( $user ) && ! empty( $user['name'] ) ? $user['name'] : 'www-data';
				return array(
					__( 'Let the PHP user use the clamd socket: add it to the clamav group and restart PHP (or set LocalSocketMode 666 in clamd.conf and restart clamd).', 'qartvelo-guard' ),
					'sudo usermod -a -G clamav ' . $user,
				);
			case 'config':
				if ( 'macos' === $platform ) {
					return array(
						__( 'clamd.conf cannot be read. Create it from the sample, remove the line that says "Example", set LocalSocket, then start the service:', 'qartvelo-guard' ),
						"cp \"$(brew --prefix)/etc/clamav/clamd.conf.sample\" \"$(brew --prefix)/etc/clamav/clamd.conf\"\nbrew services start clamav",
					);
				}
				return array( __( 'clamd.conf cannot be read. Fix the file it names (remove the line that says "Example"), then start the service:', 'qartvelo-guard' ), self::clamd_start_command() );
			case 'nodb':
			case 'nodetect':
				return array( __( 'Download the virus database, then press "Check again":', 'qartvelo-guard' ), 'macos' === $platform ? 'freshclam' : 'sudo freshclam' );
			case 'timeout':
				return array( __( 'ClamAV took too long. Start its background service so each file takes milliseconds instead of seconds:', 'qartvelo-guard' ), self::clamd_start_command() );
			case 'not_running':
				return array( __( 'The background service (clamd) is not running. Start it:', 'qartvelo-guard' ), self::clamd_start_command() );
		}
		return array( __( 'Check the message above on the server, then press "Check again".', 'qartvelo-guard' ), '' );
	}

	/**
	 * Finds a ClamAV binary (configured one first).
	 *
	 * @return string Path or ''.
	 */
	public function clamav_detect() {
		$settings   = self::service( 'settings' );
		$configured = $settings ? (string) $settings->get( 'clamav_binary', '' ) : '';
		$candidates = array_filter( array_merge( array( $configured ), Scanner::clamav_candidates() ) );
		foreach ( $candidates as $candidate ) {
			if ( self::path_allowed( $candidate ) && @is_file( $candidate ) && @is_executable( $candidate ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return wp_normalize_path( $candidate );
			}
		}
		return '';
	}

	/**
	 * Whether PHP cannot tell if ClamAV is installed: open_basedir hides the
	 * folders it is installed in, or PHP may not run programs (so it cannot
	 * look it up in PATH either).
	 *
	 * @return bool
	 */
	public static function clamav_hidden() {
		if ( ! self::function_available( 'exec' ) && ! self::function_available( 'proc_open' ) ) {
			return true;
		}
		foreach ( Scanner::clamav_candidates() as $candidate ) {
			if ( ! self::path_allowed( $candidate ) ) {
				return true;
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* Live web probes                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $key Probe key.
	 * @return array|null
	 */
	private function cached_probe( $key ) {
		$all = Network::get_transient( self::PROBE_TRANSIENT );
		return ( is_array( $all ) && isset( $all[ $key ] ) && is_array( $all[ $key ] ) ) ? $all[ $key ] : null;
	}

	/**
	 * @param string $key    Probe key.
	 * @param array  $result Result.
	 */
	private function cache_probe( $key, array $result ) {
		$all         = Network::get_transient( self::PROBE_TRANSIENT );
		$all         = is_array( $all ) ? $all : array();
		$all[ $key ] = $result;
		Network::set_transient( self::PROBE_TRANSIENT, $all, HOUR_IN_SECONDS );
	}

	/**
	 * Absolute URL of a path under the WordPress or content folder, or ''.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private static function url_for_path( $path ) {
		$path    = wp_normalize_path( $path );
		$content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
		if ( 0 === strpos( $path . '/', $content . '/' ) ) {
			return content_url( ltrim( substr( $path, strlen( $content ) ), '/' ) );
		}
		$abs = self::abspath();
		if ( 0 === strpos( $path . '/', $abs . '/' ) ) {
			return site_url( ltrim( substr( $path, strlen( $abs ) ), '/' ) );
		}
		return '';
	}

	/**
	 * Writes a temporary file, requests it over HTTP and deletes it again.
	 *
	 * @param string $file    Absolute file path.
	 * @param string $url     URL of that file.
	 * @param string $content Content.
	 * @return array { code: int, body: string, error: string }
	 */
	private function http_probe( $file, $url, $content ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === @file_put_contents( $file, $content ) ) {
			return array(
				'code'  => 0,
				'body'  => '',
				'error' => __( 'Could not write a test file.', 'qartvelo-guard' ),
			);
		}
		Fs::chmod( $file, 0644 );
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 4,
				'redirection' => 0,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core filter, same as wp-cron uses for loopback requests.
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		Fs::delete( $file );
		if ( is_wp_error( $response ) ) {
			return array(
				'code'  => 0,
				'body'  => '',
				'error' => $response->get_error_message(),
			);
		}
		return array(
			'code'  => (int) wp_remote_retrieve_response_code( $response ),
			'body'  => (string) wp_remote_retrieve_body( $response ),
			'error' => '',
		);
	}

	/**
	 * Control request for the live probes: a static file of this plugin that
	 * every server serves. When it does not load either, a refused test file
	 * proves nothing (HTTP password on staging, a firewall answering 403 to
	 * the site's own requests, a blocked loopback).
	 *
	 * @return bool True when the control file answered 200.
	 */
	private function control_reachable() {
		static $ok = null;
		if ( null !== $ok ) {
			return $ok;
		}
		$response = wp_remote_get(
			add_query_arg( 'wpcs', strtolower( wp_generate_password( 8, false, false ) ), WPCYBERSEC_URL . 'assets/css/base.css' ),
			array(
				'timeout'     => 4,
				'redirection' => 0,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core filter, same as wp-cron uses for loopback requests.
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		$ok = ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response );
		return $ok;
	}

	/**
	 * Tests whether files in the quarantine folder can be downloaded.
	 *
	 * @param bool $fresh Ignore the cached result.
	 * @return array { result: outside|blocked|reachable|unknown, code, message, time }
	 */
	public function probe_quarantine_web( $fresh = false ) {
		if ( ! $fresh ) {
			$cached = $this->cached_probe( 'quarantine_web' );
			if ( $cached ) {
				return $cached;
			}
		}
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$result  = array(
			'result'  => 'unknown',
			'code'    => 0,
			'message' => '',
			'time'    => time(),
		);
		if ( ! $storage->is_in_webroot( $storage->data_dir() ) ) {
			$result['result'] = 'outside';
			$this->cache_probe( 'quarantine_web', $result );
			return $result;
		}
		$storage->ensure();
		$dir = $storage->quarantine_dir();
		$url = self::url_for_path( $dir );
		if ( '' === $url || ! is_dir( $dir ) ) {
			$result['message'] = __( 'The data folder is inside the web root but its address could not be worked out, so web access was not tested.', 'qartvelo-guard' );
			$this->cache_probe( 'quarantine_web', $result );
			return $result;
		}
		$token = 'wpcs-' . wp_generate_password( 24, false, false );
		$name  = 'wpcs-probe-' . strtolower( wp_generate_password( 12, false, false ) ) . '.txt';
		$probe = $this->http_probe( $dir . '/' . $name, trailingslashit( $url ) . $name, $token );
		if ( $probe['error'] ) {
			/* translators: %s: error message */
			$result['message'] = sprintf( __( 'Could not test web access: the site could not reach itself (%s).', 'qartvelo-guard' ), $probe['error'] );
		} elseif ( 200 === $probe['code'] && false !== strpos( $probe['body'], $token ) ) {
			$result['result'] = 'reachable';
			$result['code']   = 200;
		} elseif ( $probe['code'] >= 400 && $this->control_reachable() ) {
			$result['result'] = 'blocked';
			$result['code']   = $probe['code'];
		} elseif ( $probe['code'] >= 400 ) {
			// A public file is refused too: an HTTP password, a firewall or a
			// blocked loopback answered, not the deny rules. Nothing was proven.
			$result['code'] = $probe['code'];
			/* translators: %d: HTTP status code */
			$result['message'] = sprintf( __( 'Could not test web access: the test file was refused (HTTP %d), but so was a file that is always public, so an HTTP password, a firewall or the host blocks the site\'s requests to itself.', 'qartvelo-guard' ), $probe['code'] );
		} else {
			/* translators: %d: HTTP status code */
			$result['message'] = sprintf( __( 'Web access test was inconclusive (HTTP %d).', 'qartvelo-guard' ), $probe['code'] );
		}
		$this->cache_probe( 'quarantine_web', $result );
		return $result;
	}

	/**
	 * Live test: does a PHP file in the uploads folder execute? Only run on request.
	 * The test file prints a reversed token, so served-as-text and executed are
	 * told apart, and it is deleted immediately.
	 *
	 * @return array { result: executed|blocked|unknown, code, message, time }
	 */
	public function probe_uploads_php() {
		$result  = array(
			'result'  => 'unknown',
			'code'    => 0,
			'message' => '',
			'time'    => time(),
		);
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) || ! is_dir( $uploads['basedir'] ) ) {
			$result['message'] = __( 'The uploads folder could not be found.', 'qartvelo-guard' );
			$this->cache_probe( 'uploads_php', $result );
			return $result;
		}
		$token = 'wpcs' . strtolower( wp_generate_password( 20, false, false ) );
		$name  = 'wpcs-probe-' . strtolower( wp_generate_password( 12, false, false ) ) . '.php';
		$code  = "<?php\n// Qartvelo Guard temporary test file. Safe to delete.\necho strrev( '" . strrev( $token ) . "' );\n";
		$file  = trailingslashit( wp_normalize_path( $uploads['basedir'] ) ) . $name;
		register_shutdown_function(
			static function () use ( $file ) {
				if ( file_exists( $file ) ) {
					Fs::delete( $file );
				}
			}
		);
		$probe = $this->http_probe( $file, trailingslashit( $uploads['baseurl'] ) . $name, $code );
		if ( $probe['error'] ) {
			/* translators: %s: error message */
			$result['message'] = sprintf( __( 'The live test could not run: %s', 'qartvelo-guard' ), $probe['error'] );
		} elseif ( 200 === $probe['code'] && $token === trim( $probe['body'] ) ) {
			$result['result'] = 'executed';
			$result['code']   = 200;
		} elseif ( 200 === $probe['code'] || $this->control_reachable() ) {
			$result['result'] = 'blocked'; // Served without running, or refused while public files load.
			$result['code']   = $probe['code'];
		} else {
			$result['code'] = $probe['code'];
			/* translators: %d: HTTP status code */
			$result['message'] = sprintf( __( 'The live test could not run: the test file was refused (HTTP %d), but so was a file that is always public, so an HTTP password, a firewall or the host blocks the site\'s requests to itself.', 'qartvelo-guard' ), $probe['code'] );
		}
		$this->cache_probe( 'uploads_php', $result );
		return $result;
	}

	/* ------------------------------------------------------------------ */
	/* Uploads .htaccess                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * @return string Absolute uploads folder ('' when unknown).
	 */
	private static function uploads_dir() {
		// Multisite: the main site's uploads folder holds every site's (sites/<id>/).
		$uploads = Network::on_main(
			static function () {
				return wp_upload_dir( null, false );
			}
		);
		return empty( $uploads['basedir'] ) ? '' : untrailingslashit( wp_normalize_path( $uploads['basedir'] ) );
	}

	/**
	 * What protects the uploads folder on Apache.
	 *
	 * @return string ours | other | none.
	 */
	public function uploads_htaccess_status() {
		$dir = self::uploads_dir();
		if ( '' === $dir || ! is_readable( $dir . '/.htaccess' ) ) {
			return 'none';
		}
		$content = (string) @file_get_contents( $dir . '/.htaccess' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( false !== strpos( $content, '# BEGIN ' . self::MARKER ) || false !== strpos( $content, '# BEGIN ' . self::LEGACY_MARKER . "\n" ) || false !== strpos( $content, '# BEGIN ' . self::LEGACY_MARKER . "\r" ) ) {
			return 'ours';
		}
		if ( preg_match( '/php_flag\s+engine\s+off|<Files(Match)?\s[^>]*php[^>]*>\s*(Require\s+all\s+denied|deny\s+from\s+all|Order)/i', $content ) ) {
			return 'other';
		}
		return 'none';
	}

	/**
	 * Apache rules that stop PHP from running in the uploads folder, wrapped in
	 * the plugin's markers. Works on Apache 2.2 and 2.4, mod_php and PHP-FPM.
	 *
	 * @return string
	 */
	public function apache_uploads_rules() {
		$lines = array(
			'# BEGIN ' . self::MARKER,
			'# Blocks PHP execution in the uploads folder. Remove this block to undo.',
			'<FilesMatch "\.(?i:php[0-9]?|phtml|phar|pht|phps)(\.|$)|\.(?i:inc)$">',
			"\t<IfModule mod_authz_core.c>",
			"\t\tRequire all denied",
			"\t</IfModule>",
			"\t<IfModule !mod_authz_core.c>",
			"\t\tOrder allow,deny",
			"\t\tDeny from all",
			"\t</IfModule>",
			'</FilesMatch>',
			'<IfModule mod_php.c>',
			"\tphp_flag engine off",
			'</IfModule>',
			'<IfModule mod_php7.c>',
			"\tphp_flag engine off",
			'</IfModule>',
			'<IfModule mod_php5.c>',
			"\tphp_flag engine off",
			'</IfModule>',
			'# END ' . self::MARKER,
		);
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Replaces the plugin's marked block (all copies) with $block, or appends it.
	 *
	 * @param string $content Existing file content.
	 * @param string $block   New block including markers.
	 * @return string
	 */
	public static function replace_marked_block( $content, $block ) {
		// A block written before 1.1.0 is replaced too.
		$legacy  = '/^[ \t]*# BEGIN ' . preg_quote( self::LEGACY_MARKER, '/' ) . '[ \t]*\R.*?^[ \t]*# END ' . preg_quote( self::LEGACY_MARKER, '/' ) . '[ \t]*(\R|\z)/ms';
		$content = (string) preg_replace( $legacy, '', (string) $content );
		$pattern = '/^[ \t]*# BEGIN ' . preg_quote( self::MARKER, '/' ) . '[ \t]*\R.*?^[ \t]*# END ' . preg_quote( self::MARKER, '/' ) . '[ \t]*(\R|\z)/ms';
		if ( ! preg_match( $pattern, $content ) ) {
			return '' === trim( $content ) ? $block : rtrim( $content, "\r\n" ) . "\n\n" . $block;
		}
		$first = false;
		return preg_replace_callback(
			$pattern,
			static function () use ( &$first, $block ) {
				if ( $first ) {
					return '';
				}
				$first = true;
				return $block;
			},
			$content
		);
	}

	/**
	 * Adds (or refreshes) the PHP blocking block in wp-content/uploads/.htaccess.
	 * Idempotent: never duplicates the block and keeps all other content. When
	 * the server answers 500 afterwards (directives not allowed), the previous
	 * file is put back.
	 *
	 * @return string|\WP_Error "written" or "unchanged".
	 */
	public function write_uploads_htaccess() {
		if ( 'nginx' === self::server_type() ) {
			// nginx never reads .htaccess: writing one would only look like a fix.
			return new \WP_Error(
				'wpcybersec_htaccess_nginx',
				/* translators: %s: nginx rule */
				sprintf( __( 'This server runs nginx, which ignores .htaccess files, so nothing was written. Add this rule to the site\'s nginx server block and reload nginx (or ask your host): %s', 'qartvelo-guard' ), self::nginx_uploads_rule() )
			);
		}
		$dir = self::uploads_dir();
		if ( '' === $dir ) {
			return new \WP_Error( 'wpcybersec_uploads', __( 'The uploads folder could not be found.', 'qartvelo-guard' ) );
		}
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'wpcybersec_uploads', __( 'The uploads folder does not exist and could not be created.', 'qartvelo-guard' ) );
		}
		$file   = $dir . '/.htaccess';
		$exists = file_exists( $file );
		if ( $exists && ( is_link( $file ) || ! is_file( $file ) ) ) {
			return new \WP_Error( 'wpcybersec_htaccess', __( 'uploads/.htaccess is not a regular file. Add the rules by hand.', 'qartvelo-guard' ) );
		}
		$old = $exists ? @file_get_contents( $file ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( false === $old ) {
			return new \WP_Error( 'wpcybersec_htaccess', __( 'uploads/.htaccess exists but cannot be read. Add the rules by hand.', 'qartvelo-guard' ) );
		}
		$new = self::replace_marked_block( (string) $old, $this->apache_uploads_rules() );
		if ( $new === $old ) {
			return $this->verify_uploads_block( null );
		}
		/*
		 * .htaccess is an executable name, so the file monitor reports (or, in
		 * strict mode, quarantines) any change it did not see coming. The new
		 * content is trusted only when everything in it was already trusted: a
		 * new file holds nothing but this block, an existing one must match the
		 * trusted fingerprint. Unreviewed content stays up for review.
		 */
		$old_trusted = $exists && self::manifest_trusts( $file, (string) $old );
		$trust_new   = ! $exists || $old_trusted;
		if ( ( $exists && ! wp_is_writable( $file ) ) || ( ! $exists && ! wp_is_writable( $dir ) ) ) {
			return new \WP_Error( 'wpcybersec_htaccess', __( 'uploads/.htaccess is not writable. Copy the rules from Settings > Advanced and add them by hand.', 'qartvelo-guard' ) );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === @file_put_contents( $file, $new, LOCK_EX ) ) {
			return new \WP_Error( 'wpcybersec_htaccess', __( 'Could not write uploads/.htaccess. Check the file permissions.', 'qartvelo-guard' ) );
		}
		Fs::chmod( $file, 0644 );

		/*
		 * Make sure normal files in uploads still load. Apache answers 500 for
		 * every file in the folder when AllowOverride does not permit these
		 * directives, so the change is undone unless a test file still loads.
		 */
		$uploads = wp_upload_dir( null, false );
		if ( in_array( self::server_type(), array( 'apache', 'litespeed', 'unknown' ), true ) ) {
			$rollback = static function () use ( $exists, $file, $old, $old_trusted ) {
				if ( $exists ) {
					@file_put_contents( $file, $old, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
					// Same bytes as before, new mtime: refresh the fingerprint so the next scan skips it.
					if ( $old_trusted ) {
						self::call( 'file_monitor', 'trust_file', array( $file ) );
					}
				} else {
					Fs::delete( $file );
				}
			};
			if ( empty( $uploads['baseurl'] ) ) {
				$rollback();
				return new \WP_Error( 'wpcybersec_htaccess_unverified', __( 'The address of the uploads folder is unknown, so the rules could not be checked and nothing was changed. Add them by hand from Settings > Advanced.', 'qartvelo-guard' ) );
			}
			$name  = 'wpcs-probe-' . strtolower( wp_generate_password( 12, false, false ) ) . '.txt';
			$probe = $this->http_probe( $dir . '/' . $name, trailingslashit( $uploads['baseurl'] ) . $name, 'ok' );
			if ( $probe['error'] ) {
				$rollback();
				return new \WP_Error(
					'wpcybersec_htaccess_unverified',
					/* translators: %s: error message */
					sprintf( __( 'The site could not reach itself to check that uploads still load after the change (%s), so nothing was changed. Add the rules by hand from Settings > Advanced, then check that images still load.', 'qartvelo-guard' ), $probe['error'] )
				);
			}
			if ( $probe['code'] >= 500 ) {
				$rollback();
				return new \WP_Error(
					'wpcybersec_htaccess_500',
					/* translators: %d: HTTP status code */
					sprintf( __( 'The server rejected the new rules (HTTP %d), so they were removed again. This host does not allow these directives in .htaccess (AllowOverride); ask your host to block PHP in the uploads folder.', 'qartvelo-guard' ), $probe['code'] )
				);
			}
		}

		$all = Network::get_transient( self::PROBE_TRANSIENT );
		if ( is_array( $all ) && isset( $all['uploads_php'] ) ) {
			unset( $all['uploads_php'] );
			Network::set_transient( self::PROBE_TRANSIENT, $all, HOUR_IN_SECONDS );
		}
		if ( $trust_new ) {
			self::call( 'file_monitor', 'trust_file', array( $file ) );
		}
		$verified = $this->verify_uploads_block(
			static function () use ( $exists, $file, $old, $old_trusted ) {
				if ( $exists ) {
					@file_put_contents( $file, $old, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
					if ( $old_trusted ) {
						self::call( 'file_monitor', 'trust_file', array( $file ) );
					}
				} else {
					Fs::delete( $file );
				}
			}
		);
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}
		self::log( 'htaccess_written', __( 'Added the PHP blocking rules to uploads/.htaccess.', 'qartvelo-guard' ), array( 'file' => $file ) );
		return 'unchanged' === $verified ? 'written' : $verified;
	}

	/**
	 * Live test after the rules are in place: does a PHP file in uploads still
	 * run? Only a test that shows PHP no longer runs counts as fixed.
	 *
	 * @param callable|null $rollback Undoes the write (null when nothing was written).
	 * @return string|\WP_Error unchanged (verified) | unverified (the test could not run) | WP_Error (PHP still runs).
	 */
	private function verify_uploads_block( $rollback ) {
		$probe = $this->probe_uploads_php();
		if ( 'executed' === $probe['result'] ) {
			if ( is_callable( $rollback ) ) {
				call_user_func( $rollback );
			}
			$message = 'litespeed' === self::server_type() && 'openlitespeed' === Guard_Manager::litespeed_edition()
				? __( 'PHP files in the uploads folder still run: OpenLiteSpeed reads only rewrite rules from .htaccess, so the change was undone. In WebAdmin add a context that denies access to .php files in the uploads folder, or ask your host.', 'qartvelo-guard' )
				: ( 'iis' === self::server_type()
				? __( 'PHP files in the uploads folder still run: IIS ignores .htaccess files. Block PHP in uploads with a web.config rule or in the IIS handler mappings.', 'qartvelo-guard' )
				: __( 'PHP files in the uploads folder still run although the rules are in uploads/.htaccess: the server ignores them (AllowOverride, or a proxy in front that runs PHP itself). The change was undone. Ask your host to block PHP in the uploads folder.', 'qartvelo-guard' ) );
			return new \WP_Error( 'wpcybersec_htaccess_ineffective', $message );
		}
		return 'blocked' === $probe['result'] ? 'unchanged' : 'unverified';
	}

	/**
	 * Whether the file monitor already trusts exactly these bytes at this path.
	 *
	 * @param string $file    Absolute path.
	 * @param string $content File content.
	 * @return bool
	 */
	private static function manifest_trusts( $file, $content ) {
		$row = self::call( 'store', 'manifest_get', array( Paths::rel( wp_normalize_path( $file ) ) ) );
		return is_array( $row )
			&& Store::STATE_TRUSTED === (string) $row['state']
			&& '' !== (string) $row['sha256']
			&& hash_equals( (string) $row['sha256'], hash( 'sha256', (string) $content ) );
	}

	/* ------------------------------------------------------------------ */
	/* Snippets                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * The recommended real cron setup: the one source every screen uses (the
	 * Environment check, the wizard's Server step, Settings > Advanced > Real
	 * cron, the hosting panel steps and the developer instructions). A quick
	 * scan every hour, a full malware scan every night, and WordPress cron
	 * every 5 minutes. bin/cron.php gets --quiet, --wp and (multisite) --url;
	 * only its normal output goes to /dev/null, so errors still reach the
	 * cron mail.
	 *
	 * Panels that ask for a PHP script and its arguments separately (Plesk
	 * "Run a PHP script") use script and args; url is set when the job is
	 * better added as "fetch a URL" (WordPress cron on multisite).
	 *
	 * @return array[] Each { id, schedule, when, command, line, script, args, url }.
	 */
	public static function cron_jobs() {
		$php    = self::php_command();
		$script = wp_normalize_path( WPCYBERSEC_DIR ) . 'bin/cron.php';
		$cron   = self::shell_arg( $script );
		$args   = ' --quiet --wp=' . self::shell_arg( self::abspath() ) . self::cron_url_arg();

		if ( is_multisite() ) {
			// "php wp-cron.php" cannot tell which site of a network to load (no
			// host name on the command line): request the main site's
			// wp-cron.php over HTTP, where every plugin event lives.
			$wp_cron = 'curl -s -o /dev/null --max-time 120 ' . self::shell_arg( network_site_url( 'wp-cron.php?doing_wp_cron' ) );
		} else {
			$wp_cron = $php . ' ' . self::shell_arg( self::abspath() . '/wp-cron.php' ) . ' > /dev/null 2>&1';
		}
		$jobs = array(
			array(
				'id'       => 'quick',
				'schedule' => '17 * * * *',
				'when'     => __( 'Quick scan, every hour (at minute 17)', 'qartvelo-guard' ),
				'command'  => $php . ' ' . $cron . $args . ' > /dev/null',
				'script'   => $script,
				'args'     => ltrim( $args ),
				'url'      => '',
			),
			array(
				'id'       => 'full',
				'schedule' => '30 3 * * *',
				'when'     => __( 'Full malware scan, every night (at 3:30)', 'qartvelo-guard' ),
				'command'  => $php . ' ' . $cron . ' --full' . $args . ' > /dev/null',
				'script'   => $script,
				'args'     => '--full' . $args,
				'url'      => '',
			),
			array(
				'id'       => 'wp_cron',
				'schedule' => '*/5 * * * *',
				'when'     => is_multisite()
					? __( 'WordPress cron of the main site, every 5 minutes', 'qartvelo-guard' )
					: __( 'The rest of WordPress cron, every 5 minutes', 'qartvelo-guard' ),
				'command'  => $wp_cron,
				'script'   => self::abspath() . '/wp-cron.php',
				'args'     => '',
				'url'      => is_multisite() ? network_site_url( 'wp-cron.php?doing_wp_cron' ) : '',
			),
		);
		foreach ( $jobs as $i => $job ) {
			$jobs[ $i ]['line'] = $job['schedule'] . ' ' . $job['command'];
		}
		return $jobs;
	}

	/**
	 * The crontab block of cron_jobs().
	 *
	 * @return string
	 */
	public static function cron_crontab() {
		$jobs = self::cron_jobs();
		return "# Qartvelo Guard: quick scan every hour, full malware scan every night.\n"
			. $jobs[0]['line'] . "\n"
			. $jobs[1]['line'] . "\n"
			. ( is_multisite() ? "# WordPress cron of the main site every 5 minutes.\n" : "# The rest of WordPress cron every 5 minutes.\n" )
			. $jobs[2]['line'];
	}

	/**
	 * The last step everywhere: switching off WP-Cron on page visits once the
	 * jobs run (the one-click button appears after the first real cron run).
	 *
	 * @return array { text, code }
	 */
	public static function cron_disable_step() {
		$text = __( 'Once the jobs have run (the plugin notices the first run within an hour), switch off WP-Cron on page visits: use the "Switch off visitor-triggered cron" button that then appears in Settings > Advanced > Real cron, or add this line to wp-config.php above "That\'s all, stop editing!":', 'qartvelo-guard' );
		if ( is_multisite() ) {
			$text = __( 'On a multisite network the other sites keep their own WP-Cron, so switch it off only when the WP-CLI variant runs cron for every site. Then use the "Switch off visitor-triggered cron" button in Settings > Advanced > Real cron, or add this line to wp-config.php:', 'qartvelo-guard' );
		}
		return array(
			'text' => $text,
			'code' => "define( 'DISABLE_WP_CRON', true );",
		);
	}

	/**
	 * Real cron snippets with absolute paths (the first is cron_crontab()).
	 *
	 * @return array[] Each { id, label, file, code, help }.
	 */
	public function cron_snippets() {
		$jobs = self::cron_jobs();
		$wp   = self::shell_arg( self::abspath() ) . self::cron_url_arg();
		$path = self::shell_arg( self::abspath() );
		$off  = self::cron_disable_step();

		// The site's own PHP when the default php is another version (wp_cli()).
		$cli        = self::wp_cli();
		$wpcli_cron = is_multisite()
			? "*/5 * * * * {$cli} site list --field=url --path={$path} | xargs -I{} {$cli} cron event run --due-now --url={} --path={$path} --quiet"
			: "*/5 * * * * {$cli} cron event run --due-now --path={$wp} --quiet";
		$cli_help   = 'wp' !== $cli
			/* translators: %s: PHP binary */
			? ' ' . sprintf( __( 'The lines start WP-CLI with this site\'s PHP (%s) because the server\'s default php is another one; a plain "wp" could stop with a fatal error from a plugin that needs this PHP version.', 'qartvelo-guard' ), self::php_binary() )
			: '';

		return array(
			array(
				'id'    => 'crontab',
				'label' => __( 'System cron with PHP (recommended)', 'qartvelo-guard' ),
				'file'  => __( 'crontab -e (as the web server user)', 'qartvelo-guard' ),
				'code'  => self::cron_crontab(),
				'help'  => is_multisite()
					? __( 'Add these lines to the crontab of the user that owns the site files (often www-data). Only one scan runs at a time, so overlapping runs are harmless. On a multisite network the plugin runs on the main site only; the other sites keep their own WP-Cron, so do not switch WP-Cron off unless the WP-CLI variant below runs it for every site.', 'qartvelo-guard' )
					: __( 'Add these lines to the crontab of the user that owns the site files (often www-data). Only one scan runs at a time, so overlapping runs are harmless.', 'qartvelo-guard' ),
			),
			array(
				'id'    => 'wpcli',
				'label' => __( 'The same with WP-CLI', 'qartvelo-guard' ),
				'file'  => __( 'crontab -e (as the web server user)', 'qartvelo-guard' ),
				'code'  => $jobs[0]['schedule'] . " {$cli} wpcybersec scan --path={$wp} --quiet\n"
					. $jobs[1]['schedule'] . " {$cli} wpcybersec scan --full --path={$wp} --quiet\n"
					. $wpcli_cron,
				'help'  => ( is_multisite()
					? __( 'Use this variant instead when WP-CLI is installed. Use the full path to wp if cron cannot find it. The last line runs the due WordPress cron events of every site of the network.', 'qartvelo-guard' )
					: __( 'Use this variant instead when WP-CLI is installed. Use the full path to wp if cron cannot find it.', 'qartvelo-guard' ) ) . $cli_help,
			),
			array(
				'id'    => 'wpconfig',
				'label' => __( 'Switch off WP-Cron on page visits', 'qartvelo-guard' ),
				'file'  => 'wp-config.php',
				'code'  => $off['code'],
				'help'  => $off['text'],
			),
		);
	}

	/**
	 * URL path (no host) of a folder under the site, or ''.
	 *
	 * @param string $path Absolute folder.
	 * @return string
	 */
	private static function url_path_for( $path ) {
		$url = self::url_for_path( $path );
		if ( '' === $url ) {
			return '';
		}
		$url_path = (string) wp_parse_url( $url, PHP_URL_PATH );
		return '/' . trim( $url_path, '/' ) . '/';
	}

	/**
	 * nginx rule that blocks PHP in uploads. The one source of this rule
	 * (Hardening's manual steps use it too).
	 *
	 * @return string
	 */
	public static function nginx_uploads_rule() {
		$path = self::url_path_for( self::uploads_dir() );
		$path = '' !== $path ? $path : '/wp-content/uploads/';
		return 'location ~* ^' . str_replace( '\\-', '-', preg_quote( $path, '#' ) ) . '.*\\.(' . self::UPLOADS_EXEC_PATTERN . ')$ {' . "\n    deny all;\n}";
	}

	/**
	 * The same uploads rule as nginx_uploads_rule() as a prefix location with
	 * the PHP block nested inside. nginx tries the regular expressions nested
	 * in the longest matching prefix location first, so a panel that includes
	 * custom rules at the end of the server block, or keeps its PHP location
	 * inside "location /", would never reach a plain regex location; this form
	 * works wherever it is placed in the server block.
	 *
	 * @return string
	 */
	public static function nginx_uploads_block() {
		$path = self::url_path_for( self::uploads_dir() );
		$path = '' !== $path ? $path : '/wp-content/uploads/';
		return 'location ^~ ' . $path . " {\n    location ~* \\.(" . self::UPLOADS_EXEC_PATTERN . ")$ {\n        deny all;\n    }\n}";
	}

	/**
	 * URL path of the uploads folder ("/wp-content/uploads/").
	 *
	 * @return string
	 */
	public static function uploads_url_path() {
		$path = self::url_path_for( self::uploads_dir() );
		return '' !== $path ? $path : '/wp-content/uploads/';
	}

	/**
	 * URL path of the data folder, '' when it is outside the web root.
	 *
	 * @return string
	 */
	public static function data_url_path() {
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		if ( ! $storage->is_in_webroot( $storage->data_dir() ) ) {
			return '';
		}
		return self::url_path_for( $storage->data_dir() );
	}

	/**
	 * nginx rule that blocks the data folder (empty comment when outside the web root).
	 *
	 * @return string
	 */
	public function nginx_data_rule() {
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$path    = self::url_path_for( $storage->data_dir() );
		if ( '' === $path || ! $storage->is_in_webroot( $storage->data_dir() ) ) {
			return '# ' . __( 'The data folder is outside the web root: nothing to block.', 'qartvelo-guard' );
		}
		return 'location ^~ ' . $path . " {\n    deny all;\n}";
	}

	/**
	 * Full nginx snippet: PHP in uploads, the data folder and the guard bootstrap.
	 *
	 * @return string
	 */
	public function nginx_rules() {
		$guard = (string) wp_parse_url( site_url( '/' ), PHP_URL_PATH );
		$guard = '/' . trim( $guard, '/' ) . '/wpcybersec-guard.php';
		$guard = str_replace( '//', '/', $guard );
		return '# ' . __( 'Inside the server { } block of this site, above the generic "location ~ \.php$" block.', 'qartvelo-guard' ) . "\n"
			. '# ' . __( 'Block PHP execution in uploads.', 'qartvelo-guard' ) . "\n"
			. self::nginx_uploads_rule() . "\n\n"
			. '# ' . __( 'Block web access to the Qartvelo Guard data folder.', 'qartvelo-guard' ) . "\n"
			. $this->nginx_data_rule() . "\n\n"
			. '# ' . __( 'The early guard bootstrap is only loaded through auto_prepend_file.', 'qartvelo-guard' ) . "\n"
			. 'location = ' . $guard . " {\n    deny all;\n}\n\n"
			. '# ' . __( 'Then test and reload:', 'qartvelo-guard' ) . "\n"
			. '#   nginx -t && systemctl reload nginx';
	}

	/**
	 * Shell commands for safe file permissions.
	 *
	 * @return string
	 */
	public function permission_commands() {
		$root    = self::shell_arg( self::abspath() );
		$config  = self::wp_config_path();
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$data    = self::shell_arg( $storage->data_dir() );
		$uploads = self::shell_arg( self::uploads_dir() );

		$lines = array(
			'# ' . __( 'Run as root or with sudo. Replace www-data and deploy with your web server user and your SSH user.', 'qartvelo-guard' ),
			'cd ' . $root,
			'find . -type d -exec chmod 755 {} +',
			'find . -type f -exec chmod 644 {} +',
		);
		if ( '' !== $config ) {
			$lines[] = 'chmod 640 ' . self::shell_arg( $config );
		}
		$lines[] = 'chmod 750 ' . $data;
		$lines[] = '';
		$lines[] = '# ' . __( 'Stricter: code owned by your SSH user and read-only for PHP; only uploads and the data folder stay writable.', 'qartvelo-guard' );
		$lines[] = '# ' . __( 'Updates from the dashboard stop working with this; update with WP-CLI as deploy instead.', 'qartvelo-guard' );
		$lines[] = '# chown -R deploy:www-data .';
		$lines[] = '# chown -R www-data:www-data ' . $uploads . ' ' . $data;
		return implode( "\n", $lines );
	}

	/**
	 * Streams the fapolicyd trust list: one "path size sha256" line for every
	 * trusted manifest file under the scan root.
	 *
	 * @return \Generator Lines without newline.
	 */
	public function fapolicyd_trust_export() {
		$store = self::service( 'store' );
		yield '# fapolicyd trust file generated by Qartvelo Guard on ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC';
		yield '# Site: ' . home_url( '/' );
		yield '# Format: path size sha256. Install it as /etc/fapolicyd/trust.d/wordpress-' . self::site_slug() . '.trust and run: fapolicyd-cli --update';
		if ( ! $store || ! method_exists( $store, 'manifest_page' ) ) {
			yield '# The file manifest is not available.';
			return;
		}
		$root    = Paths::scan_root();
		$offset  = 0;
		$limit   = 2000;
		$skipped = 0;
		$count   = 0;
		do {
			$rows = $store->manifest_page( $limit, $offset );
			foreach ( $rows as $row ) {
				$abs = Paths::is_absolute( (string) $row['path'] ) ? wp_normalize_path( $row['path'] ) : $root . ltrim( (string) $row['path'], '/' );
				$sha = strtolower( (string) $row['sha256'] );
				if ( ! preg_match( '/^[a-f0-9]{64}$/', $sha ) || preg_match( '/[\s\x00-\x1f]/', $abs ) ) {
					++$skipped;
					continue;
				}
				++$count;
				yield $abs . ' ' . (int) $row['size'] . ' ' . $sha;
			}
			$offset += $limit;
		} while ( count( $rows ) === $limit );
		yield '# ' . $count . ' files.' . ( $skipped ? ' Skipped ' . $skipped . ' files with spaces in the name or without a hash.' : '' );
	}

	/**
	 * fapolicyd rules that only let PHP-FPM open trusted PHP files of this site.
	 *
	 * @return string
	 */
	public function fapolicyd_rules() {
		$bin  = defined( 'PHP_BINARY' ) ? wp_normalize_path( (string) PHP_BINARY ) : '';
		$fpm  = ( '' !== $bin && false !== strpos( basename( $bin ), 'fpm' ) ) ? $bin : '/usr/sbin/php-fpm';
		$root = rtrim( Paths::scan_root(), '/' ) . '/';
		// One rules and trust file per site: several sites of one server each add their own.
		$name = 'wordpress-' . self::site_slug();
		return "# /etc/fapolicyd/rules.d/35-{$name}.rules\n"
			. '# ' . __( 'PHP-FPM may only open PHP files of this site that are in the trust list.', 'qartvelo-guard' ) . "\n"
			. "allow perm=open exe={$fpm} : dir={$root} ftype=text/x-php trust=1\n"
			. "deny_audit perm=open exe={$fpm} : dir={$root} ftype=text/x-php\n\n"
			. '# ' . __( 'Install the trust list downloaded above and reload:', 'qartvelo-guard' ) . "\n"
			. "#   cp {$name}.trust /etc/fapolicyd/trust.d/{$name}.trust\n"
			. "#   fagenrules --load && fapolicyd-cli --update\n"
			. '# ' . __( 'Download a fresh trust list after every update you approve, or PHP will be denied the new files.', 'qartvelo-guard' );
	}

	/**
	 * Escapes a literal for a POSIX extended regular expression.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	private static function ere_quote( $value ) {
		return preg_replace( '/([.\[\](){}*+?|^$\\\\])/', '\\\\$1', (string) $value );
	}

	/**
	 * Where the inotify watcher of this site is installed: one file per site,
	 * so two sites of one server keep their own.
	 *
	 * @return string
	 */
	public static function inotify_script_path() {
		return '/usr/local/bin/wpcybersec-watch-' . self::site_slug() . '.sh';
	}

	/**
	 * Bash watcher that runs a scan a little after files stop changing.
	 *
	 * @return string
	 */
	public function inotify_script() {
		$root    = rtrim( Paths::scan_root(), '/' );
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$exclude = array(
			self::ere_quote( $storage->data_dir() ) . '/',
			'/wp-content/(cache|upgrade|upgrade-temp-backup)/',
			'/\\.git/',
			'\\.log$',
		);
		$lines = array(
			'#!/usr/bin/env bash',
			'# Qartvelo Guard: runs a scan 20 seconds after files stop changing.',
			'# Needs inotify-tools (apt install inotify-tools / dnf install inotify-tools).',
			'# Run it as the web server user, for example from a systemd service:',
			'#   [Service]',
			'#   User=www-data',
			'#   ExecStart=' . self::inotify_script_path(),
			'#   Restart=always',
			'',
			'SITE=' . self::shell_arg( $root ),
			'PHP=' . self::shell_arg( self::php_binary() ),
			'PHPARGS=' . ( preg_match( '/^php-?cgi/i', basename( self::php_binary() ) ) ? '-q' : '' ),
			'URLARG=' . ( is_multisite() ? self::shell_arg( '--url=' . network_home_url( '/' ) ) : '' ),
			'CRON=' . self::shell_arg( wp_normalize_path( WPCYBERSEC_DIR ) . 'bin/cron.php' ),
			'WP=' . self::shell_arg( self::abspath() ),
			'DEBOUNCE=20',
			'EXCLUDE=' . self::shell_arg( '(' . implode( '|', $exclude ) . ')' ),
			'',
			'inotifywait -m -r -q -e close_write,create,moved_to,delete --exclude "$EXCLUDE" --format \'%w%f\' "$SITE" |',
			'while true; do',
			'    if IFS= read -r -t "$DEBOUNCE" changed; then',
			'        pending=1',
			'        continue',
			'    fi',
			'    rc=$?',
			'    # A status of 128 or less means inotifywait stopped: exit so systemd restarts us.',
			'    [ "$rc" -le 128 ] && exit 1',
			'    if [ "${pending:-0}" = 1 ]; then',
			'        pending=0',
			'        "$PHP" $PHPARGS "$CRON" --wp="$WP" $URLARG > /dev/null 2>&1',
			'    fi',
			'done',
		);
		return implode( "\n", $lines );
	}

	/**
	 * Linux Malware Detect (maldet) steps for this site: inotify-tools first
	 * (maldet --monitor stops with "could not find inotifywait command"
	 * without it), then the monitored path, the monitor itself, more inotify
	 * watches for big sites, start on boot, and a background scan. The package
	 * commands of the detected server family come first.
	 *
	 * @return array[] Each { text, code }.
	 */
	public function maldet_steps() {
		$root     = rtrim( Paths::scan_root(), '/' );
		$path     = self::shell_arg( $root );
		$list     = '/usr/local/maldetect/monitor_paths';
		$platform = class_exists( '\WPCyberSecurity\Admin\Clamav_Guide' ) ? Admin\Clamav_Guide::platform() : 'other';
		$apt      = 'apt-get install -y inotify-tools';
		$dnf      = 'dnf install -y epel-release && dnf install -y inotify-tools';
		if ( 'rhel' === $platform ) {
			$install = $dnf . "\n# Debian or Ubuntu: " . $apt;
		} else {
			$install = $apt . "\n# AlmaLinux, Rocky, CentOS or CloudLinux: " . $dnf;
		}
		$mode = 'MONITOR_MODE="' . $list . '"';
		$boot = array();
		foreach ( 'rhel' === $platform ? array( '/etc/sysconfig/maldet', '/etc/default/maldet' ) : array( '/etc/default/maldet', '/etc/sysconfig/maldet' ) as $i => $file ) {
			$lines = array(
				"sed -i 's|^MONITOR_MODE=.*|" . $mode . "|' " . $file,
				"grep -q '^MONITOR_MODE=' " . $file . ' || echo ' . self::shell_arg( $mode ) . ' >> ' . $file,
			);
			if ( 0 === $i ) {
				$boot = array_merge( $boot, $lines );
			} else {
				/* translators: %s: file path */
				$boot[] = '# ' . sprintf( __( 'On the other server family the file is %s:', 'qartvelo-guard' ), $file );
				foreach ( $lines as $line ) {
					$boot[] = '# ' . $line;
				}
			}
		}
		$boot[] = 'systemctl enable --now maldet';

		return array(
			array(
				'text' => __( 'Install inotify-tools: the real-time monitor needs its inotifywait command (without it, maldet --monitor stops with "could not find inotifywait command").', 'qartvelo-guard' ),
				'code' => $install,
			),
			array(
				'text' => __( 'Add this site to the monitored folders (safe to run again). maldet is installed once per server and shared by every site on it: a second site only needs this line, not its own install.', 'qartvelo-guard' ),
				'code' => 'grep -qxF ' . $path . ' ' . $list . ' || echo ' . $path . ' >> ' . $list,
			),
			array(
				'text' => __( 'Start the monitor, or restart it when it already runs for other sites (it reads the folder list only when it starts), then check its log:', 'qartvelo-guard' ),
				'code' => 'maldet --kill-monitor >/dev/null 2>&1; maldet --monitor ' . $list . "\ntail -n 20 /usr/local/maldetect/logs/inotify_log",
			),
			array(
				'text' => __( 'Big sites: allow more inotify watches, now and after a reboot:', 'qartvelo-guard' ),
				'code' => "sysctl -w fs.inotify.max_user_watches=524288\ngrep -q '^fs.inotify.max_user_watches' /etc/sysctl.conf || echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf",
			),
			array(
				'text' => __( 'Start the monitor on every boot:', 'qartvelo-guard' ),
				'code' => implode( "\n", $boot ),
			),
			array(
				'text' => __( 'Scan the files of this site changed in the last 2 days, in the background:', 'qartvelo-guard' ),
				'code' => 'maldet -b -r ' . $path . ' 2',
			),
			array( 'text' => __( 'Keep maldet\'s own quarantine off (quarantine_hits="0" in /usr/local/maldetect/conf.maldet) and let Qartvelo Guard decide, or both will move files.', 'qartvelo-guard' ) ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* cgav server script                                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * The cgav server script (ClamAV + maldet helper) with this site filled in.
	 * Shipped as includes/admin/cgav-script.txt (a .sh file would be flagged as
	 * an application file); SITE="${SITE:-<this site>}" goes right after the
	 * shebang, so /etc/cgav.conf still wins once self-install wrote it.
	 *
	 * @return string '' when the template is missing.
	 */
	public static function cgav_script() {
		$file = WPCYBERSEC_DIR . 'includes/admin/cgav-script.txt';
		$code = @is_readable( $file ) ? (string) @file_get_contents( $file ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the plugin's own template.
		if ( '' === $code ) {
			return '';
		}
		$code = str_replace( "\r\n", "\n", $code );
		$site = untrailingslashit( wp_normalize_path( ABSPATH ) );
		// Inside double quotes only \ " $ and ` are special.
		$line = 'SITE="${SITE:-' . addcslashes( $site, '\\"$`' ) . '}"';
		$pos  = strpos( $code, "\n" );
		if ( 0 === strpos( $code, '#!' ) && false !== $pos ) {
			return substr( $code, 0, $pos + 1 ) . $line . "\n" . substr( $code, $pos + 1 );
		}
		return $line . "\n" . $code;
	}

	/**
	 * One copy-paste block that writes the script, installs it and shows the status.
	 *
	 * @return string '' when the template is missing.
	 */
	public static function cgav_install_block() {
		$script = self::cgav_script();
		if ( '' === $script ) {
			return '';
		}
		// One cgav serves every site of the server: self-install adds this site to
		// its SITES list, and add-site puts it in the maldet monitor (restarting it).
		$site = self::shell_arg( untrailingslashit( wp_normalize_path( ABSPATH ) ) );
		return "cat > /root/cgav.sh <<'CGAV_EOF'\n" . rtrim( $script, "\n" ) . "\nCGAV_EOF\n"
			. 'bash /root/cgav.sh self-install ' . $site . "\n"
			. 'cgav add-site ' . $site;
	}

	/**
	 * Sections of the cgav script, for the short list next to the block.
	 *
	 * @return array command => what it does
	 */
	public static function cgav_commands() {
		return array(
			'cgav status'                     => __( 'What is installed and running, and every site the monitor watches. Run it before and after anything.', 'qartvelo-guard' ),
			'cgav sites'                      => __( 'Lists the WordPress sites on this server and which of them the monitor watches.', 'qartvelo-guard' ),
			'cgav add-site <path>'            => __( 'Adds one more site of this server to the monitor and restarts it. ClamAV and maldet are installed once per server.', 'qartvelo-guard' ),
			'cgav remove-site <path>'         => __( 'Stops watching one site.', 'qartvelo-guard' ),
			'cgav add-all'                    => __( 'Adds every WordPress site found on this server.', 'qartvelo-guard' ),
			'cgav install-clamav'             => __( 'Install ClamAV, download signatures, start the scanner service.', 'qartvelo-guard' ),
			'cgav install-maldet'             => __( 'Install Linux Malware Detect and inotify-tools, watch this site in real time, start on boot, report-only.', 'qartvelo-guard' ),
			'cgav monitor start|stop|status'  => __( 'Control the maldet real-time monitor.', 'qartvelo-guard' ),
			'cgav test'                       => __( 'Harmless EICAR test file: both engines must report it.', 'qartvelo-guard' ),
			'cgav update'                     => __( 'Update the ClamAV and maldet signatures.', 'qartvelo-guard' ),
			'cgav scan'                       => __( 'Scan the whole site now with maldet (and ClamAV when present).', 'qartvelo-guard' ),
			'cgav logs'                       => __( 'Last lines of the maldet monitor and event logs.', 'qartvelo-guard' ),
		);
	}

	/**
	 * admin-post: downloads the cgav script as cgav.sh.
	 */
	public function handle_cgav() {
		$this->check_request( 'wpcybersec_cgav' );
		$script = self::cgav_script();
		if ( '' === $script ) {
			self::flash( __( 'The server script is missing from this installation of the plugin.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( self::settings_url( 'advanced', array(), 'wpcs-antivirus' ) );
		}
		nocache_headers();
		header( 'Content-Type: text/x-shellscript; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="cgav.sh"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo $script; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- shell script download.
		exit;
	}

	/**
	 * Whether open_basedir lets PHP look at a path (true when it is not set).
	 *
	 * @param string $path Absolute path.
	 * @return bool
	 */
	public static function path_allowed( $path ) {
		return Storage::path_allowed( $path );
	}

	/**
	 * Runs a fixed command when exec() is allowed.
	 *
	 * @param string $cmd Command (already escaped).
	 * @return int|null Exit code, null when commands cannot run here.
	 */
	private static function exit_code( $cmd ) {
		if ( ! self::function_available( 'exec' ) ) {
			return null;
		}
		$out  = array();
		$code = 127;
		@exec( $cmd . ' >/dev/null 2>&1', $out, $code ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return (int) $code;
	}

	/**
	 * "Is it running on the server" rows for the Antivirus card. Never fatal:
	 * a check that the hosting does not let PHP do (open_basedir, no exec,
	 * no /proc) is reported as unknown.
	 *
	 * @return array[] Each { id, label, state ok|bad|unknown|na, text, hint, code }; hint and code
	 *                 (may be '') say why a row is unknown or not set up and give the root command.
	 */
	public function antivirus_live() {
		// Kept for this request, but rebuilt when a newer ClamAV self-test was stored in the
		// meantime ("Check again" runs one after other parts of the page already asked).
		$test = self::call( 'scanner', 'clamav_selftest_cached', array(), null );
		$at   = is_array( $test ) && isset( $test['at'] ) ? (int) $test['at'] : 0;
		if ( null !== $this->live_cache && $at === $this->live_cache_at ) {
			return $this->live_cache;
		}
		$this->live_cache    = $this->antivirus_live_rows();
		$this->live_cache_at = $at;
		return $this->live_cache;
	}

	/** @var array[]|null antivirus_live() of this request. */
	private $live_cache = null;

	/** @var int Self-test time the cached rows were built with. */
	private $live_cache_at = 0;

	/**
	 * @return array[] See antivirus_live().
	 */
	private function antivirus_live_rows() {
		$hidden = __( 'Unknown (hosting hides it)', 'qartvelo-guard' );
		$av     = $this->antivirus_status();
		$rows   = array();
		$base   = '/usr/local/maldetect';
		$site   = untrailingslashit( wp_normalize_path( ABSPATH ) );

		// ClamAV daemon (the same check the scanner uses).
		if ( 'missing' === $av['clamav']['state'] && ! empty( $av['clamav']['hidden'] ) ) {
			$rows[] = array( __( 'ClamAV scanner service (clamd)', 'qartvelo-guard' ), 'unknown', $hidden );
		} elseif ( 'missing' === $av['clamav']['state'] ) {
			$rows[] = array( __( 'ClamAV scanner service (clamd)', 'qartvelo-guard' ), 'na', __( 'ClamAV is not installed', 'qartvelo-guard' ) );
		} elseif ( ! $av['clamav']['exec'] ) {
			$rows[] = array( __( 'ClamAV scanner service (clamd)', 'qartvelo-guard' ), 'unknown', $hidden );
		} else {
			$text = $av['clamav']['daemon'] ? __( 'Reachable', 'qartvelo-guard' ) : __( 'Not running', 'qartvelo-guard' );
			if ( ! $av['clamav']['daemon'] && 'socket' === $av['clamav']['kind'] ) {
				$text = __( 'Running, but PHP may not use its socket', 'qartvelo-guard' );
			} elseif ( ! $av['clamav']['daemon'] && 'config' === $av['clamav']['kind'] ) {
				$text = __( 'Not usable: clamd.conf cannot be read', 'qartvelo-guard' );
			}
			$rows[] = array( __( 'ClamAV scanner service (clamd)', 'qartvelo-guard' ), $av['clamav']['daemon'] ? 'ok' : 'bad', $text );
		}

		// maldet installed, with its signature version.
		$bin = $base . '/maldet';
		if ( ! self::path_allowed( $bin ) ) {
			$installed = null;
			$rows[]    = array( __( 'Linux Malware Detect', 'qartvelo-guard' ), 'unknown', $hidden );
		} else {
			$installed = @is_executable( $bin ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$text      = $installed ? __( 'Installed', 'qartvelo-guard' ) : __( 'Not installed', 'qartvelo-guard' );
			$ver       = $base . '/sigs/maldet.sigs.ver';
			if ( $installed && @is_readable( $ver ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$raw = preg_replace( '/[^0-9A-Za-z._-]/', '', (string) strtok( (string) @file_get_contents( $ver, false, null, 0, 64 ) . "\n", "\n" ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				if ( '' !== $raw ) {
					/* translators: %s: signature version */
					$text .= ', ' . sprintf( __( 'signatures %s', 'qartvelo-guard' ), $raw );
				}
			}
			$state = $installed ? 'ok' : ( 'Linux' === PHP_OS_FAMILY ? 'bad' : 'na' );
			$text  = ( ! $installed && 'na' === $state ) ? __( 'Not installed (Linux only)', 'qartvelo-guard' ) : $text;
			$rows[] = array( __( 'Linux Malware Detect', 'qartvelo-guard' ), $state, $text );
		}

		// Real-time monitor: the pid file and /proc, else pgrep.
		$label = __( 'maldet real-time monitor', 'qartvelo-guard' );
		if ( false === $installed ) {
			$rows[] = array( $label, 'na', __( 'maldet is not installed', 'qartvelo-guard' ) );
		} else {
			$running = null;
			// Servers that mount /proc with hidepid (common on hardened and CloudLinux
			// hosts) hide other users' processes from PHP: the root-owned monitor is
			// invisible there, so "not found" means unknown, not stopped.
			$procs_hidden  = self::processes_hidden();
			$procs_visible = ! $procs_hidden && self::path_allowed( '/proc' ) && @is_dir( '/proc/self' ) && @file_exists( '/proc/1' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $procs_visible ) {
				// maldet 1.6 keeps the monitor's pid in monitor.pid; older versions in inotifywait.pid.
				foreach ( array( 'monitor.pid', 'inotifywait.pid' ) as $name ) {
					$pidfile = $base . '/tmp/' . $name;
					$pid     = self::path_allowed( $pidfile ) && @is_readable( $pidfile ) ? (int) trim( (string) @file_get_contents( $pidfile, false, null, 0, 32 ) ) : 0; // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
					if ( $pid > 0 && @file_exists( '/proc/' . $pid ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
						$running = true;
						break;
					}
				}
			}
			if ( null === $running ) {
				// "[i]" keeps the pattern from matching the command line of the shell that runs pgrep.
				$code = self::exit_code( 'pgrep -f ' . escapeshellarg( '[i]notifywait.*maldetect' ) );
				if ( 0 === $code ) {
					$running = true;
				} elseif ( 1 === $code && $procs_visible ) {
					$running = false; // Only trust "no match" when PHP can see other users' processes.
				}
			}
			$active_ago = null;
			if ( null === $running ) {
				// Processes hidden: the monitor writes a "{mon}" line to event_log on every
				// cycle (about every 30 seconds), so a fresh one shows it is alive.
				$log   = $base . '/logs/event_log';
				$mtime = self::path_allowed( $log ) ? @filemtime( $log ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( $mtime && time() - $mtime <= 3 * MINUTE_IN_SECONDS && @is_readable( $log ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$size = (int) @filesize( $log ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$tail = (string) @file_get_contents( $log, false, null, max( 0, $size - 4096 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
					if ( false !== strpos( $tail, '{mon}' ) ) {
						$running    = true;
						$active_ago = max( 0, time() - $mtime );
					}
				}
			}
			if ( null === $running ) {
				// Say why it cannot be told, and how root checks it.
				$hint   = self::monitor_check_hint( $procs_hidden );
				$rows[] = array( $label, 'unknown', $hidden, $hint['text'], $hint['code'] );
			} else {
				$text = $running ? __( 'Running', 'qartvelo-guard' ) : __( 'Not running', 'qartvelo-guard' );
				if ( $running && null !== $active_ago ) {
					/* translators: %s: time, for example "30 seconds" */
					$text = sprintf( __( 'Running (last activity %s ago)', 'qartvelo-guard' ), human_time_diff( time() - $active_ago, time() ) );
				}
				$rows[] = array( $label, $running ? 'ok' : 'bad', $text );
			}
		}

		// This site in monitor_paths.
		$label = __( 'This site watched by the monitor', 'qartvelo-guard' );
		$list  = $base . '/monitor_paths';
		if ( false === $installed ) {
			$rows[] = array( $label, 'na', __( 'maldet is not installed', 'qartvelo-guard' ) );
		} elseif ( ! self::path_allowed( $list ) || ( @file_exists( $list ) && ! @is_readable( $list ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$rows[] = array( $label, 'unknown', $hidden );
		} else {
			$lines = @file( $list, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$found = self::monitor_watches( is_array( $lines ) ? $lines : array(), $site );
			if ( $site === $found ) {
				$rows[] = array( $label, 'ok', __( 'Yes, in monitor_paths', 'qartvelo-guard' ) );
			} elseif ( '' !== $found ) {
				// maldet watches folders recursively: a listed parent folder covers this site.
				/* translators: %s: folder path */
				$rows[] = array( $label, 'ok', sprintf( __( 'Yes, as part of %s', 'qartvelo-guard' ), $found ) );
			} else {
				$add    = self::monitor_add_site_step();
				/* translators: %s: file path */
				$rows[] = array( $label, 'bad', sprintf( __( 'No: not listed in %s', 'qartvelo-guard' ), $list ), $add['text'], $add['code'] );
			}
		}

		// maldet quarantine off: Qartvelo Guard decides.
		$label = __( 'maldet quarantine (quarantine_hits)', 'qartvelo-guard' );
		$conf  = $base . '/conf.maldet';
		if ( false === $installed ) {
			$rows[] = array( $label, 'na', __( 'maldet is not installed', 'qartvelo-guard' ) );
		} elseif ( ! self::path_allowed( $conf ) || ! @is_readable( $conf ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$rows[] = array( $label, 'unknown', $hidden );
		} else {
			$value = preg_match( '/^quarantine_hits="?([0-9])/m', (string) @file_get_contents( $conf ), $m ) ? $m[1] : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			if ( '0' === $value ) {
				$rows[] = array( $label, 'ok', __( '0: report-only, Qartvelo Guard decides', 'qartvelo-guard' ) );
			} elseif ( '' === $value ) {
				$rows[] = array( $label, 'unknown', __( 'Not set in conf.maldet', 'qartvelo-guard' ) );
			} else {
				/* translators: %s: setting value */
				$rows[] = array( $label, 'bad', sprintf( __( '%s: maldet moves files itself, so both would act on the same file', 'qartvelo-guard' ), $value ) );
			}
		}

		// Always the same five rows, in this order.
		$ids = array( 'clamd', 'maldet', 'maldet_monitor', 'maldet_watch', 'maldet_quarantine' );
		$out = array();
		foreach ( $rows as $i => $row ) {
			$out[] = array(
				'id'    => isset( $ids[ $i ] ) ? $ids[ $i ] : 'row' . $i,
				'label' => $row[0],
				'state' => $row[1],
				'text'  => $row[2],
				'hint'  => isset( $row[3] ) ? (string) $row[3] : '',
				'code'  => isset( $row[4] ) ? (string) $row[4] : '',
			);
		}
		return $out;
	}

	/**
	 * The monitor_paths line that covers a folder: the folder itself or a
	 * parent folder (maldet watches folders recursively).
	 *
	 * @param string[] $lines Lines of monitor_paths.
	 * @param string   $site  Folder, normalized, no trailing slash.
	 * @return string The matching line (normalized), '' when none covers it.
	 */
	public static function monitor_watches( array $lines, $site ) {
		$site  = untrailingslashit( wp_normalize_path( (string) $site ) );
		$found = '';
		foreach ( $lines as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			$dir = untrailingslashit( wp_normalize_path( $line ) );
			if ( '' === $dir ) {
				$dir = '/';
			}
			if ( $dir === $site ) {
				return $site;
			}
			if ( '' === $found && ( '/' === $dir || 0 === strpos( $site . '/', $dir . '/' ) ) ) {
				$found = $dir;
			}
		}
		return $found;
	}

	/**
	 * Whether /proc hides other users' processes from PHP: it is mounted with
	 * hidepid (1, 2, invisible), normal on hardened and CloudLinux servers.
	 * PHP then sees its own processes (/proc/self) but not process 1 (init,
	 * which always exists). A check that looks for a root-owned process (pgrep,
	 * a pid file) cannot tell "stopped" from "hidden" there; checks through a
	 * socket, like the ClamAV service (clamd), are not affected.
	 *
	 * @return bool False without /proc (Windows, macOS) or when open_basedir hides it.
	 */
	public static function processes_hidden() {
		if ( '\\' === DIRECTORY_SEPARATOR || ! self::path_allowed( '/proc/self' ) || ! @is_dir( '/proc/self' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		return ! @file_exists( '/proc/1' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * The sentence for a process check that processes_hidden() made unknown.
	 *
	 * @return string
	 */
	public static function processes_hidden_text() {
		return __( 'This server hides other users\' processes from PHP (/proc is mounted with hidepid), which is normal on hardened servers, so PHP cannot see a service that runs as root.', 'qartvelo-guard' );
	}

	/**
	 * Whether the cgav server script is installed (null when open_basedir hides /usr/local/bin).
	 *
	 * @return bool|null
	 */
	public static function cgav_installed() {
		$bin = '/usr/local/bin/cgav';
		if ( ! self::path_allowed( $bin ) ) {
			return null;
		}
		return @is_file( $bin ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Why the maldet monitor state is unknown, and the root command that checks it.
	 *
	 * @param bool|null $hidden processes_hidden() (computed when null).
	 * @return array { text, code }
	 */
	public static function monitor_check_hint( $hidden = null ) {
		$hidden = null === $hidden ? self::processes_hidden() : (bool) $hidden;
		$text   = $hidden
			? self::processes_hidden_text() . ' ' . __( 'Check the monitor as root:', 'qartvelo-guard' )
			: __( 'PHP may not look for running programs here (exec() is disabled or open_basedir hides the maldet folder). Check the monitor as root:', 'qartvelo-guard' );
		$cgav = self::cgav_installed();
		if ( true === $cgav ) {
			$code = "cgav monitor status\n# or: pgrep -af inotifywait";
		} elseif ( null === $cgav ) {
			$code = "pgrep -af inotifywait\n# with the cgav script installed: cgav monitor status";
		} else {
			$code = 'pgrep -af inotifywait';
		}
		return array(
			'text' => $text,
			'code' => $code,
		);
	}

	/**
	 * How to add this site to the maldet monitor. One maldet serves every site
	 * of the server, so a second site only needs its folder added: the cgav
	 * command, else the line in monitor_paths and a monitor restart (maldet's
	 * reload_monitor only reloads its configuration, not the watched folders).
	 *
	 * @return array { text, code }
	 */
	public static function monitor_add_site_step() {
		$site = self::shell_arg( untrailingslashit( wp_normalize_path( ABSPATH ) ) );
		$list = '/usr/local/maldetect/monitor_paths';
		$cgav = 'cgav add-site ' . $site;
		if ( true === self::cgav_installed() ) {
			return array(
				'text' => __( 'maldet is installed once per server and watches every site listed in monitor_paths. Add this site as root:', 'qartvelo-guard' ),
				'code' => $cgav,
			);
		}
		return array(
			'text' => __( 'maldet is installed once per server and watches every site listed in monitor_paths. Add this site as root with the cgav script, or without it add the line and restart the monitor:', 'qartvelo-guard' ),
			'code' => $cgav . "\n# without cgav:\ngrep -qxF " . $site . ' ' . $list . ' || echo ' . $site . ' >> ' . $list . "\nsystemctl restart maldet\n# without systemd: maldet --kill-monitor && maldet --monitor " . $list,
		);
	}

	/**
	 * Whether the inotifywait command (inotify-tools) is installed.
	 *
	 * @return bool
	 */
	public static function inotifywait_installed() {
		$dirs = array( '/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin' );
		$path = (string) getenv( 'PATH' );
		foreach ( '' !== $path ? explode( PATH_SEPARATOR, $path ) : array() as $dir ) {
			$dir = rtrim( trim( $dir ), '/' );
			if ( '' !== $dir && '/' === $dir[0] ) {
				$dirs[] = $dir;
			}
		}
		foreach ( array_unique( $dirs ) as $dir ) {
			if ( @is_file( $dir . '/inotifywait' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return true;
			}
		}
		return false;
	}

	/**
	 * wp-config.php line for the allowlist tamper check, with a fresh random key.
	 *
	 * @return string
	 */
	public function hmac_snippet() {
		if ( defined( 'WPCYBERSEC_HMAC_KEY' ) && WPCYBERSEC_HMAC_KEY ) {
			return '// ' . __( 'WPCYBERSEC_HMAC_KEY is already defined in wp-config.php.', 'qartvelo-guard' );
		}
		return "define( 'WPCYBERSEC_HMAC_KEY', '" . wp_generate_password( 64, false, false ) . "' );";
	}

	/**
	 * wp-config line and shell commands to move the data folder.
	 *
	 * @return array { path, config, shell }
	 */
	public function data_dir_snippet() {
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$current = $storage->data_dir();
		// Same unique, per-install name the one-click move uses.
		$target = method_exists( $storage, 'suggested_outside_dir' ) ? $storage->suggested_outside_dir() : dirname( self::abspath() ) . '/wpcybersec-data';
		if ( $storage->is_in_webroot( $target ) ) {
			$host   = sanitize_title( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
			$target = '/var/lib/wpcybersec/' . ( $host ? $host : 'site' ) . ( method_exists( $storage, 'site_id' ) ? '-' . Storage::site_id() : '' );
		}
		$config = "define( 'WPCYBERSEC_DATA_DIR', '" . str_replace( array( '\\', "'" ), array( '\\\\', "\\'" ), $target ) . "' );";
		$shell  = 'mkdir -p ' . self::shell_arg( $target ) . "\n"
			. 'cp -a ' . self::shell_arg( $current . '/.' ) . ' ' . self::shell_arg( $target . '/' ) . "\n"
			. 'chown -R www-data:www-data ' . self::shell_arg( $target ) . "\n"
			. 'chmod 750 ' . self::shell_arg( $target ) . "\n"
			. '# ' . __( 'Then add the define() line to wp-config.php. If the early guard is installed, reinstall it afterwards. Held items keep pointing at the old folder until you approve or delete them, so the one-click "Move it outside the web root" button in Server health is the easier way: it moves everything and updates every path.', 'qartvelo-guard' );
		return array(
			'path'   => $target,
			'config' => $config,
			'shell'  => $shell,
		);
	}

	/* ------------------------------------------------------------------ */
	/* Test email                                                          */
	/* ------------------------------------------------------------------ */

	/**
	 * Sends a test alert. Uses the notifier when the recipients are the saved
	 * ones, otherwise a plain email to the addresses given.
	 *
	 * @param string[] $emails Optional recipients typed in a form (not saved yet).
	 * @return true|\WP_Error
	 */
	public function send_test_email( array $emails = array() ) {
		$emails   = array_values( array_unique( array_filter( array_map( 'sanitize_email', $emails ), 'is_email' ) ) );
		$settings = self::service( 'settings' );
		$saved    = $settings ? (array) $settings->recipients() : Network::default_recipients();
		if ( ! $emails ) {
			$emails = $saved;
		}
		$a = $emails;
		$b = $saved;
		sort( $a );
		sort( $b );

		$error    = '';
		$on_error = static function ( $wp_error ) use ( &$error ) {
			if ( is_wp_error( $wp_error ) ) {
				$error = $wp_error->get_error_message();
			}
		};
		add_action( 'wp_mail_failed', $on_error );

		$notifier = self::service( 'notifier' );
		if ( $a === $b && $notifier && method_exists( $notifier, 'send_test' ) ) {
			try {
				$ok = (bool) $notifier->send_test();
			} catch ( \Throwable $e ) {
				$ok    = false;
				$error = $e->getMessage();
			}
		} else {
			$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
			/* translators: %s: site name */
			$subject = sprintf( __( '[%s] Qartvelo Guard test email', 'qartvelo-guard' ), $site );
			$body    = __( 'This is a test message from Qartvelo Guard.', 'qartvelo-guard' ) . "\n\n"
				/* translators: %s: site address */
				. sprintf( __( 'Alerts for %s will be sent to this address once you save the settings.', 'qartvelo-guard' ), home_url( '/' ) ) . "\n";
			$ok      = wp_mail( $emails, $subject, $body );
		}
		remove_action( 'wp_mail_failed', $on_error );

		if ( $ok ) {
			return true;
		}
		$message = __( 'WordPress could not send the email. The server may not be set up to send mail; an SMTP plugin usually fixes this.', 'qartvelo-guard' );
		if ( $error ) {
			$message .= ' (' . $error . ')';
		}
		return new \WP_Error( 'wpcybersec_mail', $message );
	}

	/**
	 * @param string[] $emails Recipients.
	 * @return string
	 */
	private static function test_sent_message( array $emails ) {
		/* translators: %s: email addresses */
		return sprintf( __( 'Test email sent to %s. If it does not arrive within a few minutes, check the spam folder.', 'qartvelo-guard' ), implode( ', ', $emails ) );
	}

	/**
	 * AJAX: sends a test email to the addresses typed in the form.
	 */
	public function ajax_test_email() {
		if ( ! check_ajax_referer( Ajax::NONCE, '_ajax_nonce', false ) ) {
			wp_send_json_error( array( 'message' => __( 'Your session expired. Reload the page and try again.', 'qartvelo-guard' ) ), 403 );
		}
		if ( ! self::user_can_manage() ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'qartvelo-guard' ) ), 403 );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above.
		$raw    = isset( $_POST['emails'] ) ? sanitize_textarea_field( wp_unslash( $_POST['emails'] ) ) : '';
		$typed  = self::parse_list( $raw );
		$valid  = array_values( array_filter( array_map( 'sanitize_email', $typed ), 'is_email' ) );
		if ( $typed && ! $valid ) {
			wp_send_json_error( array( 'message' => __( 'None of the email addresses is valid.', 'qartvelo-guard' ) ) );
		}
		$result = $this->send_test_email( $valid );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		$settings = self::service( 'settings' );
		$sent_to  = $valid ? $valid : ( $settings ? $settings->recipients() : Network::default_recipients() );
		wp_send_json_success( array( 'message' => self::test_sent_message( $sent_to ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* admin-post handlers                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * Wizard form: saves the posted step and moves to the next one.
	 */
	public function handle_wizard() {
		$this->check_request( 'wpcybersec_wizard' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in check_request().
		$steps = array_keys( Admin\Wizard::steps() );
		$step  = isset( $_POST['step'] ) ? sanitize_key( wp_unslash( $_POST['step'] ) ) : '';
		$step  = in_array( $step, $steps, true ) ? $step : $steps[0];
		$nav   = isset( $_POST['wpcs_nav'] ) ? sanitize_key( wp_unslash( $_POST['wpcs_nav'] ) ) : 'next';
		$do    = isset( $_POST['wpcs_do'] ) ? sanitize_key( wp_unslash( $_POST['wpcs_do'] ) ) : '';
		$post  = wp_unslash( $_POST );
		// phpcs:enable

		if ( '' !== $do && in_array( $do, self::WIZARD_ACTIONS, true ) ) {
			$this->wizard_action( $do, $post );
			$this->redirect( self::wizard_url( $step ) );
		}

		if ( 'next' === $nav ) {
			$this->save_wizard_step( $step, $post );
		}

		$index  = (int) array_search( $step, $steps, true );
		$target = 'back' === $nav ? $steps[ max( 0, $index - 1 ) ] : $steps[ min( count( $steps ) - 1, $index + 1 ) ];

		if ( 'done' === $target ) {
			$settings = self::service( 'settings' );
			if ( $settings && ! $settings->get( 'wizard_completed', false ) ) {
				$settings->update( array( 'wizard_completed' => true ) );
				self::log( 'wizard_completed', __( 'Setup wizard completed.', 'qartvelo-guard' ) );
			}
		}
		$this->redirect( self::wizard_url( $target ) );
	}

	/**
	 * Quick actions inside a wizard step.
	 *
	 * @param string $do   Action.
	 * @param array  $post Unslashed POST data.
	 */
	private function wizard_action( $do, array $post ) {
		if ( 'write_htaccess' === $do ) {
			$this->flash_htaccess_result( $this->write_uploads_htaccess() );
			return;
		}
		if ( 'probe' === $do ) {
			$uploads    = $this->probe_uploads_php();
			$quarantine = $this->probe_quarantine_web( true );
			$problems   = ( 'executed' === $uploads['result'] ? 1 : 0 ) + ( 'reachable' === $quarantine['result'] ? 1 : 0 );
			if ( $problems ) {
				self::flash( __( 'Live tests finished. See the highlighted checks below.', 'qartvelo-guard' ), 'warn' );
			} elseif ( 'unknown' === $uploads['result'] && $uploads['message'] ) {
				self::flash( $uploads['message'], 'info' );
			} else {
				self::flash( __( 'Live tests finished: PHP does not run in uploads and the quarantine cannot be downloaded.', 'qartvelo-guard' ), 'ok' );
			}
			return;
		}
		if ( 'recommended_uploads' === $do ) {
			// "Use this" on the Protection step: Balanced, but only risky uploads are held.
			$settings = self::service( 'settings' );
			if ( $settings ) {
				$presets = Settings::presets();
				$values  = array_merge(
					$presets['balanced'],
					array(
						'upload_mode'  => 'hold_risky',
						'install_mode' => 'hold',
					)
				);
				$values['protection_level'] = $this->match_level( array_merge( $settings->all(), $values ), 'balanced' );
				$settings->update( $values );
				self::log( 'settings_saved', __( 'Setup wizard: Balanced protection, holding only risky uploads.', 'qartvelo-guard' ) );
				self::flash( __( 'Applied: Balanced protection, but only risky uploads are held. Clean images and documents pass after the malware scan; new plugins and themes still wait for you. You can change it below.', 'qartvelo-guard' ), 'ok' );
			}
			return;
		}
		if ( 'send_test' === $do ) {
			$warnings = array();
			$values   = $this->collect_notifications( $post, $warnings );
			$settings = self::service( 'settings' );
			if ( $settings ) {
				$settings->update( $values );
			}
			foreach ( $warnings as $warning ) {
				self::flash( $warning, 'warn' );
			}
			$result = $this->send_test_email();
			if ( is_wp_error( $result ) ) {
				self::flash( $result->get_error_message(), 'bad' );
			} else {
				self::flash( __( 'Saved.', 'qartvelo-guard' ) . ' ' . self::test_sent_message( $settings ? $settings->recipients() : Network::default_recipients() ), 'ok' );
			}
		}
	}

	/**
	 * Media Library uploads of the last 30 days: how many a day, and the share
	 * of users who are not administrators (they cannot approve their own files).
	 * One grouped query on the attachment index, cached for an hour; the main
	 * site's library on a network.
	 *
	 * @return array { days, total, per_day (float), non_admin (int), non_admin_pct (int) }
	 */
	public function upload_activity() {
		$cached = Network::get_transient( 'wpcybersec_upload_activity' );
		if ( is_array( $cached ) && isset( $cached['per_day'] ) ) {
			return $cached;
		}
		$days   = 30;
		$result = Network::on_main(
			static function () use ( $days ) {
				global $wpdb;
				$since = wp_date( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one grouped count, cached by the caller.
				$rows = $wpdb->get_results( $wpdb->prepare( "SELECT post_author, COUNT(*) AS n FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_status = 'inherit' AND post_date >= %s GROUP BY post_author ORDER BY n DESC LIMIT 1000", $since ), ARRAY_A );
				$total     = 0;
				$non_admin = 0;
				$ids       = array();
				foreach ( (array) $rows as $row ) {
					if ( (int) $row['post_author'] > 0 ) {
						$ids[] = (int) $row['post_author'];
					}
				}
				if ( $ids && function_exists( 'cache_users' ) ) {
					cache_users( $ids ); // One query for every author.
				}
				foreach ( (array) $rows as $row ) {
					$n      = (int) $row['n'];
					$author = (int) $row['post_author'];
					$total += $n;
					if ( $author < 1 || ! user_can( $author, 'manage_options' ) ) {
						$non_admin += $n;
					}
				}
				return array(
					'days'          => $days,
					'total'         => $total,
					'per_day'       => round( $total / $days, 1 ),
					'non_admin'     => $non_admin,
					'non_admin_pct' => $total ? (int) round( $non_admin * 100 / $total ) : 0,
				);
			}
		);
		Network::set_transient( 'wpcybersec_upload_activity', $result, HOUR_IN_SECONDS );
		return $result;
	}

	/**
	 * Saves the settings of one wizard step.
	 *
	 * @param string $step Step.
	 * @param array  $post Unslashed POST data.
	 */
	private function save_wizard_step( $step, array $post ) {
		$settings = self::service( 'settings' );
		if ( ! $settings ) {
			return;
		}
		switch ( $step ) {
			case 'protection':
				$presets = Settings::presets();
				$level   = isset( $post['level'] ) ? sanitize_key( $post['level'] ) : '';
				$base    = isset( $presets[ $level ] ) ? $presets[ $level ] : array();
				$values  = $base;

				$roles = isset( $base['upload_bypass_roles'] ) ? (array) $base['upload_bypass_roles'] : (array) $settings->get( 'upload_bypass_roles', array() );
				if ( ! empty( $post['hold_admin_uploads'] ) ) {
					$roles = array_values( array_diff( $roles, array( 'administrator' ) ) );
				} elseif ( ! in_array( 'administrator', $roles, true ) ) {
					$roles[] = 'administrator';
				}
				$values['upload_bypass_roles'] = $roles;
				if ( isset( $post['upload_mode'] ) && in_array( $post['upload_mode'], array( 'hold_all', 'hold_risky' ), true ) ) {
					$values['upload_mode'] = $post['upload_mode'];
				}
				$values['install_mode']        = ! empty( $post['hold_installs'] ) ? 'hold' : 'off';
				$values['file_mode']           = ! empty( $post['quarantine_php'] ) ? 'quarantine_exec' : 'report';

				$values['protection_level'] = $this->match_level( array_merge( $settings->all(), $values ), $level );
				$settings->update( $values );
				break;

			case 'notifications':
				$warnings = array();
				$values   = $this->collect_notifications( $post, $warnings );
				if ( isset( $post['share_stats'] ) ) {
					$values['share_stats'] = self::post_bool( $post, 'share_stats' );
				}
				$settings->update( $values );
				foreach ( $warnings as $warning ) {
					self::flash( $warning, 'warn' );
				}
				break;

			case 'hardening':
				$settings->update( array( 'freeze_mods' => ! empty( $post['freeze_mods'] ) ) );
				break;
		}
	}

	/**
	 * Which preset (if any) the given settings match.
	 *
	 * @param array  $values    Settings (merged over the current ones).
	 * @param string $preferred Level to prefer when several match.
	 * @return string strict | balanced | relaxed | custom.
	 */
	public function match_level( array $values, $preferred = '' ) {
		$settings = self::service( 'settings' );
		$values   = $settings ? $settings->sanitize( $values ) : $values;
		$matches  = array();
		foreach ( Settings::presets() as $name => $preset ) {
			$same = true;
			foreach ( $preset as $key => $expected ) {
				if ( in_array( $key, self::LEVEL_IGNORE, true ) ) {
					continue;
				}
				$actual = isset( $values[ $key ] ) ? $values[ $key ] : null;
				if ( is_array( $expected ) ) {
					$x = array_values( (array) $actual );
					$y = array_values( $expected );
					sort( $x );
					sort( $y );
					if ( $x !== $y ) {
						$same = false;
						break;
					}
				} elseif ( is_bool( $expected ) ) {
					if ( (bool) $actual !== $expected ) {
						$same = false;
						break;
					}
				} elseif ( (string) $actual !== (string) $expected ) {
					$same = false;
					break;
				}
			}
			if ( $same ) {
				$matches[] = $name;
			}
		}
		if ( $preferred && in_array( $preferred, $matches, true ) ) {
			return $preferred;
		}
		return $matches ? $matches[0] : 'custom';
	}

	/**
	 * Reads the notification fields of a form.
	 *
	 * @param array    $post     Unslashed POST data.
	 * @param string[] $warnings Receives warnings.
	 * @return array Settings values.
	 */
	private function collect_notifications( array $post, array &$warnings ) {
		$values = array();
		$enums    = Settings::enums();

		if ( isset( $post['notify_mode'] ) && in_array( $post['notify_mode'], $enums['notify_mode'], true ) ) {
			$values['notify_mode'] = $post['notify_mode'];
		}
		if ( isset( $post['notify_emails'] ) ) {
			$typed   = self::parse_list( is_array( $post['notify_emails'] ) ? implode( "\n", $post['notify_emails'] ) : sanitize_textarea_field( (string) $post['notify_emails'] ) );
			$valid   = array();
			$invalid = array();
			foreach ( $typed as $email ) {
				$clean = sanitize_email( $email );
				if ( $clean && is_email( $clean ) ) {
					$valid[] = $clean;
				} else {
					$invalid[] = $email;
				}
			}
			if ( $invalid ) {
				/* translators: %s: invalid email addresses */
				$warnings[] = sprintf( __( 'These addresses are not valid and were not saved: %s', 'qartvelo-guard' ), implode( ', ', $invalid ) );
			}
			$values['notify_emails'] = $valid;
		}
		if ( isset( $post['webhook_url'] ) ) {
			$raw = trim( sanitize_text_field( (string) $post['webhook_url'] ) );
			if ( '' === $raw ) {
				$values['webhook_url'] = '';
			} else {
				$url = esc_url_raw( $raw, array( 'https' ) );
				if ( '' === $url || 0 !== strpos( strtolower( $url ), 'https://' ) ) {
					$warnings[] = __( 'The webhook URL must start with https://. The previous value was kept.', 'qartvelo-guard' );
				} else {
					$values['webhook_url'] = $url;
				}
			}
		}
		return $values;
	}

	/**
	 * @param array  $post Unslashed POST data.
	 * @param string $key  Key.
	 * @return bool Checkbox value (hidden "0" + checkbox "1" pattern).
	 */
	private static function post_bool( array $post, $key ) {
		return isset( $post[ $key ] ) && ! is_array( $post[ $key ] ) && '1' === (string) $post[ $key ];
	}

	/**
	 * @param array  $post    Unslashed POST data.
	 * @param string $key     Enum key.
	 * @param string $current Current value (kept when the posted one is invalid).
	 * @return string
	 */
	private static function post_enum( array $post, $key, $current ) {
		$enums = Settings::enums();
		if ( isset( $post[ $key ] ) && ! is_array( $post[ $key ] ) && isset( $enums[ $key ] ) && in_array( (string) $post[ $key ], $enums[ $key ], true ) ) {
			return (string) $post[ $key ];
		}
		return $current;
	}

	/**
	 * Settings page: saves one tab.
	 */
	public function handle_save_settings() {
		$this->check_request( 'wpcybersec_save_settings' );
		$settings = self::service( 'settings' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in check_request().
		$post = wp_unslash( $_POST );
		$tab  = ( isset( $post['tab'] ) && 'advanced' === $post['tab'] ) ? 'advanced' : 'general';
		if ( ! $settings ) {
			self::flash( __( 'Settings are not available.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( self::settings_url( $tab ) );
		}

		$old      = $settings->all();
		$warnings = array();
		$values   = 'advanced' === $tab ? $this->collect_advanced( $post, $old, $warnings ) : $this->collect_general( $post, $old, $warnings );
		$new      = $settings->update( $values );
		if ( 'advanced' === $tab && ! empty( $new['clamav_enabled'] ) && empty( $old['clamav_enabled'] ) ) {
			// The toggle was switched on: refuse it like the one-click button when ClamAV does not work.
			$clam = $this->antivirus_status()['clamav'];
			if ( in_array( $clam['state'], array( 'missing', 'blocked', 'broken' ), true ) ) {
				$new = $settings->update( array( 'clamav_enabled' => false ) );
				/* translators: %s: why ClamAV does not work */
				$warnings[] = sprintf( __( 'ClamAV scanning was left off because ClamAV does not work on this server: %s', 'qartvelo-guard' ), 'broken' === $clam['state'] && '' !== $clam['error'] ? $clam['error'] : $clam['label'] );
			}
		}

		self::log(
			'settings_saved',
			/* translators: %s: tab name */
			sprintf( __( 'Settings saved (%s).', 'qartvelo-guard' ), 'advanced' === $tab ? __( 'Advanced', 'qartvelo-guard' ) : __( 'General', 'qartvelo-guard' ) ),
			array( 'changed' => array_keys( array_diff_assoc( array_map( 'wp_json_encode', $new ), array_map( 'wp_json_encode', $old ) ) ) )
		);

		foreach ( $warnings as $warning ) {
			self::flash( $warning, 'warn' );
		}
		if ( 'advanced' === $tab && ( $new['scan_root'] !== $old['scan_root'] || $new['scan_root_custom'] !== $old['scan_root_custom'] ) ) {
			// forget_baseline_on_root_change() already dropped the old baseline.
			self::flash( __( 'The scan folder changed, so the old baseline no longer applies. Rebuild the baseline from the Dashboard now; otherwise the next scan records it.', 'qartvelo-guard' ), 'warn' );
		}
		if ( 'general' === $tab && ! empty( $post['wpcs_send_test'] ) ) {
			$result = $this->send_test_email();
			if ( is_wp_error( $result ) ) {
				self::flash( $result->get_error_message(), 'bad' );
			} else {
				self::flash( self::test_sent_message( $settings->recipients() ), 'ok' );
			}
		}
		$args = array( 'settings-updated' => 1 );
		// Back to the section of Advanced that was open when Save was pressed.
		$section = isset( $post['section'] ) ? substr( sanitize_key( (string) $post['section'] ), 0, 32 ) : '';
		if ( 'advanced' === $tab && '' !== $section ) {
			$args['section'] = $section;
		}
		$this->redirect( self::settings_url( $tab, $args ) );
	}

	/**
	 * General tab fields.
	 *
	 * @param array    $post     Unslashed POST data.
	 * @param array    $old      Current settings.
	 * @param string[] $warnings Receives warnings.
	 * @return array
	 */
	private function collect_general( array $post, array $old, array &$warnings ) {
		$values = array(
			'upload_mode'     => self::post_enum( $post, 'upload_mode', $old['upload_mode'] ),
			'gate_sideloads'  => self::post_bool( $post, 'gate_sideloads' ),
			'install_mode'    => ( isset( $post['install_mode'] ) && 'hold' === $post['install_mode'] ) ? 'hold' : 'off',
			'hold_updates'    => self::post_bool( $post, 'hold_updates' ),
			'file_mode'       => self::post_enum( $post, 'file_mode', $old['file_mode'] ),
			'modified_action' => self::post_enum( $post, 'modified_action', $old['modified_action'] ),
			'auto_quarantine' => self::post_bool( $post, 'auto_quarantine' ),
			'scan_schedule'   => self::post_enum( $post, 'scan_schedule', $old['scan_schedule'] ),
			'scan_malware'    => self::post_bool( $post, 'scan_malware' ),
			'use_checksums'   => self::post_bool( $post, 'use_checksums' ),
			'min_severity'    => isset( $post['min_severity'] ) ? max( 1, min( 3, (int) $post['min_severity'] ) ) : $old['min_severity'],
			'snapshots'       => self::post_bool( $post, 'snapshots' ),
			'snapshot_max_kb' => isset( $post['snapshot_max_kb'] ) ? max( 16, min( 4096, (int) $post['snapshot_max_kb'] ) ) : $old['snapshot_max_kb'],
			'snapshot_max_files' => isset( $post['snapshot_max_files'] ) ? max( 1000, min( 1000000, (int) $post['snapshot_max_files'] ) ) : $old['snapshot_max_files'],
			'snapshot_max_mb'    => isset( $post['snapshot_max_mb'] ) ? max( 10, min( 10240, (int) $post['snapshot_max_mb'] ) ) : $old['snapshot_max_mb'],
		);

		$valid_roles = function_exists( 'wp_roles' ) ? array_keys( wp_roles()->get_names() ) : array( 'administrator' );
		$roles       = ( isset( $post['upload_bypass_roles'] ) && is_array( $post['upload_bypass_roles'] ) ) ? array_map( 'sanitize_key', $post['upload_bypass_roles'] ) : array();
		$values['upload_bypass_roles'] = array_values( array_intersect( $roles, $valid_roles ) );

		$values = array_merge( $values, $this->collect_notifications( $post, $warnings ) );
		if ( isset( $post['share_stats'] ) ) {
			$values['share_stats'] = self::post_bool( $post, 'share_stats' );
		}

		// Protection level: a level picked without JavaScript applies its preset.
		$presets = Settings::presets();
		$posted  = isset( $post['protection_level'] ) ? sanitize_key( (string) $post['protection_level'] ) : '';
		$synced  = ! empty( $post['wpcs_level_synced'] );
		if ( isset( $presets[ $posted ] ) && $posted !== $old['protection_level'] && ! $synced ) {
			$values = array_merge( $values, $presets[ $posted ] );
		}
		$values['protection_level'] = $this->match_level( array_merge( $old, $values ), $posted );
		return $values;
	}

	/**
	 * Advanced tab fields.
	 *
	 * @param array    $post     Unslashed POST data.
	 * @param array    $old      Current settings.
	 * @param string[] $warnings Receives warnings.
	 * @return array
	 */
	private function collect_advanced( array $post, array $old, array &$warnings ) {
		$values = array(
			'scan_root'                => self::post_enum( $post, 'scan_root', $old['scan_root'] ),
			'max_file_mb'              => isset( $post['max_file_mb'] ) ? (int) $post['max_file_mb'] : $old['max_file_mb'],
			'tick_seconds'             => isset( $post['tick_seconds'] ) ? (int) $post['tick_seconds'] : $old['tick_seconds'],
			'guard_action'             => self::post_enum( $post, 'guard_action', $old['guard_action'] ),
			'freeze_mods'              => self::post_bool( $post, 'freeze_mods' ),
			'disable_file_editor'      => self::post_bool( $post, 'disable_file_editor' ),
			'unlock_minutes'           => isset( $post['unlock_minutes'] ) ? (int) $post['unlock_minutes'] : $old['unlock_minutes'],
			'clamav_enabled'           => self::post_bool( $post, 'clamav_enabled' ),
			'hosting_panel'            => isset( $post['hosting_panel'] ) ? sanitize_key( (string) $post['hosting_panel'] ) : $old['hosting_panel'],
			'log_retention_days'       => isset( $post['log_retention_days'] ) ? (int) $post['log_retention_days'] : $old['log_retention_days'],
			'delete_data_on_uninstall' => self::post_bool( $post, 'delete_data_on_uninstall' ),
		);

		if ( 'custom' === $values['scan_root'] ) {
			$raw  = isset( $post['scan_root_custom'] ) ? (string) $post['scan_root_custom'] : '';
			$path = $this->validate_scan_root( $raw, $warnings );
			if ( null === $path ) {
				$values['scan_root'] = $old['scan_root'];
			} else {
				$values['scan_root_custom'] = $path;
			}
		}

		if ( isset( $post['exclusions'] ) ) {
			$values['exclusions'] = $this->clean_exclusions( $post['exclusions'], $warnings );
		}
		if ( isset( $post['exec_extensions'] ) ) {
			$values['exec_extensions'] = $this->clean_extensions( $post['exec_extensions'], $warnings );
		}
		if ( isset( $post['exec_filenames'] ) ) {
			$names                    = self::parse_list( $post['exec_filenames'] );
			$values['exec_filenames'] = array_values( array_unique( array_merge( array( '.htaccess', '.user.ini' ), array_map( 'strtolower', $names ) ) ) );
		}
		if ( isset( $post['guard_exempt'] ) ) {
			$values['guard_exempt'] = self::parse_list( $post['guard_exempt'] );
		}
		if ( isset( $post['clamav_binary'] ) ) {
			$binary = $this->validate_clamav_binary( (string) $post['clamav_binary'], $warnings );
			if ( null !== $binary ) {
				$values['clamav_binary'] = $binary;
			}
		}
		if ( isset( $post['clamav_slow_uploads'] ) ) {
			// Kept outside the settings array: Settings::sanitize() keeps only its own keys.
			Network::update_option( Scanner::FORCE_SLOW_OPTION, self::post_bool( $post, 'clamav_slow_uploads' ), false );
		}
		return $values;
	}

	/**
	 * Before "Turn on ClamAV" (Ajax::clamav_enable()): runs the self-test and
	 * refuses with the reason when no ClamAV binary works. When only a slow
	 * clamscan works it is turned on here, with a message that says what it
	 * is used for. Otherwise Ajax::clamav_enable() continues as usual.
	 */
	public function ajax_clamav_precheck() {
		if ( ! check_ajax_referer( Ajax::NONCE, '_ajax_nonce', false ) || ! Admin\Admin::can() ) {
			return; // Ajax::clamav_enable() answers with its own error.
		}
		$scanner  = self::service( 'scanner' );
		$settings = self::service( 'settings' );
		if ( ! $scanner || ! method_exists( $scanner, 'clamav_selftest' ) || ! $settings ) {
			return;
		}
		$scanner->clamav_selftest( true );
		$clam = $this->antivirus_status()['clamav'];
		if ( in_array( $clam['state'], array( 'missing', 'blocked', 'broken' ), true ) ) {
			$message = 'broken' === $clam['state']
				/* translators: %s: why ClamAV does not work */
				? sprintf( __( 'ClamAV was not turned on because its self-test failed: %s', 'qartvelo-guard' ), '' !== $clam['error'] ? $clam['error'] : $clam['label'] )
				/* translators: %s: ClamAV state */
				: sprintf( __( 'ClamAV was not turned on: %s.', 'qartvelo-guard' ), $clam['label'] );
			if ( '' !== $clam['hint'] ) {
				$message .= ' ' . $clam['hint'] . ( '' !== $clam['hint_code'] ? ' ' . $clam['hint_code'] : '' );
			}
			wp_send_json_error( array( 'message' => $message ) );
		}
		if ( ! empty( $clam['slow_only'] ) && empty( $clam['forced'] ) ) {
			$settings->update( array( 'clamav_enabled' => true ) );
			$message = sprintf(
				/* translators: %s: time per file, for example "6.6 s" */
				__( 'ClamAV is on, but only the slow clamscan works here (about %s per file), so uploads are not scanned with it while someone waits; held uploads the early guard imports by cron are. Start the clamd service for fast scans of every upload.', 'qartvelo-guard' ),
				self::duration_ms( $clam['scan_ms'] )
			);
			self::log( 'clamav_enabled', $message );
			wp_send_json_success( array( 'message' => $message ) );
		}
	}

	/**
	 * @param string   $raw      Path typed by the administrator.
	 * @param string[] $warnings Receives warnings.
	 * @return string|null Normalized real path, or null when invalid.
	 */
	public function validate_scan_root( $raw, array &$warnings ) {
		$raw = trim( sanitize_text_field( (string) $raw ) );
		if ( '' === $raw ) {
			$warnings[] = __( 'Enter a folder for the custom scan scope. The previous scope was kept.', 'qartvelo-guard' );
			return null;
		}
		$real = @realpath( $raw ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $real || ! @is_dir( $real ) || ! @is_readable( $real ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			/* translators: %s: folder path */
			$warnings[] = sprintf( __( 'The folder %s does not exist or cannot be read. The previous scan scope was kept.', 'qartvelo-guard' ), $raw );
			return null;
		}
		$real  = untrailingslashit( wp_normalize_path( $real ) );
		$depth = count( array_filter( explode( '/', preg_replace( '#^[a-zA-Z]:#', '', $real ) ), 'strlen' ) );
		if ( $depth < 2 ) {
			/* translators: %s: folder path */
			$warnings[] = sprintf( __( '%s is too close to the top of the file system to scan safely. The previous scan scope was kept.', 'qartvelo-guard' ), '' === $real ? '/' : $real );
			return null;
		}
		if ( ! Storage::is_within( ABSPATH, $real ) ) {
			$warnings[] = __( 'Note: WordPress itself is outside the custom scan folder, so its files are not checked.', 'qartvelo-guard' );
		}
		return $real;
	}

	/**
	 * @param string   $raw      Path typed by the administrator.
	 * @param string[] $warnings Receives warnings.
	 * @return string|null '' for auto-detect, the path, or null when invalid.
	 */
	public function validate_clamav_binary( $raw, array &$warnings ) {
		$raw = trim( sanitize_text_field( (string) $raw ) );
		if ( '' === $raw ) {
			return '';
		}
		$real = @realpath( $raw ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $real || ! @is_file( $real ) || ! @is_executable( $real ) || ! preg_match( '/^clamd?scan(\.exe)?$/i', basename( $real ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			/* translators: %s: path */
			$warnings[] = sprintf( __( '%s is not an executable clamscan or clamdscan binary. The previous value was kept.', 'qartvelo-guard' ), $raw );
			return null;
		}
		return wp_normalize_path( $real );
	}

	/**
	 * @param mixed    $raw      Textarea or list.
	 * @param string[] $warnings Receives warnings.
	 * @return string[]
	 */
	private function clean_exclusions( $raw, array &$warnings ) {
		$out = array();
		foreach ( self::parse_list( is_array( $raw ) ? $raw : preg_split( '/\R/', (string) $raw ) ) as $pattern ) {
			$pattern = ltrim( wp_normalize_path( $pattern ), '/' );
			if ( in_array( $pattern, array( '', '*', '**', '/', './', '.', '*/' ), true ) ) {
				/* translators: %s: exclusion pattern */
				$warnings[] = sprintf( __( 'The exclusion "%s" would hide every file and was removed.', 'qartvelo-guard' ), $pattern );
				continue;
			}
			if ( preg_match( '/^\*\.(php\d?|phtml|phar)$/i', $pattern ) ) {
				/* translators: %s: exclusion pattern */
				$warnings[] = sprintf( __( 'The exclusion "%s" hides PHP files from every scan. Keep it only if you are sure.', 'qartvelo-guard' ), $pattern );
			}
			$out[] = $pattern;
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * @param mixed    $raw      Text or list.
	 * @param string[] $warnings Receives warnings.
	 * @return string[]
	 */
	private function clean_extensions( $raw, array &$warnings ) {
		$exts = array();
		foreach ( self::parse_list( $raw ) as $ext ) {
			$ext = strtolower( ltrim( $ext, '.' ) );
			if ( preg_match( '/^[a-z0-9]{1,10}$/', $ext ) ) {
				$exts[] = $ext;
			}
		}
		$required = array( 'php', 'phtml', 'phar' );
		$missing  = array_diff( $required, $exts );
		if ( $missing ) {
			/* translators: %s: file extensions */
			$warnings[] = sprintf( __( 'These extensions are always treated as executable and were added back: %s', 'qartvelo-guard' ), implode( ', ', $missing ) );
		}
		return array_values( array_unique( array_merge( $required, $exts ) ) );
	}

	/**
	 * Early guard: install, uninstall or write .user.ini.
	 */
	public function handle_guard() {
		$this->check_request( 'wpcybersec_guard' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified in check_request().
		$op      = isset( $_REQUEST['op'] ) ? sanitize_key( wp_unslash( $_REQUEST['op'] ) ) : '';
		$methods = array(
			'install'        => 'install',
			'uninstall'      => 'uninstall',
			'write_user_ini' => 'write_user_ini',
		);
		$back    = self::settings_url( 'advanced', array(), 'wpcs-guard' );
		$manager = self::service( 'guard_manager' );
		if ( in_array( $op, array( 'ping', 'enable' ), true ) ) {
			// "Test again" and the one-click install without JavaScript.
			$hardening = self::service( 'hardening' );
			if ( ! $hardening || ! method_exists( $hardening, 'run' ) ) {
				self::flash( __( 'The early guard module is not available in this installation.', 'qartvelo-guard' ), 'bad' );
				$this->redirect( $back );
			}
			if ( 'ping' === $op ) {
				$texts = array(
					'active'   => array( __( 'Live test: PHP loads the early guard.', 'qartvelo-guard' ), 'ok' ),
					'inactive' => array( __( 'Live test: the site answered, but PHP did not load the early guard.', 'qartvelo-guard' ), 'warn' ),
					'down'     => array( __( 'Live test: the site did not answer (server error).', 'qartvelo-guard' ), 'bad' ),
					'unknown'  => array( __( 'Live test: the site did not answer its own test request (a firewall, an HTTP password or a slow server can cause this), so nothing changed.', 'qartvelo-guard' ), 'info' ),
				);
				$result = $hardening->reping( 10 );
				$text   = isset( $texts[ $result ] ) ? $texts[ $result ] : $texts['unknown'];
				$ols    = 'inactive' === $result ? Guard_Manager::ols_activation_step() : null;
				if ( $ols ) {
					// OpenLiteSpeed: the line is there, lsphp has not read it. Say what to run.
					$text[0] .= ' ' . $ols['inline'];
				}
				self::flash( $text[0], $text[1] );
			} else {
				$result = $hardening->run( 'guard' );
				self::flash( is_wp_error( $result ) ? $result->get_error_message() : ( is_string( $result ) ? $result : __( 'Fixed.', 'qartvelo-guard' ) ), is_wp_error( $result ) ? 'bad' : 'ok' );
			}
			$this->redirect( $back );
		}
		if ( ! isset( $methods[ $op ] ) ) {
			self::flash( __( 'Unknown action.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( $back );
		}
		if ( ! $manager || ! method_exists( $manager, $methods[ $op ] ) ) {
			self::flash( __( 'The early guard module is not available in this installation.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( $back );
		}
		if ( 'write_user_ini' === $op && ( ! method_exists( $manager, 'bootstrap_path' ) || ! is_file( $manager->bootstrap_path() ) ) ) {
			// A prepend line pointing at a missing file would stop every PHP request.
			self::flash( __( 'Install the guard files first: .user.ini must not point at a file that does not exist.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( $back );
		}
		try {
			$result = call_user_func( array( $manager, $methods[ $op ] ) );
		} catch ( \Throwable $e ) {
			$result = new \WP_Error( 'wpcybersec_guard', $e->getMessage() );
		}
		if ( is_wp_error( $result ) ) {
			self::flash( $result->get_error_message(), 'bad' );
			if ( 'uninstall' !== $op ) {
				Developer_Instructions::record_failure( 'guard_' . $op, $result->get_error_message() );
			}
		} elseif ( false === $result ) {
			self::flash( __( 'The action did not complete. Check the file permissions of the WordPress folder and the data folder.', 'qartvelo-guard' ), 'bad' );
			if ( 'uninstall' !== $op ) {
				Developer_Instructions::record_failure( 'guard_' . $op, __( 'The action did not complete. Check the file permissions of the WordPress folder and the data folder.', 'qartvelo-guard' ) );
			}
		} else {
			if ( 'write_user_ini' === $op ) {
				Developer_Instructions::clear_failure( 'guard' );
			}
			$messages = array(
				'install'        => __( 'The guard files are installed. The guard starts working once PHP loads it through auto_prepend_file (the one-click button or the snippets below).', 'qartvelo-guard' ),
				'uninstall'      => __( 'Early guard switched off. If you added auto_prepend_file to the server configuration, remove that line too.', 'qartvelo-guard' ),
				'write_user_ini' => __( 'auto_prepend_file was added to .user.ini. PHP picks it up within 5 minutes (user_ini.cache_ttl).', 'qartvelo-guard' ),
			);
			$ols = 'write_user_ini' === $op ? Guard_Manager::ols_activation_step() : null;
			if ( $ols ) {
				// OpenLiteSpeed does not reread .user.ini by itself: "within 5 minutes" would not come true.
				$messages['write_user_ini'] = __( 'auto_prepend_file was added to .user.ini.', 'qartvelo-guard' ) . ' ' . $ols['inline'];
			}
			// Guard_Manager logs what it did (guard_installed, guard_user_ini, guard_uninstalled): one entry, not two.
			self::flash( $messages[ $op ], 'ok' );
		}
		$this->redirect( $back );
	}

	/**
	 * Downloads: settings JSON or the fapolicyd trust list.
	 */
	public function handle_export() {
		$this->check_request( 'wpcybersec_export' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified in check_request().
		$type = isset( $_REQUEST['type'] ) ? sanitize_key( wp_unslash( $_REQUEST['type'] ) ) : '';
		$host = sanitize_title( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$host = $host ? $host : 'site';

		if ( 'settings' === $type ) {
			$settings = self::service( 'settings' );
			$data     = array(
				'plugin'      => 'qartvelo-guard',
				'version'     => WPCYBERSEC_VERSION,
				'exported_at' => gmdate( 'c' ),
				'site'        => home_url( '/' ),
				'settings'    => $settings ? $settings->all() : array(),
			);
			unset( $data['settings']['wizard_completed'] );
			self::log( 'settings_exported', __( 'Settings exported.', 'qartvelo-guard' ) );
			nocache_headers();
			header( 'Content-Type: application/json; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="qartvelo-guard-settings-' . $host . '-' . gmdate( 'Ymd' ) . '.json"' );
			header( 'X-Content-Type-Options: nosniff' );
			echo wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON download.
			exit;
		}

		if ( 'fapolicyd' === $type ) {
			if ( function_exists( 'set_time_limit' ) ) {
				@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- building the fapolicyd trust list hashes every file of the site.
			}
			self::log( 'fapolicyd_exported', __( 'fapolicyd trust list downloaded.', 'qartvelo-guard' ) );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="wordpress-' . self::site_slug() . '.trust"' );
			header( 'X-Content-Type-Options: nosniff' );
			while ( ob_get_level() > 0 ) {
				ob_end_flush();
			}
			foreach ( $this->fapolicyd_trust_export() as $line ) {
				echo $line . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain text download.
			}
			exit;
		}

		self::flash( __( 'Unknown export type.', 'qartvelo-guard' ), 'bad' );
		$this->redirect( self::settings_url( 'advanced', array(), 'wpcs-transfer' ) );
	}

	/**
	 * Imports settings from an uploaded or pasted JSON export.
	 */
	public function handle_import() {
		$this->check_request( 'wpcybersec_import' );
		$back     = self::settings_url( 'advanced', array(), 'wpcs-transfer' );
		$settings = self::service( 'settings' );
		$max      = 512 * KB_IN_BYTES;
		$json     = '';

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in check_request().
		if ( ! empty( $_FILES['wpcs_import_file']['tmp_name'] ) && is_string( $_FILES['wpcs_import_file']['tmp_name'] ) ) {
			$file = $_FILES['wpcs_import_file']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated below.
			if ( ! isset( $file['error'] ) || UPLOAD_ERR_OK !== (int) $file['error'] || ! is_uploaded_file( $file['tmp_name'] ) ) {
				self::flash( __( 'The file could not be uploaded. If the early upload guard is active, paste the JSON instead.', 'qartvelo-guard' ), 'bad' );
				$this->redirect( $back );
			}
			if ( (int) $file['size'] > $max ) {
				self::flash( __( 'The file is too large to be a settings export.', 'qartvelo-guard' ), 'bad' );
				$this->redirect( $back );
			}
			$json = (string) file_get_contents( $file['tmp_name'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		} elseif ( isset( $_POST['wpcs_import_json'] ) && is_string( $_POST['wpcs_import_json'] ) ) {
			$json = trim( wp_unslash( $_POST['wpcs_import_json'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- JSON is decoded and every value sanitized by Settings.
		}
		// phpcs:enable

		if ( '' === $json ) {
			self::flash( __( 'Choose an export file or paste its content first.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( $back );
		}
		if ( strlen( $json ) > $max ) {
			self::flash( __( 'The pasted text is too large to be a settings export.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( $back );
		}
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) ) {
			self::flash( __( 'This is not valid JSON.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( $back );
		}
		if ( isset( $data['plugin'] ) && ! in_array( $data['plugin'], array( 'qartvelo-guard', 'cybergate-security', 'wp-cyber-security' ), true ) ) {
			self::flash( __( 'This file was not exported by Qartvelo Guard.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( $back );
		}
		$incoming = ( isset( $data['settings'] ) && is_array( $data['settings'] ) ) ? $data['settings'] : $data;
		$defaults = Settings::defaults();
		$values   = array();
		foreach ( array_intersect_key( $incoming, $defaults ) as $key => $value ) {
			// Consent to share statistics is given on each site itself, never copied from another one.
			if ( 'wizard_completed' === $key || 'share_stats' === $key ) {
				continue;
			}
			$default = $defaults[ $key ];
			if ( is_array( $default ) ? ! ( is_array( $value ) || is_string( $value ) ) : ! is_scalar( $value ) ) {
				continue;
			}
			// Decoded JSON is untrusted: text is sanitized here (newlines kept for
			// the list settings), and Settings::update() validates every key again.
			if ( is_string( $value ) ) {
				$value = sanitize_textarea_field( $value );
			} elseif ( is_array( $value ) ) {
				$value = map_deep( $value, static function ( $item ) {
					return is_string( $item ) ? sanitize_textarea_field( $item ) : ( is_scalar( $item ) ? $item : '' );
				} );
			}
			$values[ $key ] = $value;
		}

		$warnings = array();
		if ( isset( $values['scan_root_custom'] ) && '' !== (string) $values['scan_root_custom'] ) {
			$path = $this->validate_scan_root( (string) $values['scan_root_custom'], $warnings );
			if ( null === $path ) {
				unset( $values['scan_root_custom'] );
				if ( isset( $values['scan_root'] ) && 'custom' === $values['scan_root'] ) {
					unset( $values['scan_root'] );
				}
			} else {
				$values['scan_root_custom'] = $path;
			}
		}
		if ( isset( $values['clamav_binary'] ) ) {
			$binary = $this->validate_clamav_binary( (string) $values['clamav_binary'], $warnings );
			if ( null === $binary ) {
				unset( $values['clamav_binary'] );
			} else {
				$values['clamav_binary'] = $binary;
			}
		}
		if ( isset( $values['exec_extensions'] ) ) {
			$values['exec_extensions'] = $this->clean_extensions( $values['exec_extensions'], $warnings );
		}
		if ( isset( $values['exclusions'] ) ) {
			$values['exclusions'] = $this->clean_exclusions( $values['exclusions'], $warnings );
		}

		if ( ! $values || ! $settings ) {
			self::flash( __( 'No known settings were found in the import.', 'qartvelo-guard' ), 'bad' );
			$this->redirect( $back );
		}
		$settings->update( $values );
		/* translators: %d: number of settings */
		$message = sprintf( _n( 'Imported %d setting.', 'Imported %d settings.', count( $values ), 'qartvelo-guard' ), count( $values ) );
		self::log( 'settings_imported', $message, array( 'keys' => array_keys( $values ) ) );
		self::flash( $message, 'ok' );
		foreach ( $warnings as $warning ) {
			self::flash( $warning, 'warn' );
		}
		$this->redirect( $back );
	}

	/**
	 * Writes the uploads .htaccess block and returns to the previous page.
	 */
	public function handle_write_htaccess() {
		$this->check_request( 'wpcybersec_write_htaccess' );
		$this->flash_htaccess_result( $this->write_uploads_htaccess() );
		$this->redirect_back( self::settings_url( 'advanced', array(), 'wpcs-hardening' ) );
	}

	/**
	 * @param string|\WP_Error $result write_uploads_htaccess() result.
	 */
	private function flash_htaccess_result( $result ) {
		if ( is_wp_error( $result ) ) {
			self::flash( $result->get_error_message(), 'bad' );
			Developer_Instructions::record_failure( 'uploads_htaccess', $result->get_error_message() );
			return;
		}
		Developer_Instructions::clear_failure( 'uploads_htaccess' );
		if ( 'unchanged' === $result ) {
			self::flash( __( 'uploads/.htaccess already contains the current rules, and a live test confirmed that PHP does not run in uploads.', 'qartvelo-guard' ), 'info' );
		} elseif ( 'unverified' === $result ) {
			self::flash( __( 'The rules are in uploads/.htaccess, but the site could not test itself, so it is not confirmed that PHP no longer runs there. Run the live test again later.', 'qartvelo-guard' ), 'info' );
		} else {
			self::flash( __( 'Added the PHP blocking rules to uploads/.htaccess, and a live test confirmed that PHP no longer runs there. Other content in the file was kept.', 'qartvelo-guard' ), 'ok' );
		}
	}

	/**
	 * Deletes every stored file copy (Settings > Advanced > Data).
	 */
	public function handle_snapshots_clear() {
		$this->check_request( 'wpcybersec_snapshots_clear' );
		$snapshots = self::service( 'snapshots' );
		$deleted   = $snapshots ? (int) $snapshots->clear() : 0;
		/* translators: %s: number of files */
		$message = sprintf( _n( 'Deleted %s stored file copy.', 'Deleted %s stored file copies.', $deleted, 'qartvelo-guard' ), number_format_i18n( $deleted ) );
		self::log( 'snapshots_cleared', $message, array( 'deleted' => $deleted ) );
		self::flash( $message, 'ok' );
		$this->redirect( self::settings_url( 'advanced', array(), 'wpcs-data' ) );
	}

	/**
	 * Sends a test email to the saved recipients and returns to the previous page.
	 */
	public function handle_test_email() {
		$this->check_request( 'wpcybersec_test_email' );
		$result = $this->send_test_email();
		if ( is_wp_error( $result ) ) {
			self::flash( $result->get_error_message(), 'bad' );
		} else {
			$settings = self::service( 'settings' );
			self::flash( self::test_sent_message( $settings ? $settings->recipients() : Network::default_recipients() ), 'ok' );
		}
		$this->redirect_back( self::settings_url( 'general', array(), 'wpcs-notifications' ) );
	}
}
