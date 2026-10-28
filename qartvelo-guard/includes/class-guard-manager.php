<?php
/**
 * Early upload guard: installation, configuration, status and spool import.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * The guard (guard/guard.php) runs through PHP's auto_prepend_file before any
 * other code, so it also holds uploads sent to scripts outside WordPress. This
 * class writes its bootstrap and config, explains how to switch it on for the
 * server type, and imports what it held (the spool) into pending items.
 *
 * Files:
 *   ABSPATH/wpcybersec-guard.php      bootstrap that auto_prepend_file points to
 *   <data>/guard/config.php           config (Guard_Config)
 *   <data>/guard/allow.php            approved hashes (Allowlist::export_guard_file)
 *   <data>/quarantine/guard/YYYY/MM/  held copies (named by content)
 *   <data>/spool/guard-uploads.jsonl  one JSON line per held upload
 *   <data>/spool/guard-uploads.work.jsonl + .pos  lines taken out of the spool
 *                                     and the import position, so a request
 *                                     that dies while importing loses nothing
 */
class Guard_Manager {

	const INSTALLED_OPTION = 'wpcybersec_guard_installed';
	const CHAIN_OPTION     = 'wpcybersec_guard_chain';
	const BOOTSTRAP_FILE   = 'wpcybersec-guard.php';
	const IMPORT_HOOK      = 'wpcybersec_guard_import';
	const SCHEDULE         = 'wpcybersec_ten_minutes';
	const MARKER           = 'Qartvelo Guard early guard';
	/** Marker written by versions before 1.1.0 (CyberGate Security); still recognised and removed. */
	const LEGACY_MARKER    = 'CyberGate Security Guard';
	const FRONT_OPTION     = 'wpcybersec_front_root';

	/** Last live test of the guard: { at, result active|inactive|down, tried }. */
	const PING_OPTION = 'wpcybersec_guard_ping_result';

	/** A live test older than this is repeated in the background. */
	const PING_TTL = 6 * HOUR_IN_SECONDS;

	/** Log events that the one-click install replaces with one summary entry (set_quiet()). */
	const QUIET_EVENTS = array( 'guard_installed', 'guard_install_failed', 'guard_user_ini', 'guard_htaccess', 'guard_uninstalled' );

	/** Lines imported per cron run, and its time budget (seconds); the rest waits for the next run. */
	const IMPORT_BATCH   = 200;
	const IMPORT_SECONDS = 20;

	/** Lines imported on an administrator's admin page load, and its time budget. */
	const ADMIN_BATCH   = 5;
	const ADMIN_SECONDS = 3;

	/** Unfinished tries of one line after which it is imported without the signature scan. */
	const SCAN_TRIES = 2;

	/** Tries of one line before it is given up (database errors, or imports that keep dying). */
	const MAX_ATTEMPTS = 6;

	/**
	 * Nothing heavy here; see register().
	 */
	/** @var bool Leave the QUIET_EVENTS out of the activity log (set_quiet()). */
	private $quiet = false;

	/** @var bool An import is running: its log entries belong to the visitor, not to the signed-in user. */
	private $importing = false;

	public function __construct() {}

	/**
	 * Hooks.
	 */
	public function register() {
		add_filter( 'cron_schedules', array( $this, 'cron_schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval
		// Multisite: a new or deleted site changes the paths in the guard config.
		add_action( 'wp_initialize_site', array( $this, 'on_sites_changed' ), 200, 0 );
		add_action( 'wp_delete_site', array( $this, 'on_sites_changed' ), 200, 0 );
		add_action( self::IMPORT_HOOK, array( $this, 'cron_import' ) );
		add_action( 'admin_init', array( $this, 'admin_init' ) );
		// Admin pages: import before the menu badge and the Reports counts are computed
		// (admin_menu runs before admin_init). AJAX requests import on admin_init.
		if ( is_admin() && ! wp_doing_ajax() ) {
			add_action( 'init', array( $this, 'early_import' ), 1 );
		}
		add_action( 'wpcybersec_settings_updated', array( $this, 'on_settings_updated' ), 10, 0 );
		add_action( 'wpcybersec_allowlist_changed', array( $this, 'on_allowlist_changed' ), 10, 0 );

		// Uploads the guard held are imported by cron and on administrators' admin
		// pages only, never in the uploader's own (possibly anonymous) request, so
		// nobody can make the site scan files on demand.

		// Re-enable (or keep disabled) the config, in admin and cron requests only.
		// On init: the config holds translated messages, and WordPress 6.7+
		// warns when translations load before init.
		if ( is_admin() || wp_doing_cron() ) {
			add_action( 'init', array( $this, 'on_init' ), 20 );
		}
	}

	/**
	 * init: keeps the config in sync (see maintain()).
	 */
	public function on_init() {
		if ( ! Network::is_main() ) {
			return; // One network-level config, kept in sync from the main site (and Network Admin).
		}
		$this->maintain();
	}

	/**
	 * Adds the 10 minute interval of the spool import. Other plugins may run
	 * this filter before init (wp_get_schedules() while scheduling their own
	 * events); translating then would load translations too early (notice
	 * since WordPress 6.7), so the label stays English until init.
	 *
	 * @param array $schedules Schedules.
	 * @return array
	 */
	public function cron_schedules( $schedules ) {
		if ( is_array( $schedules ) && ! isset( $schedules[ self::SCHEDULE ] ) ) {
			$schedules[ self::SCHEDULE ] = array(
				'interval' => 10 * MINUTE_IN_SECONDS,
				'display'  => did_action( 'init' ) ? __( 'Every 10 minutes (Qartvelo Guard)', 'qartvelo-guard' ) : 'Every 10 minutes (Qartvelo Guard)',
			);
		}
		return $schedules;
	}

	/**
	 * admin_init: small bounded import for administrators (so held uploads show
	 * up on the Reports page right away) and self-healing of the bootstrap.
	 * admin_init also runs for anonymous admin-ajax.php requests, which must not
	 * be able to trigger signature scans.
	 */
	public function admin_init() {
		if ( Admin\Admin::can() && $this->has_pending() ) {
			$this->import_spool( self::ADMIN_BATCH, self::ADMIN_SECONDS, true );
		}
		if ( $this->is_installed() ) {
			if ( Network::is_main() ) {
				$this->ensure_cron();
			}
			$this->heal_bootstrap();
			$this->observe();
		} elseif ( Admin\Admin::can() ) {
			$this->refresh_leftover_bootstrap();
		}
	}

	/**
	 * init (admin pages only, priority 1): the same bounded import as
	 * admin_init(), early enough that the menu badge and the counts of the page
	 * already include what the guard held. Costs one stat when nothing waits.
	 */
	public function early_import() {
		if ( ! $this->has_pending() || ! Admin\Admin::can() ) {
			return;
		}
		$this->import_spool( self::ADMIN_BATCH, self::ADMIN_SECONDS, true );
	}

	/**
	 * A site was added to or removed from the network.
	 */
	public function on_sites_changed() {
		Network::reset();
		if ( $this->is_installed() ) {
			$this->sync_config();
		}
	}

	/**
	 * Settings changed: rewrite the config when the guard is in use.
	 */
	public function on_settings_updated() {
		if ( $this->is_installed() || is_file( Guard_Config::file() ) ) {
			$this->sync_config();
		}
	}

	/**
	 * Allowlist changed: Allowlist already re-exported allow.php; make sure a
	 * config exists for an installed guard.
	 */
	public function on_allowlist_changed() {
		if ( $this->is_installed() && ! is_file( Guard_Config::file() ) ) {
			$this->sync_config();
		}
	}

	/**
	 * Keeps the config's enabled flag equal to "installed" and the paths current.
	 */
	private function maintain() {
		$installed = $this->is_installed();
		$current   = Guard_Config::read();
		if ( ! $installed ) {
			// Plugin activation re-enables any existing config; an uninstalled guard stays off.
			if ( $current && ! empty( $current['enabled'] ) ) {
				Guard_Config::set_enabled( false );
			}
			return;
		}
		$wanted = $this->config_array();
		$keys   = array( 'enabled', 'action', 'quarantine_dir', 'spool_file', 'allow_file', 'exempt', 'max_bytes', 'max_spool_bytes', 'max_quarantine_files', 'max_quarantine_bytes', 'min_free_bytes', 'exec_extensions', 'exec_filenames', 'home_path', 'home_paths', 'login_cookie', 'root', 'front_root' );
		foreach ( $keys as $key ) {
			if ( ! array_key_exists( $key, $current ) || $current[ $key ] !== $wanted[ $key ] ) {
				$this->sync_config();
				break;
			}
		}
		// A bootstrap that still names an old plugin folder loads nothing: cron
		// requests repair it too, not only wp-admin page views.
		$this->heal_bootstrap();
		if ( ! is_file( Guard_Config::allow_file() ) ) {
			wpcybersec()->allowlist->export_guard_file();
		}
	}

	/* ------------------------------------------------------------------ */
	/* Install / uninstall                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * @return string Absolute path of the bootstrap file.
	 */
	public function bootstrap_path() {
		return wp_normalize_path( ABSPATH . self::BOOTSTRAP_FILE );
	}

	/**
	 * @return string Absolute path of guard/guard.php.
	 */
	public function guard_file() {
		return wp_normalize_path( WPCYBERSEC_DIR . 'guard/guard.php' );
	}

	/**
	 * @return string Spool file.
	 */
	public function spool_file() {
		return wpcybersec()->storage->spool_dir() . '/guard-uploads.jsonl';
	}

	/**
	 * @return string Folder for copies held by the guard.
	 */
	public function quarantine_dir() {
		return wpcybersec()->storage->quarantine_dir() . '/guard';
	}

	/**
	 * @return bool
	 */
	public function is_installed() {
		return (bool) Network::get_option( self::INSTALLED_OPTION, false );
	}

	/**
	 * Config written for the guard, from the settings.
	 *
	 * @return array
	 */
	public function config_array() {
		$settings = wpcybersec()->settings;
		$root     = realpath( ABSPATH );
		$exempt   = array_values( array_filter( array_map( 'strval', (array) $settings->get( 'guard_exempt', array() ) ), 'strlen' ) );

		/**
		 * Filters the largest upload the guard keeps a copy of (bytes).
		 *
		 * @param int $bytes Default 256 MB.
		 */
		$max_bytes = (int) apply_filters( 'wpcybersec_guard_max_bytes', 256 * MB_IN_BYTES );

		/**
		 * Filters how many held copies the guard quarantine may contain. Uploads
		 * beyond it are refused without a copy until held items are reviewed.
		 *
		 * @param int $files Default 500.
		 */
		$max_files = (int) apply_filters( 'wpcybersec_guard_max_quarantine_files', 500 );

		/**
		 * Filters the total size of the guard quarantine (bytes).
		 *
		 * @param int $bytes Default 512 MB.
		 */
		$max_total = (int) apply_filters( 'wpcybersec_guard_max_quarantine_bytes', 512 * MB_IN_BYTES );

		/**
		 * Filters the free disk space the guard leaves untouched (bytes).
		 *
		 * @param int $bytes Default 64 MB.
		 */
		$min_free = (int) apply_filters( 'wpcybersec_guard_min_free_bytes', 64 * MB_IN_BYTES );

		// One config serves every site of a multisite network: the main site's
		// path plus the path of every site, so REST exemptions match on all of them.
		$home_paths = Network::home_paths();
		$home_path  = isset( $home_paths[0] ) ? $home_paths[0] : '';

		return array(
			'enabled'              => $this->is_installed(),
			'action'               => 'strip' === $settings->get( 'guard_action', 'block' ) ? 'strip' : 'block',
			'quarantine_dir'       => $this->quarantine_dir(),
			'spool_file'           => $this->spool_file(),
			'allow_file'           => Guard_Config::allow_file(),
			'exempt'               => $exempt,
			'max_bytes'            => max( MB_IN_BYTES, $max_bytes ),
			'max_spool_bytes'      => 20 * MB_IN_BYTES,
			'max_quarantine_files' => max( 10, $max_files ),
			'max_quarantine_bytes' => max( 16 * MB_IN_BYTES, $max_total ),
			'min_free_bytes'       => max( 1, $min_free ),
			// Same lists as Paths::is_executable(), so approvals mean the same in the guard.
			'exec_extensions'      => self::lower_list( $settings->get( 'exec_extensions', array() ) ),
			'exec_filenames'       => self::lower_list( $settings->get( 'exec_filenames', array() ) ),
			'home_path'            => untrailingslashit( wp_normalize_path( $home_path ) ),
			'home_paths'           => Network::active() ? $home_paths : array(),
			'login_cookie'         => defined( 'LOGGED_IN_COOKIE' ) ? (string) LOGGED_IN_COOKIE : '',
			'message'              => __( 'This upload is waiting for administrator approval (Qartvelo Guard). After approval, send it again and it will go through.', 'qartvelo-guard' ),
			'message_refused'      => __( 'This upload was refused because it could not be checked (Qartvelo Guard). Please contact the site administrator.', 'qartvelo-guard' ),
			'root'                 => trailingslashit( wp_normalize_path( $root ? $root : ABSPATH ) ),
			// Folder of the front controller index.php when it is not the WordPress
			// folder (WordPress in a sub folder, Bedrock): REST routes run there.
			'front_root'           => $this->front_root(),
		);
	}

	/**
	 * Folder of the site's front controller (the index.php that loads
	 * wp-blog-header.php) when it differs from the WordPress folder: WordPress
	 * in its own sub folder ("Giving WordPress its own directory") or Bedrock
	 * (web/index.php loads web/wp/). PHP reads .user.ini and Apache reads
	 * .htaccess from the folder of the requested script upwards, so the guard
	 * must be wired in there too, or requests to the front controller (pages,
	 * REST uploads through /wp-json/) run without it.
	 *
	 * @return string Real path with a trailing slash, or '' when it is ABSPATH.
	 */
	public function front_root() {
		static $cache = null;
		if ( null !== $cache ) {
			return $cache;
		}
		// Multisite: worked out from the main site's addresses, whichever site runs the request.
		$cache = (string) Network::on_main( array( $this, 'find_front_root' ) );
		return $cache;
	}

	/**
	 * front_root() without the cache, in the current site's context.
	 *
	 * @return string
	 */
	public function find_front_root() {
		$cache    = '';
		$real_abs = realpath( ABSPATH );
		$abs      = trailingslashit( wp_normalize_path( $real_abs ? $real_abs : ABSPATH ) );

		$candidates = array();
		// Site address path is a prefix of the WordPress address path: the
		// difference is the sub folder WordPress lives in.
		$home = trim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' );
		$site = trim( (string) wp_parse_url( site_url(), PHP_URL_PATH ), '/' );
		if ( $site !== $home && ( '' === $home || 0 === strpos( $site . '/', $home . '/' ) ) ) {
			$sub = trim( substr( $site, strlen( $home ) ), '/' );
			if ( '' !== $sub && substr( $abs, -strlen( $sub ) - 1 ) === $sub . '/' ) {
				$candidates[] = substr( $abs, 0, strlen( $abs ) - strlen( $sub ) - 1 );
			}
		}
		// Bedrock and similar layouts: the document root holds the front controller.
		if ( ! empty( $_SERVER['DOCUMENT_ROOT'] ) ) {
			$doc = wp_unslash( $_SERVER['DOCUMENT_ROOT'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared as a path only.
			$doc = Storage::path_allowed( $doc ) ? realpath( $doc ) : false;
			if ( $doc ) {
				$candidates[] = trailingslashit( wp_normalize_path( $doc ) );
			}
		}
		foreach ( $candidates as $dir ) {
			if ( ! Storage::path_allowed( $dir ) ) {
				continue; // open_basedir hides it: PHP could not write its .user.ini or .htaccess either.
			}
			$real = realpath( $dir );
			$dir  = $real ? trailingslashit( wp_normalize_path( $real ) ) : $dir;
			if ( $dir === $abs || 0 !== strpos( $abs, $dir ) ) {
				continue; // WordPress must live below the front controller.
			}
			if ( self::loads_wordpress( $dir . 'index.php', substr( $abs, strlen( $dir ) ) ) ) {
				$cache = $dir;
				break;
			}
		}
		// Cron and WP-CLI have no DOCUMENT_ROOT: reuse what a web request found,
		// so the guard config does not change with the kind of request.
		$stored = (string) Network::get_option( self::FRONT_OPTION, '' );
		if ( '' === $cache && empty( $_SERVER['DOCUMENT_ROOT'] ) && '' !== $stored && 0 === strpos( $abs, $stored ) && $stored !== $abs && self::loads_wordpress( $stored . 'index.php', substr( $abs, strlen( $stored ) ) ) ) {
			$cache = $stored;
		} elseif ( $cache !== $stored && ( '' !== $cache || ! empty( $_SERVER['DOCUMENT_ROOT'] ) ) ) {
			Network::update_option( self::FRONT_OPTION, $cache, false );
		}
		return $cache;
	}

	/**
	 * Whether $index is a front controller that loads this WordPress:
	 * it requires "<sub folder>/wp-blog-header.php".
	 *
	 * @param string $index index.php path.
	 * @param string $sub   WordPress folder relative to the index (trailing slash).
	 * @return bool
	 */
	private static function loads_wordpress( $index, $sub ) {
		if ( ! Storage::path_allowed( $index ) || ! @is_file( $index ) || ! @is_readable( $index ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$code = (string) @file_get_contents( $index, false, null, 0, 16384 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		return false !== strpos( $code, $sub . 'wp-blog-header.php' );
	}

	/**
	 * Folders whose .user.ini / .htaccess wire in the guard: the WordPress
	 * folder and, when different, the front controller folder.
	 *
	 * @return string[] With trailing slashes.
	 */
	public function wiring_dirs() {
		$dirs  = array( trailingslashit( wp_normalize_path( ABSPATH ) ) );
		$front = $this->front_root();
		if ( '' !== $front ) {
			$dirs[] = $front;
		}
		return $dirs;
	}

	/**
	 * LiteSpeed edition serving this request.
	 *
	 * OpenLiteSpeed ignores php_value in .htaccess (its php.ini settings come
	 * from WebAdmin, php.ini or .user.ini), LiteSpeed Enterprise reads it like
	 * Apache. Both report "LiteSpeed" in SERVER_SOFTWARE by default, so the
	 * install is checked as well: OpenLiteSpeed ships bin/openlitespeed,
	 * Enterprise needs a license key or serial file.
	 *
	 * @return string openlitespeed | enterprise | unknown | '' (not LiteSpeed)
	 */
	public static function litespeed_edition() {
		$soft    = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		$edition = isset( $_SERVER['LSWS_EDITION'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['LSWS_EDITION'] ) ) ) : '';
		if ( 'litespeed' !== PHP_SAPI && false === strpos( $soft, 'litespeed' ) ) {
			return '';
		}
		if ( false !== strpos( $soft, 'openlitespeed' ) || false !== strpos( $edition, 'open' ) ) {
			return 'openlitespeed';
		}
		if ( false !== strpos( $edition, 'enterprise' ) ) {
			return 'enterprise';
		}
		$root = getenv( 'LSWS_HOME' );
		$root = is_string( $root ) && '' !== $root ? rtrim( $root, '/' ) : '/usr/local/lsws';
		if ( @is_file( $root . '/bin/openlitespeed' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return 'openlitespeed';
		}
		if ( @is_file( $root . '/conf/license.key' ) || @is_file( $root . '/conf/serial.no' ) || @is_file( $root . '/conf/trial.key' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return 'enterprise';
		}
		return 'unknown';
	}

	/**
	 * OpenLiteSpeed (CyberPanel): the next step when .user.ini holds the guard
	 * line but the live test says PHP has not loaded it. lsphp reads .user.ini
	 * only when user ini files are switched on for it, and only after it
	 * restarts (it keeps running in detached mode), so "within a few minutes"
	 * never comes true there. Restart this account's PHP (touching
	 * ~/.lsphp_restart.txt restarts it on the next request; killall lsphp
	 * restarts every site's), test again, and if it still is not loaded use the
	 * vHost php.ini override, which does not depend on .user.ini.
	 *
	 * @return array|null { inline (one sentence with the command), text, code, next } null when the server is not OpenLiteSpeed.
	 */
	public static function ols_activation_step() {
		$edition = self::litespeed_edition();
		$ols     = 'openlitespeed' === $edition || ( 'litespeed' === PHP_SAPI && 'unknown' === $edition );
		if ( ! $ols && function_exists( 'wpcybersec' ) ) {
			$hosting = wpcybersec()->hosting;
			if ( is_object( $hosting ) && method_exists( $hosting, 'current' ) ) {
				$info = $hosting->current();
				$ols  = isset( $info['id'] ) && 'cyberpanel' === $info['id'];
			}
		}
		if ( ! $ols ) {
			return null;
		}
		$home = self::php_user_home();
		$code = '' !== $home
			? 'touch ' . Sysadmin_Tools::shell_arg( $home . '/.lsphp_restart.txt' ) . "\n# or restart the PHP of every site at once:\nkillall lsphp"
			: 'killall lsphp';
		$touch = '' !== $home ? 'touch ' . Sysadmin_Tools::shell_arg( $home . '/.lsphp_restart.txt' ) : '';
		return array(
			'inline' => sprintf(
				/* translators: %s: shell command */
				__( 'OpenLiteSpeed reads .user.ini only when lsphp has user ini files switched on, and only after lsphp restarts. As root run %s, then press "Test again" in Settings > Advanced > Early guard. If it is still not loaded, put the line into the vHost Conf phpIniOverride block (CyberPanel) or WebAdmin php.ini Override instead.', 'qartvelo-guard' ),
				'' !== $touch ? $touch . ' ' . __( '(or killall lsphp)', 'qartvelo-guard' ) : 'killall lsphp'
			),
			'text' => __( 'OpenLiteSpeed reads .user.ini only when lsphp has user ini files switched on, and only after lsphp restarts (it keeps running when the web server restarts). As root, restart this site\'s PHP, then press "Test again":', 'qartvelo-guard' ),
			'code' => $code,
			'next' => __( 'If the test still says PHP did not load the guard, lsphp does not read .user.ini on this server: put the line into the vHost Conf phpIniOverride block instead (the OpenLiteSpeed or CyberPanel steps under "Recommended for this server" below), which works without .user.ini.', 'qartvelo-guard' ),
		);
	}

	/**
	 * Home folder of the user PHP runs as (where LiteSpeed looks for
	 * .lsphp_restart.txt), '' when unknown.
	 *
	 * @return string
	 */
	private static function php_user_home() {
		if ( function_exists( 'posix_getpwuid' ) && function_exists( 'posix_geteuid' ) ) {
			$info = @posix_getpwuid( posix_geteuid() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$dir  = is_array( $info ) && ! empty( $info['dir'] ) ? untrailingslashit( wp_normalize_path( (string) $info['dir'] ) ) : '';
			if ( '' !== $dir && '/' !== $dir && false === strpos( $dir, '/nonexistent' ) ) {
				return $dir;
			}
		}
		// CyberPanel: the site user's home holds public_html.
		if ( preg_match( '#^(/home/[^/]+)/public_html/#', wp_normalize_path( ABSPATH ), $m ) ) {
			return $m[1];
		}
		return '';
	}

	/**
	 * @param mixed $list List setting.
	 * @return string[] Lowercase, unique, non-empty.
	 */
	private static function lower_list( $list ) {
		$out = array();
		foreach ( (array) $list as $value ) {
			if ( is_scalar( $value ) && '' !== trim( (string) $value ) ) {
				$out[] = strtolower( trim( (string) $value ) );
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Writes the config from the current settings.
	 *
	 * @return bool
	 */
	public function sync_config() {
		$this->ensure_dirs();
		return Guard_Config::write( $this->config_array() );
	}

	/**
	 * PHP code of the bootstrap file.
	 *
	 * @param string|null $guard_file  guard.php path (default: this plugin's).
	 * @param string|null $config_file Config path (default: Guard_Config::file()).
	 * @param string|null $chain       Another prepend file to include first ('' for none, null for the saved one).
	 * @return string
	 */
	public function bootstrap_code( $guard_file = null, $config_file = null, $chain = null ) {
		$guard_file  = null === $guard_file ? $this->guard_file() : (string) $guard_file;
		$config_file = null === $config_file ? Guard_Config::file() : (string) $config_file;
		$chain       = null === $chain ? (string) Network::get_option( self::CHAIN_OPTION, '' ) : (string) $chain;
		if ( '' !== $chain && '' !== self::other_site_root( $chain ) ) {
			$chain = ''; // Saved by an older version: never include another site's file.
		}
		return self::build_bootstrap( $guard_file, $config_file, $chain );
	}

	/**
	 * Builds the bootstrap source. Pure function (no WordPress calls), PHP 5.6 syntax.
	 *
	 * @param string $guard_file  guard.php path.
	 * @param string $config_file Config path.
	 * @param string $chain       Other prepend file to include as well, or ''.
	 * @return string
	 */
	public static function build_bootstrap( $guard_file, $config_file, $chain = '' ) {
		$guard  = var_export( (string) $guard_file, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		$config = var_export( (string) $config_file, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions

		$code  = "<?php\n";
		$code .= "/**\n";
		$code .= " * Qartvelo Guard - early upload guard bootstrap.\n";
		$code .= " *\n";
		$code .= " * PHP runs this file before every request because auto_prepend_file points to it\n";
		$code .= " * (set in .user.ini, .htaccess, the PHP-FPM pool, the nginx config or php.ini).\n";
		$code .= " * It loads the guard that holds uploaded files until an administrator approves\n";
		$code .= " * them under Qartvelo Guard > Reports in WordPress.\n";
		$code .= " *\n";
		$code .= " * To remove the guard safely:\n";
		$code .= " *   1. Remove the auto_prepend_file line from where it was added.\n";
		$code .= " *   2. Wait until PHP no longer uses it (.user.ini changes can take up to\n";
		$code .= " *      user_ini.cache_ttl seconds, 5 minutes by default) or reload PHP.\n";
		$code .= " *   3. Delete this file.\n";
		$code .= " * Deleting this file while auto_prepend_file still points to it breaks every\n";
		$code .= " * PHP request on the site. If the plugin is removed, this file does nothing.\n";
		$code .= " *\n";
		$code .= " * Generated by Qartvelo Guard. Changes are overwritten.\n";
		$code .= " */\n";
		$code .= "if ( ! defined( 'WPCYBERSEC_GUARD_BOOTSTRAPPED' ) ) {\n";
		$code .= "\tdefine( 'WPCYBERSEC_GUARD_BOOTSTRAPPED', true );\n";
		if ( '' !== $chain ) {
			$other = var_export( (string) $chain, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
			$code .= "\t// Another prepend file that was in place before; keeps it running.\n";
			$code .= "\tif ( @file_exists( {$other} ) ) {\n";
			$code .= "\t\tinclude_once {$other};\n";
			$code .= "\t}\n";
		}
		$code .= "\tif ( @file_exists( {$guard} ) && @file_exists( {$config} ) ) {\n";
		$code .= "\t\tif ( ! defined( 'WPCYBERSEC_GUARD_CONFIG' ) ) {\n";
		$code .= "\t\t\tdefine( 'WPCYBERSEC_GUARD_CONFIG', {$config} );\n";
		$code .= "\t\t}\n";
		$code .= "\t\tinclude_once {$guard};\n";
		$code .= "\t}\n";
		$code .= "}\n";
		return $code;
	}

	/**
	 * Guard, config and chain paths of a bootstrap that is exactly
	 * build_bootstrap()'s template, whatever paths it holds (a bootstrap an
	 * earlier install wrote for another data folder).
	 *
	 * @param string $code File content.
	 * @return array|null { guard, config, chain }, null when it is not the template.
	 */
	public static function bootstrap_parts( $code ) {
		$code = (string) $code;
		$lit  = "'(?:[^'\\\\]|\\\\.)*'";
		if ( strlen( $code ) > 65536 || ! preg_match( "/^\\tif \\( @file_exists\\( ($lit) \\) && @file_exists\\( ($lit) \\) \\) \\{\$/m", $code, $m ) ) {
			return null;
		}
		$chain = '';
		if ( preg_match( "/^\\tif \\( @file_exists\\( ($lit) \\) \\) \\{\$/m", $code, $c ) ) {
			$chain = self::unexport( $c[1] );
		}
		$parts = array(
			'guard'  => self::unexport( $m[1] ),
			'config' => self::unexport( $m[2] ),
			'chain'  => $chain,
		);
		// Rebuilt with the same paths it must be the same text: nothing added or changed.
		if ( self::build_bootstrap( $parts['guard'], $parts['config'], $parts['chain'] ) !== $code ) {
			return null;
		}
		return $parts;
	}

	/**
	 * @param string $literal Single-quoted PHP string as var_export() writes it.
	 * @return string
	 */
	private static function unexport( $literal ) {
		return (string) preg_replace( '/\\\\(.)/s', '$1', substr( (string) $literal, 1, -1 ) );
	}

	/**
	 * Whether a bootstrap is one this plugin wrote earlier for another data
	 * folder (left by an uninstall, or written before the data folder moved).
	 * Only the exact template counts, and only with paths that cannot run
	 * other code: this plugin's guard.php, a guard/config.php in a wpcybersec
	 * data folder that is missing or holds only data, and no chained prepend
	 * file other than the one the administrator approved.
	 *
	 * @param string $code File content.
	 * @return bool
	 */
	public function is_leftover_bootstrap( $code ) {
		$parts = self::bootstrap_parts( $code );
		if ( ! $parts ) {
			return false;
		}
		if ( wp_normalize_path( $parts['guard'] ) !== $this->guard_file() ) {
			return false;
		}
		if ( '' !== $parts['chain'] && $parts['chain'] !== (string) Network::get_option( self::CHAIN_OPTION, '' ) ) {
			return false;
		}
		$config  = wp_normalize_path( $parts['config'] );
		$current = wp_normalize_path( Guard_Config::file() );
		if ( $config === $current ) {
			return true;
		}
		$data = dirname( dirname( $config ) );
		// Every data folder this plugin creates: wp-content/wpcybersec (before
		// 1.1.0), uploads/qartvelo-guard and its fallback uploads/qartvelo-guard-<random>
		// (1.1.0), uploads/qartvelo-guard/<random 32> (1.1.1 and later).
		$name = basename( $data );
		$own  = preg_match( '/^wpcybersec(?:$|-)/', $name ) || preg_match( '/^' . preg_quote( Storage::UPLOADS_FOLDER, '/' ) . '(?:$|-)/', $name )
			|| ( preg_match( '/^[a-z0-9]{32}$/', $name ) && Storage::UPLOADS_FOLDER === basename( dirname( $data ) ) );
		if ( 'config.php' !== basename( $config ) || 'guard' !== basename( dirname( $config ) ) || ! $own ) {
			return false;
		}
		if ( ! Storage::path_allowed( $config ) ) {
			return false;
		}
		return ! @file_exists( $config ) || self::config_is_data( $config ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Whether a guard config file is only "return array( ... );" with plain
	 * values, as Guard_Config::write() creates it (guard.php includes it, so
	 * anything else could run code).
	 *
	 * @param string $file Config file.
	 * @return bool
	 */
	public static function config_is_data( $file ) {
		$size = @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 262144 || ! function_exists( 'token_get_all' ) ) {
			return false;
		}
		$code = (string) @file_get_contents( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$ok   = array( T_OPEN_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_RETURN, T_ARRAY, T_CONSTANT_ENCAPSED_STRING, T_LNUMBER, T_DNUMBER, T_DOUBLE_ARROW );
		$seen = false;
		foreach ( token_get_all( $code ) as $token ) {
			if ( is_array( $token ) ) {
				if ( T_RETURN === $token[0] ) {
					$seen = true;
				}
				if ( in_array( $token[0], $ok, true ) ) {
					continue;
				}
				if ( T_STRING === $token[0] && in_array( strtolower( $token[1] ), array( 'true', 'false', 'null' ), true ) ) {
					continue;
				}
				return false;
			}
			if ( ! in_array( $token, array( '(', ')', ',', ';', '-', '[', ']' ), true ) ) {
				return false;
			}
		}
		return $seen;
	}

	/**
	 * Brings a bootstrap left by an earlier install (another data folder) up
	 * to date, so it is not reported and points at the current folder. Runs
	 * on activation and on admin pages while the guard is not installed.
	 *
	 * @return bool Whether it was rewritten.
	 */
	public function refresh_leftover_bootstrap() {
		$path = $this->bootstrap_path();
		if ( ! @is_file( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$code = (string) @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( $code === $this->bootstrap_code() || ! $this->is_leftover_bootstrap( $code ) ) {
			return false;
		}
		if ( is_wp_error( $this->write_bootstrap() ) ) {
			return false;
		}
		$this->log( 'guard_bootstrap_refreshed', __( 'The early guard file left by an earlier install was updated to the current data folder.', 'qartvelo-guard' ) );
		return true;
	}

	/**
	 * Writes the config, the allow file and the bootstrap, and marks the guard installed.
	 * The administrator still has to point auto_prepend_file at the bootstrap (see snippets()).
	 *
	 * @return true|\WP_Error
	 */
	public function install() {
		$plugin  = wpcybersec();
		$ensured = $plugin->storage->ensure();
		if ( is_wp_error( $ensured ) ) {
			return $ensured;
		}
		$this->ensure_dirs();

		// Remember another prepend file (for example a firewall) so the bootstrap keeps it running.
		$conflict = $this->detect_conflict();
		if ( $conflict && '' === self::other_site_root( $conflict ) ) {
			Network::update_option( self::CHAIN_OPTION, $conflict, false );
		} elseif ( $conflict ) {
			Network::delete_option( self::CHAIN_OPTION ); // Another site's file: never run it from here.
		}

		Network::update_option( self::INSTALLED_OPTION, time(), false );
		if ( ! $this->sync_config() ) {
			Network::delete_option( self::INSTALLED_OPTION );
			return new \WP_Error(
				'wpcybersec_guard_config',
				/* translators: %s: file path */
				sprintf( __( 'Could not write the guard config file %s. Check that the data folder is writable.', 'qartvelo-guard' ), Guard_Config::file() )
			);
		}
		$plugin->allowlist->export_guard_file();
		$this->ensure_cron();

		$written = $this->write_bootstrap();
		if ( is_wp_error( $written ) ) {
			$this->log( 'guard_install_failed', $written->get_error_message() );
			return $written;
		}

		$this->log(
			'guard_installed',
			/* translators: %s: file path */
			sprintf( __( 'Early upload guard installed. Point auto_prepend_file to %s to switch it on.', 'qartvelo-guard' ), $this->bootstrap_path() )
		);
		return true;
	}

	/**
	 * Switches the guard off. The bootstrap file is removed only when nothing
	 * points auto_prepend_file at it any more; otherwise it stays (it is harmless
	 * without a config) so PHP does not fail on every request.
	 *
	 * @param bool $keep_bootstrap Never delete the bootstrap (used right after an
	 *                             auto_prepend_file line was removed: PHP can keep
	 *                             a cached .user.ini for minutes).
	 * @return true
	 */
	public function uninstall( $keep_bootstrap = false ) {
		Guard_Config::set_enabled( false );
		Network::delete_option( self::INSTALLED_OPTION );
		Network::delete_option( self::PING_OPTION ); // A live test of the old install says nothing now.
		Network::clear_hook( self::IMPORT_HOOK );

		// Import whatever is still waiting so nothing held is lost.
		$this->import_spool();

		$config = Guard_Config::file();
		if ( is_file( $config ) ) {
			Fs::delete( $config );
		}

		$bootstrap = $this->bootstrap_path();
		if ( $keep_bootstrap && is_file( $bootstrap ) ) {
			$this->log(
				'guard_uninstalled',
				/* translators: %s: file path */
				sprintf( __( 'Early upload guard switched off. %s was kept because PHP can still load it for a few minutes; without the guard config it does nothing.', 'qartvelo-guard' ), $bootstrap )
			);
		} elseif ( is_file( $bootstrap ) && ! $this->bootstrap_referenced() ) {
			Fs::delete( $bootstrap );
			$this->forget_file( $bootstrap );
			Network::delete_option( self::CHAIN_OPTION );
			$this->log( 'guard_uninstalled', __( 'Early upload guard removed.', 'qartvelo-guard' ) );
		} else {
			$this->log(
				'guard_uninstalled',
				/* translators: %s: file path */
				sprintf( __( 'Early upload guard switched off. auto_prepend_file still points to %s, so the file was kept. Remove the auto_prepend_file line first, then delete the file.', 'qartvelo-guard' ), $bootstrap )
			);
		}
		return true;
	}

	/**
	 * Writes the bootstrap file atomically when its content changed.
	 *
	 * @return true|\WP_Error
	 */
	private function write_bootstrap() {
		$path = $this->bootstrap_path();
		$code = $this->bootstrap_code();
		if ( is_file( $path ) && (string) @file_get_contents( $path ) === $code ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			return true;
		}
		if ( ! Guard_Config::atomic_write( $path, $code ) ) {
			return new \WP_Error(
				'wpcybersec_guard_bootstrap',
				/* translators: %s: file path */
				sprintf( __( 'Could not write %s. Create this file yourself with the content shown on the Advanced settings tab, then install the guard again.', 'qartvelo-guard' ), $path )
			);
		}
		Fs::chmod( $path, 0644 );
		$this->trust_file( $path );
		// The whole file is generated, so an open item about an older copy is stale.
		// Not done for .htaccess or .user.ini: lines outside our block survive a rewrite.
		wpcybersec()->store->items_resolve_open( Paths::rel( $path ), 'now_trusted' );
		return true;
	}

	/**
	 * Rewrites the bootstrap when the plugin moved or the file was damaged.
	 */
	public function heal_bootstrap() {
		$path = $this->bootstrap_path();
		if ( ! is_file( $path ) ) {
			return; // Not created yet or removed on purpose; install() recreates it.
		}
		if ( (string) @file_get_contents( $path ) !== $this->bootstrap_code() ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			$this->write_bootstrap();
		}
	}

	/**
	 * Creates the guard's folders.
	 */
	private function ensure_dirs() {
		$storage = wpcybersec()->storage;
		foreach ( array( $this->quarantine_dir(), $storage->spool_dir(), $storage->guard_dir() ) as $dir ) {
			if ( ! is_dir( $dir ) ) {
				wp_mkdir_p( $dir );
			}
			if ( is_dir( $dir ) ) {
				$storage->protect( $dir );
			}
		}
	}

	/**
	 * Schedules (or removes) the periodic spool import.
	 */
	private function ensure_cron() {
		$next = Network::next_scheduled( self::IMPORT_HOOK );
		if ( $this->is_installed() ) {
			if ( ! $next ) {
				Network::schedule_event( time() + 10 * MINUTE_IN_SECONDS, self::SCHEDULE, self::IMPORT_HOOK );
			}
		} elseif ( $next ) {
			Network::clear_hook( self::IMPORT_HOOK );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Status and snippets                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * @return array {
	 *     installed, active, enabled, bootstrap_path, bootstrap_exists, prepend,
	 *     points_to_bootstrap, conflict (other prepend file or null), conflict_help,
	 *     conflict_snippet, chain, sapi, recommended (snippet id), pending_spool,
	 *     config_file, config_exists, user_ini (array)
	 * }
	 */
	public function status() {
		$config    = Guard_Config::read();
		$prepend   = (string) ini_get( 'auto_prepend_file' );
		$conflict  = $this->detect_conflict();
		$bootstrap = $this->bootstrap_path();
		$ini_name  = ini_get( 'user_ini.filename' );
		$ini_name  = false === $ini_name ? '.user.ini' : (string) $ini_name;
		$ini_path  = '' !== $ini_name ? wp_normalize_path( ABSPATH . $ini_name ) : '';

		$help    = '';
		$snippet = '';
		$foreign = $conflict ? self::other_site_root( $conflict ) : '';
		if ( $foreign ) {
			$help = sprintf(
				/* translators: 1: prepend file, 2: folder of the other site */
				__( 'PHP runs %1$s before every request on this site, but that file belongs to another WordPress site (%2$s). This site then depends on the other site and runs its firewall with the other site\'s settings. It is usually left over from copying a site. Only one prepend file can be set, so the early guard cannot load. Remove the auto_prepend_file line that points to it (look in .user.ini and .htaccess in this site\'s folder, in the PHP settings of the hosting panel and in the web server\'s settings for this site), restart PHP, then install the guard. If this site uses Wordfence, run Wordfence > Firewall > Optimize the Wordfence Firewall again afterwards so it creates this site\'s own file.', 'qartvelo-guard' ),
				$conflict,
				$foreign
			);
		} elseif ( $conflict ) {
			$help = sprintf(
				/* translators: 1: other prepend file, 2: bootstrap file */
				__( 'PHP already runs %1$s through auto_prepend_file, and only one prepend file can be set. Either add the line below at the top of that file so it also loads the guard, or point auto_prepend_file to %2$s instead: the guard bootstrap includes the other file automatically, so both keep working.', 'qartvelo-guard' ),
				$conflict,
				$bootstrap
			);
			$snippet = $this->include_snippet();
		}

		$installed = $this->is_installed();
		$active    = defined( 'WPCYBERSEC_GUARD_ACTIVE' );
		$can_tell  = self::request_can_tell();
		$ping      = $this->last_ping();
		return array(
			'installed'           => $installed,
			'active'              => $active,
			// This request cannot tell (WP-CLI, cron, development server): the last live test can.
			'can_tell'            => $can_tell,
			'ping'                => $ping,
			'confirmed'           => ! $active && ! $can_tell && $installed && $ping && 'active' === $ping['result'],
			'enabled'             => ! empty( $config['enabled'] ),
			'bootstrap_path'      => $bootstrap,
			'bootstrap_exists'    => is_file( $bootstrap ),
			'prepend'             => $prepend,
			'points_to_bootstrap' => $this->points_to_bootstrap( $prepend ),
			'conflict'            => $conflict ? $conflict : null,
			'conflict_foreign'    => $foreign,
			'conflict_help'       => $help,
			'conflict_snippet'    => $snippet,
			'chain'               => (string) Network::get_option( self::CHAIN_OPTION, '' ),
			'sapi'                => PHP_SAPI,
			'litespeed'           => self::litespeed_edition(),
			'front_root'          => $this->front_root(),
			'recommended'         => $this->recommended_snippet(),
			'pending_spool'       => $this->spool_count(),
			'config_file'         => Guard_Config::file(),
			'config_exists'       => is_file( Guard_Config::file() ),
			'user_ini'            => array(
				'filename'  => $ini_name,
				'path'      => $ini_path,
				'exists'    => '' !== $ini_path && is_file( $ini_path ),
				'has_line'  => '' !== $ini_path && is_file( $ini_path ) && false !== strpos( (string) @file_get_contents( $ini_path ), self::BOOTSTRAP_FILE ), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
				'cache_ttl' => (int) ini_get( 'user_ini.cache_ttl' ),
			),
		);
	}

	/**
	 * Ways to set auto_prepend_file, one per server type.
	 *
	 * @return array[] { id, label, file, code, help, recommended }
	 */
	public function snippets() {
		$bootstrap   = $this->bootstrap_path();
		$recommended = $this->recommended_snippet();
		$ini_name    = ini_get( 'user_ini.filename' );
		$ini_name    = false === $ini_name || '' === $ini_name ? '.user.ini' : (string) $ini_name;
		$php_ini     = php_ini_loaded_file();
		$ver         = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

		$htaccess = array( '# BEGIN ' . self::MARKER );
		// mod_php names, then LiteSpeed Enterprise and mod_lsapi (CloudLinux), which read php_value too.
		// OpenLiteSpeed ignores php_value in .htaccess: it uses .user.ini or its WebAdmin instead.
		foreach ( array( 'php_module', 'php7_module', 'php5_module', 'mod_php.c', 'mod_php8.c', 'mod_php7.c', 'mod_php5.c', 'LiteSpeed', 'lsapi_module' ) as $module ) {
			$htaccess[] = '<IfModule ' . $module . '>';
			$htaccess[] = "\tphp_value auto_prepend_file \"" . $bootstrap . '"';
			$htaccess[] = '</IfModule>';
		}
		$htaccess[] = '# END ' . self::MARKER;

		$ini_files = array();
		$ht_files  = array();
		foreach ( $this->wiring_dirs() as $dir ) {
			$ini_files[] = wp_normalize_path( $dir . $ini_name );
			$ht_files[]  = wp_normalize_path( $dir . '.htaccess' );
		}
		$front = '' !== $this->front_root()
			? ' ' . __( 'This site\'s front controller (index.php) is in another folder than WordPress, so add it to both files.', 'qartvelo-guard' )
			: '';

		$snippets = array(
			array(
				'id'   => 'user_ini',
				'label' => __( '.user.ini (PHP-FPM, FastCGI, OpenLiteSpeed)', 'qartvelo-guard' ),
				'file' => implode( ' + ', $ini_files ),
				'code' => '; BEGIN ' . self::MARKER . "\nauto_prepend_file = \"" . $bootstrap . "\"\n; END " . self::MARKER,
				/* translators: %d: seconds */
				'help' => sprintf( __( 'Add this to the .user.ini file in the WordPress folder (or use the button that writes it for you). PHP reads it again every %d seconds, so the guard starts within a few minutes. Apache with mod_php ignores .user.ini; use the .htaccess snippet there.', 'qartvelo-guard' ), max( 0, (int) ini_get( 'user_ini.cache_ttl' ) ) ) . $front,
			),
			array(
				'id'   => 'htaccess',
				'label' => __( '.htaccess (Apache with mod_php, LiteSpeed Enterprise)', 'qartvelo-guard' ),
				'file' => implode( ' + ', $ht_files ),
				'code' => implode( "\n", $htaccess ),
				'help' => __( 'For Apache running PHP as a module (mod_php, PHP 5 to 8), LiteSpeed Enterprise and CloudLinux mod_lsapi. Every line is wrapped in IfModule, so the snippet is ignored on other servers instead of causing a 500 error. OpenLiteSpeed ignores it: use .user.ini or the OpenLiteSpeed snippet there. Takes effect on the next request.', 'qartvelo-guard' ) . $front,
			),
			array(
				'id'    => 'openlitespeed',
				'label' => __( 'OpenLiteSpeed (WebAdmin, CyberPanel)', 'qartvelo-guard' ),
				'file'  => __( 'WebAdmin > Virtual Hosts > this site > General > php.ini Override (CyberPanel: /usr/local/lsws/conf/vhosts/<domain>/vhost.conf, phpIniOverride block)', 'qartvelo-guard' ),
				'code'  => 'php_value auto_prepend_file ' . $bootstrap,
				'help'  => __( 'OpenLiteSpeed ignores php_value in .htaccess. Add this line, then restart OpenLiteSpeed (and stop the lsphp processes when PHP runs in detached mode, for example: killall lsphp). It applies to this site only. A .user.ini file also works when lsphp has user ini files switched on (LSPHP_ENABLE_USER_INI=on), but only after PHP restarts.', 'qartvelo-guard' ),
			),
			array(
				'id'   => 'fpm',
				'label' => __( 'PHP-FPM pool', 'qartvelo-guard' ),
				/* translators: %s: PHP version */
				'file' => sprintf( __( 'The pool file of this site, for example /etc/php/%s/fpm/pool.d/www.conf', 'qartvelo-guard' ), $ver ),
				'code' => 'php_admin_value[auto_prepend_file] = ' . $bootstrap,
				'help' => __( 'The strongest option: php_admin_value cannot be changed by .user.ini or by PHP code. Reload PHP-FPM afterwards (for example: systemctl reload php-fpm).', 'qartvelo-guard' ),
			),
			array(
				'id'   => 'nginx',
				'label' => __( 'nginx (fastcgi_param)', 'qartvelo-guard' ),
				'file' => __( 'The location ~ \.php$ block of this site', 'qartvelo-guard' ),
				'code' => 'fastcgi_param PHP_VALUE "auto_prepend_file=' . $bootstrap . '";',
				'help' => __( 'Add it next to the other fastcgi_param lines and reload nginx. PHP_VALUE replaces any other PHP_VALUE set in the same block, and PHP-FPM may keep it for other sites served by the same pool, so prefer the pool setting when the pool is shared.', 'qartvelo-guard' ),
			),
			array(
				'id'   => 'php_ini',
				'label' => __( 'php.ini', 'qartvelo-guard' ),
				'file' => $php_ini ? wp_normalize_path( $php_ini ) : __( 'The php.ini used by the web server', 'qartvelo-guard' ),
				'code' => 'auto_prepend_file = "' . $bootstrap . '"',
				'help' => __( 'Applies to every site that uses this PHP installation, so only use it on a server dedicated to this site. Restart PHP (or the web server) afterwards.', 'qartvelo-guard' ),
			),
		);

		// The hosting panel's own way comes first and is the recommended one
		// (CyberPanel vHost Conf, cPanel MultiPHP INI Editor, aaPanel's locked
		// .user.ini, Plesk PHP Settings, ...). Read only where snippets are shown.
		$hosting = function_exists( 'wpcybersec' ) ? wpcybersec()->hosting : null;
		$panel   = $hosting && method_exists( $hosting, 'prepend_snippet' ) ? $hosting->prepend_snippet() : null;
		if ( is_array( $panel ) ) {
			array_unshift( $snippets, $panel );
			$recommended = 'panel';
		}

		foreach ( $snippets as &$snippet ) {
			$snippet['recommended'] = $snippet['id'] === $recommended;
		}
		unset( $snippet );
		return $snippets;
	}

	/**
	 * Snippet id that fits the running PHP SAPI.
	 *
	 * @return string
	 */
	public function recommended_snippet() {
		switch ( PHP_SAPI ) {
			case 'apache2handler':
				return 'htaccess';
			case 'litespeed':
				return 'openlitespeed' === self::litespeed_edition() ? 'openlitespeed' : 'htaccess';
			case 'fpm-fcgi':
			case 'cgi-fcgi':
			case 'cgi':
				return 'user_ini';
			default:
				return 'php_ini';
		}
	}

	/**
	 * Adds or updates auto_prepend_file in .user.ini of the WordPress folder
	 * and, when different, of the front controller folder (see front_root()).
	 * A failure in one folder undoes the other, so nothing is half wired.
	 *
	 * @return true|\WP_Error
	 */
	public function write_user_ini() {
		$name = ini_get( 'user_ini.filename' );
		$name = false === $name ? '.user.ini' : (string) $name;
		if ( '' === $name ) {
			return new \WP_Error( 'wpcybersec_user_ini_off', __( 'This server has .user.ini files turned off (user_ini.filename is empty). Use one of the other snippets.', 'qartvelo-guard' ) );
		}
		$done = array();
		foreach ( $this->wiring_dirs() as $dir ) {
			$result = $this->write_user_ini_file( wp_normalize_path( $dir . $name ) );
			if ( is_wp_error( $result ) ) {
				foreach ( $done as $file ) {
					$this->remove_user_ini_file( $file );
				}
				return $result;
			}
			$done[] = wp_normalize_path( $dir . $name );
		}
		return true;
	}

	/**
	 * Adds or updates auto_prepend_file in one .user.ini file.
	 *
	 * @param string $file File.
	 * @return true|\WP_Error
	 */
	private function write_user_ini_file( $file ) {
		$bootstrap = $this->bootstrap_path();
		$content   = is_file( $file ) ? (string) @file_get_contents( $file ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		$lines     = '' === $content ? array() : preg_split( '/\r\n|\n|\r/', $content );
		$ours      = 'auto_prepend_file = "' . $bootstrap . '"';
		$found     = false;

		foreach ( $lines as $i => $line ) {
			// Markers of versions before 1.1.0 get the current name.
			if ( in_array( trim( $line ), array( '; BEGIN ' . self::LEGACY_MARKER, '; END ' . self::LEGACY_MARKER ), true ) ) {
				$lines[ $i ] = str_replace( self::LEGACY_MARKER, self::MARKER, trim( $line ) );
				continue;
			}
			if ( ! preg_match( '/^\s*auto_prepend_file\s*=\s*(.*)$/i', $line, $match ) ) {
				continue;
			}
			$value = trim( trim( $match[1] ), "\"'" );
			if ( false !== strpos( $value, self::BOOTSTRAP_FILE ) ) {
				$lines[ $i ] = $ours;
				$found       = true;
				continue;
			}
			if ( '' !== $value ) {
				return new \WP_Error(
					'wpcybersec_user_ini_conflict',
					sprintf(
						/* translators: 1: file, 2: other prepend file, 3: php line */
						__( '%1$s already sets auto_prepend_file to %2$s, and only one prepend file can be set. Add this line at the top of that file instead: %3$s', 'qartvelo-guard' ),
						$file,
						$value,
						$this->include_snippet()
					)
				);
			}
		}

		if ( ! $found ) {
			while ( $lines && '' === trim( (string) end( $lines ) ) ) {
				array_pop( $lines );
			}
			$lines[] = '; BEGIN ' . self::MARKER;
			$lines[] = $ours;
			$lines[] = '; END ' . self::MARKER;
		}
		$new = implode( "\n", $lines ) . "\n";
		if ( $new === $content ) {
			return true;
		}
		// Plain write keeps the file's owner and permissions.
		if ( false === @file_put_contents( $file, $new, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			return new \WP_Error(
				'wpcybersec_user_ini_write',
				/* translators: %s: file path */
				sprintf( __( 'Could not write %s. Add the line yourself.', 'qartvelo-guard' ), $file )
			);
		}
		$this->trust_file( $file );
		$this->log(
			'guard_user_ini',
			/* translators: %s: file path */
			sprintf( __( 'Added the guard to %s. PHP picks it up within a few minutes.', 'qartvelo-guard' ), $file )
		);
		return true;
	}

	/**
	 * Removes the guard lines from .user.ini in every folder write_user_ini() writes.
	 *
	 * @return true|\WP_Error
	 */
	public function remove_user_ini() {
		$name   = ini_get( 'user_ini.filename' );
		$name   = false === $name || '' === $name ? '.user.ini' : (string) $name;
		$result = true;
		foreach ( $this->wiring_dirs() as $dir ) {
			$one = $this->remove_user_ini_file( wp_normalize_path( $dir . $name ) );
			if ( is_wp_error( $one ) ) {
				$result = $one;
			}
		}
		return $result;
	}

	/**
	 * Removes the guard lines from one .user.ini file.
	 *
	 * @param string $file File.
	 * @return true|\WP_Error
	 */
	private function remove_user_ini_file( $file ) {
		if ( ! is_file( $file ) ) {
			return true;
		}
		$content = (string) @file_get_contents( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		$kept    = array();
		foreach ( preg_split( '/\r\n|\n|\r/', $content ) as $line ) {
			$trimmed = trim( $line );
			if ( in_array( $trimmed, array( '; BEGIN ' . self::MARKER, '; END ' . self::MARKER, '; BEGIN ' . self::LEGACY_MARKER, '; END ' . self::LEGACY_MARKER ), true ) ) {
				continue;
			}
			if ( preg_match( '/^\s*auto_prepend_file\s*=/i', $line ) && false !== strpos( $line, self::BOOTSTRAP_FILE ) ) {
				continue;
			}
			$kept[] = $line;
		}
		$new = rtrim( implode( "\n", $kept ) ) . "\n";
		if ( "\n" === $new ) {
			$new = '';
		}
		if ( $new !== $content && false === @file_put_contents( $file, $new, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_user_ini_write', sprintf( __( 'Could not write %s. Remove the auto_prepend_file line yourself.', 'qartvelo-guard' ), $file ) );
		}
		$this->trust_file( $file );
		return true;
	}

	/**
	 * Adds the .htaccess snippet (mod_php, LiteSpeed Enterprise, mod_lsapi)
	 * between markers to the WordPress folder and, when different, the front
	 * controller folder. A failure in one folder undoes the other.
	 *
	 * @return true|\WP_Error
	 */
	public function write_htaccess() {
		$done = array();
		foreach ( $this->wiring_dirs() as $dir ) {
			$file   = wp_normalize_path( $dir . '.htaccess' );
			$result = $this->write_htaccess_file( $file );
			if ( is_wp_error( $result ) ) {
				foreach ( $done as $written ) {
					$this->remove_htaccess_file( $written );
				}
				return $result;
			}
			$done[] = $file;
		}
		return true;
	}

	/**
	 * Adds the snippet to one .htaccess file.
	 *
	 * @param string $file File.
	 * @return true|\WP_Error
	 */
	private function write_htaccess_file( $file ) {
		$legacy = self::drop_legacy_htaccess_block( $file );
		if ( is_wp_error( $legacy ) ) {
			return $legacy;
		}
		if ( is_file( $file ) ) {
			$content = (string) @file_get_contents( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			$outside = preg_replace( '/# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '/s', '', $content );
			if ( preg_match( '/^\s*php_value\s+auto_prepend_file\s+["\']?([^"\'\r\n]+)/im', (string) $outside, $match ) && false === strpos( $match[1], self::BOOTSTRAP_FILE ) ) {
				return new \WP_Error(
					'wpcybersec_htaccess_conflict',
					sprintf(
						/* translators: 1: other prepend file, 2: php line */
						__( '.htaccess already sets auto_prepend_file to %1$s, and only one prepend file can be set. Add this line at the top of that file instead: %2$s', 'qartvelo-guard' ),
						trim( $match[1] ),
						$this->include_snippet()
					)
				);
			}
		}
		$snippet = null;
		foreach ( $this->snippets() as $candidate ) {
			if ( 'htaccess' === $candidate['id'] ) {
				$snippet = $candidate;
			}
		}
		$lines = explode( "\n", $snippet['code'] );
		// insert_with_markers adds its own BEGIN/END lines.
		$lines = array_values( array_filter( $lines, static function ( $line ) {
			return 0 !== strpos( $line, '# BEGIN ' ) && 0 !== strpos( $line, '# END ' );
		} ) );

		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		if ( ! insert_with_markers( $file, self::MARKER, $lines ) ) {
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_htaccess_write', sprintf( __( 'Could not write %s. Add the snippet yourself.', 'qartvelo-guard' ), $file ) );
		}
		$this->trust_file( $file );
		$this->log(
			'guard_htaccess',
			/* translators: %s: file path */
			sprintf( __( 'Added the guard to %s.', 'qartvelo-guard' ), $file )
		);
		return true;
	}

	/**
	 * Removes the guard block from .htaccess in every folder write_htaccess() writes.
	 *
	 * @return true|\WP_Error
	 */
	public function remove_htaccess() {
		$result = true;
		foreach ( $this->wiring_dirs() as $dir ) {
			$one = $this->remove_htaccess_file( wp_normalize_path( $dir . '.htaccess' ) );
			if ( is_wp_error( $one ) ) {
				$result = $one;
			}
		}
		return $result;
	}

	/**
	 * Removes the guard block from one .htaccess file.
	 *
	 * @param string $file File.
	 * @return true|\WP_Error
	 */
	private function remove_htaccess_file( $file ) {
		if ( ! is_file( $file ) ) {
			return true;
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$legacy = self::drop_legacy_htaccess_block( $file );
		if ( is_wp_error( $legacy ) ) {
			return $legacy;
		}
		if ( false === strpos( (string) @file_get_contents( $file ), '# BEGIN ' . self::MARKER ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
			return true;
		}
		if ( ! insert_with_markers( $file, self::MARKER, array() ) ) {
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_htaccess_write', sprintf( __( 'Could not write %s. Remove the guard block yourself.', 'qartvelo-guard' ), $file ) );
		}
		$this->trust_file( $file );
		return true;
	}

	/**
	 * Removes the guard block a version before 1.1.0 wrote into $file (marker
	 * LEGACY_MARKER), with its BEGIN and END lines.
	 *
	 * @param string $file .htaccess file.
	 * @return true|\WP_Error
	 */
	private static function drop_legacy_htaccess_block( $file ) {
		if ( ! is_file( $file ) ) {
			return true;
		}
		$content = (string) @file_get_contents( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( false === strpos( $content, '# BEGIN ' . self::LEGACY_MARKER ) ) {
			return true;
		}
		$new = preg_replace( '/^[ \t]*# BEGIN ' . preg_quote( self::LEGACY_MARKER, '/' ) . '[ \t]*\R.*?^[ \t]*# END ' . preg_quote( self::LEGACY_MARKER, '/' ) . '[ \t]*(\R|\z)/ms', '', $content );
		if ( null === $new || $new === $content ) {
			return true;
		}
		if ( false === @file_put_contents( $file, $new, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_htaccess_write', sprintf( __( 'Could not write %s. Remove the guard block yourself.', 'qartvelo-guard' ), $file ) );
		}
		return true;
	}

	/**
	 * One line that loads the guard from another prepend file.
	 *
	 * @return string
	 */
	public function include_snippet() {
		$bootstrap = var_export( $this->bootstrap_path(), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		return "if ( file_exists( {$bootstrap} ) ) { include_once {$bootstrap}; }";
	}

	/**
	 * Another prepend file in effect for this request (for example Wordfence's
	 * wordfence-waf.php) that does not load the guard.
	 *
	 * @return string Its path, or '' when there is no conflict.
	 */
	private function detect_conflict() {
		$prepend = trim( (string) ini_get( 'auto_prepend_file' ) );
		if ( '' === $prepend || $this->points_to_bootstrap( $prepend ) ) {
			return '';
		}
		// An old bootstrap of this plugin (site moved): not another firewall, never chain it.
		if ( self::BOOTSTRAP_FILE === basename( wp_normalize_path( $prepend ) ) ) {
			return '';
		}
		// Already loads the guard itself?
		if ( @is_readable( $prepend ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$head = (string) @file_get_contents( $prepend, false, null, 0, 65536 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			if ( false !== strpos( $head, self::BOOTSTRAP_FILE ) ) {
				return '';
			}
		}
		return wp_normalize_path( $prepend );
	}

	/**
	 * Folder of another WordPress site that a prepend file belongs to, or ''.
	 * A copied site often keeps the original's firewall line (for example
	 * Wordfence's wordfence-waf.php), so every request then runs a file of a
	 * different website with that website's settings. Such a file is never
	 * chained by the bootstrap.
	 *
	 * @param string $path Prepend file.
	 * @return string
	 */
	public static function other_site_root( $path ) {
		$path = wp_normalize_path( trim( (string) $path ) );
		if ( '' === $path ) {
			return '';
		}
		$own = array();
		foreach ( array( ABSPATH, dirname( ABSPATH ), Paths::home_dir() ) as $dir ) {
			$dir = untrailingslashit( wp_normalize_path( (string) $dir ) );
			if ( '' !== $dir ) {
				$own[] = $dir;
				$real  = @realpath( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( $real ) {
					$own[] = untrailingslashit( wp_normalize_path( $real ) );
				}
			}
		}
		$real = @realpath( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$dir  = dirname( $real ? wp_normalize_path( $real ) : $path );
		for ( $i = 0; $i < 4 && strlen( $dir ) > 1; $i++ ) {
			if ( in_array( $dir, $own, true ) ) {
				return ''; // Inside this site.
			}
			if ( Storage::path_allowed( $dir ) && ( @is_file( $dir . '/wp-load.php' ) || @is_file( $dir . '/wp-config.php' ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return $dir;
			}
			$dir = dirname( $dir );
		}
		// Cannot look there (open_basedir): compare the account folders of hosting layouts like /home/<site>/.
		if ( preg_match( '#^(/home\d*/[^/]+)/#', $path, $theirs ) && preg_match( '#^(/home\d*/[^/]+)/#', wp_normalize_path( ABSPATH ), $ours ) && $theirs[1] !== $ours[1] ) {
			return $theirs[1];
		}
		return '';
	}

	/**
	 * Where a prepend file of another site may be set, and the root command
	 * that finds the line: the server-wide php.ini of this PHP (often the
	 * cause: every site of that PHP version then runs it), the hosting panel's
	 * per-site PHP settings and this site's .user.ini and .htaccess.
	 *
	 * @return array { text, code, note }
	 */
	public function foreign_prepend_hint() {
		$places = array();
		$loaded = php_ini_loaded_file();
		if ( $loaded ) {
			$places[] = dirname( wp_normalize_path( $loaded ) );
		} elseif ( defined( 'PHP_CONFIG_FILE_PATH' ) && '' !== PHP_CONFIG_FILE_PATH ) {
			$places[] = untrailingslashit( wp_normalize_path( PHP_CONFIG_FILE_PATH ) ); // No php.ini loaded: where PHP looks for one.
		}
		$scanned = php_ini_scanned_files();
		if ( $scanned ) {
			// The conf.d folder of the extra .ini files (pool files and panel snippets live there too).
			$first    = trim( (string) strtok( (string) $scanned, ",\n" ) );
			$places[] = '' !== $first ? dirname( wp_normalize_path( $first ) ) : '';
		}
		$id = '';
		if ( function_exists( 'wpcybersec' ) && is_object( wpcybersec()->hosting ) && method_exists( wpcybersec()->hosting, 'current' ) ) {
			$info = wpcybersec()->hosting->current();
			$id   = isset( $info['id'] ) ? (string) $info['id'] : '';
		}
		if ( 'cyberpanel' === $id || '' !== self::litespeed_edition() ) {
			// lsphp's own php.ini, and the vHost php.ini override of every site (CyberPanel vhost.conf).
			$places[] = '/usr/local/lsws/lsphp*/etc/php/*/litespeed/php.ini';
			$places[] = '/usr/local/lsws/conf/vhosts/*/vhost.conf';
		}
		if ( 'cpanel' === $id ) {
			$places[] = '/opt/cpanel/ea-php*/root/etc';
		}
		if ( 'plesk' === $id ) {
			$places[] = '/opt/plesk/php/*/etc';
			$places[] = '/var/www/vhosts/system/*/etc/php.ini';
		}
		$places[] = '/etc/php*';
		foreach ( $this->wiring_dirs() as $dir ) {
			$places[] = wp_normalize_path( $dir . '.user.ini' );
			$places[] = wp_normalize_path( $dir . '.htaccess' );
		}
		$args = array();
		foreach ( array_unique( array_filter( $places ) ) as $place ) {
			// Wildcards stay unquoted so the shell expands them; other paths are quoted.
			$args[] = preg_match( '#^[A-Za-z0-9_./*-]+$#', $place ) ? $place : Sysadmin_Tools::shell_arg( $place );
		}
		return array(
			'text' => __( 'The line may come from the server-wide php.ini (then every site of this PHP version runs that file) rather than from this site\'s settings. As root, find where it is set:', 'qartvelo-guard' ),
			'code' => 'grep -rn auto_prepend_file ' . implode( ' ', $args ) . ' 2>/dev/null',
			'note' => __( 'Removing it from a shared php.ini removes it for the original site too: that site then needs the line in its own vHost or site settings (its .user.ini, the vHost php.ini override or its PHP-FPM pool).', 'qartvelo-guard' ),
		);
	}

	/**
	 * @param string $prepend auto_prepend_file value.
	 * @return bool
	 */
	private function points_to_bootstrap( $prepend ) {
		$prepend = trim( (string) $prepend );
		if ( '' === $prepend ) {
			return false;
		}
		$bootstrap = $this->bootstrap_path();
		$real_a    = realpath( $prepend );
		$real_b    = realpath( $bootstrap );
		if ( $real_a && $real_b ) {
			return wp_normalize_path( $real_a ) === wp_normalize_path( $real_b );
		}
		return wp_normalize_path( $prepend ) === $bootstrap;
	}

	/**
	 * Whether anything known still points auto_prepend_file at the bootstrap:
	 * the running PHP, or .user.ini / .htaccess in the WordPress folder (checked
	 * too because WP-CLI does not see web server settings).
	 *
	 * @return bool
	 */
	private function bootstrap_referenced() {
		if ( $this->points_to_bootstrap( (string) ini_get( 'auto_prepend_file' ) ) ) {
			return true;
		}
		$ini_name = ini_get( 'user_ini.filename' );
		$ini_name = false === $ini_name || '' === $ini_name ? '.user.ini' : (string) $ini_name;
		$files = array( ABSPATH . $ini_name, ABSPATH . '.htaccess', dirname( ABSPATH ) . '/' . $ini_name, dirname( ABSPATH ) . '/.htaccess' );
		foreach ( $this->wiring_dirs() as $dir ) {
			$files[] = $dir . $ini_name;
			$files[] = $dir . '.htaccess';
		}
		foreach ( array_unique( $files ) as $file ) {
			if ( ! @is_readable( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			foreach ( preg_split( '/\r\n|\n|\r/', (string) @file_get_contents( $file ) ) as $line ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
				$line = ltrim( $line );
				if ( '' === $line || ';' === $line[0] || '#' === $line[0] ) {
					continue;
				}
				if ( false !== stripos( $line, 'auto_prepend_file' ) && false !== strpos( $line, self::BOOTSTRAP_FILE ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* Spool import                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * @return string Lines taken out of the spool and being imported.
	 */
	private function work_file() {
		return wpcybersec()->storage->spool_dir() . '/guard-uploads.work.jsonl';
	}

	/**
	 * @return string Import position in the work file: { offset, tries }.
	 */
	private function pos_file() {
		return wpcybersec()->storage->spool_dir() . '/guard-uploads.work.pos';
	}

	/**
	 * @return string Lock file that keeps two imports from running at once.
	 */
	private function lock_file() {
		return wpcybersec()->storage->spool_dir() . '/guard-import.lock';
	}

	/**
	 * Whether anything waits to be imported (cheap).
	 *
	 * @return bool
	 */
	public function has_pending() {
		$spool = $this->spool_file();
		$work  = $this->work_file();
		clearstatcache( true, $spool );
		clearstatcache( true, $work );
		// filesize() is false for a missing spool: one stat each.
		return (int) @filesize( $spool ) > 0 || @file_exists( $work ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Cron callback: full-size import plus housekeeping of the guard quarantine.
	 */
	public function cron_import() {
		$this->cleanup_partial_copies();
		$this->import_spool();
		$this->maybe_reping( 10 );
	}

	/* ------------------------------------------------------------------ */
	/* Live state                                                          */
	/* ------------------------------------------------------------------ */

	/**
	 * Whether this request can see whether PHP loads the guard: WP-CLI, cron
	 * runs from the command line and PHP's built-in development server never
	 * read .user.ini or .htaccess, so "not active here" means nothing there.
	 *
	 * @return bool
	 */
	public static function request_can_tell() {
		return ! in_array( PHP_SAPI, array( 'cli', 'cli-server', 'phpdbg', 'embed' ), true );
	}

	/**
	 * Stores the result of a live test. "unknown" (the site did not answer its
	 * own test request) keeps the previous result and only notes the try.
	 *
	 * @param string $result active | inactive | down | unknown.
	 */
	public function record_ping( $result ) {
		$last = $this->last_ping();
		if ( ! in_array( $result, array( 'active', 'inactive', 'down' ), true ) ) {
			$last          = $last ? $last : array( 'at' => 0, 'result' => '' );
			$last['tried'] = time();
			Network::update_option( self::PING_OPTION, $last, false );
			return;
		}
		Network::update_option(
			self::PING_OPTION,
			array(
				'at'     => time(),
				'result' => $result,
				'tried'  => time(),
			),
			false
		);
	}

	/**
	 * @return array|null { at, result, tried } of the last live test.
	 */
	public function last_ping() {
		$ping = Network::get_option( self::PING_OPTION, array() );
		if ( ! is_array( $ping ) || ! isset( $ping['at'], $ping['result'] ) ) {
			return null;
		}
		return array(
			'at'     => (int) $ping['at'],
			'result' => (string) $ping['result'],
			'tried'  => isset( $ping['tried'] ) ? (int) $ping['tried'] : (int) $ping['at'],
		);
	}

	/**
	 * Web requests see the answer themselves: remember it (at most hourly,
	 * or at once when it changed), so WP-CLI and cron can show it.
	 */
	private function observe() {
		if ( ! self::request_can_tell() || wp_doing_ajax() ) {
			return;
		}
		$seen = defined( 'WPCYBERSEC_GUARD_ACTIVE' ) ? 'active' : 'inactive';
		$last = $this->last_ping();
		if ( ! $last || $last['result'] !== $seen || $last['at'] < time() - HOUR_IN_SECONDS ) {
			$this->record_ping( $seen );
		}
	}

	/**
	 * Repeats the live test when the last one is older than PING_TTL (at most
	 * one try per PING_TTL, also when the site did not answer).
	 *
	 * @param int $timeout Seconds per test request.
	 */
	public function maybe_reping( $timeout = 10 ) {
		if ( ! $this->is_installed() ) {
			return;
		}
		if ( self::request_can_tell() ) {
			$this->observe();
			return;
		}
		$last = $this->last_ping();
		if ( $last && max( $last['at'], $last['tried'] ) > time() - self::PING_TTL ) {
			return;
		}
		$hardening = wpcybersec()->hardening;
		if ( is_object( $hardening ) && method_exists( $hardening, 'reping' ) ) {
			$hardening->reping( $timeout );
		}
	}

	/**
	 * What to show for the guard: this request's answer when it can tell,
	 * else the last live test.
	 *
	 * @param array|null $status status() (computed when null).
	 * @return array { state active|confirmed|installed|off, label, tone, at }
	 */
	public function live_state( $status = null ) {
		$status = is_array( $status ) ? $status : $this->status();
		if ( ! empty( $status['active'] ) ) {
			return array(
				'state' => 'active',
				'label' => __( 'Active', 'qartvelo-guard' ),
				'tone'  => 'ok',
				'at'    => time(),
			);
		}
		if ( ! empty( $status['confirmed'] ) ) {
			$at = (int) $status['ping']['at'];
			return array(
				'state' => 'confirmed',
				/* translators: %s: time ago, for example "5 minutes ago" */
				'label' => sprintf( __( 'Active (confirmed by a live test %s)', 'qartvelo-guard' ), Admin\Admin::ago( $at ) ),
				'tone'  => 'ok',
				'at'    => $at,
			);
		}
		if ( ! empty( $status['installed'] ) ) {
			return array(
				'state' => 'installed',
				'label' => __( 'Installed, not loaded yet', 'qartvelo-guard' ),
				'tone'  => 'medium',
				'at'    => 0,
			);
		}
		return array(
			'state' => 'off',
			'label' => __( 'Not installed', 'qartvelo-guard' ),
			'tone'  => 'muted',
			'at'    => 0,
		);
	}

	/**
	 * Turns uploads held by the guard into pending upload items.
	 *
	 * Lines are moved from the spool into a work file under the guard's own lock
	 * and imported one by one. The position in the work file is saved before
	 * and after every line, so a request that dies (time limit, fatal error)
	 * loses nothing: the next run continues with the same line. A line whose
	 * import never finished twice is imported without the signature scan, so one
	 * file that makes the scanner hang cannot block the queue.
	 *
	 * @param int  $max_lines   Lines to import in this call (0: IMPORT_BATCH).
	 * @param int  $max_seconds Time budget in seconds (0: IMPORT_SECONDS).
	 * @param bool $fresh_only  Stop at a line whose earlier try never finished
	 *                          (admin page loads leave those to cron).
	 * @return int Items created.
	 */
	public function import_spool( $max_lines = 0, $max_seconds = 0, $fresh_only = false ) {
		$max_lines   = (int) $max_lines > 0 ? (int) $max_lines : self::IMPORT_BATCH;
		$max_seconds = (int) $max_seconds > 0 ? (int) $max_seconds : self::IMPORT_SECONDS;
		if ( ! $this->has_pending() ) {
			return 0;
		}
		$lock = $this->acquire_import_lock();
		if ( ! $lock ) {
			return 0; // Another request is importing right now.
		}

		$imported        = 0;
		$this->importing = true;
		try {
			$deadline = microtime( true ) + $max_seconds;
			$done     = 0;
			while ( $done < $max_lines && microtime( true ) < $deadline ) {
				$next = $this->next_work_line();
				if ( false === $next ) {
					break; // The work file cannot be read or the position cannot be saved.
				}
				if ( null === $next ) {
					if ( ! $this->claim_spool() ) {
						break; // Nothing waiting.
					}
					continue;
				}

				if ( $fresh_only && $next['tries'] > 0 ) {
					break;
				}

				// Record the try before anything that can hang or die.
				$tries = $next['tries'] + 1;
				if ( $tries > self::MAX_ATTEMPTS ) {
					// Even the import without a scan keeps dying: give this line up.
					$this->log( 'guard_import_error', __( 'Skipped a line of the early guard spool that could not be imported after several tries.', 'qartvelo-guard' ) );
					if ( ! $this->write_pos( $next['end'], 0 ) ) {
						break;
					}
					continue;
				}
				if ( ! $this->write_pos( $next['offset'], $tries ) ) {
					break;
				}
				++$done;

				$result = 'skipped';
				$entry  = json_decode( $next['line'], true );
				if ( is_array( $entry ) ) {
					$attempts = ( isset( $entry['attempts'] ) ? max( 0, (int) $entry['attempts'] ) : 0 ) + 1;
					try {
						$result = $this->import_entry( $entry, $tries <= self::SCAN_TRIES );
					} catch ( \Throwable $e ) {
						$result = 'retry';
						$this->log(
							'guard_import_error',
							/* translators: %s: error message */
							sprintf( __( 'Could not import an upload held by the early guard: %s', 'qartvelo-guard' ), $e->getMessage() )
						);
					}
					if ( 'retry' === $result ) {
						if ( $attempts < self::MAX_ATTEMPTS ) {
							$entry['attempts'] = $attempts;
							$this->append_spool( array( wp_json_encode( $entry ) ) );
						} else {
							$this->log(
								'guard_import_error',
								sprintf(
									/* translators: 1: file name, 2: SHA-256 */
									__( 'Gave up importing the held upload "%1$s" (SHA-256 %2$s) after several failed tries. Its copy stays in the guard quarantine folder.', 'qartvelo-guard' ),
									Upload_Gate::safe_name( isset( $entry['name'] ) ? (string) $entry['name'] : '' ),
									isset( $entry['sha256'] ) ? sanitize_key( (string) $entry['sha256'] ) : ''
								)
							);
						}
					}
				}

				if ( ! $this->write_pos( $next['end'], 0 ) ) {
					break;
				}
				if ( 'imported' === $result ) {
					++$imported;
				} elseif ( 'retry' === $result ) {
					break; // Most likely the database; try again on the next run.
				}
			}
		} finally {
			$this->importing = false;
			$this->release_import_lock( $lock );
		}
		return $imported;
	}

	/**
	 * @return resource|null Lock handle, or null when another import holds it.
	 */
	private function acquire_import_lock() {
		$dir = wpcybersec()->storage->spool_dir();
		if ( ! is_dir( $dir ) ) {
			return null;
		}
		$handle = @fopen( $this->lock_file(), 'c' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		if ( ! $handle ) {
			return null;
		}
		if ( ! @flock( $handle, LOCK_EX | LOCK_NB ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
			@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
			return null;
		}
		return $handle;
	}

	/**
	 * @param resource $handle Lock handle.
	 */
	private function release_import_lock( $handle ) {
		@flock( $handle, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
		@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
	}

	/**
	 * Moves everything waiting in the spool into a new work file. Runs under the
	 * guard's own spool lock, and the spool file keeps its identity (it is
	 * emptied, never renamed), so a guard writing at the same time loses nothing.
	 *
	 * @return bool Whether a work file was created.
	 */
	private function claim_spool() {
		$spool = $this->spool_file();
		$work  = $this->work_file();
		clearstatcache( true, $spool );
		if ( ! is_file( $spool ) || 0 === (int) @filesize( $spool ) || @is_file( $work ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$handle = @fopen( $spool, 'c+' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		if ( ! $handle ) {
			return false;
		}
		if ( ! @flock( $handle, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
			@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
			return false;
		}
		$ok   = false;
		$tmp  = $work . '.' . wp_generate_password( 12, false ) . '.tmp';
		$stat = fstat( $handle );
		$size = is_array( $stat ) ? (int) $stat['size'] : 0;
		if ( $size > 0 ) {
			$out = @fopen( $tmp, 'xb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- native handle needed for flock() and streaming; WP_Filesystem has neither.
			if ( $out ) {
				rewind( $handle );
				$copied = stream_copy_to_stream( $handle, $out );
				$ok     = false !== $copied && (int) $copied === $size && @fflush( $out ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
				@fclose( $out ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
				// The position file belongs to the work file; start the new one at 0.
				if ( $ok && is_file( $this->pos_file() ) ) {
					$ok = Fs::delete( $this->pos_file() );
				}
				$ok = $ok && Fs::replace( $tmp, $work );
				if ( $ok ) {
					// Only now that every line is safe in the work file.
					ftruncate( $handle, 0 );
					fflush( $handle );
				} else {
					Fs::delete( $tmp );
				}
			}
		}
		@flock( $handle, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
		@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		return $ok;
	}

	/**
	 * Next line of the work file.
	 *
	 * @return array|null|false { line, offset, end, tries }, null when there is no
	 *                          work left, false when the work file cannot be used.
	 */
	private function next_work_line() {
		$work = $this->work_file();
		clearstatcache( true, $work );
		if ( ! is_file( $work ) ) {
			if ( is_file( $this->pos_file() ) ) {
				Fs::delete( $this->pos_file() );
			}
			return null;
		}
		$pos    = $this->read_pos();
		$handle = @fopen( $work, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		if ( ! $handle ) {
			return false;
		}
		$offset = $pos['offset'];
		$tries  = $pos['tries'];
		$result = null;
		while ( true ) {
			if ( 0 !== fseek( $handle, $offset ) ) {
				break;
			}
			$line = fgets( $handle );
			if ( false === $line ) {
				break; // End of the work file.
			}
			$end = ftell( $handle );
			if ( '' !== trim( $line ) ) {
				$result = array(
					'line'   => trim( $line ),
					'offset' => $offset,
					'end'    => (int) $end,
					'tries'  => $tries,
				);
				break;
			}
			$offset = (int) $end;
			$tries  = 0;
		}
		@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.

		if ( null === $result ) {
			// Everything in the work file is imported.
			Fs::delete( $work );
			Fs::delete( $this->pos_file() );
			clearstatcache( true, $work );
			return is_file( $work ) ? false : null;
		}
		return $result;
	}

	/**
	 * @return array { offset, tries }
	 */
	private function read_pos() {
		$pos  = array(
			'offset' => 0,
			'tries'  => 0,
		);
		$file = $this->pos_file();
		if ( ! is_file( $file ) ) {
			return $pos;
		}
		$data = json_decode( (string) @file_get_contents( $file ), true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( is_array( $data ) ) {
			$pos['offset'] = isset( $data['offset'] ) ? max( 0, (int) $data['offset'] ) : 0;
			$pos['tries']  = isset( $data['tries'] ) ? max( 0, (int) $data['tries'] ) : 0;
		}
		return $pos;
	}

	/**
	 * @param int $offset Byte offset of the next line to import.
	 * @param int $tries  Unfinished tries of that line.
	 * @return bool
	 */
	private function write_pos( $offset, $tries ) {
		$json = wp_json_encode(
			array(
				'offset' => (int) $offset,
				'tries'  => (int) $tries,
			)
		);
		return Guard_Config::atomic_write( $this->pos_file(), (string) $json );
	}

	/**
	 * Removes copies the guard left half-written (the request died while copying).
	 */
	private function cleanup_partial_copies() {
		$list = @glob( $this->quarantine_dir() . '/*/*/*.part', GLOB_NOSORT ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $list ) ) {
			return;
		}
		$cutoff = time() - DAY_IN_SECONDS;
		foreach ( array_slice( $list, 0, 1000 ) as $path ) {
			$mtime = @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false !== $mtime && $mtime < $cutoff ) {
				Fs::delete( $path );
			}
		}
	}

	/**
	 * @param array $entry Spool line.
	 * @param bool  $scan  Run the signature scan on the held copy.
	 * @return string imported | skipped | retry
	 */
	private function import_entry( array $entry, $scan = true ) {
		$plugin = wpcybersec();
		$sha256 = isset( $entry['sha256'] ) ? strtolower( (string) $entry['sha256'] ) : '';
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $sha256 ) ) {
			return 'skipped';
		}

		// Never trust a path from the spool unless it is inside the guard quarantine.
		$held_path = isset( $entry['quarantine_path'] ) ? wp_normalize_path( (string) $entry['quarantine_path'] ) : '';
		if ( '' !== $held_path && ( ! is_file( $held_path ) || ! Storage::is_within( $held_path, $this->quarantine_dir() ) ) ) {
			$held_path = '';
		}
		$stub       = array( 'quarantine_path' => $held_path );
		$raw_name   = isset( $entry['name'] ) ? (string) $entry['name'] : '';
		$name       = Upload_Gate::safe_name( $raw_name, $sha256 );
		$executable = ! empty( $entry['exec'] ) || Upload_Gate::name_is_executable( $raw_name ) || Upload_Gate::name_is_executable( $name );

		// Approved in the meantime (an approval under a harmless name does not cover an executable one).
		if ( $plugin->allowlist->is_allowed_hash( $sha256, $executable ) ) {
			if ( '' !== $held_path ) {
				$plugin->quarantine->purge( $stub );
			}
			return 'skipped';
		}

		// Same content under the same kind of name already waiting: keep one item.
		$existing = $this->find_open_upload( $sha256, $executable );
		if ( $existing ) {
			$update = array(
				'details' => array(
					'repeat_count' => ( isset( $existing['details']['repeat_count'] ) ? (int) $existing['details']['repeat_count'] : 0 ) + 1,
					'last_attempt' => Store::now(),
				),
			);
			// Copies are named by content, so the new copy may be the item's own copy: never purge that one.
			$existing_path = '' !== (string) $existing['quarantine_path'] ? wp_normalize_path( (string) $existing['quarantine_path'] ) : '';
			if ( '' !== $held_path && $existing_path !== $held_path ) {
				if ( $plugin->quarantine->exists( $existing ) ) {
					$plugin->quarantine->purge( $stub );
				} else {
					$update['quarantine_path'] = $held_path;
				}
			}
			$plugin->store->item_update( $existing['id'], $update );
			return 'skipped';
		}

		$note = isset( $entry['note'] ) ? sanitize_key( (string) $entry['note'] ) : '';

		$hits = array();
		if ( '' !== $held_path && ! $scan ) {
			// Earlier tries never finished (the scan probably hung): import without it.
			$hits[] = array(
				'sig'      => 'scan_incomplete',
				'title'    => __( 'The malware check of this file did not finish, so it was not checked. Treat it as unknown.', 'qartvelo-guard' ),
				'severity' => Store::SEV_MEDIUM,
				'line'     => 0,
				'snippet'  => '',
			);
		} elseif ( '' !== $held_path && $plugin->scanner && method_exists( $plugin->scanner, 'scan_upload' ) ) {
			try {
				$hits = $plugin->scanner->scan_upload( $held_path, $name );
				$hits = is_array( $hits ) ? array_values( array_filter( $hits, 'is_array' ) ) : array();
			} catch ( \Throwable $e ) {
				$hits = array();
			}
		}
		$severity = 0;
		if ( $plugin->scanner && method_exists( $plugin->scanner, 'max_severity' ) ) {
			$severity = (int) $plugin->scanner->max_severity( $hits );
		} else {
			foreach ( $hits as $hit ) {
				$severity = max( $severity, isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 );
			}
		}

		$ip      = isset( $entry['ip'] ) && filter_var( (string) $entry['ip'], FILTER_VALIDATE_IP ) ? (string) $entry['ip'] : '';
		$time    = isset( $entry['time'] ) ? (int) $entry['time'] : 0;
		$created = $time > 0 && $time <= time() + HOUR_IN_SECONDS ? gmdate( 'Y-m-d H:i:s', $time ) : Store::now();
		$script  = isset( $entry['script'] ) ? Upload_Gate::cut( sanitize_text_field( (string) $entry['script'] ), 255 ) : '';

		$id = $plugin->store->item_insert(
			array(
				'type'            => Store::TYPE_UPLOAD,
				'status'          => Store::STATUS_PENDING,
				'severity'        => $severity,
				'path'            => $name,
				'original_path'   => '',
				'quarantine_path' => $held_path,
				'sha256'          => $sha256,
				'size'            => isset( $entry['size'] ) ? max( 0, (int) $entry['size'] ) : 0,
				'mime'            => $this->mime_for( $held_path, $name, isset( $entry['type'] ) ? (string) $entry['type'] : '' ),
				'source'          => 'guard',
				'user_id'         => 0,
				'ip'              => $ip,
				'created_at'      => $created,
				'details'         => array(
					'context'         => 'guard',
					'script'          => $script,
					'request_uri'     => isset( $entry['uri'] ) ? Upload_Gate::cut( sanitize_text_field( (string) $entry['uri'] ), 1000 ) : '',
					'method'          => isset( $entry['method'] ) ? substr( sanitize_key( (string) $entry['method'] ), 0, 10 ) : '',
					'field'           => isset( $entry['field'] ) ? Upload_Gate::cut( sanitize_text_field( (string) $entry['field'] ), 255 ) : '',
					'user_agent'      => isset( $entry['ua'] ) ? Upload_Gate::cut( sanitize_text_field( (string) $entry['ua'] ), 255 ) : '',
					'guard_action'    => isset( $entry['action'] ) && 'strip' === $entry['action'] ? 'strip' : 'block',
					'held'            => '' !== $held_path,
					'note'            => $note,
					'executable'      => $executable,
					'scan_incomplete' => '' !== $held_path && ! $scan,
					'hits'            => array_slice( $hits, 0, 50 ),
				) + $this->site_of_entry( $entry ),
			)
		);
		if ( ! $id ) {
			return 'retry';
		}

		if ( 'too_large' === $note ) {
			/* translators: 1: file name, 2: script */
			$message = sprintf( __( 'Early guard refused "%1$s" sent to %2$s (too large to keep a copy). Approving it allows the file next time.', 'qartvelo-guard' ), $name, $script );
		} elseif ( in_array( $note, array( 'quota_full', 'no_space', 'copy_failed' ), true ) ) {
			/* translators: 1: file name, 2: script */
			$message = sprintf( __( 'Early guard refused "%1$s" sent to %2$s without keeping a copy, because the guard quarantine is full or could not be written. Review the held uploads to free space. Approving it allows the file next time.', 'qartvelo-guard' ), $name, $script );
		} else {
			/* translators: 1: file name, 2: script */
			$message = sprintf( __( 'Early guard held "%1$s" sent to %2$s.', 'qartvelo-guard' ), $name, $script );
		}
		$this->log(
			'guard_upload_held',
			$message,
			array(
				'item_id'  => $id,
				'sha256'   => $sha256,
				'severity' => $severity,
				'ip'       => $ip,
			)
		);

		if ( $plugin->notifier && method_exists( $plugin->notifier, 'item_created' ) ) {
			try {
				$plugin->notifier->item_created( $id );
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}
		return 'imported';
	}

	/**
	 * Multisite: the site a held request was sent to, from its host and path.
	 *
	 * @param array $entry Spool line.
	 * @return array { blog_id } or empty.
	 */
	private function site_of_entry( array $entry ) {
		if ( ! Network::active() || ! function_exists( 'get_site_by_path' ) ) {
			return array();
		}
		// Like core (ms-load.php) only the default ports are dropped: a network
		// on another port stores "host:port" as the domain of its sites.
		$host = isset( $entry['host'] ) ? strtolower( (string) preg_replace( '/:(?:80|443)$/', '', (string) $entry['host'] ) ) : '';
		$path = isset( $entry['uri'] ) ? (string) wp_parse_url( (string) $entry['uri'], PHP_URL_PATH ) : '/';
		$path = '' !== $path ? $path : '/';
		if ( '' === $host ) {
			$port = (int) wp_parse_url( network_home_url(), PHP_URL_PORT );
			$host = strtolower( (string) wp_parse_url( network_home_url(), PHP_URL_HOST ) ) . ( $port && ! in_array( $port, array( 80, 443 ), true ) ? ':' . $port : '' );
		}
		$site = get_site_by_path( $host, $path );
		if ( ! $site && false !== strpos( $host, ':' ) ) {
			$site = get_site_by_path( (string) preg_replace( '/:\d+$/', '', $host ), $path ); // Domain stored without the port.
		}
		return $site ? array( 'blog_id' => (int) $site->blog_id ) : array();
	}

	/**
	 * @param string[] $lines JSON lines to put back.
	 */
	private function append_spool( array $lines ) {
		$handle = @fopen( $this->spool_file(), 'ab' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		if ( ! $handle ) {
			return;
		}
		if ( @flock( $handle, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
			@fwrite( $handle, implode( "\n", $lines ) . "\n" ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- native handle needed for flock() and streaming; WP_Filesystem has neither.
			@fflush( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
			@flock( $handle, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
		}
		@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
	}

	/**
	 * @return int Lines waiting in the spool and in the unfinished part of the work file.
	 */
	private function spool_count() {
		$count = $this->count_lines( $this->spool_file(), 0 );
		if ( is_file( $this->work_file() ) ) {
			$pos    = $this->read_pos();
			$count += $this->count_lines( $this->work_file(), $pos['offset'] );
		}
		return $count;
	}

	/**
	 * @param string $file   File.
	 * @param int    $offset Start offset.
	 * @return int Newlines after $offset.
	 */
	private function count_lines( $file, $offset ) {
		if ( ! is_file( $file ) || (int) @filesize( $file ) <= $offset ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return 0;
		}
		$count  = 0;
		$handle = @fopen( $file, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		if ( ! $handle ) {
			return 0;
		}
		if ( $offset > 0 ) {
			fseek( $handle, $offset );
		}
		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, 65536 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- native handle needed for flock() and streaming; WP_Filesystem has neither.
			if ( false === $chunk ) {
				break;
			}
			$count += substr_count( $chunk, "\n" );
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		return $count;
	}

	/**
	 * @param string $sha256     Hash.
	 * @param bool   $executable Whether the new upload has an executable name.
	 * @return array|null Open upload item with this content and the same kind of name.
	 */
	private function find_open_upload( $sha256, $executable = false ) {
		$result = wpcybersec()->store->items_query(
			array(
				'type'     => Store::TYPE_UPLOAD,
				'status'   => Store::STATUS_PENDING,
				'search'   => $sha256,
				'per_page' => 5,
			)
		);
		foreach ( $result['rows'] as $row ) {
			if ( $row['sha256'] === $sha256 && Upload_Gate::item_is_executable( $row ) === (bool) $executable ) {
				return $row;
			}
		}
		return null;
	}

	/**
	 * @param string $path        Held copy ('' when none).
	 * @param string $name        File name.
	 * @param string $client_type Browser supplied type.
	 * @return string
	 */
	private function mime_for( $path, $name, $client_type ) {
		if ( '' !== $path ) {
			$check = wp_check_filetype_and_ext( $path, $name );
			if ( ! empty( $check['type'] ) ) {
				return (string) $check['type'];
			}
			if ( function_exists( 'finfo_open' ) ) {
				$finfo = @finfo_open( FILEINFO_MIME_TYPE ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( $finfo ) {
					$mime = @finfo_file( $finfo, $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
					finfo_close( $finfo );
					if ( $mime ) {
						return substr( sanitize_mime_type( $mime ), 0, 100 );
					}
				}
			}
		}
		$client_type = sanitize_mime_type( $client_type );
		return $client_type ? substr( $client_type, 0, 100 ) : 'application/octet-stream';
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Tells the file monitor that a file this plugin wrote is expected.
	 *
	 * @param string $path File.
	 */
	private function trust_file( $path ) {
		$monitor = wpcybersec()->file_monitor;
		if ( $monitor && method_exists( $monitor, 'trust_file' ) && is_file( $path ) ) {
			try {
				$monitor->trust_file( $path );
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}
	}

	/**
	 * @param string $path File that no longer exists.
	 */
	private function forget_file( $path ) {
		$monitor = wpcybersec()->file_monitor;
		if ( $monitor && method_exists( $monitor, 'forget_file' ) ) {
			try {
				$monitor->forget_file( $path );
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}
	}

	/**
	 * @param string $event   Event.
	 * @param string $message Message.
	 * @param array  $context Context ('ip': the visitor's address, for entries of an import).
	 * @return int Log id (0 when nothing was logged).
	 */
	private function log( $event, $message, array $context = array() ) {
		if ( $this->quiet && in_array( $event, self::QUIET_EVENTS, true ) ) {
			return 0;
		}
		$logger = wpcybersec()->logger;
		if ( ! $logger ) {
			return 0;
		}
		$id = (int) $logger->log( $event, $message, $context );
		if ( $id && $this->importing ) {
			// The import runs in whatever request comes next (often an administrator's page
			// load), but what it records happened in the visitor's request: no user, the
			// visitor's address (the item shows "Visitor, Early guard" too).
			global $wpdb;
			$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				Store::table( 'log' ),
				array(
					'user_id' => 0,
					'ip'      => isset( $context['ip'] ) ? (string) $context['ip'] : '',
				),
				array( 'id' => $id ),
				array( '%d', '%s' ),
				array( '%d' )
			);
		}
		return $id;
	}

	/**
	 * Leaves the install and wiring entries (QUIET_EVENTS) out of the activity
	 * log while the one-click install runs, which logs one summary instead.
	 *
	 * @param bool $quiet On or off.
	 */
	public function set_quiet( $quiet ) {
		$this->quiet = (bool) $quiet;
	}
}
