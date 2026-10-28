<?php
/**
 * Private data directory (quarantine, scan job files, guard spool).
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves and protects the plugin's data directory.
 *
 * Default: a random folder inside wp-content/uploads/qartvelo-guard
 * (wp-content/wpcybersec before 1.1.0, moved automatically). System administrators can move it outside
 * the web root with define( 'WPCYBERSEC_DATA_DIR', '/var/lib/wpcybersec/site' )
 * in wp-config.php. Works before the plugin is booted (activation hooks).
 */
class Storage {

	/** Option set by the one-click "move the data folder" fix (single sites only). */
	const DIR_OPTION = 'wpcybersec_data_dir';

	/**
	 * State of a move that has not finished: { source, target, phase, time }.
	 * phase "copy": copying, nothing switched yet. phase "switched": the plugin
	 * uses the new folder; the old one still has to be emptied.
	 */
	const MOVE_OPTION = 'wpcybersec_data_move';

	/** Lock row (in the options table) held while a move runs: "<time>:<token>". */
	const MOVE_LOCK = 'wpcybersec_data_move_lock';

	/** A lock not refreshed for this long belongs to a request that died. */
	const MOVE_LOCK_STALE = 1800;

	/** File that ties a moved data folder to this site (see site_id()). */
	const MARKER_FILE = '.wpcybersec-site';

	/** Deny files written by protect(). */
	const DENY_FILES = array( '.htaccess', 'index.php', 'web.config' );

	/**
	 * Files of the guard spool that are never copied as they are: their lines
	 * hold absolute paths, so they are moved line by line (migrate_spool()).
	 */
	const SPOOL_RUNTIME = array( 'spool/guard-uploads.jsonl', 'spool/guard-uploads.work.jsonl', 'spool/guard-uploads.work.pos', 'spool/guard-import.lock' );

	/**
	 * Folder inside the uploads folder used when no configured folder is
	 * writable (read-only wp-content, FTP-owned files, read-only containers).
	 * Holds the absolute path with a random suffix; a site option on multisite.
	 */
	const FALLBACK_OPTION = 'wpcybersec_data_fallback';

	/** Last storage state seen by check(): { state, dir, primary, time }. */
	const STATUS_OPTION = 'wpcybersec_storage_status';

	/** When the move away from the pre-1.1.0 folder was last tried (Hardening::move_legacy_data_dir()). */
	const LEGACY_MOVE_OPTION = 'wpcybersec_legacy_move';

	/** Random name of the default data folder inside uploads/qartvelo-guard (default_dir()). */
	const TOKEN_OPTION = 'wpcybersec_data_token';

	/** Folder in uploads that holds the default data folder. */
	const UPLOADS_FOLDER = 'qartvelo-guard';

	/** @var string Value of the move lock this request holds. */
	private $lock_value = '';

	/** @var int Last time the move lock was refreshed. */
	private $lock_beat = 0;

	/** @var array|null Per-request result of resolve(), shared by every instance. */
	private static $resolved = null;

	/**
	 * The folder in use. Resolution order, first writable one wins:
	 *   1. WPCYBERSEC_DATA_DIR constant,
	 *   2. a fallback folder inside uploads that is already in use (it keeps
	 *      being used until the data is moved, so held items stay reachable),
	 *   3. the folder chosen by the one-click move (option, single sites only),
	 *   4. wp-content/uploads/qartvelo-guard/<random> (default_dir()),
	 *   5. a new fallback folder wp-content/uploads/qartvelo-guard-<random>.
	 * When none is writable, status() says "unavailable" and this returns the
	 * configured folder (ensure() then fails with an explanation).
	 *
	 * @return string Absolute path, no trailing slash.
	 */
	public function data_dir() {
		$status = $this->resolve();
		return $status['dir'];
	}

	/**
	 * The folder the configuration asks for, without looking at permissions:
	 * the constant, else the moved folder, else default_dir().
	 *
	 * @return string
	 */
	public function configured_dir() {
		if ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) {
			return untrailingslashit( wp_normalize_path( WPCYBERSEC_DATA_DIR ) );
		}
		$moved = $this->moved_dir();
		return '' !== $moved ? $moved : $this->default_dir();
	}

	/**
	 * Folder chosen by the one-click move, when it still exists.
	 *
	 * @return string '' when none.
	 */
	private function moved_dir() {
		// On multisite every site shares one folder, so a per-site option cannot move it.
		if ( ! is_multisite() ) {
			$moved = Network::get_option( self::DIR_OPTION, '' );
			if ( is_string( $moved ) && '' !== $moved && Paths::is_absolute( wp_normalize_path( $moved ) ) && @is_dir( $moved ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return untrailingslashit( wp_normalize_path( $moved ) );
			}
		}
		// Installs from before 1.1.0 keep their folder until it is moved (Hardening::admin_upkeep()).
		return $this->legacy_in_use() ? $this->legacy_dir() : '';
	}

	/**
	 * The data folder of versions before 1.1.0 (wp-content/wpcybersec). Only
	 * read, never created: new installs use default_dir().
	 *
	 * @return string
	 */
	public function legacy_dir() {
		return untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) . '/wpcybersec';
	}

	/**
	 * Whether this site still keeps its data in legacy_dir().
	 *
	 * @return bool
	 */
	public function legacy_in_use() {
		if ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) {
			return false;
		}
		$legacy = $this->legacy_dir();
		if ( $legacy === $this->default_dir() || ! @is_dir( $legacy ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		foreach ( array( 'quarantine', 'guard', 'jobs', 'spool' ) as $sub ) {
			if ( @is_dir( $legacy . '/' . $sub ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return true;
			}
		}
		return false;
	}

	/**
	 * Where the data lives and why.
	 *
	 * @return array {
	 *     state   ok (the configured folder) | fallback (another writable folder) | unavailable,
	 *     dir     folder in use (the configured one when unavailable),
	 *     primary configured folder (constant, moved folder or the default),
	 *     source  constant | moved | default | fallback (where dir comes from),
	 *     primary_ok whether the configured folder is writable now
	 * }
	 */
	public function status() {
		return $this->resolve();
	}

	/**
	 * Whether held files, scan files and the guard config can be stored at all.
	 *
	 * @return bool
	 */
	public function available() {
		$status = $this->resolve();
		return 'unavailable' !== $status['state'];
	}

	/**
	 * Forgets the resolved folder (after a move or a permission change).
	 */
	public static function reset() {
		self::$resolved = null;
		self::$default  = null;
	}

	/**
	 * Resolves the folder once per request.
	 *
	 * @return array See status().
	 */
	private function resolve() {
		if ( null !== self::$resolved ) {
			return self::$resolved;
		}
		$const   = defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ? untrailingslashit( wp_normalize_path( WPCYBERSEC_DATA_DIR ) ) : '';
		$moved   = $this->moved_dir();
		$default = $this->default_dir();
		$primary = '' !== $const ? $const : ( '' !== $moved ? $moved : $default );

		$candidates = array();
		if ( '' !== $const ) {
			$candidates[] = array( $const, 'constant' );
		}
		// A fallback folder in use keeps being used (held items and the guard
		// config live there) until its data is moved away; the folder of a move
		// that has switched over is the old one and no longer counts.
		$fallback = $this->stored_fallback();
		$move     = Network::get_option( self::MOVE_OPTION, null );
		$leaving  = is_array( $move ) && ! empty( $move['source'] ) && 'switched' === ( isset( $move['phase'] ) ? $move['phase'] : '' ) ? untrailingslashit( wp_normalize_path( (string) $move['source'] ) ) : '';
		if ( '' !== $fallback && $fallback !== $leaving && @is_dir( $fallback ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$candidates[] = array( $fallback, 'fallback' );
		}
		if ( '' !== $moved ) {
			$candidates[] = array( $moved, 'moved' );
		}
		$candidates[] = array( $default, 'default' );

		$primary_ok = self::dir_ok( $primary );
		$found      = null;
		foreach ( $candidates as $candidate ) {
			if ( $candidate[0] === $primary ? $primary_ok : self::dir_ok( $candidate[0] ) ) {
				$found = $candidate;
				break;
			}
		}
		if ( null === $found ) {
			$new = $this->new_fallback();
			if ( '' !== $new && self::dir_ok( $new ) ) {
				$found = array( $new, 'fallback' );
			}
		}

		if ( null === $found ) {
			$state = 'unavailable';
			$dir   = $primary;
			$from  = '' !== $const ? 'constant' : ( '' !== $moved ? 'moved' : 'default' );
		} else {
			$dir   = $found[0];
			$from  = $found[1];
			$state = $dir === $primary ? 'ok' : 'fallback';
		}
		self::$resolved = array(
			'state'      => $state,
			'dir'        => $dir,
			'primary'    => $primary,
			'source'     => $from,
			'primary_ok' => $primary_ok,
		);
		return self::$resolved;
	}

	/**
	 * Whether a folder is writable, or can be created because its nearest
	 * existing parent is writable.
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	private static function dir_ok( $dir ) {
		$dir = (string) $dir;
		if ( '' === $dir || ! self::path_allowed( $dir ) ) {
			return false;
		}
		if ( @is_dir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! wp_is_writable( $dir ) ) {
				return false;
			}
			// A folder copied by another user can be writable at the top only.
			$quarantine = $dir . '/quarantine';
			return ! @is_dir( $quarantine ) || wp_is_writable( $quarantine ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		if ( @file_exists( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$parent = dirname( $dir );
		for ( $i = 0; $i < 20; $i++ ) {
			if ( ! self::path_allowed( $parent ) ) {
				return false; // wp_mkdir_p() would have to look outside open_basedir.
			}
			if ( @is_dir( $parent ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return wp_is_writable( $parent );
			}
			if ( @file_exists( $parent ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return false;
			}
			$up = dirname( $parent );
			if ( $up === $parent ) {
				break;
			}
			$parent = $up;
		}
		return false;
	}

	/**
	 * Fallback folder remembered earlier (it may not exist any more).
	 *
	 * @return string
	 */
	public function stored_fallback() {
		$value = Network::get_option( self::FALLBACK_OPTION, '' );
		if ( ! is_string( $value ) || '' === $value || ! Paths::is_absolute( wp_normalize_path( $value ) ) ) {
			return '';
		}
		return untrailingslashit( wp_normalize_path( $value ) );
	}

	/**
	 * A fallback folder inside the uploads folder, with a random name so it
	 * cannot be guessed on servers that ignore the deny files (nginx). The
	 * name is remembered, so every request uses the same folder.
	 *
	 * @return string '' when the uploads folder is unknown.
	 */
	private function new_fallback() {
		$stored = $this->stored_fallback();
		if ( '' !== $stored ) {
			return $stored;
		}
		// On multisite the main site's uploads folder: a sub site's folder is deleted with the site.
		$base = self::uploads_basedir();
		if ( '' === $base ) {
			return '';
		}
		if ( ! self::dir_ok( $base . '/qartvelo-guard-probe' ) ) {
			return ''; // Nothing to remember while uploads is not writable either.
		}
		$dir = $base . '/qartvelo-guard-' . strtolower( wp_generate_password( 16, false, false ) );
		Network::update_option( self::FALLBACK_OPTION, $dir, true );
		return $dir;
	}

	/**
	 * Checks where the data can be stored (activation, settings and plugin
	 * pages), remembers the result and logs a change of state.
	 *
	 * @return array See status().
	 */
	public function check() {
		self::reset();
		$status = $this->resolve();
		$saved  = Network::get_option( self::STATUS_OPTION, array() );
		$saved  = is_array( $saved ) ? $saved : array();
		if ( ! isset( $saved['state'], $saved['dir'] ) || $saved['state'] !== $status['state'] || $saved['dir'] !== $status['dir'] ) {
			Network::update_option(
				self::STATUS_OPTION,
				array(
					'state'   => $status['state'],
					'dir'     => $status['dir'],
					'primary' => $status['primary'],
					'time'    => time(),
				),
				false
			);
			if ( 'unavailable' === $status['state'] ) {
				/* translators: %s: folder path */
				self::log( 'storage_unavailable', sprintf( __( 'No writable data folder: %s is not writable and neither is the uploads folder. Uploads are not held (only uploads that look malicious are blocked) and scans cannot run.', 'qartvelo-guard' ), '' !== $status['primary'] ? $status['primary'] : __( 'the uploads folder', 'qartvelo-guard' ) ) );
			} elseif ( 'fallback' === $status['state'] ) {
				/* translators: 1: folder in use, 2: configured folder */
				self::log( 'storage_fallback', sprintf( __( 'Data is kept in %1$s because %2$s is not writable (or the data was kept there before).', 'qartvelo-guard' ), $status['dir'], $status['primary'] ) );
			} elseif ( isset( $saved['state'] ) ) {
				/* translators: %s: folder path */
				self::log( 'storage_ok', sprintf( __( 'The data folder %s is writable.', 'qartvelo-guard' ), $status['dir'] ) );
			}
		}
		return $status;
	}

	/**
	 * Plain explanation of a storage state that needs attention, for the admin
	 * notice and the environment check.
	 *
	 * @param array|null $status status() result (current when null).
	 * @return array|null { level error|warning, title, text, fix, code } or null when all is well.
	 */
	public function problem( $status = null ) {
		$status  = is_array( $status ) ? $status : $this->resolve();
		$primary = $status['primary'];
		$const   = defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR;
		$outside = $this->suggested_outside_dir();
		$hint    = '';
		if ( ! self::path_allowed( $outside ) ) {
			$hint = self::basedir_hint() . ' '; // Never suggest a folder PHP may not use.
		}
		if ( '' !== $hint || $this->is_in_webroot( $outside ) ) {
			$outside = '/path/outside/the/web/root/wpcybersec'; // Nothing suitable was found: a placeholder to fill in.
		}
		$code = "define( 'WPCYBERSEC_DATA_DIR', " . var_export( $outside, true ) . ' );'; // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		if ( 'unavailable' === $status['state'] ) {
			return array(
				'level' => 'error',
				'title' => __( 'Qartvelo Guard cannot store any data', 'qartvelo-guard' ),
				/* translators: %s: folder path */
				'text'  => sprintf( __( '%s is not writable for WordPress, and neither is the uploads folder. Uploads are not held for approval right now (only uploads that look malicious are blocked), held files cannot be kept and scans cannot run.', 'qartvelo-guard' ), $primary ),
				'fix'   => $const
					? __( 'Fix: make the folder set by WPCYBERSEC_DATA_DIR in wp-config.php writable for the web server user, or point it to a folder that is.', 'qartvelo-guard' )
					: $hint . __( 'Fix: make wp-content writable for the web server user (so WordPress can create the wpcybersec folder), or add this line to wp-config.php with a folder outside the web root that the web server user can write:', 'qartvelo-guard' ),
				'code'  => $const ? '' : $code,
			);
		}
		if ( 'fallback' !== $status['state'] ) {
			return null;
		}
		if ( $status['primary_ok'] ) {
			return array(
				'level' => 'warning',
				'title' => __( 'Qartvelo Guard keeps its data in a temporary folder', 'qartvelo-guard' ),
				/* translators: 1: folder in use, 2: configured folder */
				'text'  => sprintf( __( 'The data is kept in %1$s (inside the uploads folder) because %2$s was not writable earlier. That folder is writable now.', 'qartvelo-guard' ), $status['dir'], $primary ),
				'fix'   => is_multisite()
					? __( 'Fix: on a multisite network set WPCYBERSEC_DATA_DIR in wp-config.php to a folder outside the web root, then move the files of the folder above into it.', 'qartvelo-guard' )
					: __( 'Fix: move the data back with the button below. Held items keep working.', 'qartvelo-guard' ),
				'code'  => '',
			);
		}
		return array(
			'level' => 'warning',
			'title' => __( 'Qartvelo Guard uses a fallback data folder', 'qartvelo-guard' ),
			/* translators: 1: configured folder, 2: folder in use */
			'text'  => sprintf( __( '%1$s is not writable for WordPress, so held files and scan data are kept in %2$s inside the uploads folder. Everything works, but a folder outside the web root is safer.', 'qartvelo-guard' ), $primary, $status['dir'] ),
			'fix'   => $const
				? __( 'Fix: make the folder set by WPCYBERSEC_DATA_DIR in wp-config.php writable for the web server user, or point it to a folder that is.', 'qartvelo-guard' )
				/* translators: %s: folder path */
				: $hint . sprintf( __( 'Fix: make wp-content writable for the web server user; a button to move the data back then appears here. Or create a folder outside the web root that the web server user can write, copy everything from %s into it, and add this line to wp-config.php:', 'qartvelo-guard' ), $status['dir'] ),
			'code'  => $const ? '' : $code,
		);
	}

	/**
	 * The default folder: a folder with a random 32 character name inside
	 * qartvelo-guard in the uploads folder (the main site's uploads folder on
	 * multisite, since a sub site's folder is deleted with the site), for
	 * example uploads/qartvelo-guard/k3v9.../. The deny files written by
	 * protect() work on Apache, LiteSpeed and IIS; nginx ignores them, so the
	 * random name keeps every path unguessable there, and both folders hold an
	 * index.php so they cannot be listed. Inside, held files also have random
	 * names ending in .bin.
	 *
	 * @return string '' when WordPress cannot report the uploads folder.
	 */
	public function default_dir() {
		if ( null === self::$default ) {
			$base          = self::uploads_basedir();
			self::$default = '' === $base ? '' : $this->private_dir( $base . '/' . self::UPLOADS_FOLDER );
		}
		return self::$default;
	}

	/**
	 * The random folder inside $root: remembered in TOKEN_OPTION, found again
	 * through this site's marker file when the option was lost, else new.
	 *
	 * @param string $root uploads/qartvelo-guard.
	 * @return string
	 */
	private function private_dir( $root ) {
		// Version 1.1.0 kept the data in $root itself: keep using it.
		if ( @is_dir( $root . '/quarantine' ) || @is_dir( $root . '/jobs' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $root;
		}
		$token = Network::get_option( self::TOKEN_OPTION, '' );
		if ( ! is_string( $token ) || ! preg_match( '/^[a-z0-9]{32}$/', $token ) ) {
			$token = '';
			$names = @is_dir( $root ) ? @scandir( $root ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors
			foreach ( is_array( $names ) ? $names : array() as $name ) {
				if ( preg_match( '/^[a-z0-9]{32}$/', $name ) && $this->marker_matches( $root . '/' . $name ) ) {
					$token = $name;
					break;
				}
			}
			if ( '' === $token ) {
				$token = strtolower( wp_generate_password( 32, false, false ) );
			}
			Network::update_option( self::TOKEN_OPTION, $token, true );
		}
		return $root . '/' . $token;
	}

	/** @var string|null default_dir() of this request. */
	private static $default = null;

	/**
	 * The uploads folder, resolved at runtime (the main site's on multisite).
	 *
	 * @return string '' when WordPress reports an error.
	 */
	public static function uploads_basedir() {
		$switched = false;
		if ( is_multisite() && function_exists( 'get_main_site_id' ) && ! is_main_site() ) {
			$switched = switch_to_blog( get_main_site_id() );
		}
		$uploads = wp_upload_dir( null, false );
		if ( $switched ) {
			restore_current_blog();
		}
		if ( ! is_array( $uploads ) || ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			return '';
		}
		return untrailingslashit( wp_normalize_path( (string) $uploads['basedir'] ) );
	}

	/**
	 * Short id of this WordPress install: the same for every request of this
	 * site, different for another install (or another table prefix) on the
	 * same server. uninstall.php computes it the same way.
	 *
	 * @return string 8 hex characters.
	 */
	public static function site_id() {
		global $wpdb;
		// The base prefix: every site of a multisite network shares one id (and one data folder).
		$prefix = ( isset( $wpdb ) && is_object( $wpdb ) && isset( $wpdb->base_prefix ) ) ? (string) $wpdb->base_prefix : '';
		return substr( md5( ABSPATH . $prefix ), 0, 8 );
	}

	/**
	 * Suggested folder outside the web root: next to the WordPress folder,
	 * named after the site plus this install's id, so several sites (even with
	 * the same host name, like example.com and example.com/blog) never share one.
	 *
	 * @return string
	 */
	public function suggested_outside_dir() {
		$host = (string) wp_parse_url( Network::home_url(), PHP_URL_HOST );
		$slug = sanitize_key( str_replace( '.', '-', $host ) );
		$name = 'wpcybersec-' . ( $slug ? $slug : 'data' ) . '-' . self::site_id();

		// Walk up from the WordPress folder. A folder that contains an index file
		// is most likely served by a web server itself (for example a default
		// localhost site whose sub folders are the real sites), so skip it.
		$dir = wp_normalize_path( dirname( untrailingslashit( ABSPATH ) ) );
		for ( $i = 0; $i < 3; $i++ ) {
			if ( ! self::path_allowed( $dir ) || ! self::path_allowed( $dir . '/' . $name ) ) {
				break; // Never suggest (or look at) a folder open_basedir hides.
			}
			if ( ! self::looks_served( $dir ) && Fs::is_writable( $dir ) && ! $this->is_in_webroot( $dir . '/' . $name ) ) {
				return $dir . '/' . $name;
			}
			$up = wp_normalize_path( dirname( $dir ) );
			if ( $up === $dir || '' === trim( $up, '/' ) ) {
				break;
			}
			$dir = $up;
		}
		$fallback = wp_normalize_path( dirname( untrailingslashit( ABSPATH ) ) ) . '/' . $name;
		if ( self::path_allowed( $fallback ) ) {
			return $fallback;
		}
		// open_basedir hides the folders next to WordPress: a folder inside one of
		// the allowed ones that the web server does not serve (never a temp folder).
		$temp = array_filter( array( '/tmp', '/var/tmp', '/dev/shm', untrailingslashit( wp_normalize_path( (string) sys_get_temp_dir() ) ), untrailingslashit( wp_normalize_path( (string) ini_get( 'upload_tmp_dir' ) ) ) ) );
		foreach ( explode( PATH_SEPARATOR, (string) ini_get( 'open_basedir' ) ) as $allowed ) {
			$allowed = untrailingslashit( wp_normalize_path( trim( $allowed ) ) );
			if ( '' === $allowed || '.' === $allowed[0] || in_array( $allowed, $temp, true ) || ! @is_dir( $allowed ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			if ( ! self::looks_served( $allowed ) && Fs::is_writable( $allowed ) && ! $this->is_in_webroot( $allowed . '/' . $name ) ) {
				return $allowed . '/' . $name;
			}
		}
		return $fallback; // Callers check path_allowed() and explain open_basedir.
	}

	/**
	 * Hint for a data folder suggestion that open_basedir does not allow.
	 *
	 * @return string '' when open_basedir is not set.
	 */
	public static function basedir_hint() {
		$limit = trim( (string) ini_get( 'open_basedir' ) );
		if ( '' === $limit ) {
			return '';
		}
		/* translators: %s: open_basedir value */
		return sprintf( __( 'PHP on this site may only use these folders (open_basedir): %s. The data folder must be inside one of them and not served by the web server, or the host must add it to open_basedir.', 'qartvelo-guard' ), $limit );
	}

	/**
	 * Whether open_basedir lets PHP look at a path (true when it is not set).
	 * Paths outside it are never touched or suggested: every file function
	 * on them prints an "open_basedir restriction in effect" warning.
	 *
	 * @param string $path Absolute path.
	 * @return bool
	 */
	public static function path_allowed( $path ) {
		$limit = trim( (string) ini_get( 'open_basedir' ) );
		if ( '' === $limit ) {
			return true;
		}
		$path = wp_normalize_path( (string) $path );
		foreach ( explode( PATH_SEPARATOR, $limit ) as $dir ) {
			$dir = trim( $dir );
			if ( '' === $dir ) {
				continue;
			}
			if ( '.' === $dir || 0 === strpos( $dir, './' ) ) {
				continue; // Relative to the running script: cannot be judged here.
			}
			$dir = rtrim( wp_normalize_path( $dir ), '/' );
			if ( '' === $dir ) {
				return true; // "/" allows everything.
			}
			if ( $path === $dir || 0 === strpos( $path, $dir . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a folder looks like a web document root (has an index page).
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	public static function looks_served( $dir ) {
		foreach ( array( 'index.php', 'index.html', 'index.htm', 'wp-config.php', 'wp-load.php' ) as $index ) {
			if ( @file_exists( $dir . '/' . $index ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return true;
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* Site marker                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Whether $dir carries this site's marker file.
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	public function marker_matches( $dir ) {
		$file = untrailingslashit( wp_normalize_path( (string) $dir ) ) . '/' . self::MARKER_FILE;
		if ( ! @is_file( $file ) || @is_link( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$text = (string) @file_get_contents( $file, false, null, 0, 1024 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		return (bool) preg_match( '/^site:\s*' . preg_quote( self::site_id(), '/' ) . '\s*$/m', $text );
	}

	/**
	 * Writes this site's marker file into $dir.
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	public function write_marker( $dir ) {
		$file = untrailingslashit( wp_normalize_path( (string) $dir ) ) . '/' . self::MARKER_FILE;
		$text = "Qartvelo Guard data folder. uninstall.php only removes it when the site id matches.\nsite: " . self::site_id() . "\nhome: " . Network::home_url( '/' ) . "\n";
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== @file_put_contents( $file, $text );
	}

	/**
	 * Whether the data folder may be moved into $dir: it does not exist yet, is
	 * empty, or already belongs to this site (marker file).
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	public function dir_usable( $dir ) {
		$dir = untrailingslashit( wp_normalize_path( (string) $dir ) );
		if ( ! self::path_allowed( $dir ) ) {
			return false;
		}
		if ( ! @file_exists( $dir ) && ! @is_link( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return true;
		}
		if ( ! @is_dir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		return self::is_empty_dir( $dir ) || $this->marker_matches( $dir );
	}

	/**
	 * @param string $dir Folder.
	 * @return bool
	 */
	private static function is_empty_dir( $dir ) {
		$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $entries ) ) {
			return false;
		}
		return ! array_diff( $entries, array( '.', '..' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Moving the data folder                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Moves the whole data folder (quarantine, scan files, guard files) to $target
	 * and remembers the new location. Held items keep working: their stored
	 * quarantine paths are rewritten.
	 *
	 * Phase 1 copies everything into $target (hard links on the same disk) and
	 * checks every file; the old folder is not touched. Any failure here removes
	 * the partial copy and nothing is switched. Phase 2 switches the option,
	 * rewrites the stored paths and calls $after_switch (the guard follows the
	 * new folder there). Phase 3 copies what arrived in the old folder meanwhile,
	 * moves the guard's waiting spool lines and only then removes files from the
	 * old folder that are safely in the new one. When phase 3 cannot finish
	 * (for example the guard still points at the old folder), it is retried on
	 * the plugin's admin pages (resume_move()).
	 *
	 * @param string        $target       Absolute folder (created when missing).
	 * @param callable|null $after_switch Called as ( $source, $target ) right after
	 *                                    the switch; a WP_Error keeps the old folder.
	 * @return true|\WP_Error
	 */
	public function relocate( $target, $after_switch = null ) {
		if ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) {
			return new \WP_Error( 'wpcybersec_storage_const', __( 'The data folder is set by WPCYBERSEC_DATA_DIR in wp-config.php. Change it there.', 'qartvelo-guard' ) );
		}
		if ( is_multisite() ) {
			return new \WP_Error( 'wpcybersec_storage_multisite', __( 'On a multisite network all sites share one data folder, so it can only be moved with WPCYBERSEC_DATA_DIR in wp-config.php.', 'qartvelo-guard' ) );
		}
		$target = untrailingslashit( wp_normalize_path( (string) $target ) );
		if ( '' === $target || ! Paths::is_absolute( $target ) ) {
			return new \WP_Error( 'wpcybersec_storage_target', __( 'The new folder must be an absolute path.', 'qartvelo-guard' ) );
		}
		if ( ! self::path_allowed( $target ) ) {
			return new \WP_Error(
				'wpcybersec_storage_basedir',
				/* translators: %s: folder path */
				sprintf( __( 'PHP may not use %s on this server (open_basedir). Nothing was moved. Add the folder to open_basedir in the PHP settings of this site, or choose a folder inside the allowed ones.', 'qartvelo-guard' ), $target )
			);
		}
		$locked = $this->acquire_move_lock();
		if ( is_wp_error( $locked ) ) {
			return $locked;
		}
		self::keep_running();
		$old_umask = umask( 0077 );
		try {
			$result = $this->relocate_locked( $target, $after_switch );
		} finally {
			umask( $old_umask );
			$this->release_move_lock();
		}
		return $result;
	}

	/**
	 * Finishes a move that was interrupted (called on the plugin's admin pages).
	 *
	 * @return bool|\WP_Error True when nothing is left to do, false when files
	 *                        are still waiting in the old folder.
	 */
	public function resume_move() {
		if ( ! $this->move_state() ) {
			return true;
		}
		$locked = $this->acquire_move_lock();
		if ( is_wp_error( $locked ) ) {
			return $locked;
		}
		self::keep_running();
		$old_umask = umask( 0077 );
		try {
			$state = $this->move_state();
			if ( $state && 'copy' === $state['phase'] ) {
				// The copying request died. Nothing was switched: drop the partial copy.
				$this->drop_partial_copy( $state['target'] );
				Network::delete_option( self::MOVE_OPTION );
				$result = true;
			} else {
				$result = $this->finish_move_locked();
			}
		} finally {
			umask( $old_umask );
			$this->release_move_lock();
		}
		return $result;
	}

	/**
	 * Whether a switched move still has files to bring over from the old folder.
	 *
	 * @return bool
	 */
	public function move_pending() {
		$state = $this->move_state();
		return $state && 'switched' === $state['phase'];
	}

	/**
	 * @return array|null { source, target, phase, time }
	 */
	private function move_state() {
		$state = Network::get_option( self::MOVE_OPTION, null );
		if ( ! is_array( $state ) || empty( $state['source'] ) || empty( $state['target'] ) || empty( $state['phase'] ) ) {
			return null;
		}
		return array(
			'source' => untrailingslashit( wp_normalize_path( (string) $state['source'] ) ),
			'target' => untrailingslashit( wp_normalize_path( (string) $state['target'] ) ),
			'phase'  => (string) $state['phase'],
			'time'   => isset( $state['time'] ) ? (int) $state['time'] : 0,
		);
	}

	/**
	 * @param string $source Old folder.
	 * @param string $target New folder.
	 * @param string $phase  copy | switched.
	 */
	private function save_move_state( $source, $target, $phase ) {
		Network::update_option(
			self::MOVE_OPTION,
			array(
				'source' => $source,
				'target' => $target,
				'phase'  => $phase,
				'time'   => time(),
			),
			false
		);
	}

	/**
	 * relocate() under the move lock.
	 *
	 * @param string        $target       Normalized target.
	 * @param callable|null $after_switch Callback.
	 * @return true|\WP_Error
	 */
	private function relocate_locked( $target, $after_switch ) {
		// An earlier move that switched over but did not finish comes first.
		$state    = $this->move_state();
		$finished = true;
		if ( $state && 'switched' === $state['phase'] ) {
			$finished = $this->finish_move_locked();
			$state    = null;
		}

		$source = $this->data_dir();
		if ( $target === $source ) {
			return true;
		}
		if ( true !== $finished ) {
			return is_wp_error( $finished ) ? $finished : new \WP_Error( 'wpcybersec_storage_pending', __( 'An earlier move of the data folder is still being finished. Try again in a few minutes.', 'qartvelo-guard' ) );
		}
		if ( 0 === strpos( trailingslashit( $target ), trailingslashit( $source ) ) ) {
			return new \WP_Error( 'wpcybersec_storage_nested', __( 'The new folder cannot be inside the current one.', 'qartvelo-guard' ) );
		}
		if ( 0 === strpos( trailingslashit( $source ), trailingslashit( $target ) ) ) {
			return new \WP_Error( 'wpcybersec_storage_nested', __( 'The new folder cannot contain the current one.', 'qartvelo-guard' ) );
		}

		// A copy into another folder that never finished (the request died): drop it.
		$resume = false;
		if ( $state && 'copy' === $state['phase'] ) {
			if ( $state['target'] === $target && $state['source'] === $source ) {
				$resume = true; // Same move again: files already copied are kept.
			} else {
				$this->drop_partial_copy( $state['target'] );
				Network::delete_option( self::MOVE_OPTION );
			}
		}

		if ( ! $this->dir_usable( $target ) ) {
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_taken', sprintf( __( '%s already exists and holds files that do not belong to this site. Nothing was moved; empty that folder or use another one.', 'qartvelo-guard' ), $target ) );
		}
		$created_root = ! is_dir( $target );
		if ( $created_root && ! wp_mkdir_p( $target ) ) {
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_mkdir', sprintf( __( 'Could not create %s. The parent folder is not writable for WordPress.', 'qartvelo-guard' ), $target ) );
		}
		if ( ! Fs::is_writable( $target ) ) {
			if ( $created_root ) {
				Fs::rmdir( $target );
			}
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_write', sprintf( __( '%s is not writable for WordPress.', 'qartvelo-guard' ), $target ) );
		}
		// Everything inside the target is ours to remove again when this move fails.
		$owned = $created_root || $resume || self::is_empty_dir( $target );
		if ( $created_root && is_dir( $source ) ) {
			Fs::chmod( $target, @fileperms( $source ) & 0777 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		if ( ! $this->write_marker( $target ) ) {
			$this->undo_copy( $target, array(), $owned, $created_root );
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_write', sprintf( __( '%s is not writable for WordPress.', 'qartvelo-guard' ), $target ) );
		}
		$this->save_move_state( $source, $target, 'copy' );

		// No guard spool import may run on the old folder while it is copied.
		$import_lock = self::lock_file( $source . '/spool/guard-import.lock', 30 );
		if ( false === $import_lock ) {
			$this->undo_copy( $target, array(), $owned, $created_root );
			Network::delete_option( self::MOVE_OPTION );
			return new \WP_Error( 'wpcybersec_storage_busy', __( 'The early guard is importing held uploads right now. Nothing was moved; try again in a minute.', 'qartvelo-guard' ) );
		}

		// Phase 1: copy and check. The old folder stays as it is.
		$created = array();
		$copied  = $this->copy_into( $source, $target, $created, false );
		if ( is_wp_error( $copied ) ) {
			self::unlock_file( $import_lock );
			$this->undo_copy( $target, $created, $owned, $created_root );
			Network::delete_option( self::MOVE_OPTION );
			return new \WP_Error(
				'wpcybersec_storage_move',
				/* translators: 1: error message, 2: folder */
				sprintf( __( '%1$s Nothing was switched over: the data folder is still %2$s and the partial copy was removed.', 'qartvelo-guard' ), $copied->get_error_message(), $source )
			);
		}

		// Phase 2: switch over.
		$this->save_move_state( $source, $target, 'switched' );
		Network::update_option( self::DIR_OPTION, $target, true );
		self::reset();
		$this->ensure();
		$this->rewrite_item_paths( $source, $target );
		self::unlock_file( $import_lock );

		if ( is_callable( $after_switch ) ) {
			$after = call_user_func( $after_switch, $source, $target );
			if ( is_wp_error( $after ) ) {
				return $after; // Switched; the old folder is kept until the cause is fixed.
			}
		}

		// Phase 3: bring over what arrived meanwhile, then empty the old folder.
		$finished = $this->finish_move_locked();
		if ( is_wp_error( $finished ) ) {
			self::log(
				'data_dir_move',
				/* translators: %s: error message */
				sprintf( __( 'The data folder was moved, but the old folder could not be emptied yet: %s It is retried when an administrator opens the plugin.', 'qartvelo-guard' ), $finished->get_error_message() )
			);
		}
		return true;
	}

	/**
	 * Phase 3 of a switched move, under the move lock.
	 *
	 * @return bool|\WP_Error True when done, false when files are left for a retry.
	 */
	private function finish_move_locked() {
		$state = $this->move_state();
		if ( ! $state || 'switched' !== $state['phase'] ) {
			return true;
		}
		$source = $state['source'];
		$target = $state['target'];
		if ( ! is_dir( $target ) ) {
			return new \WP_Error( 'wpcybersec_storage_target', __( 'The new data folder is missing.', 'qartvelo-guard' ) );
		}
		if ( ! is_dir( $source ) ) {
			$this->rewrite_item_paths( $source, $target );
			Network::delete_option( self::MOVE_OPTION );
			return true;
		}
		if ( self::guard_uses( $source ) ) {
			return new \WP_Error( 'wpcybersec_storage_guard', __( 'The early guard file still points to the old data folder, so the old folder is kept until the guard is updated.', 'qartvelo-guard' ) );
		}
		$import_lock = self::lock_file( $source . '/spool/guard-import.lock', 30 );
		if ( false === $import_lock ) {
			return new \WP_Error( 'wpcybersec_storage_busy', __( 'The early guard is importing held uploads from the old folder right now.', 'qartvelo-guard' ) );
		}
		$left = 0;
		try {
			// Files written to the old folder after the copy (for example uploads held meanwhile).
			$created = array();
			$copied  = $this->copy_into( $source, $target, $created, true );
			if ( is_wp_error( $copied ) ) {
				return $copied;
			}
			$moved = $this->migrate_spool( $source, $target );
			if ( is_wp_error( $moved ) ) {
				return $moved;
			}
			$this->rewrite_item_paths( $source, $target );
			$left = self::remove_copied( $source, $target, '' );
		} finally {
			self::unlock_file( $import_lock );
		}
		if ( 0 === $left ) {
			Fs::delete( $source . '/spool/guard-import.lock' );
			Fs::rmdir( $source . '/spool' );
			Fs::rmdir( $source );
			Network::delete_option( self::MOVE_OPTION );
			return true;
		}
		return false;
	}

	/**
	 * Whether the installed early guard still loads its config from $dir.
	 * The guard bootstrap has the config path written into it, so the old
	 * folder must stay until the bootstrap points to the new one.
	 *
	 * @param string $dir Data folder.
	 * @return bool
	 */
	private static function guard_uses( $dir ) {
		if ( ! Network::get_option( 'wpcybersec_guard_installed', false ) ) {
			return false;
		}
		$bootstrap = ABSPATH . 'wpcybersec-guard.php';
		if ( ! @is_file( $bootstrap ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$code = (string) @file_get_contents( $bootstrap, false, null, 0, 65536 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		return false !== strpos( $code, var_export( $dir . '/guard/config.php', true ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
	}

	/**
	 * Removes a partial copy left by a move that never switched over.
	 *
	 * @param string $dir Target of that move.
	 */
	private function drop_partial_copy( $dir ) {
		if ( '' === $dir || ! is_dir( $dir ) || $dir === $this->data_dir() || $dir === $this->default_dir() ) {
			return;
		}
		if ( $this->marker_matches( $dir ) ) {
			self::empty_dir( $dir ); // The folder itself stays: an administrator may have created it.
		}
	}

	/**
	 * Undoes phase 1 after a failure.
	 *
	 * @param string   $target       Target folder.
	 * @param string[] $created      Files and folders this move created, in order.
	 * @param bool     $owned        Everything inside the target belongs to this move.
	 * @param bool     $created_root This move created the target folder itself.
	 */
	private function undo_copy( $target, array $created, $owned, $created_root ) {
		if ( $owned ) {
			self::empty_dir( $target );
			if ( $created_root ) {
				Fs::rmdir( $target );
			}
			return;
		}
		foreach ( array_reverse( $created ) as $path ) {
			if ( is_dir( $path ) && ! is_link( $path ) ) {
				Fs::rmdir( $path );
			} else {
				Fs::delete( $path );
			}
		}
	}

	/**
	 * Copies the data folder into $target. On the same disk files are hard
	 * linked (instant, no extra space, the old folder stays intact); otherwise
	 * they are copied. Every file is checked afterwards.
	 *
	 * @param string   $source       Old folder.
	 * @param string   $target       New folder.
	 * @param string[] $created      Receives every file and folder created.
	 * @param bool     $only_missing Only copy files the target does not have yet.
	 * @return true|\WP_Error
	 */
	private function copy_into( $source, $target, array &$created, $only_missing ) {
		if ( ! is_dir( $source ) ) {
			return true;
		}
		$tree = self::list_tree( $source );
		$link = self::same_device( $source, $target ) && self::can_link();

		if ( ! $link ) {
			$need = 0;
			foreach ( $tree['files'] as $rel => $size ) {
				if ( ! is_file( $target . '/' . $rel ) ) {
					$need += $size;
				}
			}
			$free = function_exists( 'disk_free_space' ) ? @disk_free_space( $target ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( is_numeric( $free ) && (float) $free < $need + 32 * MB_IN_BYTES ) {
				return new \WP_Error(
					'wpcybersec_storage_space',
					/* translators: 1: size, 2: folder, 3: size */
					sprintf( __( 'The data needs %1$s but %2$s has only %3$s free.', 'qartvelo-guard' ), size_format( $need + 32 * MB_IN_BYTES ), $target, size_format( (float) $free ) )
				);
			}
		}

		foreach ( $tree['dirs'] as $rel ) {
			$made = $this->make_dir( $source . '/' . $rel, $target . '/' . $rel, $created );
			if ( is_wp_error( $made ) ) {
				return $made;
			}
		}
		foreach ( $tree['files'] as $rel => $size ) {
			$to = $target . '/' . $rel;
			if ( is_file( $to ) && ( $only_missing || (int) @filesize( $to ) === (int) $size ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue; // Copied by an earlier try.
			}
			if ( ! self::copy_file( $source . '/' . $rel, $to, $link ) ) {
				/* translators: 1: file, 2: folder */
				return new \WP_Error( 'wpcybersec_storage_copy', sprintf( __( 'Could not copy %1$s into %2$s.', 'qartvelo-guard' ), $source . '/' . $rel, $target ) );
			}
			$created[] = $to;
			$this->beat_move_lock();
		}
		if ( $only_missing ) {
			return true;
		}

		// Check: every file of the old folder is in the new one with the same size.
		// A file that changed or appeared while copying is copied once more.
		$check = self::list_tree( $source );
		foreach ( $check['dirs'] as $rel ) {
			$made = $this->make_dir( $source . '/' . $rel, $target . '/' . $rel, $created );
			if ( is_wp_error( $made ) ) {
				return $made;
			}
		}
		foreach ( $check['files'] as $rel => $size ) {
			$to = $target . '/' . $rel;
			clearstatcache( true, $to );
			if ( is_file( $to ) && (int) @filesize( $to ) === (int) $size ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			if ( ! self::copy_file( $source . '/' . $rel, $to, $link ) ) {
				/* translators: %s: file */
				return new \WP_Error( 'wpcybersec_storage_verify', sprintf( __( 'The copy of %s could not be checked.', 'qartvelo-guard' ), $source . '/' . $rel ) );
			}
			$created[] = $to;
		}
		return true;
	}

	/**
	 * Creates one folder of the copy with the permissions of the original.
	 *
	 * @param string   $from    Original folder.
	 * @param string   $to      New folder.
	 * @param string[] $created Receives the folder when it was created.
	 * @return true|\WP_Error
	 */
	private function make_dir( $from, $to, array &$created ) {
		if ( is_dir( $to ) ) {
			return true;
		}
		if ( file_exists( $to ) || is_link( $to ) || ! Fs::mkdir( $to, 0700 ) ) {
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_mkdir', sprintf( __( 'Could not create %s.', 'qartvelo-guard' ), $to ) );
		}
		$created[] = $to;
		$perms = @fileperms( $from ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $perms ) {
			Fs::chmod( $to, $perms & 0777 );
		}
		return true;
	}

	/**
	 * Copies (or hard links) one file and checks its size.
	 *
	 * @param string $from Source file.
	 * @param string $to   Target file.
	 * @param bool   $link Try a hard link first.
	 * @return bool
	 */
	private static function copy_file( $from, $to, $link ) {
		if ( file_exists( $to ) || is_link( $to ) ) {
			Fs::delete( $to );
		}
		if ( $link && @link( $from, $to ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return true;
		}
		if ( ! @copy( $from, $to ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Fs::delete( $to );
			return false;
		}
		$perms = @fileperms( $from ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		Fs::chmod( $to, $perms ? ( $perms & 0777 ) : 0600 );
		clearstatcache( true, $from );
		clearstatcache( true, $to );
		return (int) @filesize( $to ) === (int) @filesize( $from ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Folders and files of the data folder, without symlinks, the marker and
	 * the guard spool runtime files.
	 *
	 * @param string $root Folder.
	 * @return array { dirs: string[] (parents first), files: array rel => size }
	 */
	private static function list_tree( $root ) {
		$dirs  = array();
		$files = array();
		$stack = array( '' );
		while ( $stack ) {
			$rel     = array_pop( $stack );
			$abs     = '' === $rel ? $root : $root . '/' . $rel;
			$entries = @scandir( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! is_array( $entries ) ) {
				continue;
			}
			foreach ( $entries as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$child = '' === $rel ? $entry : $rel . '/' . $entry;
				$path  = $abs . '/' . $entry;
				if ( is_link( $path ) ) {
					continue; // Never followed, never copied.
				}
				if ( is_dir( $path ) ) {
					$dirs[]  = $child;
					$stack[] = $child;
					continue;
				}
				if ( self::MARKER_FILE === $child || in_array( $child, self::SPOOL_RUNTIME, true ) || 0 === strpos( $child, 'spool/guard-uploads.work.jsonl.' ) ) {
					continue;
				}
				$files[ $child ] = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
		}
		usort(
			$dirs,
			static function ( $a, $b ) {
				return substr_count( $a, '/' ) - substr_count( $b, '/' );
			}
		);
		return array(
			'dirs'  => $dirs,
			'files' => $files,
		);
	}

	/**
	 * Moves the guard's waiting spool lines (and the unfinished rest of its work
	 * file) from the old folder to the new one, with their held-copy paths
	 * rewritten, so uploads held during the move keep their copies.
	 *
	 * @param string $source Old folder.
	 * @param string $target New folder.
	 * @return true|\WP_Error
	 */
	private function migrate_spool( $source, $target ) {
		$dir = $source . '/spool';
		if ( ! is_dir( $dir ) ) {
			return true;
		}
		$lines = array();
		$work  = $dir . '/guard-uploads.work.jsonl';
		if ( is_file( $work ) ) {
			$offset = 0;
			$pos    = json_decode( (string) @file_get_contents( $dir . '/guard-uploads.work.pos' ), true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			if ( is_array( $pos ) && isset( $pos['offset'] ) ) {
				$offset = max( 0, (int) $pos['offset'] );
			}
			$size = (int) @filesize( $work ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $offset < $size ) {
				$rest  = @file_get_contents( $work, false, null, $offset ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
				$lines = array_merge( $lines, preg_split( '/\r\n|\n|\r/', (string) $rest ) );
			}
		}

		// Lock the old spool so a guard request still using it cannot add a line
		// between reading and emptying it.
		$spool  = $dir . '/guard-uploads.jsonl';
		$handle = null;
		if ( is_file( $spool ) ) {
			$handle = @fopen( $spool, 'c+' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- native handle needed for flock() and streaming; WP_Filesystem has neither.
			if ( ! $handle || ! @flock( $handle, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
				if ( $handle ) {
					@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
				}
				return new \WP_Error( 'wpcybersec_storage_spool', __( 'Could not lock the early guard spool in the old folder.', 'qartvelo-guard' ) );
			}
			rewind( $handle );
			$lines = array_merge( $lines, preg_split( '/\r\n|\n|\r/', (string) stream_get_contents( $handle ) ) );
		}

		$out = '';
		foreach ( $lines as $line ) {
			$line = trim( (string) $line );
			if ( '' !== $line ) {
				$out .= self::rewrite_spool_line( $line, $source, $target ) . "\n";
			}
		}
		$ok = true;
		if ( '' !== $out ) {
			$ok = false;
			if ( is_dir( $target . '/spool' ) || wp_mkdir_p( $target . '/spool' ) ) {
				$out_handle = @fopen( $target . '/spool/guard-uploads.jsonl', 'ab' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- native handle needed for flock() and streaming; WP_Filesystem has neither.
				if ( $out_handle ) {
					if ( @flock( $out_handle, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
						$ok = strlen( $out ) === @fwrite( $out_handle, $out ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- native handle needed for flock() and streaming; WP_Filesystem has neither.
						@fflush( $out_handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
						@flock( $out_handle, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
					}
					@fclose( $out_handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
				}
			}
		}
		if ( $ok ) {
			if ( $handle ) {
				ftruncate( $handle, 0 );
				fflush( $handle );
			}
			Fs::delete( $work );
			Fs::delete( $dir . '/guard-uploads.work.pos' );
		}
		if ( $handle ) {
			@flock( $handle, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
			@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		}
		return $ok ? true : new \WP_Error( 'wpcybersec_storage_spool', __( 'Could not move the early guard\'s waiting uploads to the new folder.', 'qartvelo-guard' ) );
	}

	/**
	 * @param string $line   One spool line (JSON).
	 * @param string $source Old folder.
	 * @param string $target New folder.
	 * @return string
	 */
	private static function rewrite_spool_line( $line, $source, $target ) {
		$entry = json_decode( $line, true );
		if ( ! is_array( $entry ) || ! isset( $entry['quarantine_path'] ) || ! is_string( $entry['quarantine_path'] ) ) {
			return $line;
		}
		$path = wp_normalize_path( $entry['quarantine_path'] );
		if ( 0 !== strpos( $path, $source . '/' ) ) {
			return $line;
		}
		$entry['quarantine_path'] = $target . substr( $path, strlen( $source ) );
		$json                     = wp_json_encode( $entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		return is_string( $json ) && '' !== $json ? $json : $line;
	}

	/**
	 * Points held items at the new folder. Rows are read and written by id and
	 * the prefix is replaced in PHP, so multibyte paths stay intact.
	 *
	 * @param string $from Old folder.
	 * @param string $to   New folder.
	 */
	private function rewrite_item_paths( $from, $to ) {
		global $wpdb;
		$table = Store::table( 'items' );
		$like  = $wpdb->esc_like( $from . '/' ) . '%';
		$last  = 0;
		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is Store::table(): $wpdb->prefix plus a fixed name.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, quarantine_path FROM {$table} WHERE id > %d AND quarantine_path LIKE %s ORDER BY id ASC LIMIT 500", $last, $like ), ARRAY_A );
			$rows = is_array( $rows ) ? $rows : array();
			foreach ( $rows as $row ) {
				$last = (int) $row['id'];
				$path = wp_normalize_path( (string) $row['quarantine_path'] );
				if ( 0 !== strpos( $path, $from . '/' ) ) {
					continue; // LIKE ignores case; the prefix must match exactly.
				}
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->update( $table, array( 'quarantine_path' => $to . substr( $path, strlen( $from ) ) ), array( 'id' => $last ), array( '%s' ), array( '%d' ) );
			}
		} while ( 500 === count( $rows ) );
	}

	/**
	 * Deletes files of the old folder that are in the new folder (and our own
	 * deny files and emptied spool files). Anything else stays for a retry.
	 *
	 * @param string $src Old folder (or a sub folder of it).
	 * @param string $dst Matching folder in the new location.
	 * @param string $rel Relative path of $src.
	 * @return int Files left behind.
	 */
	private static function remove_copied( $src, $dst, $rel ) {
		$left    = 0;
		$entries = @scandir( $src ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $entries ) ) {
			return 1;
		}
		foreach ( $entries as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path  = $src . '/' . $entry;
			$child = '' === $rel ? $entry : $rel . '/' . $entry;
			if ( is_link( $path ) ) {
				Fs::delete( $path );
				continue;
			}
			if ( is_dir( $path ) ) {
				$left += self::remove_copied( $path, $dst . '/' . $entry, $child );
				Fs::rmdir( $path );
				continue;
			}
			if ( 'spool/guard-import.lock' === $child ) {
				continue; // Held by this request; removed after unlocking.
			}
			if ( in_array( $child, self::SPOOL_RUNTIME, true ) ) {
				clearstatcache( true, $path );
				if ( 0 === (int) @filesize( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					Fs::delete( $path );
				} else {
					++$left; // A line arrived after it was moved: next run.
				}
				continue;
			}
			$ours = self::MARKER_FILE === $child || in_array( $entry, self::DENY_FILES, true ) || 0 === strpos( $child, 'spool/guard-uploads.work.jsonl.' );
			if ( $ours || is_file( $dst . '/' . $entry ) ) {
				if ( ! Fs::delete( $path ) ) {
					++$left;
				}
				continue;
			}
			++$left;
		}
		return $left;
	}

	/**
	 * Takes the move lock (a row in the options table, created atomically).
	 *
	 * @return true|\WP_Error
	 */
	private function acquire_move_lock() {
		global $wpdb;
		$value = time() . ':' . wp_generate_password( 16, false );
		for ( $try = 0; $try < 2; $try++ ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$added = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", self::MOVE_LOCK, $value ) );
			if ( 1 === (int) $added ) {
				$this->lock_value = $value;
				$this->lock_beat  = time();
				return true;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$current = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::MOVE_LOCK ) );
			$since   = (int) strtok( $current, ':' );
			if ( $since > time() - self::MOVE_LOCK_STALE ) {
				break;
			}
			// Left behind by a request that died: take it over.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", self::MOVE_LOCK, $current ) );
		}
		return new \WP_Error( 'wpcybersec_storage_busy', __( 'The data folder is being moved right now. Try again in a few minutes.', 'qartvelo-guard' ) );
	}

	/**
	 * Refreshes the move lock during a long copy.
	 */
	private function beat_move_lock() {
		global $wpdb;
		if ( '' === $this->lock_value || time() - $this->lock_beat < 60 ) {
			return;
		}
		$value = time() . ':' . substr( $this->lock_value, strpos( $this->lock_value, ':' ) + 1 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s", $value, self::MOVE_LOCK, $this->lock_value ) );
		$this->lock_value = $value;
		$this->lock_beat  = time();
	}

	/**
	 * Releases the move lock taken by this request.
	 */
	private function release_move_lock() {
		global $wpdb;
		if ( '' === $this->lock_value ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", self::MOVE_LOCK, $this->lock_value ) );
		$this->lock_value = '';
	}

	/**
	 * Exclusive flock on $file, waiting up to $wait seconds.
	 *
	 * @param string $file Lock file.
	 * @param int    $wait Seconds.
	 * @return resource|null|false Handle, null when there is nothing to lock (no folder), false when busy.
	 */
	private static function lock_file( $file, $wait ) {
		if ( ! is_dir( dirname( $file ) ) ) {
			return null;
		}
		$handle = @fopen( $file, 'c' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		if ( ! $handle ) {
			return false;
		}
		$until = microtime( true ) + $wait;
		while ( ! @flock( $handle, LOCK_EX | LOCK_NB ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
			if ( microtime( true ) >= $until ) {
				@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
				return false;
			}
			usleep( 200000 );
		}
		return $handle;
	}

	/**
	 * @param resource|null|false $handle From lock_file().
	 */
	private static function unlock_file( $handle ) {
		if ( is_resource( $handle ) ) {
			@flock( $handle, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- errors are handled through the return value.
			@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- native handle needed for flock() and streaming; WP_Filesystem has neither.
		}
	}

	/**
	 * @param string $a Folder.
	 * @param string $b Folder.
	 * @return bool
	 */
	private static function same_device( $a, $b ) {
		$sa = @stat( $a ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$sb = @stat( $b ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return is_array( $sa ) && is_array( $sb ) && isset( $sa['dev'], $sb['dev'] ) && $sa['dev'] === $sb['dev'];
	}

	/**
	 * @return bool Whether link() can be used.
	 */
	private static function can_link() {
		if ( ! function_exists( 'link' ) ) {
			return false;
		}
		$disabled = array_map( 'trim', explode( ',', strtolower( (string) ini_get( 'disable_functions' ) ) ) );
		return ! in_array( 'link', $disabled, true );
	}

	/**
	 * Lets a long file operation finish even when the browser gives up.
	 */
	public static function keep_running() {
		if ( function_exists( 'ignore_user_abort' ) ) {
			@ignore_user_abort( true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- moving the data folder must not stop half way; it is resumable, but a timeout leaves two copies until the next run.
		}
	}

	/**
	 * Activity log entry when the plugin is booted.
	 *
	 * @param string $event   Event.
	 * @param string $message Message.
	 */
	private static function log( $event, $message ) {
		if ( ! function_exists( 'wpcybersec' ) ) {
			return;
		}
		$plugin = wpcybersec();
		if ( isset( $plugin->logger ) && is_object( $plugin->logger ) ) {
			$plugin->logger->log( $event, $message );
		}
	}

	/**
	 * Recursive delete (does not follow symlinks).
	 *
	 * @param string $path File or folder.
	 */
	private static function delete_tree( $path ) {
		if ( is_link( $path ) || is_file( $path ) ) {
			Fs::delete( $path );
			return;
		}
		if ( ! is_dir( $path ) ) {
			return;
		}
		foreach ( (array) scandir( $path ) as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			self::delete_tree( $path . '/' . $entry );
		}
		Fs::rmdir( $path );
	}

	/**
	 * Deletes everything inside a folder, keeping the folder.
	 *
	 * @param string $dir Folder.
	 */
	private static function empty_dir( $dir ) {
		if ( is_link( $dir ) || ! is_dir( $dir ) ) {
			return;
		}
		foreach ( (array) scandir( $dir ) as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			self::delete_tree( $dir . '/' . $entry );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Paths                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $sub Sub path inside the data dir.
	 * @return string
	 */
	public function path( $sub = '' ) {
		return $this->data_dir() . ( $sub ? '/' . ltrim( $sub, '/' ) : '' );
	}

	/** @return string */
	public function quarantine_dir() {
		return $this->path( 'quarantine' );
	}

	/** @return string */
	public function jobs_dir() {
		return $this->path( 'jobs' );
	}

	/** @return string */
	public function spool_dir() {
		return $this->path( 'spool' );
	}

	/** @return string */
	public function guard_dir() {
		return $this->path( 'guard' );
	}

	/**
	 * Creates the directory tree and drops deny files into each folder.
	 *
	 * @return true|\WP_Error
	 */
	public function ensure() {
		$status = $this->resolve();
		if ( 'unavailable' === $status['state'] ) {
			return new \WP_Error(
				'wpcybersec_storage',
				/* translators: %s: directory path */
				sprintf( __( 'No writable data folder: %s is not writable for WordPress, and neither is the uploads folder. Make the uploads folder writable or set WPCYBERSEC_DATA_DIR in wp-config.php to a writable folder.', 'qartvelo-guard' ), '' !== $status['primary'] ? $status['primary'] : __( 'the uploads folder', 'qartvelo-guard' ) )
			);
		}
		$dirs = array( $this->data_dir(), $this->quarantine_dir(), $this->jobs_dir(), $this->spool_dir(), $this->guard_dir() );
		foreach ( $dirs as $dir ) {
			if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
				/* translators: %s: directory path */
				return new \WP_Error( 'wpcybersec_storage', sprintf( __( 'Could not create %s. Check folder permissions.', 'qartvelo-guard' ), $dir ) );
			}
			$this->protect( $dir );
		}
		// The folder around the random one: no listing, no web access where the server reads the deny files.
		if ( self::UPLOADS_FOLDER === basename( dirname( $status['dir'] ) ) && preg_match( '/^[a-z0-9]{32}$/', basename( $status['dir'] ) ) ) {
			$this->protect( dirname( $status['dir'] ) );
		}
		// A folder inside uploads is found and removed by uninstall.php through this marker.
		if ( in_array( $status['source'], array( 'fallback', 'default' ), true ) && ! $this->marker_matches( $status['dir'] ) ) {
			$this->write_marker( $status['dir'] );
		}
		return true;
	}

	/**
	 * Blocks web access to a folder on Apache, LiteSpeed and IIS, and hides listings.
	 * Nginx ignores these files, so the advanced settings page shows an nginx rule.
	 *
	 * @param string $dir Directory.
	 */
	public function protect( $dir ) {
		$files = array(
			'.htaccess'  => "# Qartvelo Guard: no web access.\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\nOptions -Indexes\n<IfModule mod_php.c>\n\tphp_flag engine off\n</IfModule>\n<IfModule mod_php7.c>\n\tphp_flag engine off\n</IfModule>\n",
			'index.php'  => "<?php\n// Silence is golden.\n",
			'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
		);
		foreach ( $files as $name => $content ) {
			$file = $dir . '/' . $name;
			if ( ! file_exists( $file ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				@file_put_contents( $file, $content );
			}
		}
	}

	/**
	 * Whether a path is reachable through the web server document root.
	 *
	 * @param string $path Absolute path.
	 * @return bool
	 */
	public function is_in_webroot( $path ) {
		$real  = self::path_allowed( $path ) ? realpath( $path ) : false;
		$path  = wp_normalize_path( (string) ( $real ? $real : $path ) );
		$roots = array( wp_normalize_path( (string) ( realpath( ABSPATH ) ?: ABSPATH ) ) );
		if ( ! empty( $_SERVER['DOCUMENT_ROOT'] ) ) {
			$doc = realpath( wp_unslash( $_SERVER['DOCUMENT_ROOT'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( $doc ) {
				$roots[] = wp_normalize_path( $doc );
			}
		}
		foreach ( $roots as $root ) {
			if ( 0 === strpos( trailingslashit( $path ), trailingslashit( $root ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether $path is inside $dir (after resolving symlinks and "..").
	 *
	 * @param string $path File or folder.
	 * @param string $dir  Parent folder.
	 * @return bool
	 */
	public static function is_within( $path, $dir ) {
		$real_dir  = realpath( $dir );
		$real_path = realpath( $path );
		if ( false === $real_path ) {
			$parent    = realpath( dirname( $path ) );
			$real_path = $parent ? $parent . '/' . basename( $path ) : false;
		}
		if ( ! $real_dir || ! $real_path ) {
			return false;
		}
		return 0 === strpos( trailingslashit( wp_normalize_path( $real_path ) ), trailingslashit( wp_normalize_path( $real_dir ) ) )
			|| wp_normalize_path( $real_path ) === wp_normalize_path( $real_dir );
	}
}
