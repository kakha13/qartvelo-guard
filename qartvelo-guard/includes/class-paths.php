<?php
/**
 * Path helpers shared by scanner, monitor and gates.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Relative paths are always relative to the scan root, use forward slashes,
 * and never start with a slash. Example: "wp-content/plugins/foo/foo.php".
 *
 * Scan set: a whole-site scan walks the scan root plus the WordPress folders
 * that lie outside it (scan_set()): the WordPress folder (wp_root()),
 * WP_CONTENT_DIR, WP_PLUGIN_DIR, WPMU_PLUGIN_DIR and the uploads folder in
 * full, the home folder (WordPress in a subfolder, Bedrock's web/) at its top
 * level only, and a wp-config.php one folder above the WordPress folder.
 * Every folder is resolved with realpath() and
 * dropped when another folder of the set already covers it, so no file is
 * listed twice. Files outside the scan root keep their absolute path as the
 * manifest key (rel() returns it), which is stable and unique.
 */
class Paths {

	/** @var array|null scan_set() cache, keyed by the scan root it was built for. */
	private static $set = null;

	/** @var string|null Real data folder path with a trailing slash ('' when unknown). */
	private static $data_real = null;

	/** @var string Real path of the folder around the random data folder inside uploads/qartvelo-guard ('' otherwise). */
	private static $outer_real = '';

	/** @var string[]|null config_includes() cache. */
	private static $loaded = null;

	/** @var string|null wp_root() cache (the folder cannot change during a request). */
	private static $wp_root = null;

	/** @var string[]|null core_roots() cache: the WordPress folder as defined and resolved. */
	private static $core_roots = null;

	/** Option: files wp-config.php loaded the last time a request included it. */
	const LOADED_OPTION = 'wpcybersec_config_includes';

	/** At most this many files loaded by wp-config.php are added to the scan set. */
	const LOADED_CAP = 300;

	/**
	 * The WordPress folder: the one that holds wp-load.php, wp-admin/ and
	 * wp-includes/.
	 *
	 * A file integrity scanner cannot work without it. Core files are compared
	 * with the official checksums of WordPress by their path inside this
	 * folder, the whole-site scan starts here, and the files the web server and
	 * WordPress read from it (.htaccess, .user.ini, wp-config.php) are the ones
	 * an attacker changes first, so the plugin has to name them exactly.
	 *
	 * WordPress has no function that returns this folder: get_home_path() is
	 * the folder of the front page (a different folder when WordPress lives in
	 * a subfolder) and exists in wp-admin only, and site_url() is an address,
	 * not a folder. WordPress itself keeps it in one constant, which is read
	 * here and nowhere else in the plugin; every other class asks this method.
	 * The only other mentions of the constant are the "direct access" guards at
	 * the top of each file and the includes of WordPress's own files, written
	 * the way WordPress documents them.
	 *
	 * This is the WordPress folder only. wp-content, plugins, mu-plugins,
	 * themes, languages and uploads have their own WordPress constant or
	 * function (WP_CONTENT_DIR, WP_PLUGIN_DIR, WPMU_PLUGIN_DIR,
	 * get_theme_root(), WP_LANG_DIR, wp_upload_dir()) and are never built from
	 * this folder plus a name.
	 *
	 * Trailing slash rule: the result always ends with one slash, so a name is
	 * appended directly: Paths::wp_root() . 'wp-admin/'. Callers that need the
	 * folder without it use untrailingslashit().
	 *
	 * @param bool $as_defined True for the value exactly as WordPress defined
	 *                         it (not normalized). Only for Storage::site_id(),
	 *                         whose hash must stay the same on servers where
	 *                         the two forms differ (Windows backslashes).
	 * @return string Absolute path with forward slashes and a trailing slash.
	 */
	public static function wp_root( $as_defined = false ) {
		$defined = (string) ABSPATH;
		if ( $as_defined ) {
			return $defined;
		}
		if ( null === self::$wp_root ) {
			self::$wp_root = trailingslashit( wp_normalize_path( $defined ) );
		}
		return self::$wp_root;
	}

	/**
	 * Whether a path is inside wp-admin, wp-includes or this plugin's own
	 * folder. The plugin reads and checks those folders but never creates or
	 * overwrites a file in them: WordPress's own updater is the only code that
	 * writes there. What the plugin does do there is move a file out, into
	 * quarantine (by hand on the Reports page, or the automatic quarantine);
	 * Quarantine::restore() asks this method and refuses to put such a file
	 * back.
	 *
	 * The WordPress folder is compared as defined and resolved (the document
	 * root is often a symlink, and WP-CLI may be started with either form in
	 * --path), and the path as given and resolved; for a file that is not there
	 * (it was moved away) the nearest folder that exists is resolved.
	 *
	 * @param string $abs Absolute path.
	 * @return bool
	 */
	public static function in_core_dir( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs ) {
			return false;
		}
		$forms = array( $abs );
		$real  = self::resolve_missing( $abs );
		if ( '' !== $real && $real !== $abs ) {
			$forms[] = $real;
		}
		foreach ( self::core_roots() as $root ) {
			foreach ( $forms as $form ) {
				if ( 0 === stripos( $form, $root ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * The folders in_core_dir() answers for, each with a trailing slash:
	 * wp-admin and wp-includes below the WordPress folder as defined and as
	 * resolved (realpath; the same two forms as Core_Repair::roots()), and the
	 * plugin's own folder in both forms. Kept for the request.
	 *
	 * @return string[]
	 */
	private static function core_roots() {
		if ( null === self::$core_roots ) {
			$bases = array( self::wp_root() );
			$real  = @realpath( self::wp_root() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- open_basedir may hide the resolved folder.
			if ( $real ) {
				$bases[] = trailingslashit( wp_normalize_path( $real ) );
			}
			$roots = array();
			foreach ( $bases as $base ) {
				$roots[] = $base . 'wp-admin/';
				$roots[] = $base . WPINC . '/';
			}
			$own     = trailingslashit( wp_normalize_path( WPCYBERSEC_DIR ) );
			$roots[] = $own;
			$real    = @realpath( $own ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- open_basedir may hide the resolved folder.
			if ( $real ) {
				$roots[] = trailingslashit( wp_normalize_path( $real ) );
			}
			self::$core_roots = array_values( array_unique( $roots ) );
		}
		return self::$core_roots;
	}

	/**
	 * realpath() that also works for a path that does not exist: the nearest
	 * folder that exists is resolved and the rest of the path is appended.
	 *
	 * @param string $abs Absolute path, forward slashes.
	 * @return string Resolved path with forward slashes, '' when nothing of it can be resolved.
	 */
	private static function resolve_missing( $abs ) {
		$tail = '';
		$path = $abs;
		for ( $i = 0; $i < 64; $i++ ) {
			$real = @realpath( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- a missing path, or one outside open_basedir, is expected here.
			if ( $real ) {
				return untrailingslashit( wp_normalize_path( $real ) ) . $tail;
			}
			$parent = dirname( $path );
			if ( $parent === $path || '' === $parent || '.' === $parent ) {
				break;
			}
			$tail = '/' . basename( $path ) . $tail;
			$path = $parent;
		}
		return '';
	}

	/**
	 * Folder the scanner walks, with a trailing slash.
	 *
	 * @return string
	 */
	public static function scan_root() {
		$settings = wpcybersec()->settings;
		$mode     = $settings->get( 'scan_root', 'abspath' );
		$root     = self::wp_root();

		if ( 'parent' === $mode ) {
			$parent = dirname( untrailingslashit( self::wp_root() ) );
			if ( @is_readable( $parent ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$root = $parent;
			}
		} elseif ( 'custom' === $mode ) {
			$custom = $settings->get( 'scan_root_custom', '' );
			if ( $custom && @is_dir( $custom ) && @is_readable( $custom ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$root = $custom;
			}
		}

		$real = realpath( $root );
		return trailingslashit( wp_normalize_path( $real ? $real : $root ) );
	}

	/**
	 * Folders and files a whole-site scan covers. The first entry is always
	 * the scan root.
	 *
	 * Each entry: path (absolute, realpath, folders with a trailing slash),
	 * depth ('all' walks the folder, 'top' lists only its own files, 'file' is
	 * one file), kind (root | wordpress | content | plugins | mu-plugins |
	 * uploads | home | config) and alias (how files inside are named relative
	 * to the WordPress folder, for exclusions; '' for none).
	 *
	 * @return array[]
	 */
	public static function scan_set() {
		$root = self::scan_root();
		if ( is_array( self::$set ) && isset( self::$set[ $root ] ) ) {
			return self::$set[ $root ];
		}

		$set = array(
			array(
				'path'  => $root,
				'depth' => 'all',
				'kind'  => 'root',
				'alias' => '',
			),
		);

		// Candidates, most general first, so a folder inside another one of the
		// set is dropped (WP_PLUGIN_DIR inside WP_CONTENT_DIR, for example).
		$candidates = array(
			array( self::wp_root(), 'wordpress', '' ),
			array( WP_CONTENT_DIR, 'content', 'wp-content/' ),
			array( WP_PLUGIN_DIR, 'plugins', 'wp-content/plugins/' ),
			array( WPMU_PLUGIN_DIR, 'mu-plugins', 'wp-content/mu-plugins/' ),
			array( self::uploads_basedir(), 'uploads', 'wp-content/uploads/' ),
		);
		$full = array( $root );
		foreach ( $candidates as $candidate ) {
			$dir = self::real_dir( $candidate[0] );
			if ( '' === $dir || self::covered( $dir, $full ) ) {
				continue;
			}
			$full[] = $dir;
			$set[]  = array(
				'path'  => $dir,
				'depth' => 'all',
				'kind'  => $candidate[1],
				'alias' => $candidate[2],
			);
		}

		// The home folder (index.php and .htaccess when WordPress lives in a
		// subfolder): only its own files, never its subfolders, so a parent web
		// root that also holds other sites is not walked.
		$home = self::home_dir();
		if ( '' !== $home && ! self::covered( $home, $full ) ) {
			$set[] = array(
				'path'  => $home,
				'depth' => 'top',
				'kind'  => 'home',
				'alias' => '',
			);
		}

		// wp-config.php one folder above the WordPress folder (WordPress loads it from there).
		$tops = array();
		foreach ( $set as $entry ) {
			if ( 'top' === $entry['depth'] ) {
				$tops[] = $entry['path'];
			}
		}
		$config = class_exists( __NAMESPACE__ . '\\Config_Editor' ) ? Config_Editor::path() : '';
		if ( '' !== $config ) {
			$real   = realpath( $config );
			$config = wp_normalize_path( $real ? $real : $config );
			if ( ! self::covered( $config, $full ) && ! in_array( trailingslashit( wp_normalize_path( dirname( $config ) ) ), $tops, true ) ) {
				$set[] = array(
					'path'  => $config,
					'depth' => 'file',
					'kind'  => 'config',
					'alias' => '',
				);
			}
		}

		// Bedrock: web/wp-config.php loads ../config/application.php, which loads
		// config/environments/<env>.php. That folder runs on every request, so it
		// is walked in full (only when the layout is clear).
		$bedrock = self::bedrock_config_dir( $home, $config );
		if ( '' !== $bedrock && ! self::covered( $bedrock, $full ) ) {
			$full[] = $bedrock;
			$set[]  = array(
				'path'  => $bedrock,
				'depth' => 'all',
				'kind'  => 'config-dir',
				'alias' => '',
			);
		}

		// Other PHP files wp-config.php loads before WordPress starts (a config
		// file next to the web root, Composer's autoloader): each file on its
		// own, never their folders.
		$listed = array();
		foreach ( $set as $entry ) {
			if ( 'file' === $entry['depth'] ) {
				$listed[ $entry['path'] ] = true;
			}
		}
		foreach ( self::config_includes( $config ) as $file ) {
			if ( isset( $listed[ $file ] ) || self::covered( $file, $full ) || in_array( trailingslashit( wp_normalize_path( dirname( $file ) ) ), $tops, true ) ) {
				continue;
			}
			$listed[ $file ] = true;
			$set[]           = array(
				'path'  => $file,
				'depth' => 'file',
				'kind'  => 'loaded',
				'alias' => '',
			);
		}

		/**
		 * Filters the folders and files a whole-site scan covers. Entries must
		 * keep the shape described in Paths::scan_set(); the first one (the scan
		 * root) must stay first.
		 *
		 * @param array[] $set  Scan set.
		 * @param string  $root Scan root.
		 */
		$filtered = function_exists( 'apply_filters' ) ? apply_filters( 'wpcybersec_scan_set', $set, $root ) : $set;
		if ( is_array( $filtered ) && isset( $filtered[0]['path'] ) && $filtered[0]['path'] === $root ) {
			$set = array_values( $filtered );
		}

		if ( ! is_array( self::$set ) ) {
			self::$set = array();
		}
		self::$set[ $root ] = $set;
		return $set;
	}

	/**
	 * Entries of scan_set() other than the scan root.
	 *
	 * @return array[]
	 */
	public static function extra_roots() {
		return array_slice( self::scan_set(), 1 );
	}

	/**
	 * Drops the cached scan set (tests, settings changes in the same request).
	 */
	public static function reset() {
		self::$set        = null;
		self::$data_real  = null;
		self::$outer_real = '';
		self::$loaded     = null;
	}

	/**
	 * Whether a file or folder is covered by a whole-site scan.
	 *
	 * @param string $abs Absolute path (resolved or not).
	 * @return bool
	 */
	public static function in_scope( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs ) {
			return false;
		}
		$real = realpath( $abs );
		$abs  = $real ? wp_normalize_path( $real ) : $abs;
		return '' !== self::scope_entry( $abs );
	}

	/**
	 * Whether a folder lies inside a fully walked folder of the scan set (a
	 * folder update rebaselines and path-limited scans may use).
	 *
	 * @param string $abs_dir Absolute folder (realpath).
	 * @return bool
	 */
	public static function in_full_scope( $abs_dir ) {
		$dir = trailingslashit( wp_normalize_path( (string) $abs_dir ) );
		foreach ( self::scan_set() as $entry ) {
			if ( 'all' === $entry['depth'] && 0 === strpos( $dir, $entry['path'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Kind of the scan set entry that covers a resolved path ('' when none).
	 *
	 * @param string $abs Absolute resolved path.
	 * @return string
	 */
	public static function scope_entry( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		foreach ( self::scan_set() as $entry ) {
			if ( 'all' === $entry['depth'] && ( 0 === strpos( $abs, $entry['path'] ) || trailingslashit( $abs ) === $entry['path'] ) ) {
				return $entry['kind'];
			}
			if ( 'top' === $entry['depth'] && trailingslashit( wp_normalize_path( dirname( $abs ) ) ) === $entry['path'] ) {
				return $entry['kind'];
			}
			if ( 'file' === $entry['depth'] && $abs === $entry['path'] ) {
				return $entry['kind'];
			}
		}
		return '';
	}

	/**
	 * WordPress folders that lie outside the configured scan root and are
	 * scanned as well (for the settings and dashboard note).
	 *
	 * @return array[] { path, kind, depth }
	 */
	public static function outside_root() {
		$out = array();
		foreach ( self::extra_roots() as $entry ) {
			$out[] = array(
				'path'  => untrailingslashit( $entry['path'] ),
				'kind'  => $entry['kind'],
				'depth' => $entry['depth'],
			);
		}
		return $out;
	}

	/**
	 * Name of a file outside the scan root relative to the WordPress folder
	 * (WP_CONTENT_DIR/cache/x.php gives "wp-content/cache/x.php"), '' when
	 * the file is not in a folder of the scan set that has such a name.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	public static function alias( $abs ) {
		$abs  = wp_normalize_path( (string) $abs );
		$best = '';
		$len  = 0;
		foreach ( self::extra_roots() as $entry ) {
			if ( 'all' !== $entry['depth'] || 0 !== strpos( $abs, $entry['path'] ) || strlen( $entry['path'] ) <= $len ) {
				continue;
			}
			if ( '' === $entry['alias'] && 'wordpress' !== $entry['kind'] ) {
				continue;
			}
			$len  = strlen( $entry['path'] );
			$best = $entry['alias'] . substr( $abs, $len );
		}
		return $best;
	}

	/**
	 * @param string $dir Folder (may be '' or missing).
	 * @return string Real folder with a trailing slash, '' when it is not a readable folder.
	 */
	private static function real_dir( $dir ) {
		$dir = (string) $dir;
		if ( '' === $dir || ! @is_dir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return '';
		}
		$real = realpath( $dir );
		return trailingslashit( wp_normalize_path( $real ? $real : $dir ) );
	}

	/**
	 * @param string   $path  Resolved path (folders with a trailing slash).
	 * @param string[] $roots Fully walked folders with a trailing slash.
	 * @return bool Whether one of the folders contains the path (or is it).
	 */
	private static function covered( $path, array $roots ) {
		foreach ( $roots as $root ) {
			if ( 0 === strpos( $path, $root ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Uploads base folder of this site ('' when unknown).
	 *
	 * @return string
	 */
	private static function uploads_basedir() {
		if ( ! function_exists( 'wp_upload_dir' ) ) {
			return '';
		}
		// Multisite: the main site's folder, which holds every site's uploads (sites/<id>/).
		$dirs = Network::on_main(
			static function () {
				return wp_upload_dir( null, false );
			}
		);
		return ! empty( $dirs['basedir'] ) ? (string) $dirs['basedir'] : '';
	}

	/**
	 * Folder that serves the site's front page when it is not the WordPress
	 * folder (WordPress in a subfolder, Bedrock's web/). Worked out from the
	 * home and site URLs like get_home_path(), without $_SERVER (which is wrong
	 * under cron and the CLI), and confirmed by an index.php that loads
	 * wp-blog-header.php one folder above the WordPress folder.
	 *
	 * @return string Real folder with a trailing slash, '' when it is the WordPress folder or unknown.
	 */
	public static function home_dir() {
		$abspath = self::wp_root();
		$found   = '';
		if ( function_exists( 'get_option' ) ) {
			// Multisite: the main site's addresses (a site's path is not a folder).
			$urls = Network::on_main(
				static function () {
					return array( (string) get_option( 'home' ), (string) get_option( 'siteurl' ) );
				}
			);
			$home = (string) wp_parse_url( $urls[0], PHP_URL_PATH );
			$site = (string) wp_parse_url( $urls[1], PHP_URL_PATH );
			$home = trim( $home, '/' );
			$site = trim( $site, '/' );
			if ( $site !== $home && ( '' === $home || 0 === strpos( $site . '/', $home . '/' ) ) ) {
				$sub  = trim( '' === $home ? $site : substr( $site, strlen( $home ) ), '/' );
				$tail = '/' . $sub . '/';
				if ( '' !== $sub && strlen( $abspath ) > strlen( $tail ) && strtolower( substr( $abspath, -strlen( $tail ) ) ) === strtolower( $tail ) ) {
					$found = substr( $abspath, 0, -strlen( $tail ) + 1 );
				}
			}
		}
		if ( '' === $found ) {
			$parent = trailingslashit( wp_normalize_path( dirname( untrailingslashit( $abspath ) ) ) );
			$index  = $parent . 'index.php';
			if ( $parent !== $abspath && @is_file( $index ) && @filesize( $index ) < 8192 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$code = (string) @file_get_contents( $index ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				if ( false !== strpos( $code, 'wp-blog-header.php' ) ) {
					$found = $parent;
				}
			}
		}
		$found = self::real_dir( $found );
		$real  = self::real_dir( $abspath );
		return $found === $real ? '' : $found;
	}

	/**
	 * Bedrock's config/ folder next to the web root: the home folder is
	 * <project>/web/, <project>/config/application.php exists and the
	 * wp-config.php in web/ loads it.
	 *
	 * @param string $home   home_dir() result.
	 * @param string $config Resolved wp-config.php path ('' when unknown).
	 * @return string Real folder with a trailing slash, '' when the layout is not Bedrock's.
	 */
	private static function bedrock_config_dir( $home, $config ) {
		$home = (string) $home;
		if ( '' === $home || '' === (string) $config || 'web' !== basename( untrailingslashit( $home ) ) ) {
			return '';
		}
		if ( trailingslashit( wp_normalize_path( dirname( $config ) ) ) !== $home ) {
			return '';
		}
		$project = trailingslashit( wp_normalize_path( dirname( untrailingslashit( $home ) ) ) );
		if ( ! Storage::path_allowed( $project . 'config' ) || ! @is_file( $project . 'config/application.php' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return '';
		}
		$code = (string) @file_get_contents( $config, false, null, 0, 65536 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === strpos( $code, 'config/application.php' ) ) {
			return '';
		}
		return self::real_dir( $project . 'config' );
	}

	/**
	 * PHP files wp-config.php loads before WordPress starts (wp-settings.php),
	 * such as Bedrock's config/application.php and Composer's autoloader.
	 *
	 * Taken from get_included_files() when this request included wp-config.php
	 * itself (web, wp-cron.php) and remembered in an option, so a
	 * request that did not (WP-CLI evaluates wp-config.php instead of including
	 * it) scans the same files. Without that list, the plain require/include
	 * lines of wp-config.php are read instead.
	 *
	 * @param string $config Resolved wp-config.php path ('' when unknown).
	 * @return string[] Real paths of existing files, at most LOADED_CAP.
	 */
	public static function config_includes( $config ) {
		$config = (string) $config;
		if ( '' === $config ) {
			return array();
		}
		if ( is_array( self::$loaded ) ) {
			return self::$loaded;
		}
		$can_save = function_exists( 'get_option' ) && class_exists( __NAMESPACE__ . '\\Network' );
		$found    = self::loaded_now( $config );
		if ( null !== $found ) {
			if ( $can_save && Network::get_option( self::LOADED_OPTION, null ) !== $found ) {
				Network::update_option( self::LOADED_OPTION, $found, false );
			}
		} else {
			$saved = $can_save ? Network::get_option( self::LOADED_OPTION, null ) : null;
			$found = is_array( $saved ) ? $saved : self::parse_includes( $config );
		}
		$out = array();
		foreach ( (array) $found as $file ) {
			$file = wp_normalize_path( (string) $file );
			if ( '' === $file || ! self::is_absolute( $file ) || false !== strpos( $file, '://' ) || ! Storage::path_allowed( $file ) || ! @is_file( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			$out[] = $file;
			if ( count( $out ) >= self::LOADED_CAP ) {
				break;
			}
		}
		self::$loaded = array_values( array_unique( $out ) );
		return self::$loaded;
	}

	/**
	 * Files included after wp-config.php and before wp-settings.php in this
	 * request.
	 *
	 * @param string $config Resolved wp-config.php path.
	 * @return string[]|null Null when this request did not include wp-config.php itself.
	 */
	private static function loaded_now( $config ) {
		$settings = self::real_file( self::wp_root() . 'wp-settings.php' );
		$started  = false;
		$out      = array();
		foreach ( get_included_files() as $file ) {
			$real = self::real_file( $file );
			if ( ! $started ) {
				$started = ( $real === $config );
				continue;
			}
			if ( $real === $settings ) {
				return array_values( array_unique( $out ) );
			}
			if ( '' !== $real ) {
				$out[] = $real;
			}
		}
		return null;
	}

	/**
	 * Fallback: the require/include lines of wp-config.php whose path is a
	 * plain string, optionally after __DIR__, dirname( __FILE__ ) or
	 * dirname( __DIR__ ). One level only; nothing is executed.
	 *
	 * @param string $config Resolved wp-config.php path.
	 * @return string[]
	 */
	private static function parse_includes( $config ) {
		$size = @filesize( $config ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 262144 ) {
			return array();
		}
		$code = (string) @file_get_contents( $config ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$dir  = untrailingslashit( wp_normalize_path( dirname( $config ) ) );
		$up   = untrailingslashit( wp_normalize_path( dirname( $dir ) ) );
		$out  = array();
		$re   = '~\b(?:require|include)(?:_once)?\s*\(?\s*(?:(dirname\s*\(\s*__DIR__\s*\)|dirname\s*\(\s*dirname\s*\(\s*__FILE__\s*\)\s*\)|__DIR__|dirname\s*\(\s*__FILE__\s*\))\s*\.\s*)?([\'"])([^\'"$]+)\2~i';
		if ( ! preg_match_all( $re, $code, $matches, PREG_SET_ORDER ) ) {
			return array();
		}
		foreach ( $matches as $m ) {
			$base = strtolower( preg_replace( '/\s+/', '', $m[1] ) );
			if ( '' === $base ) {
				$path = self::is_absolute( $m[3] ) ? $m[3] : $dir . '/' . $m[3];
			} elseif ( 'dirname(__dir__)' === $base || 'dirname(dirname(__file__))' === $base ) {
				$path = $up . '/' . ltrim( $m[3], '/' );
			} else {
				$path = $dir . '/' . ltrim( $m[3], '/' );
			}
			$real = self::real_file( $path );
			if ( '' !== $real ) {
				$out[] = $real;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * @param string $file Path.
	 * @return string Normalized real path of a local file, '' otherwise.
	 */
	private static function real_file( $file ) {
		$file = (string) $file;
		if ( '' === $file || false !== strpos( $file, '://' ) || ! Storage::path_allowed( wp_normalize_path( $file ) ) ) {
			return '';
		}
		$real = realpath( $file );
		return $real ? wp_normalize_path( $real ) : '';
	}

	/**
	 * @param string $abs Absolute path.
	 * @return string Path relative to the scan root, or the normalized absolute path when outside it.
	 */
	public static function rel( $abs ) {
		$abs  = wp_normalize_path( $abs );
		$root = self::scan_root();
		if ( 0 === strpos( $abs, $root ) ) {
			return ltrim( substr( $abs, strlen( $root ) ), '/' );
		}
		// The scan lists files by their real folder (a symlinked WordPress or
		// uploads folder), so a path given through a link gets the same key.
		// The file name itself is kept: a symlinked file is listed by its own name.
		if ( self::is_absolute( $abs ) && false === strpos( $abs, '/../' ) ) {
			$dir = realpath( dirname( $abs ) );
			if ( $dir ) {
				$real = trailingslashit( wp_normalize_path( $dir ) ) . basename( $abs );
				if ( 0 === strpos( $real, $root ) ) {
					return ltrim( substr( $real, strlen( $root ) ), '/' );
				}
				return $real;
			}
		}
		return $abs;
	}

	/**
	 * @param string $rel Relative (or absolute) path.
	 * @return string Absolute path.
	 */
	public static function abs( $rel ) {
		$rel = wp_normalize_path( $rel );
		if ( self::is_absolute( $rel ) ) {
			return $rel;
		}
		return self::scan_root() . ltrim( $rel, '/' );
	}

	/**
	 * @param string $path Path.
	 * @return bool
	 */
	public static function is_absolute( $path ) {
		return '' !== $path && ( '/' === $path[0] || preg_match( '#^[a-zA-Z]:/#', $path ) );
	}

	/**
	 * Manifest primary key for a relative path.
	 *
	 * @param string $rel Relative path.
	 * @return string 40 hex chars.
	 */
	public static function hash( $rel ) {
		return sha1( $rel );
	}

	/**
	 * Lowercase last extension. ".htaccess" gives "htaccess", "a.tar.gz" gives "gz".
	 *
	 * @param string $name File name or path.
	 * @return string
	 */
	public static function ext( $name ) {
		$base = basename( $name );
		$pos  = strrpos( $base, '.' );
		return false === $pos ? '' : strtolower( substr( $base, $pos + 1 ) );
	}

	/**
	 * True for server-executable files, including disguised names such as
	 * "shell.php.jpg" or "x.PHTML", and config files like .htaccess.
	 *
	 * @param string $name File name or path.
	 * @return bool
	 */
	public static function is_executable( $name ) {
		$settings = wpcybersec()->settings;
		$base     = strtolower( basename( $name ) );
		if ( in_array( $base, array_map( 'strtolower', (array) $settings->get( 'exec_filenames', array() ) ), true ) ) {
			return true;
		}
		$exts  = (array) $settings->get( 'exec_extensions', array() );
		$parts = explode( '.', $base );
		array_shift( $parts ); // Drop the name before the first dot.
		foreach ( $parts as $part ) {
			if ( in_array( $part, $exts, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a relative path is excluded from scanning. The plugin's own data
	 * directory is always excluded.
	 *
	 * @param string $rel Relative path (files or folders; folders may end with "/").
	 * @return bool
	 */
	public static function is_excluded( $rel ) {
		$rel     = wp_normalize_path( (string) $rel );
		$rel_dir = rtrim( $rel, '/' ) . '/';
		$data    = self::data_rel();
		if ( '' !== $data && 0 === strpos( $rel_dir, $data ) ) {
			return true;
		}
		// The deny files the plugin writes around its random data folder
		// (uploads/qartvelo-guard/.htaccess, index.php, web.config). Only
		// those three names: anything else dropped into that folder is scanned.
		$outer = self::outer_rel();
		if ( '' !== $outer && in_array( basename( rtrim( $rel, '/' ) ), Storage::DENY_FILES, true ) && trailingslashit( dirname( rtrim( $rel, '/' ) ) ) === $outer ) {
			return true;
		}
		if ( self::is_absolute( $rel ) ) {
			// A file outside the scan root: the exclusions are written relative to
			// the WordPress folder ("wp-content/cache/"), so they are also tested
			// against the name the file has there (WP_CONTENT_DIR files as
			// "wp-content/...", plugins as "wp-content/plugins/...").
			$alias = self::alias( $rel );
			if ( '' !== $alias && self::matches_exclusions( $alias ) ) {
				return true;
			}
		}
		return self::matches_exclusions( $rel );
	}

	/**
	 * Resolves the data folder once per request. Both sides are resolved with
	 * realpath(), so a data folder reached through a symlink (or given with
	 * "..") is still recognised. When the data folder is the random folder
	 * inside uploads/qartvelo-guard, the folder around it is remembered too:
	 * the plugin writes its deny files there (see is_excluded()).
	 */
	private static function resolve_data() {
		if ( null !== self::$data_real ) {
			return;
		}
		self::$data_real  = '';
		self::$outer_real = '';
		$dir              = function_exists( 'wpcybersec' ) && wpcybersec()->storage ? (string) wpcybersec()->storage->data_dir() : '';
		if ( '' === $dir ) {
			return;
		}
		$real            = realpath( $dir );
		self::$data_real = trailingslashit( wp_normalize_path( $real ? $real : $dir ) );
		if ( Storage::UPLOADS_FOLDER === basename( dirname( $dir ) ) && preg_match( '/^[a-z0-9]{32}$/', basename( $dir ) ) ) {
			self::$outer_real = trailingslashit( dirname( untrailingslashit( self::$data_real ) ) );
		}
	}

	/**
	 * The plugin's data folder as a relative path (scan root) with a trailing
	 * slash.
	 *
	 * @return string
	 */
	private static function data_rel() {
		self::resolve_data();
		if ( '' === self::$data_real ) {
			return '';
		}
		return trailingslashit( self::rel( untrailingslashit( self::$data_real ) ) );
	}

	/**
	 * The folder around the random data folder (uploads/qartvelo-guard) as a
	 * relative path with a trailing slash, '' for any other data folder.
	 *
	 * @return string
	 */
	private static function outer_rel() {
		self::resolve_data();
		if ( '' === self::$outer_real ) {
			return '';
		}
		return trailingslashit( self::rel( untrailingslashit( self::$outer_real ) ) );
	}

	/**
	 * Whether a path matches one of the exclusion patterns.
	 *
	 * @param string $rel Relative path (or absolute for files outside the scan root).
	 * @return bool
	 */
	private static function matches_exclusions( $rel ) {
		$rel_dir = rtrim( $rel, '/' ) . '/';
		foreach ( (array) wpcybersec()->settings->get( 'exclusions', array() ) as $pattern ) {
			$pattern = ltrim( wp_normalize_path( trim( $pattern ) ), '/' );
			if ( '' === $pattern ) {
				continue;
			}
			if ( false !== strpos( $pattern, '*' ) || false !== strpos( $pattern, '?' ) ) {
				if ( fnmatch( $pattern, rtrim( $rel, '/' ) ) || fnmatch( $pattern, basename( rtrim( $rel, '/' ) ) ) ) {
					return true;
				}
				continue;
			}
			$pattern_dir = rtrim( $pattern, '/' ) . '/';
			if ( rtrim( $rel, '/' ) === rtrim( $pattern, '/' ) || 0 === strpos( $rel_dir, $pattern_dir ) ) {
				return true;
			}
			// A bare name ("error_log") matches that name in every folder.
			if ( false === strpos( $pattern, '/' ) && basename( rtrim( $rel, '/' ) ) === $pattern ) {
				return true;
			}
		}
		return false;
	}
}
