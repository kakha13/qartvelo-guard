<?php
/**
 * Qartvelo Guard - early upload guard.
 *
 * PHP loads this file before every request through auto_prepend_file (via the
 * bootstrap wpcybersec-guard.php in the WordPress root). It holds files uploaded
 * to ANY PHP script, not only to WordPress, until an administrator approves them
 * on the plugin's Reports page.
 *
 * For every uploaded file without an upload error:
 *   - the SHA-256 is computed; approved hashes (allow file) pass untouched. An
 *     approval made under a non-executable name (level 1) does not cover the same
 *     bytes sent under an executable name such as x.php or x.php.jpg (level 2);
 *   - otherwise the file is copied into the guard quarantine folder, a JSON line
 *     is appended to the spool file (WordPress imports it as a pending item),
 *     the temporary upload is deleted, and the request is either answered with
 *     403 (action "block") or continues without the file (action "strip").
 *
 * Holding uploads is the guard's job, so it fails closed for anything that
 * concerns an upload: when the quarantine is full, the disk is low, a copy or
 * the spool write fails, or the upload has more files or deeper nesting than
 * the guard checks, the upload is refused (blocked or stripped) instead of
 * being let through. A refused upload without a kept copy is still spooled
 * ("dropped": true) when possible, so the administrator can approve its hash.
 *
 * Rules for this file:
 *   - Standalone: no WordPress functions. PHP 5.6 compatible syntax.
 *   - Never fatal and never prints PHP warnings. Errors unrelated to a specific
 *     upload (no config, unreadable config) let the request continue untouched.
 *   - Cheap: requests without uploaded files return before any file is read.
 *
 * Config (WPCYBERSEC_GUARD_CONFIG, written by the plugin) returns:
 *   enabled, action (block|strip), quarantine_dir, spool_file, allow_file,
 *   exempt (list), max_bytes, max_spool_bytes, max_quarantine_files,
 *   max_quarantine_bytes, min_free_bytes, exec_extensions, exec_filenames,
 *   home_path, home_paths (multisite: URL path of every site), login_cookie,
 *   message, message_refused, root (WordPress folder),
 *   front_root (folder of the front controller index.php when it is not root).
 *
 * @package WPCyberSecurity
 */

// No direct access. ABSPATH does not exist yet when PHP prepends this file, so
// the guard only refuses to be the requested script itself.
if ( ! defined( 'ABSPATH' ) ) {
	if ( isset( $_SERVER['SCRIPT_FILENAME'] ) && @realpath( (string) $_SERVER['SCRIPT_FILENAME'] ) === __FILE__ ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- only compared with this file's path.
		exit;
	}
}

/*
 * Why this file does not use WordPress functions: it is not loaded by
 * WordPress. PHP runs it through auto_prepend_file before the requested script
 * starts, so WordPress (ABSPATH, wp_unslash(), sanitize_*(), nonces, the
 * current user, $wpdb, WP_Filesystem) is not loaded yet, and for uploads sent
 * to a script outside WordPress it never will be. That is why it reads
 * $_FILES and $_SERVER directly, uses plain PHP file functions, and validates
 * input with its own helpers. It is only active after an administrator turns
 * on Settings > Advanced > Early guard (or adds the auto_prepend_file line
 * shown there). Turning it off there, or deactivating the plugin, switches it
 * off; uninstalling with "Delete all data" also removes the lines the plugin
 * wrote. A leftover bootstrap does nothing once this file or its config is gone.
 * It makes no network requests, and the only file it includes is its own
 * config, written by the plugin.
 *
 * This file runs before WordPress: there are no nonces, no logged-in user and
 * no sanitize or unslash functions yet (and WordPress has not added slashes to
 * the request). The guard reads the request only to decide whether an upload
 * is held. Request values are compared, or cleaned with clean() and
 * file_name() before they go into the spool (JSON) or the plain text or JSON
 * refusal (sent with X-Content-Type-Options: nosniff).
 */
// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput

if ( ! defined( 'WPCYBERSEC_GUARD_ACTIVE' ) ) {
	define( 'WPCYBERSEC_GUARD_ACTIVE', true );

	if ( ! class_exists( 'WPCyberSec_Guard', false ) ) {

		/**
		 * Static helper so nothing leaks into the global function namespace.
		 */
		final class WPCyberSec_Guard {

			/** Hard limits that protect the guard itself. Uploads beyond them are refused. */
			const MAX_FILES = 200;
			const MAX_DEPTH = 8;

			/** @var bool Set when an upload has more files or deeper nesting than the guard checks. */
			private static $overflow = false;

			/**
			 * Entry point.
			 */
			public static function run() {
				if ( empty( $_FILES ) || ! is_array( $_FILES ) ) {
					return;
				}
				$config = self::config();
				if ( ! $config ) {
					return;
				}
				if ( self::is_exempt( $config ) ) {
					return;
				}

				self::$overflow = false;
				$files          = array();
				foreach ( $_FILES as $field => $spec ) {
					if ( is_array( $spec ) && isset( $spec['tmp_name'] ) ) {
						self::walk( $spec, (string) $field, $spec['tmp_name'], array(), 0, $files );
					}
				}
				if ( self::$overflow ) {
					// Files the guard did not look at must not reach the application.
					self::fail( new Exception( 'refused an upload with more than ' . self::MAX_FILES . ' files or nesting deeper than ' . self::MAX_DEPTH . ' levels' ) );
					self::refuse_all( $config );
					return;
				}
				if ( ! $files ) {
					return;
				}

				$allow = null;
				$held  = array();
				foreach ( $files as $file ) {
					$tmp = (string) $file['tmp_name'];
					if ( '' === $tmp || ! @is_uploaded_file( $tmp ) ) {
						continue;
					}
					$sha256 = @hash_file( 'sha256', $tmp );
					if ( ! is_string( $sha256 ) || 64 !== strlen( $sha256 ) ) {
						// Unreadable upload: refuse it rather than let it through unchecked.
						self::fail( new Exception( 'cannot hash an upload' ) );
						$held[] = self::refused_entry( $file, 'hash_failed' );
						continue;
					}
					$sha256 = strtolower( $sha256 );
					if ( null === $allow ) {
						$allow = self::allowlist( $config );
					}
					$exec = self::is_executable_name( $config, $file['name'] );
					if ( isset( $allow[ $sha256 ] ) && $allow[ $sha256 ] >= ( $exec ? 2 : 1 ) ) {
						continue;
					}
					$held[] = self::hold( $config, $file, $tmp, $sha256, $exec );
				}

				if ( ! $held ) {
					return;
				}

				$lines = array();
				foreach ( $held as $entry ) {
					if ( ! empty( $entry['spooled'] ) ) {
						$lines[] = $entry['line'];
					}
				}
				if ( $lines ) {
					// Tells code running later in this request (strip mode) what was held.
					$GLOBALS['wpcybersec_guard_held'] = $lines;
				}

				if ( 'strip' === $config['action'] ) {
					self::strip( $held );
					return;
				}
				// Nothing reached the review list (spool full or unwritable): say it was refused, not held.
				self::block( $config, $held, $lines ? null : $config['message_refused'] );
			}

			/**
			 * Logs an internal error without printing anything.
			 *
			 * @param mixed $error Exception or Throwable.
			 */
			public static function fail( $error ) {
				$message = is_object( $error ) && method_exists( $error, 'getMessage' ) ? $error->getMessage() : 'unknown error';
				@error_log( 'Qartvelo Guard guard: ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log, WordPress.PHP.NoSilencedErrors.Discouraged -- runs before WordPress (auto_prepend_file); the PHP error log is the only log there.
			}

			/**
			 * Reads and normalizes the config.
			 *
			 * @return array Empty when the guard is off or misconfigured.
			 */
			private static function config() {
				$file = defined( 'WPCYBERSEC_GUARD_CONFIG' ) ? (string) WPCYBERSEC_GUARD_CONFIG : '';
				if ( '' === $file || ! @is_file( $file ) || ! @is_readable( $file ) ) {
					return array();
				}
				// Drop a cached copy if the file changed, even with validate_timestamps=0.
				if ( function_exists( 'opcache_invalidate' ) ) {
					@opcache_invalidate( $file, false );
				}
				$config = @include $file;
				if ( ! is_array( $config ) || empty( $config['enabled'] ) ) {
					return array();
				}
				if ( empty( $config['quarantine_dir'] ) || empty( $config['spool_file'] ) ) {
					return array();
				}
				$message = 'This upload is waiting for administrator approval (Qartvelo Guard). After approval, send it again and it will go through.';
				return array(
					'action'               => isset( $config['action'] ) && 'strip' === $config['action'] ? 'strip' : 'block',
					'quarantine_dir'       => rtrim( str_replace( '\\', '/', (string) $config['quarantine_dir'] ), '/' ),
					'spool_file'           => str_replace( '\\', '/', (string) $config['spool_file'] ),
					'allow_file'           => isset( $config['allow_file'] ) ? (string) $config['allow_file'] : '',
					'exempt'               => isset( $config['exempt'] ) && is_array( $config['exempt'] ) ? $config['exempt'] : array(),
					'max_bytes'            => self::positive( $config, 'max_bytes', 268435456 ),
					'max_spool_bytes'      => self::positive( $config, 'max_spool_bytes', 20971520 ),
					'max_quarantine_files' => self::positive( $config, 'max_quarantine_files', 500 ),
					'max_quarantine_bytes' => self::positive( $config, 'max_quarantine_bytes', 536870912 ),
					'min_free_bytes'       => self::positive( $config, 'min_free_bytes', 67108864 ),
					// Same lists as the plugin's Paths::is_executable(); built-in defaults for configs written before they were added.
					'exec_extensions'      => self::lower_list( isset( $config['exec_extensions'] ) ? $config['exec_extensions'] : null, array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps', 'inc', 'shtml', 'cgi', 'pl', 'py', 'sh', 'asp', 'aspx', 'jsp' ) ),
					'exec_filenames'       => self::lower_list( isset( $config['exec_filenames'] ) ? $config['exec_filenames'] : null, array( '.htaccess', '.user.ini', 'php.ini', 'web.config' ) ),
					'home_path'            => isset( $config['home_path'] ) ? rtrim( str_replace( '\\', '/', (string) $config['home_path'] ), '/' ) : '',
					'home_paths'           => self::path_list( isset( $config['home_paths'] ) ? $config['home_paths'] : null ),
					'login_cookie'         => isset( $config['login_cookie'] ) ? (string) $config['login_cookie'] : '',
					'message'              => isset( $config['message'] ) && '' !== (string) $config['message'] ? (string) $config['message'] : $message,
					'message_refused'      => isset( $config['message_refused'] ) && '' !== (string) $config['message_refused'] ? (string) $config['message_refused'] : 'This upload was refused because it could not be checked (Qartvelo Guard). Please contact the site administrator.',
					'root'                 => isset( $config['root'] ) && '' !== (string) $config['root'] ? rtrim( str_replace( '\\', '/', (string) $config['root'] ), '/' ) . '/' : '',
					// Front controller folder when WordPress lives in a sub folder (or Bedrock's web/).
					'front_root'           => isset( $config['front_root'] ) && '' !== (string) $config['front_root'] ? rtrim( str_replace( '\\', '/', (string) $config['front_root'] ), '/' ) . '/' : '',
				);
			}

			/**
			 * @param array  $config  Raw config.
			 * @param string $key     Key.
			 * @param int    $default Default.
			 * @return int
			 */
			private static function positive( array $config, $key, $default ) {
				return isset( $config[ $key ] ) && (int) $config[ $key ] > 0 ? (int) $config[ $key ] : (int) $default;
			}

			/**
			 * @param mixed $list    List from the config, or null when missing.
			 * @param array $default Default list.
			 * @return string[] Lowercase values.
			 */
			private static function lower_list( $list, array $default ) {
				if ( ! is_array( $list ) ) {
					$list = $default;
				}
				$out = array();
				foreach ( $list as $value ) {
					if ( is_scalar( $value ) && '' !== (string) $value ) {
						$out[] = strtolower( (string) $value );
					}
				}
				return $out;
			}

			/**
			 * Approved hashes. The file is parsed as text instead of included, so a
			 * stale OPcache entry (validate_timestamps=0, or an approval made from
			 * WP-CLI, whose cache is separate) can never hide a fresh approval.
			 *
			 * @param array $config Config.
			 * @return array sha256 => 1 (non-executable names only) | 2 (any name)
			 */
			private static function allowlist( array $config ) {
				$file = $config['allow_file'];
				if ( '' === $file || ! @is_file( $file ) ) {
					return array();
				}
				$raw = @file_get_contents( $file );
				if ( ! is_string( $raw ) || '' === $raw ) {
					return array();
				}
				$map = array();
				if ( preg_match_all( '/[\'"]([a-fA-F0-9]{64})[\'"]\s*=>\s*([0-9]*)/', $raw, $matches, PREG_SET_ORDER ) ) {
					foreach ( $matches as $match ) {
						$hash  = strtolower( $match[1] );
						$level = '2' === $match[2] ? 2 : 1;
						if ( ! isset( $map[ $hash ] ) || $level > $map[ $hash ] ) {
							$map[ $hash ] = $level;
						}
					}
				}
				return $map;
			}

			/**
			 * Whether a client file name is executable on the server. Uses the same
			 * rules as the plugin's Paths::is_executable() (exact names such as
			 * .htaccess, and any extension after the first dot, so x.php.jpg counts),
			 * applied to the raw name and to the forms applications commonly turn it
			 * into (characters removed, cut at ":" or ";", trailing dots trimmed).
			 *
			 * @param array  $config Config.
			 * @param string $name   Client file name.
			 * @return bool
			 */
			private static function is_executable_name( array $config, $name ) {
				$name = strtolower( str_replace( '\\', '/', (string) $name ) );
				$pos  = strrpos( $name, '/' );
				if ( false !== $pos ) {
					$name = substr( $name, $pos + 1 );
				}
				$plain = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $name );
				$clean = str_replace( array( '?', '[', ']', '=', '<', '>', ':', ';', ',', "'", '"', '&', '$', '#', '*', '(', ')', '|', '~', '`', '!', '{', '}', '%', '+' ), '', $plain );
				$clean = trim( (string) preg_replace( '/\s+/', '-', $clean ), '.-_' );
				$cut   = rtrim( (string) preg_replace( '/[:;\x00].*$/s', '', $name ), '. ' );

				foreach ( array_unique( array( $name, $plain, $clean, $cut, rtrim( $plain, '. ' ) ) ) as $base ) {
					if ( '' === $base ) {
						continue;
					}
					if ( in_array( $base, $config['exec_filenames'], true ) ) {
						return true;
					}
					$parts = explode( '.', $base );
					array_shift( $parts ); // Drop the name before the first dot.
					foreach ( $parts as $part ) {
						if ( in_array( $part, $config['exec_extensions'], true ) || in_array( trim( $part ), $config['exec_extensions'], true ) ) {
							return true;
						}
					}
				}
				return false;
			}

			/**
			 * Exemptions. Each one only applies when the script that actually runs
			 * matches it, so query strings, duplicate parameters or PATH_INFO cannot
			 * be used to sneak an upload past the guard:
			 *   "/wp-admin/async-upload.php"  the running script is that file
			 *   "/wp-json/wp/v2/media"        WordPress's index.php serves that route from
			 *                                 the URL path (home path + route, no rest_route
			 *                                 parameter that would override it)
			 *   "rest_route=/wp/v2/media"     WordPress's index.php, and the value PHP and
			 *                                 WordPress actually use is that route
			 * Exemptions for WordPress's own endpoints (scripts in /wp-admin/, REST
			 * routes in the wp/v2 namespace) also need WordPress login credentials in
			 * the request: those endpoints refuse anonymous uploads anyway, while
			 * other code that handles uploads early in any request would not.
			 *
			 * @param array $config Config.
			 * @return bool
			 */
			private static function is_exempt( array $config ) {
				if ( ! $config['exempt'] ) {
					return false;
				}
				$uri  = self::server( 'REQUEST_URI', 4096 );
				$qpos = strpos( $uri, '?' );
				$path = false === $qpos ? $uri : substr( $uri, 0, $qpos );
				$path = (string) preg_replace( '#/+#', '/', str_replace( '\\', '/', rawurldecode( $path ) ) );

				$script = self::script_file();
				// WordPress's front controller: index.php in the WordPress folder, or the
				// index.php that loads it from the site root (WordPress in a sub folder, Bedrock).
				$is_root_index = '' !== $script && (
					( '' !== $config['root'] && $script === $config['root'] . 'index.php' )
					|| ( '' !== $config['front_root'] && $script === $config['front_root'] . 'index.php' )
				);

				$login = null;
				foreach ( $config['exempt'] as $pattern ) {
					$pattern = trim( (string) $pattern );
					if ( '' === $pattern ) {
						continue;
					}
					if ( false !== strpos( $pattern, '=' ) ) {
						$match = $is_root_index && self::param_is( $pattern );
					} else {
						$pattern = '/' . ltrim( str_replace( '\\', '/', $pattern ), '/' );
						if ( '.php' === strtolower( substr( $pattern, -4 ) ) ) {
							$match = '' !== $script && self::ends_with( $script, $pattern );
						} else {
							$match = $is_root_index && self::route_is( $config, $path, rtrim( $pattern, '/' ) );
						}
					}
					if ( ! $match ) {
						continue;
					}
					if ( ! self::is_core_endpoint( $pattern ) ) {
						return true;
					}
					if ( null === $login ) {
						$login = self::has_credentials( $config );
					}
					if ( $login ) {
						return true;
					}
				}
				return false;
			}

			/**
			 * Whether an exemption is for one of WordPress's own upload endpoints,
			 * which only logged-in users can use: a script in /wp-admin/, or a REST
			 * route in WordPress's namespace (wp/v2).
			 *
			 * @param string $pattern Exemption (path, script or key=value).
			 * @return bool
			 */
			private static function is_core_endpoint( $pattern ) {
				$pattern = strtolower( $pattern );
				if ( false !== strpos( $pattern, '/wp-admin/' ) ) {
					return true;
				}
				return (bool) preg_match( '#(^|/|=)wp/v[0-9]+(/|$)#', $pattern );
			}

			/**
			 * Whether the request carries WordPress login credentials: a logged-in
			 * cookie or an Authorization header (application passwords). Only
			 * their shape can be checked here (WordPress is not loaded, so the
			 * cookie signature cannot be verified): the exemption only decides
			 * which gate holds the upload, the WordPress one instead of this one,
			 * and WordPress itself still refuses the request when the credentials
			 * are forged.
			 *
			 * @param array $config Config.
			 * @return bool
			 */
			private static function has_credentials( array $config ) {
				foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $key ) {
					$auth = self::server( $key, 4096 );
					// "Basic <base64 of user:password>" (application passwords) or "Bearer <token>".
					if ( preg_match( '#^Basic [A-Za-z0-9+/]{4,}={0,2}$#', $auth ) && false !== strpos( (string) base64_decode( substr( $auth, 6 ), true ), ':' ) ) {
						return true;
					}
					if ( preg_match( '#^Bearer [A-Za-z0-9._~+/=-]{16,}$#', $auth ) ) {
						return true;
					}
				}
				if ( '' !== self::server( 'PHP_AUTH_USER', 256 ) && '' !== self::server( 'PHP_AUTH_PW', 256 ) ) {
					return true;
				}
				if ( empty( $_COOKIE ) || ! is_array( $_COOKIE ) ) {
					return false;
				}
				$now    = time();
				$wanted = (string) $config['login_cookie']; // LOGGED_IN_COOKIE of this site, '' when unknown.
				foreach ( $_COOKIE as $name => $value ) {
					if ( ! is_string( $value ) || '' === $value ) {
						continue;
					}
					$name = (string) $name;
					if ( '' !== $wanted ) {
						$ours = $name === $wanted;
					} else {
						$ours = 0 === strpos( $name, 'wordpress_logged_in_' );
					}
					if ( ! $ours ) {
						continue;
					}
					// user|expiry|session token|signature, as wp_generate_auth_cookie() writes it, and not expired.
					$parts = explode( '|', $value );
					if ( 4 === count( $parts ) && '' !== $parts[0] && preg_match( '/^[0-9]{1,12}$/', $parts[1] ) && (int) $parts[1] > $now && preg_match( '/^[A-Za-z0-9]{20,}$/', $parts[2] ) && preg_match( '/^[0-9a-f]{32,64}$/', $parts[3] ) ) {
						return true;
					}
				}
				return false;
			}

			/**
			 * "key=value": the value PHP and WordPress will actually use for key is
			 * value or starts with "value/". PHP keeps the last of duplicate keys and
			 * turns "." and " " in names into "_", so the parsed $_GET/$_POST are
			 * checked, never the raw query string. WordPress takes a POST value over
			 * a GET value, so both must agree when both are present.
			 *
			 * @param string $pattern key=value.
			 * @return bool
			 */
			private static function param_is( $pattern ) {
				$pos  = strpos( $pattern, '=' );
				$key  = str_replace( array( '.', ' ' ), '_', substr( $pattern, 0, $pos ) );
				$want = rtrim( substr( $pattern, $pos + 1 ), '/' );
				if ( '' === $key || '' === $want ) {
					return false;
				}
				$get  = isset( $_GET ) && is_array( $_GET ) && array_key_exists( $key, $_GET ) ? $_GET[ $key ] : null;
				$post = isset( $_POST ) && is_array( $_POST ) && array_key_exists( $key, $_POST ) ? $_POST[ $key ] : null;
				if ( ( null !== $get && ! is_string( $get ) ) || ( null !== $post && ! is_string( $post ) ) ) {
					return false;
				}
				if ( null !== $get && null !== $post && $get !== $post ) {
					return false;
				}
				$value = null !== $post ? $post : $get;
				if ( null === $value ) {
					return false;
				}
				return $value === $want || 0 === strpos( $value, $want . '/' );
			}

			/**
			 * Whether WordPress will serve the route $pattern for this URL path: the
			 * path is the home path plus the route (or plus /index.php and the route),
			 * and no rest_route parameter overrides the route taken from the path.
			 *
			 * @param array  $config  Config.
			 * @param string $path    Decoded request path.
			 * @param string $pattern Route path, for example /wp-json/wp/v2/media.
			 * @return bool
			 */
			private static function route_is( array $config, $path, $pattern ) {
				if ( '' === $pattern || '/' === $pattern ) {
					return false;
				}
				if ( ( isset( $_GET ) && is_array( $_GET ) && array_key_exists( 'rest_route', $_GET ) ) || ( isset( $_POST ) && is_array( $_POST ) && array_key_exists( 'rest_route', $_POST ) ) ) {
					return false;
				}
				if ( preg_match( '#/\.\.?(/|$)#', $path ) ) {
					return false; // Dot segments: not a plain route path.
				}
				// Multisite: every site of the network has its own path (subdirectory networks).
				$homes = $config['home_paths'] ? $config['home_paths'] : array( $config['home_path'] );
				foreach ( $homes as $home ) {
					foreach ( array( $home . $pattern, $home . '/index.php' . $pattern ) as $prefix ) {
						if ( $path === $prefix || 0 === strpos( $path, $prefix . '/' ) ) {
							return true;
						}
					}
				}
				return false;
			}

			/**
			 * URL paths from the config: strings without a trailing slash, at most 5000.
			 *
			 * @param mixed $list Raw list.
			 * @return array
			 */
			private static function path_list( $list ) {
				$out = array();
				if ( ! is_array( $list ) ) {
					return $out;
				}
				foreach ( $list as $value ) {
					if ( is_string( $value ) && strlen( $value ) < 300 ) {
						$out[] = rtrim( str_replace( '\\', '/', $value ), '/' );
						if ( count( $out ) >= 5000 ) {
							break;
						}
					}
				}
				return array_values( array_unique( $out ) );
			}

			/**
			 * Real path of the script PHP is running, with forward slashes.
			 *
			 * @return string
			 */
			private static function script_file() {
				$file = self::server( 'SCRIPT_FILENAME', 4096 );
				if ( '' === $file && '' !== self::server( 'DOCUMENT_ROOT', 4096 ) && '' !== self::server( 'SCRIPT_NAME', 4096 ) ) {
					$file = rtrim( self::server( 'DOCUMENT_ROOT', 4096 ), '/\\' ) . '/' . ltrim( self::server( 'SCRIPT_NAME', 4096 ), '/\\' );
				}
				if ( '' === $file ) {
					return '';
				}
				$real = @realpath( $file );
				return str_replace( '\\', '/', false !== $real ? $real : $file );
			}

			/**
			 * @param string $haystack String.
			 * @param string $needle   Suffix starting with "/".
			 * @return bool
			 */
			private static function ends_with( $haystack, $needle ) {
				$len = strlen( $needle );
				return $len > 1 && strlen( $haystack ) >= $len && 0 === strcasecmp( substr( $haystack, -$len ), $needle );
			}

			/**
			 * Flattens a $_FILES entry, including nested names such as files[] or a[b][c].
			 * Entries with an upload error (including "no file") are skipped. More than
			 * MAX_FILES files, or a real upload nested deeper than MAX_DEPTH, sets the
			 * overflow flag so the request is refused.
			 *
			 * @param array  $spec  The $_FILES[field] array.
			 * @param string $field Top-level field name.
			 * @param mixed  $node  Current tmp_name node.
			 * @param array  $keys  Keys below the field.
			 * @param int    $depth Depth.
			 * @param array  $out   Collected files.
			 */
			private static function walk( array $spec, $field, $node, array $keys, $depth, array &$out ) {
				if ( self::$overflow ) {
					return;
				}
				if ( $depth > self::MAX_DEPTH ) {
					if ( self::has_upload( $node ) ) {
						self::$overflow = true;
					}
					return;
				}
				if ( is_array( $node ) ) {
					foreach ( $node as $key => $child ) {
						$sub   = $keys;
						$sub[] = $key;
						self::walk( $spec, $field, $child, $sub, $depth + 1, $out );
					}
					return;
				}
				$error = (int) self::dig( isset( $spec['error'] ) ? $spec['error'] : 0, $keys );
				if ( 0 !== $error ) {
					return; // Upload errors (including "no file") are not ours to judge.
				}
				if ( count( $out ) >= self::MAX_FILES ) {
					self::$overflow = true;
					return;
				}
				$label = $field;
				foreach ( $keys as $key ) {
					$label .= '[' . $key . ']';
				}
				$out[] = array(
					'field'    => $label,
					'top'      => $field,
					'keys'     => $keys,
					'name'     => (string) self::dig( isset( $spec['name'] ) ? $spec['name'] : '', $keys ),
					'type'     => (string) self::dig( isset( $spec['type'] ) ? $spec['type'] : '', $keys ),
					'tmp_name' => (string) $node,
					'error'    => $error,
					'size'     => (int) self::dig( isset( $spec['size'] ) ? $spec['size'] : 0, $keys ),
				);
			}

			/**
			 * @param mixed $node tmp_name node.
			 * @return bool Whether it holds at least one uploaded file.
			 */
			private static function has_upload( $node ) {
				if ( ! is_array( $node ) ) {
					return is_string( $node ) && '' !== $node;
				}
				$found = false;
				array_walk_recursive(
					$node,
					function ( $value ) use ( &$found ) {
						if ( is_string( $value ) && '' !== $value ) {
							$found = true;
						}
					}
				);
				return $found;
			}

			/**
			 * @param mixed $value Nested array.
			 * @param array $keys  Path.
			 * @return mixed Scalar at the path, '' when missing.
			 */
			private static function dig( $value, array $keys ) {
				foreach ( $keys as $key ) {
					if ( ! is_array( $value ) || ! array_key_exists( $key, $value ) ) {
						return '';
					}
					$value = $value[ $key ];
				}
				return is_array( $value ) ? '' : $value;
			}

			/**
			 * Copies one upload into quarantine and spools it. Always returns an
			 * entry: the upload is held, or refused without a copy when it cannot be
			 * held (fail closed).
			 *
			 * @param array  $config Config.
			 * @param array  $file   File entry.
			 * @param string $tmp    Temp path.
			 * @param string $sha256 Hash.
			 * @param bool   $exec   Whether the client name is executable.
			 * @return array Entry { line, top, keys, spooled }.
			 */
			private static function hold( array $config, array $file, $tmp, $sha256, $exec ) {
				$size = @filesize( $tmp );
				$size = false === $size ? (int) $file['size'] : (int) $size;

				$spool_size = @is_file( $config['spool_file'] ) ? (int) @filesize( $config['spool_file'] ) : 0;
				$note       = '';
				$dest       = '';
				$created    = false;

				if ( $spool_size >= $config['max_spool_bytes'] ) {
					$note = 'spool_full'; // Too many unreviewed uploads: refuse without keeping a copy.
				} elseif ( $size > $config['max_bytes'] ) {
					$note = 'too_large'; // Refused without a copy; the admin can still approve the hash.
				} else {
					// Named by content, so the same bytes sent again do not take more space.
					$dir  = $config['quarantine_dir'] . '/' . gmdate( 'Y' ) . '/' . gmdate( 'm' );
					$dest = $dir . '/' . $sha256 . ( $exec ? '-x' : '' ) . '.bin';
					if ( ! @is_file( $dest ) ) {
						$note = self::copy_into_quarantine( $config, $tmp, $dir, $dest, $size );
						if ( '' === $note ) {
							$created = true;
						} else {
							$dest = '';
						}
					}
				}

				$line = array(
					'time'            => time(),
					'script'          => self::server( 'SCRIPT_NAME', 255 ),
					'uri'             => self::server( 'REQUEST_URI', 1000 ),
					'host'            => self::server( 'HTTP_HOST', 255 ),
					'method'          => self::server( 'REQUEST_METHOD', 10 ),
					'ip'              => self::server( 'REMOTE_ADDR', 45 ),
					'ua'              => self::server( 'HTTP_USER_AGENT', 255 ),
					'field'           => self::clean( $file['field'], 255 ),
					'name'            => self::file_name( $file['name'], $sha256 ),
					'size'            => $size,
					'sha256'          => $sha256,
					'quarantine_path' => $dest,
					'type'            => self::clean( $file['type'], 100 ),
					'exec'            => (bool) $exec,
					'held'            => '' !== $dest,
					'dropped'         => '' === $dest,
					'note'            => $note,
					'action'          => $config['action'],
				);

				$spooled = false;
				if ( 'spool_full' !== $note ) {
					$spooled = self::spool( $config, $line );
					if ( ! $spooled ) {
						// Nobody would ever see a copy without its spool line: remove it, refuse the upload.
						if ( $created ) {
							@unlink( $dest ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
						}
						self::fail( new Exception( 'cannot write the spool file; the upload was refused' ) );
					}
				}

				if ( @is_file( $tmp ) ) {
					@unlink( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
				}
				return array(
					'line'    => $line,
					'top'     => $file['top'],
					'keys'    => $file['keys'],
					'spooled' => $spooled,
				);
			}

			/**
			 * Copies the upload to $dest when the quarantine has room.
			 *
			 * @param array  $config Config.
			 * @param string $tmp    Temp path.
			 * @param string $dir    Target folder.
			 * @param string $dest   Target file.
			 * @param int    $size   Size in bytes.
			 * @return string '' on success, else the note: quota_full | no_space | copy_failed.
			 */
			private static function copy_into_quarantine( array $config, $tmp, $dir, $dest, $size ) {
				$usage = self::quarantine_usage( $config );
				if ( $usage['files'] >= $config['max_quarantine_files'] || $usage['bytes'] + $size > $config['max_quarantine_bytes'] ) {
					self::fail( new Exception( 'the guard quarantine is full; an upload was refused without a copy' ) );
					return 'quota_full';
				}
				if ( function_exists( 'disk_free_space' ) ) {
					$probe = @is_dir( $config['quarantine_dir'] ) ? $config['quarantine_dir'] : dirname( $config['quarantine_dir'] );
					$free  = @disk_free_space( $probe );
					if ( is_numeric( $free ) && (float) $free < (float) $size + (float) $config['min_free_bytes'] ) {
						self::fail( new Exception( 'not enough free disk space; an upload was refused without a copy' ) );
						return 'no_space';
					}
				}
				if ( ! @is_dir( $dir ) && ! @mkdir( $dir, 0700, true ) && ! @is_dir( $dir ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
					self::fail( new Exception( 'cannot create ' . $dir . '; an upload was refused without a copy' ) );
					return 'copy_failed';
				}
				// Copy to a temporary name first, so a half-written copy is never taken for a held file.
				$part = $dest . '.' . self::random_name() . '.part';
				$ok   = @copy( $tmp, $part );
				if ( $ok ) {
					clearstatcache();
					$ok = (int) @filesize( $part ) === (int) $size && @rename( $part, $dest ); // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
				}
				if ( ! $ok ) {
					@unlink( $part ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
					self::fail( new Exception( 'cannot copy an upload into ' . $dir . '; it was refused without a copy' ) );
					return 'copy_failed';
				}
				@chmod( $dest, 0600 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
				return '';
			}

			/**
			 * Files and bytes in the guard quarantine. Stops counting once a limit is
			 * reached. The plugin deletes copies when items are approved or denied.
			 *
			 * @param array $config Config.
			 * @return array { files, bytes }
			 */
			private static function quarantine_usage( array $config ) {
				$usage = array(
					'files' => 0,
					'bytes' => 0,
				);
				$list  = @glob( $config['quarantine_dir'] . '/*/*/*.bin', GLOB_NOSORT );
				if ( ! is_array( $list ) ) {
					return $usage;
				}
				foreach ( $list as $path ) {
					++$usage['files'];
					$usage['bytes'] += (int) @filesize( $path );
					if ( $usage['files'] >= $config['max_quarantine_files'] || $usage['bytes'] > $config['max_quarantine_bytes'] ) {
						break;
					}
				}
				return $usage;
			}

			/**
			 * Entry for an upload refused without a copy or a spool line.
			 *
			 * @param array  $file File entry.
			 * @param string $note Reason.
			 * @return array
			 */
			private static function refused_entry( array $file, $note ) {
				$tmp = (string) $file['tmp_name'];
				if ( '' !== $tmp && @is_uploaded_file( $tmp ) && @is_file( $tmp ) ) {
					@unlink( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
				}
				return array(
					'line'    => array(
						'name' => self::file_name( $file['name'], str_repeat( '0', 64 ) ),
						'note' => $note,
					),
					'top'     => $file['top'],
					'keys'    => $file['keys'],
					'spooled' => false,
				);
			}

			/**
			 * Refuses every file of the request (more files or deeper nesting than
			 * the guard checks): 403 in block mode, all files removed in strip mode.
			 *
			 * @param array $config Config.
			 */
			private static function refuse_all( array $config ) {
				if ( 'strip' === $config['action'] ) {
					$_FILES = array();
					return;
				}
				self::block( $config, array(), $config['message_refused'] );
			}

			/**
			 * Appends one JSON line to the spool under an exclusive lock.
			 *
			 * @param array $config Config.
			 * @param array $line   Data.
			 * @return bool
			 */
			private static function spool( array $config, array $line ) {
				$flags = 0;
				if ( defined( 'JSON_UNESCAPED_SLASHES' ) ) {
					$flags |= JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
				}
				$json = json_encode( $line, $flags );
				if ( ! is_string( $json ) || '' === $json ) {
					return false;
				}
				$dir = dirname( $config['spool_file'] );
				if ( ! @is_dir( $dir ) && ! @mkdir( $dir, 0700, true ) && ! @is_dir( $dir ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
					return false;
				}
				$handle = @fopen( $config['spool_file'], 'ab' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
				if ( ! $handle ) {
					return false;
				}
				$ok = false;
				if ( @flock( $handle, LOCK_EX ) ) {
					$data = $json . "\n";
					$ok   = strlen( $data ) === @fwrite( $handle, $data ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
					@fflush( $handle );
					@flock( $handle, LOCK_UN );
				}
				@fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- runs before WordPress is loaded, so the WordPress filesystem API does not exist.
				return $ok;
			}

			/**
			 * Removes held files from $_FILES so the target script sees no upload.
			 * Top-level files are removed; nested ones are marked "no file uploaded"
			 * so array shapes stay intact for the application.
			 *
			 * @param array $held Held entries.
			 */
			private static function strip( array $held ) {
				foreach ( $held as $entry ) {
					$top = $entry['top'];
					if ( ! isset( $_FILES[ $top ] ) ) {
						continue;
					}
					if ( ! $entry['keys'] ) {
						unset( $_FILES[ $top ] );
						continue;
					}
					$values = array(
						'name'     => '',
						'type'     => '',
						'tmp_name' => '',
						'error'    => 4, // UPLOAD_ERR_NO_FILE.
						'size'     => 0,
					);
					foreach ( $values as $prop => $value ) {
						if ( isset( $_FILES[ $top ][ $prop ] ) && is_array( $_FILES[ $top ][ $prop ] ) ) {
							self::set_path( $_FILES[ $top ][ $prop ], $entry['keys'], $value );
						}
					}
				}
			}

			/**
			 * @param array $target Array to change.
			 * @param array $keys   Path.
			 * @param mixed $value  Value.
			 */
			private static function set_path( array &$target, array $keys, $value ) {
				$ref  = &$target;
				$last = array_pop( $keys );
				foreach ( $keys as $key ) {
					if ( ! isset( $ref[ $key ] ) || ! is_array( $ref[ $key ] ) ) {
						return;
					}
					$ref = &$ref[ $key ];
				}
				if ( is_array( $ref ) && array_key_exists( $last, $ref ) ) {
					$ref[ $last ] = $value;
				}
			}

			/**
			 * Answers 403 and stops the request.
			 *
			 * @param array       $config  Config.
			 * @param array       $held    Held entries.
			 * @param string|null $message Message (default: the config message).
			 */
			private static function block( array $config, array $held, $message = null ) {
				$names = array();
				foreach ( $held as $entry ) {
					$names[] = $entry['line']['name'];
				}
				$message = null === $message ? $config['message'] : (string) $message;
				$accept  = strtolower( self::server( 'HTTP_ACCEPT', 1000 ) );
				$xhr     = 'xmlhttprequest' === strtolower( self::server( 'HTTP_X_REQUESTED_WITH', 32 ) );
				$json    = $xhr || false !== strpos( $accept, 'application/json' );

				while ( ob_get_level() > 0 && @ob_end_clean() ) {
					// Drop anything buffered so far.
					continue;
				}
				if ( ! headers_sent() ) {
					if ( function_exists( 'http_response_code' ) ) {
						http_response_code( 403 );
					} else {
						header( 'HTTP/1.1 403 Forbidden', true, 403 );
					}
					header( 'Content-Type: ' . ( $json ? 'application/json' : 'text/plain' ) . '; charset=utf-8' );
					header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
					header( 'X-Content-Type-Options: nosniff' );
					header( 'X-WPCyberSec-Guard: held' );
				}

				if ( $json ) {
					$body  = array(
						'success' => false,
						'code'    => 'wpcybersec_upload_held',
						'message' => $message,
						'files'   => $names,
						'data'    => array(
							'code'    => 'wpcybersec_upload_held',
							'message' => $message,
						),
					);
					// Escaped for any context: <, >, &, ' and " become \u00XX escapes.
					$flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
					echo json_encode( $body, $flags ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped, WordPress.WP.AlternativeFunctions.json_encode_json_encode -- JSON response sent before WordPress loads (wp_json_encode() does not exist yet); the JSON_HEX_* flags escape every HTML special character.
				} else {
					echo $message . ( $names ? "\n\n" . 'Held: ' . implode( ', ', $names ) : '' ) . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- text/plain response with nosniff; names went through file_name().
				}
				exit;
			}

			/**
			 * Safe original file name for the spool.
			 *
			 * @param string $name   Client file name.
			 * @param string $sha256 Hash for the fallback.
			 * @return string
			 */
			private static function file_name( $name, $sha256 ) {
				$name = str_replace( '\\', '/', (string) $name );
				$pos  = strrpos( $name, '/' );
				if ( false !== $pos ) {
					$name = substr( $name, $pos + 1 );
				}
				$name = self::clean( $name, 200 );
				$name = trim( str_replace( array( '<', '>', '"', "'", '`', '|', ':', '*', '?' ), '', $name ) );
				return '' !== $name ? $name : 'upload-' . substr( $sha256, 0, 8 );
			}

			/**
			 * Drops control characters, fixes invalid UTF-8 and limits the length.
			 *
			 * @param string $value Value.
			 * @param int    $max   Max bytes.
			 * @return string
			 */
			/**
			 * One request header or server value, sanitized: control characters
			 * removed, invalid UTF-8 replaced and cut to $max bytes. The guard runs
			 * before WordPress loads, so WordPress sanitizing functions do not exist yet.
			 *
			 * @param string $key Key in $_SERVER.
			 * @param int    $max Maximum length in bytes.
			 * @return string '' when missing or not a string.
			 */
			private static function server( $key, $max ) {
				if ( ! isset( $_SERVER[ $key ] ) || ! is_scalar( $_SERVER[ $key ] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- checked only, sanitized below.
					return '';
				}
				return self::clean( (string) $_SERVER[ $key ], (int) $max ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- sanitized by clean().
			}

			private static function clean( $value, $max ) {
				$value = (string) $value;
				if ( ! @preg_match( '//u', $value ) ) {
					$value = preg_replace( '/[^\x20-\x7E]/', '?', $value );
				}
				$value = preg_replace( '/[\x00-\x1F\x7F]/', '', (string) $value );
				if ( strlen( (string) $value ) > $max ) {
					$value = substr( (string) $value, 0, $max );
					// Drop a multibyte character cut in half at the end.
					$value = preg_replace( '/[\xC0-\xFF][\x80-\xBF]*$/', '', (string) $value );
				}
				if ( ! @preg_match( '//u', (string) $value ) ) {
					$value = preg_replace( '/[^\x20-\x7E]/', '?', (string) $value );
				}
				return (string) $value;
			}

			/**
			 * @return string 24 random hex characters.
			 */
			private static function random_name() {
				if ( function_exists( 'random_bytes' ) ) {
					try {
						return bin2hex( random_bytes( 12 ) );
					} catch ( Exception $e ) {
						unset( $e );
					}
				}
				if ( function_exists( 'openssl_random_pseudo_bytes' ) ) {
					$bytes = @openssl_random_pseudo_bytes( 12 );
					if ( is_string( $bytes ) && 12 === strlen( $bytes ) ) {
						return bin2hex( $bytes );
					}
				}
				return substr( md5( uniqid( '', true ) . microtime() . getmypid() ), 0, 24 );
			}
		}
	}

	try {
		WPCyberSec_Guard::run();
	} catch ( Exception $wpcybersec_guard_error ) {
		WPCyberSec_Guard::fail( $wpcybersec_guard_error );
	} catch ( Throwable $wpcybersec_guard_error ) {
		WPCyberSec_Guard::fail( $wpcybersec_guard_error );
	}
	unset( $wpcybersec_guard_error );
}
