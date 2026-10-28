<?php
/**
 * File scanner: malware signatures, official checksums and optional ClamAV.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Stateless per file, but keeps per-request caches so verify() stays cheap:
 * the core checksum map and each plugin checksum map are loaded once per
 * request (from transients, or from wordpress.org at most every 12 hours).
 */
class Scanner {

	/** Transient prefixes (the rest is an md5, well under the 172 char limit). */
	const CORE_TRANSIENT    = 'wpcybersec_core_sums_';
	const PLUGIN_TRANSIENT  = 'wpcybersec_plugin_sums_';
	const OFFLINE_TRANSIENT = 'wpcybersec_sums_offline';

	/** Key in the cached core checksum map that remembers the locale it was downloaded for (never a file path). */
	const LOCALE_KEY = '?locale';

	const CACHE_TTL      = 12 * HOUR_IN_SECONDS;
	const MISS_TTL       = 6 * HOUR_IN_SECONDS;
	const NETWORK_ERR_TTL = HOUR_IN_SECONDS;

	/** @var array|false|null path => md5, false when unavailable, null before loading. */
	private $core_map = null;

	/** @var array|null plugin folder => version. */
	private $plugin_versions = null;

	/** @var array plugin folder => display name (filled with $plugin_versions). */
	private $plugin_names = array();

	/** @var array slug@version => array|false */
	private $plugin_maps = array();

	/** @var int Network failures in this request (circuit breaker). */
	private $fetch_failures = 0;

	/** @var string[]|null Usable ClamAV binaries, daemon client first. */
	private $clamav_bins = null;

	/** Network option with the last ClamAV self-test (see clamav_selftest()). */
	const SELFTEST_OPTION = 'wpcybersec_clamav_selftest';

	/** A self-test older than this is run again in the background (scheduled scans, daily maintenance). */
	const SELFTEST_TTL = 6 * HOUR_IN_SECONDS;

	/** A plain clamscan slower than this (ms per file) is not used while someone waits for an upload. */
	const SLOW_MS = 3000;

	/** Network option: use a slow clamscan for uploads anyway (Settings > Advanced > Antivirus engines). */
	const FORCE_SLOW_OPTION = 'wpcybersec_clamav_slow_uploads';

	/** File in the plugin folder that lists the sha256 of every shipped file (bin/build-checksums.php). */
	const SELF_CHECKSUMS = 'checksums.json';

	/** @var array|false|null Own checksums: inner path => sha256, false when missing or unreadable. */
	private $self_map = null;

	/** @var string[]|null Plugin folder roots (as given and resolved), with trailing slash. */
	private $self_roots = null;

	/** @var string Locale of the loaded core checksum map ('' before loading). */
	private $core_locale = '';

	/** @var bool The last scan_file() read less than max_file_mb because memory was short. */
	private $memory_limited = false;

	/** Lowercase names in wp-admin/ and wp-includes/ that hosts and tools leave behind (never code). */
	const CORE_JUNK = array( 'error_log', 'php_errorlog', 'php_error.log', '.ds_store', 'thumbs.db', 'desktop.ini' );

	/**
	 * Hooks.
	 */
	public function register() {
		// After an update the installed versions change; drop per-request caches
		// before Install_Gate re-baselines the updated folders.
		add_action( 'upgrader_process_complete', array( $this, 'reset_caches' ), 1 );
		add_action( 'wpcybersec_settings_updated', array( $this, 'on_settings_updated' ), 10, 2 );
		// The ClamAV self-test is refreshed in the background, never while an upload waits.
		add_action( 'wpcybersec_scheduled_scan', array( $this, 'refresh_selftest_if_stale' ), 5 );
		add_action( 'wpcybersec_maintenance', array( $this, 'refresh_selftest_if_stale' ), 5 );
	}

	/**
	 * Drops per-request caches.
	 */
	public function reset_caches() {
		$this->core_map        = null;
		$this->core_locale     = '';
		$this->plugin_versions = null;
		$this->plugin_names    = array();
		$this->plugin_maps     = array();
		$this->self_map        = null; // An update of this plugin ships a new checksums.json.
		if ( function_exists( 'wp_clean_plugins_cache' ) ) {
			wp_clean_plugins_cache( false );
		}
	}

	/**
	 * Forgets the detected ClamAV binary (after settings change).
	 */
	public function reset_clamav() {
		$this->clamav_bins = null;
	}

	/* ------------------------------------------------------------------ */
	/* Malware scanning                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Malware hits for a file on disk.
	 *
	 * @param string $abs Absolute path.
	 * @param string $rel Relative path (computed when empty).
	 * @return array[] Hits { sig, title, severity, line, snippet }.
	 */
	public function scan_file( $abs, $rel = '' ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs || ! @is_file( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return array();
		}
		if ( '' === $rel ) {
			$rel = Paths::rel( $abs );
		}
		$min                  = $this->min_severity();
		$cap                  = $this->read_cap();
		$this->memory_limited = false;
		if ( $cap < $this->max_bytes() ) {
			$size                 = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$this->memory_limited = false !== $size && $size > $cap && $size <= $this->max_bytes() && Signatures::KIND_BINARY !== Signatures::kind_for( $abs ) && Signatures::KIND_IMAGE !== Signatures::kind_for( $abs );
		}
		// Path rules and skip_path are written for the usual layout
		// ("wp-content/uploads/..."): a file outside the scan root is matched by
		// its name relative to the WordPress folder (Bedrock's app/uploads).
		$rule_rel = $rel;
		if ( Paths::is_absolute( $rel ) ) {
			$alias    = Paths::alias( $abs );
			$rule_rel = '' !== $alias ? $alias : $rel;
		}
		$hits = Signatures::inspect_file( $abs, $rule_rel, $min, $cap );

		// Custom upload folders (UPLOADS constant) are not under wp-content/uploads.
		if ( $this->in_custom_uploads( $abs ) && $this->is_php_name( $abs ) && 1 >= $min && ! $this->has_sig( $hits, 'path_php_in_uploads' ) && ! $this->is_harmless_stub( $abs ) ) {
			$hits[] = array(
				'sig'      => 'path_php_in_uploads',
				'title'    => __( 'PHP file inside the uploads folder', 'qartvelo-guard' ),
				'severity' => Store::SEV_MEDIUM,
				'line'     => 0,
				'snippet'  => Signatures::clean_snippet( $rel ),
			);
		}

		// ClamAV per file only through the daemon client (clamscan reloads its
		// database for every file, far too slow for a site scan), and only for
		// files that can run code.
		if ( $this->settings()->get( 'clamav_enabled', false ) && $this->clamav_daemon_available() ) {
			$kind = Signatures::kind_for( $abs );
			if ( Paths::is_executable( $abs ) || in_array( $kind, array( Signatures::KIND_PHP, Signatures::KIND_JS, Signatures::KIND_HTML ), true ) ) {
				$clam = $this->clamav_scan( $abs, true );
				if ( is_array( $clam ) ) {
					$hits = array_merge( $hits, $clam );
				}
			}
		}

		return Signatures::unique( $hits );
	}

	/**
	 * Hits for an incoming upload. Severity >= 2 means "malicious".
	 *
	 * @param string $tmp_path      Temporary file.
	 * @param string $original_name Name the visitor sent.
	 * @return array[] Hits.
	 */
	public function scan_upload( $tmp_path, $original_name ) {
		$name = (string) $original_name;
		$hits = $this->name_hits( $name );

		$tmp_path = (string) $tmp_path;
		if ( '' === $tmp_path || ! @is_file( $tmp_path ) || ! @is_readable( $tmp_path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $hits;
		}

		$min   = $this->min_severity();
		$max   = $this->max_bytes();
		$size  = (int) @filesize( $tmp_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$kind  = Signatures::kind_for( $name );
		$clean = basename( str_replace( array( '\\', "\0" ), array( '/', '' ), $name ) );
		$hits  = array_merge( $hits, Signatures::inspect_file( $tmp_path, '', $min, $max, '' !== $clean ? $clean : 'upload.bin' ) );

		$head = $size > 0 ? (string) @file_get_contents( $tmp_path, false, null, 0, 4096 ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.

		// PHP disguised as something else (a ".pdf" or ".zip" that is really a script).
		if ( Signatures::KIND_PHP !== $kind && Signatures::looks_like_php( $head ) && ! $this->has_sig( $hits, 'image_php_code' ) ) {
			$hits[] = array(
				'sig'      => 'upload_php_disguised',
				'title'    => __( 'PHP script disguised as another file type', 'qartvelo-guard' ),
				'severity' => Store::SEV_HIGH,
				'line'     => 1,
				'snippet'  => Signatures::clean_snippet( substr( $head, 0, 120 ) ),
			);
			if ( $size <= $max ) {
				$hits = array_merge( $hits, Signatures::match( (string) @file_get_contents( $tmp_path, false, null, 0, $max ), Signatures::KIND_PHP, $min ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			}
		}

		// Images: look for PHP anywhere in the file, not only head and tail. The
		// short echo tag (for example "<?=" followed by `$_GET[0]`) runs code too; it
		// only counts when code follows it, because the three bytes "<?=" turn up
		// by chance in large images.
		if ( Signatures::KIND_IMAGE === $kind && ! $this->has_sig( $hits, 'image_php_code' ) && $size <= $max ) {
			$tag = '';
			if ( $this->file_contains( $tmp_path, '<?php' ) ) {
				$tag = '<?php';
			} elseif ( $this->file_matches( $tmp_path, '~<\?=\s{0,8}+(?:[`$@]|[a-z_][a-z0-9_]{0,40}+\s{0,8}+\()~i' ) ) {
				$tag = '<?=';
			}
			if ( '' !== $tag ) {
				$hits[] = array(
					'sig'      => 'image_php_code',
					'title'    => __( 'PHP code hidden in an image file', 'qartvelo-guard' ),
					'severity' => Store::SEV_CRITICAL,
					'line'     => 0,
					'snippet'  => $tag,
				);
			}
		}

		// SVG can carry scripts that run in the admin's browser.
		if ( 'svg' === Paths::ext( $clean ) && $size <= $max ) {
			$svg = (string) @file_get_contents( $tmp_path, false, null, 0, $max ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			if ( preg_match( '~<script\b|\bon[a-z]{3,20}\s*=|javascript\s*:|<foreignObject\b|<iframe\b|<embed\b~i', $svg, $m, PREG_OFFSET_CAPTURE ) ) {
				$hits[] = array(
					'sig'      => 'upload_svg_script',
					'title'    => __( 'SVG image contains scripts or event handlers', 'qartvelo-guard' ),
					'severity' => Store::SEV_HIGH,
					'line'     => Signatures::line_at( $svg, $m[0][1] ),
					'snippet'  => Signatures::snippet( $svg, $m[0][1], strlen( $m[0][0] ) ),
				);
			}
		}

		if ( $this->settings()->get( 'clamav_enabled', false ) ) {
			$clam = $this->clamav_scan( $tmp_path );
			if ( is_array( $clam ) ) {
				$hits = array_merge( $hits, $clam );
			}
		}

		$hits = Signatures::unique( $hits );
		return array_values(
			array_filter(
				$hits,
				static function ( $hit ) use ( $min ) {
					return (int) $hit['severity'] >= $min;
				}
			)
		);
	}

	/**
	 * Name based checks for uploads.
	 *
	 * @param string $name Original file name.
	 * @return array[] Hits.
	 */
	private function name_hits( $name ) {
		$hits    = array();
		$lower   = strtolower( $name );
		$base    = basename( str_replace( '\\', '/', $lower ) );
		$exec    = array_map( 'strtolower', (array) $this->settings()->get( 'exec_extensions', array() ) );
		$snippet = Signatures::clean_snippet( $name );

		if ( false !== strpos( $name, "\0" ) || false !== strpos( $lower, '%00' ) || false !== strpos( $lower, '::$data' ) || rtrim( $base, '. ' ) !== $base ) {
			$hits[] = array(
				'sig'      => 'upload_bad_name',
				'title'    => __( 'File name uses tricks to hide its real type', 'qartvelo-guard' ),
				'severity' => Store::SEV_HIGH,
				'line'     => 0,
				'snippet'  => $snippet,
			);
		}

		$parts = explode( '.', rtrim( $base, '. ' ) );
		array_shift( $parts );
		$last = $parts ? array_pop( $parts ) : '';
		foreach ( $parts as $part ) {
			if ( in_array( $part, $exec, true ) ) {
				$hits[] = array(
					'sig'      => 'upload_double_extension',
					'title'    => __( 'Double extension hides a script (for example shell.php.jpg)', 'qartvelo-guard' ),
					'severity' => Store::SEV_HIGH,
					'line'     => 0,
					'snippet'  => $snippet,
				);
				break;
			}
		}

		$exec_names = array_map( 'strtolower', (array) $this->settings()->get( 'exec_filenames', array() ) );
		if ( in_array( $last, $exec, true ) || in_array( $base, $exec_names, true ) ) {
			$hits[] = array(
				'sig'      => 'upload_executable',
				'title'    => __( 'Executable script or server configuration file', 'qartvelo-guard' ),
				'severity' => Store::SEV_HIGH,
				'line'     => 0,
				'snippet'  => $snippet,
			);
		}
		return $hits;
	}

	/**
	 * Highest severity among hits.
	 *
	 * @param array $hits Hits.
	 * @return int
	 */
	public function max_severity( array $hits ) {
		return Signatures::max_severity( $hits );
	}

	/* ------------------------------------------------------------------ */
	/* Checksums                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Verifies a file against official checksums.
	 *
	 * @param string $rel    Relative path.
	 * @param string $sha256 Known sha256 (computed when needed and empty).
	 * @param string $md5    Known md5 (computed when needed and empty).
	 * @return string match | mismatch | unknown
	 */
	public function verify( $rel, $sha256 = '', $md5 = '' ) {
		$result = $this->verify_details( $rel, $sha256, $md5 );
		return $result['verdict'];
	}

	/**
	 * Like verify() but also says which list was used and why.
	 *
	 * Files inside this plugin's own folder are checked against the
	 * checksums.json shipped with it (source "self"), whatever use_checksums
	 * says: the signature file holds the patterns as data and would otherwise
	 * flag itself. A file listed there that differs is a "mismatch" (tampered
	 * security plugin); a file not listed is "unknown_file" and is treated like
	 * any unknown file. Without checksums.json the verdict is unknown with
	 * source "self" and no reason.
	 *
	 * @param string $rel    Relative path.
	 * @param string $sha256 Known sha256.
	 * @param string $md5    Known md5.
	 * @return array { verdict: match|mismatch|unknown, source: self|core|plugin|'', reason: mismatch|unknown_file|'' }
	 */
	public function verify_details( $rel, $sha256 = '', $md5 = '' ) {
		$out = array(
			'verdict' => 'unknown',
			'source'  => '',
			'reason'  => '',
		);
		$rel = wp_normalize_path( (string) $rel );
		// Files outside the scan root are keyed by their absolute path (Paths::rel()):
		// keep it. Any other leading slash is dropped as before.
		if ( '/' === substr( $rel, 0, 1 ) && ! Paths::in_scope( $rel ) ) {
			$rel = ltrim( $rel, '/' );
		}
		$abs = Paths::abs( $rel );

		$self_rel = $this->self_relative( $abs );
		if ( '' !== $self_rel ) {
			return $this->verify_self( $self_rel, $abs, $sha256 );
		}

		if ( ! $this->settings()->get( 'use_checksums', true ) ) {
			return $out;
		}

		$core_rel = $this->core_relative( $abs );
		if ( '' !== $core_rel ) {
			$map = $this->core_map();
			if ( is_array( $map ) ) {
				if ( isset( $map[ $core_rel ] ) ) {
					if ( '' === $md5 ) {
						$md5 = (string) @md5_file( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
					}
					if ( '' !== $md5 && ( hash_equals( strtolower( (string) $map[ $core_rel ] ), strtolower( $md5 ) ) || in_array( strtolower( (string) $map[ $core_rel ] ), $this->line_ending_hashes( $abs, 'md5' ), true ) ) ) {
						return array(
							'verdict' => 'match',
							'source'  => 'core',
							'reason'  => '',
						);
					}
					if ( 'wp-includes/version.php' === $core_rel && $this->core_locale !== $this->package_locale() && $this->version_file_matches( $abs, (string) $map[ $core_rel ] ) ) {
						return array(
							'verdict' => 'match',
							'source'  => 'core',
							'reason'  => '',
						);
					}
					// Bundled themes and plugins in wp-content are updated on their own,
					// so a difference there is not a core mismatch.
					if ( 0 !== strpos( $core_rel, 'wp-content/' ) ) {
						return array(
							'verdict' => 'mismatch',
							'source'  => 'core',
							'reason'  => 'mismatch',
						);
					}
				} elseif ( preg_match( '~^wp-(?:admin|includes)/~', $core_rel ) ) {
					return array(
						'verdict' => 'unknown',
						'source'  => 'core',
						'reason'  => 'unknown_file',
					);
				}
			}
		}

		$slug = $this->plugin_slug_for( $rel );
		if ( '' !== $slug ) {
			$map = $this->plugin_map( $slug );
			if ( is_array( $map ) ) {
				$inner = $this->plugin_inner_path( $abs, $slug );
				if ( '' === $inner ) {
					return $out;
				}
				if ( ! isset( $map[ $inner ] ) ) {
					return array(
						'verdict' => 'unknown',
						'source'  => 'plugin',
						'reason'  => 'unknown_file',
					);
				}
				if ( '' === $sha256 ) {
					$sha256 = (string) @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				}
				$ok = '' !== $sha256 && in_array( strtolower( $sha256 ), (array) $map[ $inner ], true );
				if ( ! $ok && '' !== $sha256 ) {
					// Same file with other line endings (git autocrlf, FTP text mode) is the original.
					$ok = (bool) array_intersect( $this->line_ending_hashes( $abs, 'sha256' ), (array) $map[ $inner ] );
				}
				return array(
					'verdict' => $ok ? 'match' : 'mismatch',
					'source'  => 'plugin',
					'reason'  => $ok ? '' : 'mismatch',
				);
			}
		}
		return $out;
	}

	/**
	 * Whether a PHP file can run nothing: empty, or only an open tag plus
	 * comments and whitespace (placeholder index.php files).
	 *
	 * @param string $abs  File.
	 * @param int    $size Size in bytes.
	 * @return bool
	 */
	public function is_inert_php( $abs, $size ) {
		if ( ! in_array( Paths::ext( $abs ), Signatures::php_extensions(), true ) ) {
			return false;
		}
		if ( 0 === (int) $size ) {
			return true;
		}
		if ( (int) $size > 2048 || ! function_exists( 'token_get_all' ) ) {
			return false;
		}
		$code = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( '' === trim( $code ) ) {
			return true;
		}
		$inert = array( T_OPEN_TAG, T_CLOSE_TAG, T_COMMENT, T_DOC_COMMENT, T_WHITESPACE );
		foreach ( token_get_all( $code ) as $token ) {
			if ( ! is_array( $token ) || ! in_array( $token[0], $inert, true ) ) {
				return false; // Any statement, string, ; or inline HTML counts as content.
			}
		}
		return true;
	}

	/**
	 * Hashes of a text file with its line endings converted to LF and to CRLF.
	 * Only used after a checksum mismatch, so the normal path pays nothing.
	 * Deployments through git (autocrlf) or FTP in text mode change line
	 * endings without changing a single line of code.
	 *
	 * @param string $abs  File.
	 * @param string $algo md5 | sha256.
	 * @return string[]
	 */
	private function line_ending_hashes( $abs, $algo ) {
		$size = (int) @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $size <= 0 || $size > 4 * MB_IN_BYTES ) {
			return array();
		}
		$content = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( '' === $content || false !== strpos( substr( $content, 0, 8192 ), "\0" ) ) {
			return array(); // Binary: line endings do not apply.
		}
		$lf   = str_replace( "\r\n", "\n", $content );
		$crlf = str_replace( "\n", "\r\n", $lf );
		$out  = array();
		foreach ( array( $lf, $crlf ) as $variant ) {
			if ( $variant !== $content ) {
				$out[] = hash( $algo, $variant );
			}
		}
		return $out;
	}

	/**
	 * Verdict for a file inside this plugin's folder.
	 *
	 * @param string $self_rel Path inside the plugin folder.
	 * @param string $abs      Absolute path.
	 * @param string $sha256   Known sha256 (computed when empty).
	 * @return array Same shape as verify_details().
	 */
	private function verify_self( $self_rel, $abs, $sha256 ) {
		$map = $this->self_map();
		if ( ! is_array( $map ) ) {
			return array(
				'verdict' => 'unknown',
				'source'  => 'self',
				'reason'  => '',
			);
		}
		if ( ! isset( $map[ $self_rel ] ) ) {
			return array(
				'verdict' => 'unknown',
				'source'  => 'self',
				'reason'  => 'unknown_file',
			);
		}
		if ( '' === (string) $sha256 ) {
			$sha256 = (string) @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		$ok = '' !== $sha256 && hash_equals( $map[ $self_rel ], strtolower( (string) $sha256 ) );
		return array(
			'verdict' => $ok ? 'match' : 'mismatch',
			'source'  => 'self',
			'reason'  => $ok ? '' : 'mismatch',
		);
	}

	/**
	 * Own checksums from checksums.json, parsed once per request.
	 *
	 * @return array|false Inner path => lowercase sha256, false when unavailable.
	 */
	public function self_map() {
		if ( null !== $this->self_map ) {
			return $this->self_map;
		}
		$this->self_map = false;
		if ( ! defined( 'WPCYBERSEC_DIR' ) ) {
			return false;
		}
		$file = trailingslashit( wp_normalize_path( WPCYBERSEC_DIR ) ) . self::SELF_CHECKSUMS;
		$size = @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size < 2 || $size > 4 * MB_IN_BYTES ) {
			return false;
		}
		$data = json_decode( (string) @file_get_contents( $file ), true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return false;
		}
		$map = array();
		foreach ( $data['files'] as $path => $sha ) {
			if ( ! is_string( $sha ) || ! preg_match( '~^[a-f0-9]{64}$~i', $sha ) ) {
				continue;
			}
			$path = ltrim( wp_normalize_path( (string) $path ), '/' );
			if ( '' === $path || false !== strpos( $path, '../' ) ) {
				continue;
			}
			$map[ $path ] = strtolower( $sha );
		}
		if ( $map ) {
			$this->self_map = $map;
		}
		return $this->self_map;
	}

	/**
	 * Path inside this plugin's folder, '' when the file is elsewhere.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	private function self_relative( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		foreach ( $this->self_roots() as $root ) {
			if ( 0 === strpos( $abs, $root ) ) {
				return substr( $abs, strlen( $root ) );
			}
		}
		return '';
	}

	/**
	 * This plugin's folder as given, resolved, and as seen through the plugins
	 * folder (a symlinked install), with trailing slashes.
	 *
	 * @return string[]
	 */
	private function self_roots() {
		if ( null !== $this->self_roots ) {
			return $this->self_roots;
		}
		$roots = array();
		if ( defined( 'WPCYBERSEC_DIR' ) ) {
			$roots[] = trailingslashit( wp_normalize_path( WPCYBERSEC_DIR ) );
			$real    = realpath( WPCYBERSEC_DIR );
			if ( $real ) {
				$roots[] = trailingslashit( wp_normalize_path( $real ) );
			}
		}
		if ( defined( 'WP_PLUGIN_DIR' ) && defined( 'WPCYBERSEC_BASENAME' ) ) {
			$folder = dirname( (string) WPCYBERSEC_BASENAME );
			if ( '' !== $folder && '.' !== $folder ) {
				$roots[] = trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) ) . $folder . '/';
				$real    = realpath( WP_PLUGIN_DIR . '/' . $folder );
				if ( $real ) {
					$roots[] = trailingslashit( wp_normalize_path( $real ) );
				}
			}
		}
		$this->self_roots = array_values( array_unique( $roots ) );
		return $this->self_roots;
	}

	/**
	 * Whether a relative path is a WordPress core file (wp-admin, wp-includes
	 * or a root core file).
	 *
	 * @param string $rel Relative path.
	 * @return bool
	 */
	public function is_core_path( $rel ) {
		$core_rel = $this->core_relative( Paths::abs( $rel ) );
		if ( '' === $core_rel ) {
			return false;
		}
		if ( preg_match( '~^wp-(?:admin|includes)/~', $core_rel ) ) {
			return true;
		}
		if ( false === strpos( $core_rel, '/' ) ) {
			$map = $this->settings()->get( 'use_checksums', true ) ? $this->core_map() : false;
			if ( is_array( $map ) ) {
				return isset( $map[ $core_rel ] );
			}
			return 1 === preg_match( '~^(?:index\.php|xmlrpc\.php|license\.txt|readme\.html|wp-(?:activate|blog-header|comments-post|config-sample|cron|links-opml|load|login|mail|settings|signup|trackback)\.php)$~', $core_rel );
		}
		return false;
	}

	/**
	 * Structural problem of a path, judged from where the file is and the
	 * official core file list only (no content needed, so it is cheap enough to
	 * run for unchanged files too):
	 *
	 *   core_unknown_file    an executable file (or one whose content is PHP)
	 *                        inside wp-admin/ or wp-includes/ that is not part
	 *                        of the installed WordPress release (only when the
	 *                        core checksums could be loaded); other unknown
	 *                        files there (logs, images...) are not reported;
	 *   core_unknown_config  the same for .htaccess / .user.ini style files
	 *                        (often added on purpose to protect wp-admin);
	 *   root_php             a PHP file at the top of the WordPress folder that
	 *                        is not a core file, not wp-config.php, not this
	 *                        plugin's own guard bootstrap (exact content) and
	 *                        not a plain Wordfence firewall loader.
	 *
	 * Log and OS leftovers (error_log, *.log, .DS_Store...) are never reported.
	 *
	 * @param string $rel Relative path (scan root).
	 * @return string '' when nothing is wrong.
	 */
	public function integrity_issue( $rel ) {
		$abs      = Paths::abs( $rel );
		$core_rel = $this->core_relative( $abs );
		if ( '' === $core_rel ) {
			return '';
		}
		if ( 0 === strpos( $core_rel, 'wp-admin/' ) || 0 === strpos( $core_rel, 'wp-includes/' ) ) {
			if ( ! $this->settings()->get( 'use_checksums', true ) ) {
				return '';
			}
			$map = $this->core_map();
			if ( ! is_array( $map ) || isset( $map[ $core_rel ] ) ) {
				return ''; // Checksums unavailable (offline): nothing can be said.
			}
			$base = strtolower( basename( $core_rel ) );
			if ( in_array( $base, self::CORE_JUNK, true ) || 'log' === Paths::ext( $base ) ) {
				return '';
			}
			if ( in_array( $base, array( '.htaccess', '.htpasswd', '.user.ini', 'php.ini', 'web.config' ), true ) ) {
				return 'core_unknown_config';
			}
			if ( Paths::is_executable( $abs ) || $this->content_is_php( $abs ) ) {
				return 'core_unknown_file';
			}
			return '';
		}
		if ( false !== strpos( $core_rel, '/' ) ) {
			return '';
		}
		if ( ! in_array( Paths::ext( $core_rel ), Signatures::php_extensions(), true ) ) {
			return '';
		}
		if ( 'wp-config.php' === strtolower( $core_rel ) || $this->is_core_path( $rel ) || $this->is_own_bootstrap( $abs ) || $this->is_wordfence_loader( $abs ) ) {
			return '';
		}
		return 'root_php';
	}

	/**
	 * Whether a file with a name that does not run code holds PHP anyway
	 * (a loader hidden as .ico, .txt or without an extension).
	 *
	 * @param string $abs Path.
	 * @return bool
	 */
	private function content_is_php( $abs ) {
		$head = (string) @file_get_contents( $abs, false, null, 0, 8192 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		return '' !== $head && ( Signatures::looks_like_php( $head ) || false !== stripos( $head, '<?php' ) );
	}

	/**
	 * Whether ABSPATH/wordfence-waf.php is only Wordfence's firewall loader:
	 * comments, if / file_exists / defined / define and an include of
	 * wp-content/plugins/wordfence/waf/bootstrap.php, nothing else. Any other
	 * code (a variable, another function call, another include) and it is
	 * reported like any unknown root PHP file.
	 *
	 * @param string $abs Absolute path.
	 * @return bool
	 */
	public function is_wordfence_loader( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( 'wordfence-waf.php' !== $this->core_relative( $abs ) || ! function_exists( 'token_get_all' ) ) {
			return false;
		}
		$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 16384 ) {
			return false;
		}
		try {
			$tokens = @token_get_all( (string) @file_get_contents( $abs ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		} catch ( \Throwable $e ) {
			return false;
		}
		$allowed_tokens = array( T_OPEN_TAG, T_CLOSE_TAG, T_COMMENT, T_DOC_COMMENT, T_WHITESPACE, T_IF, T_STRING, T_CONSTANT_ENCAPSED_STRING, T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE, T_DIR, T_BOOLEAN_AND, T_ENDIF );
		$allowed_calls  = array( 'file_exists', 'is_file', 'is_readable', 'define', 'defined', 'true', 'false' );
		$allowed_chars  = array( '(', ')', '{', '}', ';', ',', '.', '!', ':' );
		$includes       = 0;
		$in_include     = false;
		$from_dir       = false;
		$target         = '';
		foreach ( $tokens as $token ) {
			if ( is_string( $token ) ) {
				if ( ! in_array( $token, $allowed_chars, true ) ) {
					return false;
				}
				if ( $in_include && ';' === $token ) {
					if ( ! $this->is_wordfence_bootstrap( $target, $from_dir, $abs ) ) {
						return false;
					}
					$in_include = false;
				}
				continue;
			}
			list( $id, $text ) = $token;
			if ( ! in_array( $id, $allowed_tokens, true ) ) {
				return false;
			}
			if ( T_STRING === $id && ! in_array( strtolower( $text ), $allowed_calls, true ) ) {
				return false;
			}
			if ( in_array( $id, array( T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE ), true ) ) {
				if ( $in_include ) {
					return false;
				}
				$in_include = true;
				$target     = '';
				$from_dir   = false;
				++$includes;
			} elseif ( $in_include && T_DIR === $id ) {
				$from_dir = true;
			} elseif ( $in_include && T_CONSTANT_ENCAPSED_STRING === $id ) {
				$target .= wp_normalize_path( substr( $text, 1, -1 ) );
			} elseif ( $in_include && T_STRING === $id ) {
				return false; // Only literal paths (and __DIR__) are included.
			}
		}
		return $includes > 0 && ! $in_include;
	}

	/**
	 * Whether a path included by wordfence-waf.php is Wordfence's firewall
	 * bootstrap: WP_PLUGIN_DIR/wordfence/waf/bootstrap.php (as configured or
	 * resolved, so Bedrock's web/app/plugins works), or the classic
	 * .../wp-content/plugins/wordfence/waf/bootstrap.php path the loader keeps
	 * after a site moved.
	 *
	 * @param string $target   Literal path parts of the include.
	 * @param bool   $from_dir The include starts with __DIR__.
	 * @param string $abs      Loader file.
	 * @return bool
	 */
	private function is_wordfence_bootstrap( $target, $from_dir, $abs ) {
		$target = wp_normalize_path( (string) $target );
		if ( '/wordfence/waf/bootstrap.php' !== substr( $target, -28 ) ) {
			return false;
		}
		if ( preg_match( '~/wp-content/plugins/wordfence/waf/bootstrap\.php$~', $target ) ) {
			return true;
		}
		$path = $from_dir ? wp_normalize_path( dirname( $abs ) ) . '/' . ltrim( $target, '/' ) : $target;
		// Resolve "." and ".." segments without touching the disk.
		$parts = array();
		foreach ( explode( '/', $path ) as $i => $part ) {
			if ( '..' === $part ) {
				array_pop( $parts );
			} elseif ( '.' !== $part && ( '' !== $part || 0 === $i ) ) {
				$parts[] = $part;
			}
		}
		$path       = implode( '/', $parts );
		$candidates = array();
		foreach ( $this->plugin_roots() as $root ) {
			$candidates[] = $root . 'wordfence/waf/bootstrap.php';
		}
		if ( in_array( $path, $candidates, true ) ) {
			return true;
		}
		$real = realpath( $path );
		return $real && in_array( wp_normalize_path( $real ), $candidates, true );
	}

	/**
	 * Whether a file is exactly the early guard bootstrap this plugin writes
	 * (ABSPATH/wpcybersec-guard.php), or one an earlier install wrote for
	 * another data folder (Guard_Manager::is_leftover_bootstrap(): the exact
	 * template with paths that cannot run other code). A file with that name
	 * but other content is not trusted.
	 *
	 * @param string $abs Absolute path.
	 * @return bool
	 */
	public function is_own_bootstrap( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( 'wpcybersec-guard.php' !== basename( $abs ) ) {
			return false;
		}
		$guard = function_exists( 'wpcybersec' ) && isset( wpcybersec()->guard_manager ) ? wpcybersec()->guard_manager : null;
		// Only the copy at the top of the WordPress folder is the bootstrap.
		if ( ! $guard || ! method_exists( $guard, 'bootstrap_code' ) || 'wpcybersec-guard.php' !== $this->core_relative( $abs ) ) {
			return false;
		}
		$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 65536 ) {
			return false;
		}
		try {
			$code = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			if ( $code === (string) $guard->bootstrap_code() ) {
				return true;
			}
			return method_exists( $guard, 'is_leftover_bootstrap' ) && $guard->is_leftover_bootstrap( $code );
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * Core files that are missing from the WordPress folder (listed in the
	 * official checksums but not on disk). Bundled themes and plugins
	 * (wp-content/) and the files hardening guides tell people to delete
	 * (readme.html, license.txt, wp-config-sample.php) are not counted.
	 *
	 * @return int Count, -1 when the core checksums are not available.
	 */
	public function missing_core_count() {
		if ( ! $this->settings()->get( 'use_checksums', true ) ) {
			return -1;
		}
		$map = $this->core_map();
		if ( ! is_array( $map ) ) {
			return -1;
		}
		$root    = trailingslashit( wp_normalize_path( ABSPATH ) );
		$skip    = array( 'readme.html', 'license.txt', 'wp-config-sample.php' );
		$missing = 0;
		foreach ( array_keys( $map ) as $core_rel ) {
			$core_rel = (string) $core_rel;
			if ( 0 === strpos( $core_rel, 'wp-content/' ) || in_array( $core_rel, $skip, true ) ) {
				continue;
			}
			if ( ! @file_exists( $root . $core_rel ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				++$missing;
			}
		}
		return $missing;
	}

	/**
	 * Plugin folder name for a relative path, '' when the file is not inside a
	 * plugin folder (single file plugins such as hello.php return '').
	 *
	 * @param string $rel Relative path.
	 * @return string
	 */
	public function plugin_slug_for( $rel ) {
		$abs = Paths::abs( $rel );
		foreach ( $this->plugin_roots() as $root ) {
			if ( 0 === strpos( $abs, $root ) ) {
				$sub = substr( $abs, strlen( $root ) );
				$pos = strpos( $sub, '/' );
				return false === $pos ? '' : substr( $sub, 0, $pos );
			}
		}
		return '';
	}

	/**
	 * Installed version of a plugin folder ('' when unknown).
	 *
	 * @param string $slug Folder.
	 * @return string
	 */
	public function plugin_version( $slug ) {
		if ( null === $this->plugin_versions ) {
			$this->plugin_versions = array();
			if ( ! function_exists( 'get_plugins' ) && is_readable( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			if ( function_exists( 'get_plugins' ) ) {
				foreach ( (array) get_plugins() as $file => $data ) {
					$folder = dirname( (string) $file );
					if ( '.' !== $folder && ! isset( $this->plugin_versions[ $folder ] ) && ! empty( $data['Version'] ) ) {
						$this->plugin_versions[ $folder ] = (string) $data['Version'];
						$this->plugin_names[ $folder ]    = ! empty( $data['Name'] ) ? (string) $data['Name'] : $folder;
					}
				}
			}
		}
		return isset( $this->plugin_versions[ $slug ] ) ? $this->plugin_versions[ $slug ] : '';
	}

	/**
	 * Display name of a plugin folder (the folder name when unknown).
	 *
	 * @param string $slug Folder.
	 * @return string
	 */
	public function plugin_name( $slug ) {
		$this->plugin_version( $slug ); // Loads the names too.
		return isset( $this->plugin_names[ $slug ] ) ? $this->plugin_names[ $slug ] : (string) $slug;
	}

	/**
	 * Path of a file relative to the WordPress folder ('' when outside it), the
	 * form core checksums and the core SVN tags use.
	 *
	 * @param string $rel Relative path (scan root).
	 * @return string
	 */
	public function core_path( $rel ) {
		return $this->core_relative( Paths::abs( $rel ) );
	}

	/**
	 * Path of a file inside its plugin folder ('' when it is not in $slug).
	 *
	 * @param string $rel  Relative path (scan root).
	 * @param string $slug Plugin folder.
	 * @return string
	 */
	public function plugin_path( $rel, $slug ) {
		return $this->plugin_inner_path( Paths::abs( $rel ), $slug );
	}

	/**
	 * Whether a file belongs to this plugin's own folder.
	 *
	 * @param string $rel Relative path (scan root).
	 * @return bool
	 */
	public function is_own_path( $rel ) {
		return '' !== $this->self_relative( Paths::abs( $rel ) );
	}

	/**
	 * Installed WordPress version (read from version.php).
	 *
	 * @return string
	 */
	public function installed_wp_version() {
		return $this->wp_version();
	}

	/**
	 * Core checksum map for the installed version (path => md5).
	 *
	 * @return array|false
	 */
	public function core_map() {
		if ( null !== $this->core_map ) {
			return $this->core_map;
		}
		$this->core_map = false;

		$version = $this->wp_version();
		$locale  = $this->package_locale();
		if ( '' === $version ) {
			return false;
		}
		$key    = self::CORE_TRANSIENT . md5( $version . '|' . $locale );
		$cached = get_site_transient( $key );
		if ( is_array( $cached ) && $cached ) {
			$this->core_map    = $cached;
			$this->core_locale = isset( $cached[ self::LOCALE_KEY ] ) ? (string) $cached[ self::LOCALE_KEY ] : $locale;
			unset( $this->core_map[ self::LOCALE_KEY ] );
			return $this->core_map;
		}
		if ( 'none' === $cached || $this->offline() ) {
			return false;
		}

		if ( ! function_exists( 'get_core_checksums' ) && is_readable( ABSPATH . 'wp-admin/includes/update.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( ! function_exists( 'get_core_checksums' ) ) {
			return false;
		}
		$used = $locale;
		$sums = get_core_checksums( $version, $locale );
		if ( ( ! is_array( $sums ) || ! $sums ) && 'en_US' !== $locale ) {
			$used = 'en_US';
			$sums = get_core_checksums( $version, 'en_US' );
		}
		if ( is_array( $sums ) && $sums ) {
			$clean = array();
			foreach ( $sums as $path => $md5 ) {
				if ( is_string( $md5 ) && preg_match( '~^[a-f0-9]{32}$~i', $md5 ) ) {
					$clean[ ltrim( wp_normalize_path( (string) $path ), '/' ) ] = strtolower( $md5 );
				}
			}
			if ( $clean ) {
				set_site_transient( $key, array_merge( $clean, array( self::LOCALE_KEY => $used ) ), self::CACHE_TTL );
				$this->core_map    = $clean;
				$this->core_locale = $used;
				return $clean;
			}
		}
		set_site_transient( $key, 'none', self::MISS_TTL );
		return false;
	}

	/**
	 * Checksum map of a wordpress.org plugin (inner path => list of sha256),
	 * false when the plugin is not on wordpress.org, the version is unknown,
	 * or the map does not fit the installed copy (a premium build that shares
	 * the folder name of a free plugin).
	 *
	 * @param string $slug Plugin folder.
	 * @return array|false
	 */
	public function plugin_map( $slug ) {
		$slug    = (string) $slug;
		$version = $this->plugin_version( $slug );
		$id      = $slug . '@' . $version;
		if ( array_key_exists( $id, $this->plugin_maps ) ) {
			return $this->plugin_maps[ $id ];
		}
		$this->plugin_maps[ $id ] = false;

		$map = $this->checksum_map( $slug, $version );
		if ( ! $map || ! $this->map_fits( $slug, $map ) ) {
			return false;
		}
		$this->plugin_maps[ $id ] = $map;
		return $map;
	}

	/**
	 * Official wordpress.org checksums of one plugin version (path inside
	 * the plugin folder => list of sha256), whatever is installed. The same
	 * list and cache plugin_map() uses; Install_Gate checks an unpacked
	 * package against it.
	 *
	 * @param string $slug    Plugin folder.
	 * @param string $version Version.
	 * @return array|false False when it is not a wordpress.org plugin version or cannot be fetched.
	 */
	public function checksum_map( $slug, $version ) {
		$slug    = (string) $slug;
		$version = (string) $version;
		if ( '' === $slug || '' === $version || ! preg_match( '~^[a-z0-9._-]{1,100}$~i', $slug ) || ! preg_match( '~^[a-z0-9._+-]{1,40}$~i', $version ) ) {
			return false;
		}
		$key    = self::PLUGIN_TRANSIENT . md5( $slug . '@' . $version );
		$cached = get_site_transient( $key );
		if ( is_string( $cached ) && 0 === strpos( $cached, "v1\n" ) ) {
			return $this->unpack_map( $cached );
		}
		if ( 'none' === $cached || $this->offline() || $this->fetch_failures >= 2 ) {
			return false;
		}
		return $this->fetch_plugin_map( $slug, $version, $key );
	}

	/**
	 * Whether a file has one of the sha256 sums a checksum map lists for it
	 * (other line endings count as the same file).
	 *
	 * @param array  $map   checksum_map() result.
	 * @param string $inner Path inside the plugin folder.
	 * @param string $abs   File to check.
	 * @return bool
	 */
	public function matches_map( array $map, $inner, $abs ) {
		$inner = ltrim( wp_normalize_path( (string) $inner ), '/' );
		if ( '' === $inner || ! isset( $map[ $inner ] ) ) {
			return false;
		}
		$sha = strtolower( (string) @hash_file( 'sha256', $abs ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( '' === $sha ) {
			return false;
		}
		return in_array( $sha, (array) $map[ $inner ], true ) || (bool) array_intersect( $this->line_ending_hashes( $abs, 'sha256' ), (array) $map[ $inner ] );
	}

	/**
	 * Downloads and caches a plugin checksum file.
	 *
	 * @param string $slug    Slug.
	 * @param string $version Version.
	 * @param string $key     Transient key.
	 * @return array|false
	 */
	private function fetch_plugin_map( $slug, $version, $key ) {
		$url      = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		// Never let one download outlast what is left of max_execution_time.
		$left    = Scan_Job::exec_seconds_left();
		$timeout = null === $left ? 10 : (int) max( 2, min( 10, floor( ( $left - 5 ) / 2 ) ) );
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => $timeout,
				'redirection' => 2,
			)
		);
		if ( is_wp_error( $response ) ) {
			++$this->fetch_failures;
			if ( $this->fetch_failures >= 2 ) {
				set_site_transient( self::OFFLINE_TRANSIENT, 1, self::NETWORK_ERR_TTL );
			}
			return false;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			// 404: not a wordpress.org plugin or unknown version. 5xx: try later.
			set_site_transient( $key, 'none', $code >= 500 ? self::NETWORK_ERR_TTL : self::MISS_TTL );
			return false;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			set_site_transient( $key, 'none', self::MISS_TTL );
			return false;
		}

		$map = array();
		foreach ( $data['files'] as $path => $sums ) {
			if ( ! is_array( $sums ) || ! isset( $sums['sha256'] ) ) {
				continue;
			}
			$list = array();
			foreach ( (array) $sums['sha256'] as $sha ) {
				if ( is_string( $sha ) && preg_match( '~^[a-f0-9]{64}$~i', $sha ) ) {
					$list[] = strtolower( $sha );
				}
			}
			$path = ltrim( wp_normalize_path( (string) $path ), '/' );
			if ( $list && '' !== $path && false === strpos( $path, "\t" ) && false === strpos( $path, "\n" ) ) {
				$map[ $path ] = $list;
			}
		}
		if ( ! $map ) {
			set_site_transient( $key, 'none', self::MISS_TTL );
			return false;
		}
		set_site_transient( $key, $this->pack_map( $map ), self::CACHE_TTL );
		return $map;
	}

	/**
	 * Compact text form: "v1\npath\tsha[,sha]\n..." (about half the size of a
	 * serialized array, which matters for plugins with thousands of files).
	 *
	 * @param array $map Map.
	 * @return string
	 */
	private function pack_map( array $map ) {
		$lines = array( 'v1' );
		foreach ( $map as $path => $list ) {
			$lines[] = $path . "\t" . implode( ',', $list );
		}
		return implode( "\n", $lines );
	}

	/**
	 * @param string $packed Packed map.
	 * @return array
	 */
	private function unpack_map( $packed ) {
		$map = array();
		foreach ( explode( "\n", $packed ) as $i => $line ) {
			if ( 0 === $i || '' === $line ) {
				continue;
			}
			$tab = strrpos( $line, "\t" );
			if ( false === $tab ) {
				continue;
			}
			$map[ substr( $line, 0, $tab ) ] = explode( ',', substr( $line, $tab + 1 ) );
		}
		return $map;
	}

	/**
	 * Sanity check: compares a few small files. When none of up to 8 sampled
	 * files match and at least 3 differ, the installed copy is not the
	 * wordpress.org build of that version and the map is ignored.
	 *
	 * @param string $slug Plugin folder.
	 * @param array  $map  Map.
	 * @return bool
	 */
	private function map_fits( $slug, array $map ) {
		$dir = $this->plugin_dir_for( $slug );
		if ( '' === $dir ) {
			return false;
		}
		$match    = 0;
		$mismatch = 0;
		$checked  = 0;
		foreach ( $map as $inner => $list ) {
			$file = $dir . $inner;
			$size = @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $size || $size > 262144 || ! @is_readable( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			$sha = (string) @hash_file( 'sha256', $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( in_array( $sha, (array) $list, true ) ) {
				++$match;
			} else {
				++$mismatch;
			}
			if ( ++$checked >= 8 || $match >= 2 ) {
				break;
			}
		}
		return ! ( 0 === $match && $mismatch >= 3 );
	}

	/**
	 * True while wordpress.org could not be reached recently.
	 *
	 * @return bool
	 */
	private function offline() {
		return (bool) get_site_transient( self::OFFLINE_TRANSIENT );
	}

	/**
	 * Installed WordPress version, read from version.php so it is right even
	 * in the request that just updated core.
	 *
	 * @return string
	 */
	private function wp_version() {
		$file = ABSPATH . ( defined( 'WPINC' ) ? WPINC : 'wp-includes' ) . '/version.php';
		$code = @file_get_contents( $file, false, null, 0, 4096 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( $code && preg_match( '~\$wp_version\s*=\s*[\x27"]([^\x27"]+)[\x27"]~', $code, $m ) ) {
			return $m[1];
		}
		return isset( $GLOBALS['wp_version'] ) ? (string) $GLOBALS['wp_version'] : '';
	}

	/**
	 * Locale of the installed WordPress package: $wp_local_package in
	 * version.php (written by localized downloads and updates), en_US when it
	 * is not set. This is what the core files were built for, unlike
	 * get_locale() (the site language, which can be switched without changing
	 * a single core file). WP-CLI's core verify-checksums does the same.
	 *
	 * @return string
	 */
	public function package_locale() {
		$file = ABSPATH . ( defined( 'WPINC' ) ? WPINC : 'wp-includes' ) . '/version.php';
		$code = @file_get_contents( $file, false, null, 0, 16384 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( $code && preg_match( '~^\s*\$wp_local_package\s*=\s*[\x27"]([A-Za-z]{2,3}(?:_[A-Za-z0-9]{2,8}){0,2})[\x27"]\s*;~m', $code, $m ) ) {
			return $m[1];
		}
		return 'en_US';
	}

	/**
	 * wp-includes/version.php of a localized package is the en_US file plus a
	 * "$wp_local_package = 'xx_XX';" line at the end. When the checksums of
	 * another locale had to be used (the localized list was not available),
	 * the file is compared without that line.
	 *
	 * @param string $abs      File.
	 * @param string $expected md5 from the checksum map.
	 * @return bool
	 */
	private function version_file_matches( $abs, $expected ) {
		$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 65536 ) {
			return false;
		}
		$code     = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$stripped = preg_replace( '~(?:\r?\n)*\$wp_local_package\s*=\s*[\x27"][A-Za-z0-9_@-]{2,20}[\x27"]\s*;[ \t]*(\r?\n)?$~', '$1', $code, 1, $count );
		if ( ! $count || ! is_string( $stripped ) ) {
			return false;
		}
		return hash_equals( strtolower( (string) $expected ), md5( $stripped ) );
	}

	/**
	 * Path relative to ABSPATH, '' when outside WordPress.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	private function core_relative( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		foreach ( $this->abspaths() as $root ) {
			if ( 0 === strpos( $abs, $root ) ) {
				return substr( $abs, strlen( $root ) );
			}
		}
		return '';
	}

	/**
	 * ABSPATH as given and resolved (symlinked installs), with trailing slash.
	 *
	 * @return string[]
	 */
	private function abspaths() {
		static $roots = null;
		if ( null === $roots ) {
			$roots = array( trailingslashit( wp_normalize_path( ABSPATH ) ) );
			$real  = realpath( ABSPATH );
			if ( $real ) {
				$roots[] = trailingslashit( wp_normalize_path( $real ) );
			}
			$roots = array_values( array_unique( $roots ) );
		}
		return $roots;
	}

	/**
	 * Plugin folder roots (as given and resolved), with trailing slash.
	 *
	 * @return string[]
	 */
	private function plugin_roots() {
		static $roots = null;
		if ( null === $roots ) {
			$roots = array();
			if ( defined( 'WP_PLUGIN_DIR' ) ) {
				$roots[] = trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) );
				$real    = realpath( WP_PLUGIN_DIR );
				if ( $real ) {
					$roots[] = trailingslashit( wp_normalize_path( $real ) );
				}
			}
			$roots = array_values( array_unique( $roots ) );
		}
		return $roots;
	}

	/**
	 * @param string $slug Folder.
	 * @return string Absolute folder with trailing slash, '' when missing.
	 */
	private function plugin_dir_for( $slug ) {
		foreach ( $this->plugin_roots() as $root ) {
			if ( @is_dir( $root . $slug ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return $root . $slug . '/';
			}
		}
		return '';
	}

	/**
	 * Path inside the plugin folder.
	 *
	 * @param string $abs  Absolute path.
	 * @param string $slug Folder.
	 * @return string
	 */
	private function plugin_inner_path( $abs, $slug ) {
		foreach ( $this->plugin_roots() as $root ) {
			$prefix = $root . $slug . '/';
			if ( 0 === strpos( $abs, $prefix ) ) {
				return substr( $abs, strlen( $prefix ) );
			}
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/* ClamAV                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Whether ClamAV can be used at all: a binary is installed, PHP may run it
	 * and it did not fail its self-test (binaries not tested yet count).
	 *
	 * @return bool
	 */
	public function clamav_available() {
		return (bool) $this->clamav_working();
	}

	/**
	 * Details for the settings and diagnostics screens.
	 *
	 * @return array {
	 *     available: bool, binary: string, daemon: bool (a clamdscan that works), can_exec: bool,
	 *     tested: bool, selftest: array|null, installed: string[] (every binary found),
	 *     daemon_ms: int|null, scan_ms: int|null (plain clamscan), slow_only: bool,
	 *     error: string (why nothing works, from the self-test), uploads: bool (uploads use it while they wait)
	 * }
	 */
	public function clamav_info() {
		$bins    = $this->clamav_binaries();
		$working = $this->clamav_working();
		$test    = $this->clamav_selftest_cached();
		$info    = array(
			'available' => (bool) $working,
			'binary'    => $working ? $working[0] : ( $bins ? $bins[0] : '' ),
			'daemon'    => $this->clamav_daemon_available(),
			'can_exec'  => $this->can_exec(),
			'tested'    => null !== $test,
			'selftest'  => $test,
			'installed' => $bins,
			'daemon_ms' => null,
			'scan_ms'   => null,
			'slow_only' => false,
			'error'     => '',
			'uploads'   => (bool) $this->clamav_plan( 'upload', true ),
		);
		if ( $test ) {
			foreach ( $test['bins'] as $bin => $row ) {
				if ( empty( $row['ok'] ) ) {
					if ( '' === $info['error'] ) {
						$info['error'] = (string) $row['error'];
					}
					continue;
				}
				$key = ! empty( $row['daemon'] ) ? 'daemon_ms' : 'scan_ms';
				if ( null === $info[ $key ] || (int) $row['ms'] < $info[ $key ] ) {
					$info[ $key ] = (int) $row['ms'];
				}
			}
			if ( '' === $info['error'] && ! empty( $test['error'] ) ) {
				$info['error'] = (string) $test['error'];
			}
			$info['slow_only'] = null === $info['daemon_ms'] && null !== $info['scan_ms'] && $info['scan_ms'] > self::SLOW_MS;
		}
		return $info;
	}

	/**
	 * Scans one file with ClamAV.
	 *
	 * @param string $path        File.
	 * @param bool   $daemon_only Only use clamdscan (whole-site scans).
	 * @return array[]|null Hits (empty when clean), null when ClamAV is unavailable or failed.
	 */
	public function clamav_scan( $path, $daemon_only = false ) {
		$path = (string) $path;
		if ( '' === $path || ! @is_file( $path ) || ! @is_readable( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return null;
		}
		foreach ( $this->clamav_plan( $daemon_only ? 'scan' : 'upload' ) as $run ) {
			$cmd    = escapeshellarg( $run['bin'] ) . ' ' . $run['flags'] . ' ' . escapeshellarg( $path ) . ' 2>&1';
			$result = $this->run_command( $cmd, $run['daemon'] ? 30 : 120 );
			if ( null === $result ) {
				continue;
			}
			list( $code, $output ) = $result;
			if ( 0 === $code ) {
				return array();
			}
			if ( 1 === $code ) {
				$hits = array();
				foreach ( preg_split( '~\r?\n~', (string) $output ) as $line ) {
					if ( preg_match( '~:\s*(\S[^:]*?)\s+FOUND\s*$~', $line, $m ) ) {
						$hits[] = array(
							'sig'      => 'clamav',
							/* translators: %s: ClamAV signature name */
							'title'    => sprintf( __( 'ClamAV: %s', 'qartvelo-guard' ), Signatures::clean_snippet( $m[1] ) ),
							'severity' => Store::SEV_CRITICAL,
							'line'     => 0,
							'snippet'  => Signatures::clean_snippet( $m[1] ),
						);
					}
				}
				if ( ! $hits ) {
					$hits[] = array(
						'sig'      => 'clamav',
						'title'    => __( 'ClamAV: infected file', 'qartvelo-guard' ),
						'severity' => Store::SEV_CRITICAL,
						'line'     => 0,
						'snippet'  => '',
					);
				}
				return $hits;
			}
			// Exit code 2 (daemon stopped since the self-test, database error): try the next binary.
		}
		return null;
	}

	/**
	 * Whether a working daemon client (clamdscan) is there.
	 *
	 * @return bool
	 */
	private function clamav_daemon_available() {
		foreach ( $this->clamav_working() as $bin ) {
			if ( self::is_daemon_bin( $bin ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $bin Binary path.
	 * @return bool Whether it is the daemon client (clamdscan).
	 */
	private static function is_daemon_bin( $bin ) {
		return false !== strpos( basename( (string) $bin ), 'clamdscan' );
	}

	/**
	 * Installed binaries that did not fail their last self-test.
	 *
	 * @return string[]
	 */
	private function clamav_working() {
		$test = $this->clamav_selftest_cached();
		$list = array();
		foreach ( $this->clamav_binaries() as $bin ) {
			if ( $test && isset( $test['bins'][ $bin ] ) && empty( $test['bins'][ $bin ]['ok'] ) ) {
				continue;
			}
			$list[] = $bin;
		}
		return $list;
	}

	/**
	 * Binaries to run for one file, in order, with the options their
	 * self-test worked with. A binary that failed its self-test is skipped (so
	 * a broken clamdscan never makes every upload wait for clamscan), whole-site
	 * scans use only the daemon client, and while someone waits for an upload a
	 * plain clamscan slower than SLOW_MS (or not timed yet) is left out unless
	 * the administrator forced it: it loads its whole database for every file.
	 * Cron and command line runs (held uploads the early guard imports, for
	 * example) still use it.
	 *
	 * @param string $context  upload | scan.
	 * @param bool   $waiting  Treat the call as an upload someone waits for.
	 * @return array[] { bin, daemon, flags }
	 */
	private function clamav_plan( $context, $waiting = null ) {
		$test    = $this->clamav_selftest_cached();
		$force   = (bool) Network::get_option( self::FORCE_SLOW_OPTION, false );
		$waiting = null === $waiting ? self::upload_waits() : (bool) $waiting;
		$plan    = array();
		foreach ( $this->clamav_binaries() as $bin ) {
			$daemon = self::is_daemon_bin( $bin );
			$row    = $test && isset( $test['bins'][ $bin ] ) ? $test['bins'][ $bin ] : null;
			if ( $row && empty( $row['ok'] ) ) {
				continue;
			}
			if ( ! $daemon && ( 'scan' === $context || ( $waiting && ! $force && ( ! $row || (int) $row['ms'] > self::SLOW_MS ) ) ) ) {
				continue;
			}
			$plan[] = array(
				'bin'    => $bin,
				'daemon' => $daemon,
				'flags'  => $row && ! empty( $row['flags'] ) ? (string) $row['flags'] : ( $daemon ? '--no-summary --fdpass' : '--no-summary --stdout' ),
			);
		}
		return $plan;
	}

	/**
	 * Whether a person waits for this request (a web request, not cron or the command line).
	 *
	 * @return bool
	 */
	private static function upload_waits() {
		return ! ( wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) || in_array( PHP_SAPI, array( 'cli', 'phpdbg' ), true ) );
	}

	/**
	 * The EICAR antivirus test string, put together at run time so that no
	 * file of the plugin contains it (antivirus software on the server would
	 * otherwise report the plugin itself).
	 *
	 * @return string
	 */
	private static function eicar() {
		$parts = array( 'X5O!P%@AP[4', '\\PZX54(P^)7CC)7}', '$EICAR-STAN', 'DARD-ANTIV', 'IRUS-TEST-', 'FILE!$H+H*' );
		return implode( '', $parts );
	}

	/**
	 * Last self-test result, also when it is older than SELFTEST_TTL (scans
	 * and uploads never wait for a new one). Null when there is none for the
	 * binaries installed now.
	 *
	 * @return array|null { at, key, error, bins: { path: { ok, error, kind, ms, daemon, flags } } }
	 */
	public function clamav_selftest_cached() {
		$saved = Network::get_option( self::SELFTEST_OPTION, array() );
		if ( ! is_array( $saved ) || empty( $saved['at'] ) || ! isset( $saved['bins'] ) || ! is_array( $saved['bins'] ) ) {
			return null;
		}
		if ( ! isset( $saved['key'] ) || $saved['key'] !== $this->selftest_key() ) {
			return null; // Other binaries now (setting changed, ClamAV installed or removed).
		}
		return $saved;
	}

	/**
	 * Runs (or returns the cached) ClamAV self-test: the EICAR test file is
	 * scanned with every installed binary, with a time limit, and the result,
	 * the first line of any error and the time taken are stored per binary.
	 *
	 * @param bool $fresh Run it now even when a recent result exists.
	 * @return array See clamav_selftest_cached().
	 */
	public function clamav_selftest( $fresh = false ) {
		$cached = $this->clamav_selftest_cached();
		if ( ! $fresh && $cached && (int) $cached['at'] > time() - self::SELFTEST_TTL ) {
			return $cached;
		}
		$result        = $this->run_selftest( $this->clamav_binaries() );
		$result['key'] = $this->selftest_key();
		Network::update_option( self::SELFTEST_OPTION, $result, false );
		return $result;
	}

	/**
	 * Background refresh (scheduled scans, daily maintenance): only when ClamAV
	 * is installed and turned on, and the last result is older than SELFTEST_TTL.
	 * Without "Also scan uploads with ClamAV" no program runs in the background.
	 */
	public function refresh_selftest_if_stale() {
		if ( ! $this->settings()->get( 'clamav_enabled', false ) || ! $this->clamav_binaries() ) {
			return;
		}
		$cached = $this->clamav_selftest_cached();
		$failed = false;
		foreach ( $cached && isset( $cached['bins'] ) ? (array) $cached['bins'] : array() as $row ) {
			$failed = $failed || empty( $row['ok'] );
		}
		// A failure is often temporary (clamd restarting, the server short of memory), so it is
		// tested again after 15 minutes instead of being kept for the whole SELFTEST_TTL.
		$ttl = $failed ? 15 * MINUTE_IN_SECONDS : self::SELFTEST_TTL;
		if ( ! $cached || (int) $cached['at'] <= time() - $ttl ) {
			$this->clamav_selftest( true );
		}
	}

	/**
	 * Settings changed: forget the detected binaries, and test again when a
	 * ClamAV setting changed (unless a test ran a moment ago, as the one-click
	 * "Turn on" does first).
	 *
	 * @param array $new New settings.
	 * @param array $old Old settings.
	 */
	public function on_settings_updated( $new = array(), $old = array() ) {
		$this->reset_clamav();
		$changed = false;
		foreach ( array( 'clamav_enabled', 'clamav_binary' ) as $key ) {
			$a = is_array( $new ) && isset( $new[ $key ] ) ? $new[ $key ] : null;
			$b = is_array( $old ) && isset( $old[ $key ] ) ? $old[ $key ] : null;
			if ( $a !== $b ) {
				$changed = true;
			}
		}
		if ( ! $changed || ! $this->clamav_binaries() ) {
			return;
		}
		$cached = $this->clamav_selftest_cached();
		if ( ! $cached || (int) $cached['at'] < time() - MINUTE_IN_SECONDS ) {
			$this->clamav_selftest( true );
		}
	}

	/**
	 * @return string Identifies the set of binaries a self-test belongs to.
	 */
	private function selftest_key() {
		return md5( implode( '|', $this->clamav_binaries() ) );
	}

	/**
	 * @param string[] $bins Binaries.
	 * @return array
	 */
	private function run_selftest( array $bins ) {
		$result = array(
			'at'    => time(),
			'error' => '',
			'bins'  => array(),
		);
		if ( ! $bins ) {
			$result['error'] = $this->can_exec()
				? __( 'ClamAV was not found.', 'qartvelo-guard' )
				: __( 'PHP may not run programs on this server (exec and proc_open are disabled).', 'qartvelo-guard' );
			return $result;
		}
		$file = function_exists( 'wp_tempnam' ) ? wp_tempnam( 'wpcs-clamav-test' ) : '';
		if ( '' === $file || ! Fs::direct()->put_contents( $file, self::eicar(), 0644 ) ) {
			if ( '' !== $file ) {
				Fs::delete( $file );
			}
			$result['error'] = __( 'The test file could not be written to the temporary folder, so ClamAV was not tested.', 'qartvelo-guard' );
			return $result;
		}
		try {
			foreach ( $bins as $bin ) {
				$result['bins'][ $bin ] = $this->test_binary( $bin, $file );
			}
		} finally {
			Fs::delete( $file );
		}
		return $result;
	}

	/**
	 * Scans the test file with one binary. The daemon client tries passing the
	 * open file to clamd first (--fdpass), then sending its content (--stream)
	 * when clamd cannot take a file descriptor (a TCP socket).
	 *
	 * @param string $bin  Binary.
	 * @param string $file Test file.
	 * @return array { ok, error, kind, ms, daemon, flags }
	 */
	private function test_binary( $bin, $file ) {
		$daemon  = self::is_daemon_bin( $bin );
		$timeout = $daemon ? 15 : 90;
		$row     = array();
		foreach ( $daemon ? array( '--no-summary --fdpass', '--no-summary --stream' ) : array( '--no-summary --stdout' ) as $flags ) {
			$start = microtime( true );
			$run   = $this->run_command( escapeshellarg( $bin ) . ' ' . $flags . ' ' . escapeshellarg( $file ) . ' 2>&1', $timeout );
			$row   = array(
				'ok'     => false,
				'error'  => '',
				'kind'   => '',
				'ms'     => (int) round( ( microtime( true ) - $start ) * 1000 ),
				'daemon' => $daemon,
				'flags'  => $flags,
			);
			if ( null === $run ) {
				$row['kind'] = 'timeout';
				/* translators: %d: seconds */
				$row['error'] = sprintf( __( 'It did not answer within %d seconds.', 'qartvelo-guard' ), $timeout );
				return $row;
			}
			list( $code, $output ) = $run;
			if ( 1 === $code && false !== strpos( (string) $output, 'FOUND' ) ) {
				$row['ok'] = true;
				return $row;
			}
			if ( 0 === $code ) {
				$row['kind']  = 'nodetect';
				$row['error'] = __( 'It did not recognise the EICAR test file, so its virus database is probably missing or empty (run freshclam).', 'qartvelo-guard' );
				return $row;
			}
			$line         = self::first_line( (string) $output );
			$row['kind']  = self::error_kind( $line );
			$row['error'] = '' !== $line
				? $line
				/* translators: %d: exit code */
				: sprintf( __( 'It stopped with exit code %d and no message.', 'qartvelo-guard' ), (int) $code );
			if ( 'socket' === $row['kind'] ) {
				$row['error'] = sprintf(
					/* translators: 1: user name, 2: error message */
					__( 'clamd runs, but PHP (user %1$s) may not use its socket: %2$s', 'qartvelo-guard' ),
					self::php_user(),
					$line
				);
			}
			if ( 'fdpass' !== $row['kind'] ) {
				return $row;
			}
		}
		return $row;
	}

	/**
	 * @param string $output Program output.
	 * @return string First non-empty line, cleaned and shortened.
	 */
	private static function first_line( $output ) {
		foreach ( preg_split( '~\r?\n~', $output ) as $line ) {
			$line = trim( wp_strip_all_tags( $line ) );
			if ( '' !== $line ) {
				return function_exists( 'mb_substr' ) ? mb_substr( $line, 0, 300 ) : substr( $line, 0, 300 );
			}
		}
		return '';
	}

	/**
	 * What kind of failure a ClamAV error line describes.
	 *
	 * @param string $line Error line.
	 * @return string socket | not_running | config | fdpass | nodb | other
	 */
	private static function error_kind( $line ) {
		$l = strtolower( $line );
		if ( false !== strpos( $l, 'fdpass' ) || false !== strpos( $l, 'file descriptor' ) ) {
			return 'fdpass';
		}
		if ( ( false !== strpos( $l, 'connect' ) || false !== strpos( $l, 'socket' ) ) && ( false !== strpos( $l, 'permission denied' ) || false !== strpos( $l, 'access denied' ) ) ) {
			return 'socket';
		}
		if ( false !== strpos( $l, 'connect' ) ) {
			return 'not_running';
		}
		if ( false !== strpos( $l, 'configuration' ) || false !== strpos( $l, 'clamd.conf' ) ) {
			return 'config';
		}
		if ( false !== strpos( $l, 'database' ) || false !== strpos( $l, 'cli_loaddb' ) ) {
			return 'nodb';
		}
		return 'other';
	}

	/**
	 * @return string Name of the user PHP runs as ('' when unknown).
	 */
	private static function php_user() {
		if ( function_exists( 'posix_geteuid' ) && function_exists( 'posix_getpwuid' ) ) {
			$info = @posix_getpwuid( posix_geteuid() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( is_array( $info ) && ! empty( $info['name'] ) ) {
				return (string) $info['name'];
			}
		}
		$user = function_exists( 'get_current_user' ) ? (string) get_current_user() : '';
		return '' !== $user ? $user : '?';
	}

	/**
	 * Where ClamAV is installed on common systems, the daemon client first.
	 * Distribution packages, /usr/local builds, cPanel's bundled ClamAV,
	 * Homebrew (local development) and the Windows installer.
	 *
	 * @return string[]
	 */
	public static function clamav_candidates() {
		$dirs = array( '/usr/bin/', '/usr/local/bin/', '/usr/sbin/', '/bin/', '/usr/local/cpanel/3rdparty/bin/', '/opt/homebrew/bin/' );
		$exe  = '';
		if ( '\\' === DIRECTORY_SEPARATOR ) {
			$dirs = array( 'C:/Program Files/ClamAV/', 'C:/Program Files (x86)/ClamAV/', 'C:/ClamAV/' );
			$exe  = '.exe';
		}
		$list = array();
		foreach ( array( 'clamdscan', 'clamscan' ) as $name ) {
			foreach ( $dirs as $dir ) {
				$list[] = $dir . $name . $exe;
			}
		}
		return $list;
	}

	/**
	 * Usable ClamAV binaries, the daemon client first.
	 *
	 * @return string[]
	 */
	private function clamav_binaries() {
		if ( null !== $this->clamav_bins ) {
			return $this->clamav_bins;
		}
		$this->clamav_bins = array();
		if ( ! $this->can_exec() ) {
			return array();
		}
		$candidates = array();
		$custom     = (string) $this->settings()->get( 'clamav_binary', '' );
		if ( '' !== $custom ) {
			$candidates[] = $custom;
		}
		$seen = array();
		foreach ( array_unique( array_merge( $candidates, self::clamav_candidates() ) ) as $bin ) {
			$base = basename( $bin );
			if ( 0 !== strpos( $base, 'clamdscan' ) && 0 !== strpos( $base, 'clamscan' ) ) {
				continue; // Only ever run ClamAV binaries, whatever the setting says.
			}
			if ( @is_file( $bin ) && @is_executable( $bin ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				// /bin is often a link to /usr/bin: one program is tested and run once.
				$real = @realpath( $bin ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$real = $real ? $real : $bin;
				if ( isset( $seen[ $real ] ) ) {
					continue;
				}
				$seen[ $real ]       = true;
				$this->clamav_bins[] = $bin;
			}
		}
		usort(
			$this->clamav_bins,
			static function ( $a, $b ) {
				return (int) ( false === strpos( basename( $a ), 'clamdscan' ) ) - (int) ( false === strpos( basename( $b ), 'clamdscan' ) );
			}
		);
		return $this->clamav_bins;
	}

	/**
	 * Whether proc_open or exec may be used.
	 *
	 * @return bool
	 */
	private function can_exec() {
		return $this->function_enabled( 'proc_open' ) || $this->function_enabled( 'exec' );
	}

	/**
	 * @param string $name Function.
	 * @return bool
	 */
	private function function_enabled( $name ) {
		if ( ! function_exists( $name ) ) {
			return false;
		}
		$disabled = array_map( 'trim', explode( ',', strtolower( (string) ini_get( 'disable_functions' ) ) ) );
		return ! in_array( strtolower( $name ), $disabled, true );
	}

	/**
	 * Runs a command with a timeout.
	 *
	 * @param string $cmd     Shell command (arguments already escaped).
	 * @param int    $timeout Seconds.
	 * @return array|null [ exit code, output ] or null on failure / timeout.
	 */
	private function run_command( $cmd, $timeout ) {
		if ( $this->function_enabled( 'proc_open' ) ) {
			$pipes = array();
			$proc  = @proc_open( $cmd, array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes ); // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found, WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open, WordPress.PHP.NoSilencedErrors.Discouraged -- the server's clamscan/clamdscan with escapeshellarg() arguments: the EICAR self-test when an admin opens the antivirus status, and file scans once the admin turned ClamAV on.
			if ( ! is_resource( $proc ) ) {
				return null;
			}
			stream_set_blocking( $pipes[1], false );
			stream_set_blocking( $pipes[2], false );
			$output = '';
			$code   = null;
			$end    = microtime( true ) + $timeout;
			while ( microtime( true ) < $end ) {
				$output .= (string) stream_get_contents( $pipes[1] ) . (string) stream_get_contents( $pipes[2] );
				$status  = proc_get_status( $proc );
				if ( ! $status['running'] ) {
					$code = (int) $status['exitcode'];
					break;
				}
				usleep( 50000 );
			}
			$output .= (string) stream_get_contents( $pipes[1] ) . (string) stream_get_contents( $pipes[2] );
			// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- proc_open() pipes, not files.
			fclose( $pipes[1] );
			fclose( $pipes[2] );
			// phpcs:enable WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			if ( null === $code ) {
				@proc_terminate( $proc ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				@proc_close( $proc ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return null;
			}
			@proc_close( $proc ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return array( $code, substr( $output, 0, 65536 ) );
		}
		if ( $this->function_enabled( 'exec' ) ) {
			$lines = array();
			$code  = 0;
			// exec() cannot be interrupted from PHP: the coreutils timeout
			// program bounds it instead (exit code 124 when the time is up).
			$bin = self::timeout_binary();
			$run = '' !== $bin ? escapeshellarg( $bin ) . ' ' . max( 1, (int) ceil( (float) $timeout ) ) . ' ' . $cmd : $cmd;
			@exec( $run, $lines, $code ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec, WordPress.PHP.NoSilencedErrors.Discouraged -- the server's clamscan/clamdscan with escapeshellarg() arguments: the EICAR self-test when an admin opens the antivirus status, and file scans once the admin turned ClamAV on.
			if ( '' !== $bin && 124 === (int) $code ) {
				return null;
			}
			return array( (int) $code, implode( "\n", array_slice( $lines, 0, 500 ) ) );
		}
		return null;
	}

	/**
	 * The coreutils "timeout" program, '' when the server has none.
	 *
	 * @return string
	 */
	private static function timeout_binary() {
		static $bin = null;
		if ( null === $bin ) {
			$bin = '';
			foreach ( array( '/usr/bin/timeout', '/bin/timeout', '/usr/local/bin/timeout' ) as $candidate ) {
				if ( @is_executable( $candidate ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$bin = $candidate;
					break;
				}
			}
		}
		return $bin;
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * @return Settings
	 */
	private function settings() {
		return wpcybersec()->settings;
	}

	/**
	 * @return int 1..3
	 */
	private function min_severity() {
		return max( 1, min( 3, (int) $this->settings()->get( 'min_severity', 1 ) ) );
	}

	/**
	 * @return int Bytes.
	 */
	public function max_bytes() {
		return max( 1, (int) $this->settings()->get( 'max_file_mb', 10 ) ) * 1048576;
	}

	/**
	 * How much of a file scan_file() may read now: max_file_mb, lowered when
	 * the memory left under memory_limit could not hold it. A file is held
	 * about four times while it is matched (the content, a lowercase copy and
	 * the match buffers), and some room is kept for WordPress itself. When the
	 * room is short the limit is raised first (wp_raise_memory_limit(), only
	 * where the host allows ini_set).
	 *
	 * @return int Bytes (at least 64 KB).
	 */
	public function read_cap() {
		$max  = $this->max_bytes();
		$room = self::memory_room();
		if ( null === $room ) {
			return $max;
		}
		if ( $room < 4 * $max + 8 * MB_IN_BYTES && function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'admin' );
			$room = self::memory_room();
			if ( null === $room ) {
				return $max;
			}
		}
		$cap = (int) floor( ( $room - 8 * MB_IN_BYTES ) / 4 );
		return max( 65536, min( $max, $cap ) );
	}

	/**
	 * Bytes left under memory_limit, null when there is no limit.
	 *
	 * @return int|null
	 */
	public static function memory_room() {
		$limit = (string) ini_get( 'memory_limit' );
		$bytes = function_exists( 'wp_convert_hr_to_bytes' ) ? (int) wp_convert_hr_to_bytes( $limit ) : (int) $limit;
		if ( $bytes <= 0 ) {
			return null;
		}
		return $bytes - memory_get_usage();
	}

	/**
	 * Whether the last scan_file() skipped the content of a file that
	 * max_file_mb allows, because the memory left was too small.
	 *
	 * @return bool
	 */
	public function memory_limited() {
		return $this->memory_limited;
	}

	/**
	 * @param array[] $hits Hits.
	 * @param string  $sig  Signature id.
	 * @return bool
	 */
	private function has_sig( array $hits, $sig ) {
		foreach ( $hits as $hit ) {
			if ( isset( $hit['sig'] ) && $sig === $hit['sig'] ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $abs Path.
	 * @return bool
	 */
	private function is_php_name( $abs ) {
		return in_array( Paths::ext( $abs ), Signatures::php_extensions(), true );
	}

	/**
	 * True for files under a custom uploads folder that the path rule
	 * (wp-content/uploads) does not cover.
	 *
	 * @param string $abs Path.
	 * @return bool
	 */
	private function in_custom_uploads( $abs ) {
		static $base = null;
		if ( null === $base ) {
			$base = '';
			if ( function_exists( 'wp_upload_dir' ) ) {
				$dirs = wp_upload_dir( null, false );
				if ( ! empty( $dirs['basedir'] ) ) {
					$base = trailingslashit( wp_normalize_path( $dirs['basedir'] ) );
				}
			}
			// The scan lists files by their real path (uploads -> ../files on
			// Pantheon, shared/uploads on Capistrano deployments).
			$real = '' !== $base ? realpath( $base ) : false;
			$real = $real ? trailingslashit( wp_normalize_path( $real ) ) : $base;
			if ( false !== strpos( $base, '/wp-content/uploads/' ) && false !== strpos( $real, '/wp-content/uploads/' ) ) {
				$base = ''; // Covered by the path rule.
			} else {
				$base = $real;
			}
		}
		return '' !== $base && 0 === strpos( $abs, $base );
	}

	/**
	 * "Silence is golden" style index files.
	 *
	 * @param string $abs Path.
	 * @return bool
	 */
	private function is_harmless_stub( $abs ) {
		$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 400 ) {
			return false;
		}
		$tiny = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		return false === strpos( $tiny, '<?' ) || (bool) preg_match( '~^\s*<\?php\s*(?://[^\n]*\n?|#[^\n]*\n?|/\*.*?\*/|\s+)*(?:\?>\s*)?$~s', $tiny );
	}

	/**
	 * Regex search of a file in 1 MB chunks (with a small overlap so a match
	 * across a chunk border is still found).
	 *
	 * @param string $path    File.
	 * @param string $pattern PCRE (must only match short strings, under 128 bytes).
	 * @return bool
	 */
	private function file_matches( $path, $pattern ) {
		$handle = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( ! $handle ) {
			return false;
		}
		$carry = '';
		$found = false;
		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, 1048576 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			$data = $carry . $chunk;
			if ( 0 !== @preg_match( $pattern, $data ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$found = true; // A match, or a PCRE error (fail closed).
				break;
			}
			$carry = substr( $data, -128 );
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		return $found;
	}

	/**
	 * Case-insensitive search of a file in 1 MB chunks.
	 *
	 * @param string $path   File.
	 * @param string $needle Needle (ASCII).
	 * @return bool
	 */
	private function file_contains( $path, $needle ) {
		$handle = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		if ( ! $handle ) {
			return false;
		}
		$needle = strtolower( $needle );
		$carry  = '';
		$found  = false;
		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, 1048576 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			if ( false !== strpos( strtolower( $carry . $chunk ), $needle ) ) {
				$found = true;
				break;
			}
			$carry = substr( $chunk, - ( strlen( $needle ) - 1 ) );
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		return $found;
	}
}
