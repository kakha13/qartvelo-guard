<?php
/**
 * Stored copies of file versions, used to show what changed in a file.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Content-addressed, gzip compressed copies of the versions of PHP and
 * configuration files the plugin trusted or reported, so the Reports page can
 * show exactly what changed (a git diff like view) instead of only "the file
 * was modified".
 *
 * Layout: <data_dir>/snapshots/<k[0:2]>/<k[2:4]>/<k>.gz (mode 0600), where
 * k = HMAC-SHA256( sha256 of the content, random key ). The key means
 * a leaked fingerprint (the reports, alert emails and webhooks show SHA-256
 * values) can never be turned into a download address on a server that ignores
 * the .htaccess deny rules (nginx). A multisite network has one store, one key
 * and one manifest for all its sites (Network).
 *
 * Files that hold secrets are never copied as they are: wp-config.php, .env,
 * .ini and similar names (is_secret_name()), and any other file in which
 * Diff::redact() finds a password, key or token, are stored already redacted
 * (REDACTED_MAGIC, a JSON header with the real sha256, the fingerprints of the
 * hidden values and the sha256 of the redacted text, then the redacted text),
 * so even someone who has the database and can download the folder never
 * reads a password from a copy. The changes view only ever shows redacted
 * text, so nothing is lost.
 *
 * What is copied: executable names (Paths::is_executable: PHP, .htaccess,
 * .user.ini, ...), configuration files and .js/.html/.svg files, at most
 * snapshot_max_kb, never binary content (a NUL byte in the first 8 KB). Files
 * that match an official WordPress.org checksum are skipped by store_trusted():
 * their original can be downloaded and verified again (Originals).
 *
 * Every read checks the SHA-256 of the decompressed content (of the redacted
 * text for a redacted copy).
 *
 * Limits: at most snapshot_max_files copies and snapshot_max_mb on disk
 * (shared hosts count inodes). The running totals live in USAGE_OPTION; a
 * new copy is refused while the store is full, and enforce_cap() (after
 * every scan and from prune()) deletes the least recently used copies until
 * the store is back under 90 % of both limits. usage() reports the numbers,
 * refused copies and write failures for the dashboard.
 */
class Snapshots {

	/** Folder inside the data folder. */
	const DIR = 'snapshots';

	/** Random HMAC key for file names (not autoloaded). */
	const KEY_OPTION = 'wpcybersec_snapshot_key';

	/**
	 * "done:<generation>" once a whole-site scan copied the files trusted
	 * before copies existed, "pending:<generation>" while that is still to do.
	 * Every reset raises the generation, so a scan that was running during a
	 * reset does not mark the new backfill done.
	 */
	const BACKFILL_OPTION = 'wpcybersec_snapshot_backfill';

	/** Last top-level folder prune() finished, so a large store is pruned over several days. */
	const CURSOR_OPTION = 'wpcybersec_snapshot_prune_cursor';

	/** Cached stats(). */
	const STATS_TRANSIENT = 'wpcybersec_snapshot_stats';

	/** Running totals: { files, bytes, at (last exact count), failures, refused, last_failure }. */
	const USAGE_OPTION = 'wpcybersec_snapshot_usage';

	/** enforce_cap() deletes down to this share of the limits. */
	const CAP_TARGET = 0.9;

	/** Hard cap for one copy (also for downloaded originals). */
	const HARD_MAX = 4194304;

	/** Name based extras besides executable names. */
	const CONFIG_NAMES    = array( '.htaccess', '.user.ini', 'php.ini', 'web.config', 'wp-config.php' );
	const TEXT_EXTENSIONS = array( 'js', 'mjs', 'html', 'htm', 'svg' );

	/** Unreferenced copies younger than this are kept (a running scan may not have saved its rows yet). */
	const GRACE = DAY_IN_SECONDS;

	/** First line of a copy stored redacted. */
	const REDACTED_MAGIC = "WPCS-REDACTED/1\n";

	/**
	 * Content that may hold a password, key or token, so it is run through
	 * Diff::redact() before it is stored (a cheap test; redact() decides).
	 */
	const SECRET_HINT = '/define\s*+\(\s*+[\'"][A-Za-z0-9_]*(?:PASSWORD|PASS|SECRET|TOKEN|_KEY|_SALT|AUTH)|(?:pass(?:word|wd)?|pwd|secret|api_?key|token|credential)[\'"]?\s*+(?:=>|\.?=|:)\s*+[\'"][^\'"\s]{3}|^[ \t]*+(?:export[ \t]++)?[A-Za-z0-9_]*(?:PASSWORD|PASS|SECRET|TOKEN|KEY)[ \t]*+=[ \t]*+\S|SetEnv\s++\S*+|PRIVATE KEY-----|\b(?:AKIA|ASIA)[0-9A-Z]{16}|\b(?:sk|rk)_live_|\bxox[abposr]-|\bSG\.[\w\-]{16}|\bgh[pousr]_[A-Za-z0-9]{30}|\bAIza[\w\-]{35}|:\/\/[^\s:\/@"\']++:[^\s\/@"\']++@|new\s++\\\\?(?:wpdb|mysqli|PDO)\s*+\(|mysqli?_(?:real_)?connect\s*+\(|putenv\s*+\(|Bearer\s/im';

	/** Legacy copies of secret files re-stored redacted per prune() run. */
	const HARDEN_PER_RUN = 200;

	/** Work limits for one prune() run. */
	const PRUNE_SECONDS = 8.0;
	const PRUNE_FILES   = 20000;

	/** @var string|null HMAC key for this request. */
	private $key = null;

	/** @var bool Whether the folder was created and protected in this request. */
	private $ready = false;

	/** @var array|null USAGE_OPTION loaded for this request. */
	private $usage = null;

	/** @var int Changes to $usage not saved yet. */
	private $usage_dirty = 0;

	/** @var bool A shutdown save of $usage is registered. */
	private $usage_hooked = false;

	/**
	 * Hooks: re-copy trusted files when copies are switched on or allowed to be larger.
	 */
	public function register() {
		add_action( 'wpcybersec_settings_updated', array( $this, 'on_settings_updated' ), 10, 2 );
	}

	/**
	 * @param array $new New settings.
	 * @param array $old Previous settings.
	 */
	public function on_settings_updated( $new, $old ) {
		$new_on  = ! empty( $new['snapshots'] );
		$old_on  = ! empty( $old['snapshots'] );
		$new_max = isset( $new['snapshot_max_kb'] ) ? (int) $new['snapshot_max_kb'] : 0;
		$old_max = isset( $old['snapshot_max_kb'] ) ? (int) $old['snapshot_max_kb'] : 0;
		// Copies refused while the store was full can be taken once a limit is raised.
		$raised = false;
		foreach ( array( 'snapshot_max_files', 'snapshot_max_mb' ) as $key ) {
			if ( isset( $new[ $key ], $old[ $key ] ) && (int) $new[ $key ] > (int) $old[ $key ] ) {
				$raised = true;
			}
		}
		if ( ( $new_on && ! $old_on ) || ( $new_on && $new_max > $old_max ) || ( $new_on && $raised ) ) {
			$this->reset_backfill();
		}
	}

	/* ------------------------------------------------------------------ */
	/* Policy                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * @return bool Whether copies are taken (setting on and zlib available).
	 */
	public function enabled() {
		return function_exists( 'gzencode' ) && (bool) wpcybersec()->settings->get( 'snapshots', true );
	}

	/**
	 * @return int Largest file copied, in bytes.
	 */
	public function max_bytes() {
		$kb = (int) wpcybersec()->settings->get( 'snapshot_max_kb', 256 );
		return min( self::HARD_MAX, max( 16, $kb ) * 1024 );
	}

	/**
	 * Whether the kind of file is copied (by name only, no disk access).
	 *
	 * @param string $name File name or path.
	 * @return bool
	 */
	public static function is_diffable_name( $name ) {
		$name = (string) $name;
		if ( '' === $name ) {
			return false;
		}
		$base = strtolower( basename( wp_normalize_path( $name ) ) );
		if ( in_array( $base, self::CONFIG_NAMES, true ) || in_array( Paths::ext( $base ), self::TEXT_EXTENSIONS, true ) ) {
			return true;
		}
		return Paths::is_executable( $base );
	}

	/**
	 * Cheap check before reading a file: copies on, copyable name, small enough.
	 *
	 * @param string $abs  Path.
	 * @param int    $size Size in bytes (-1 to read it).
	 * @return bool
	 */
	public function wants( $abs, $size = -1 ) {
		if ( ! $this->enabled() || ! self::is_diffable_name( $abs ) ) {
			return false;
		}
		$size = (int) $size;
		if ( $size < 0 ) {
			$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $size ) {
				return false;
			}
		}
		return (int) $size <= $this->max_bytes();
	}

	/**
	 * Binary content: a NUL byte in the first 8 KB.
	 *
	 * @param string $content Content.
	 * @return bool
	 */
	public static function is_binary( $content ) {
		return false !== strpos( substr( (string) $content, 0, 8192 ), "\0" );
	}

	/**
	 * @param string $sha Value.
	 * @return bool Whether it is a lowercase or uppercase sha256 hex string.
	 */
	public static function is_sha( $sha ) {
		return is_string( $sha ) && 1 === preg_match( '/^[a-f0-9]{64}$/i', $sha );
	}

	/**
	 * Names of files that hold secrets: wp-config.php (and copies such as
	 * wp-config.php.bak), .env files, .ini and similar configuration. Their
	 * copies are always stored redacted, and excerpts of them are redacted
	 * more strictly.
	 *
	 * @param string $name File name or path.
	 * @return bool
	 */
	public static function is_secret_name( $name ) {
		$base = strtolower( basename( wp_normalize_path( (string) $name ) ) );
		if ( '' === $base ) {
			return false;
		}
		if ( 0 === strpos( $base, 'wp-config' ) || 0 === strpos( $base, '.env' ) || '.env' === substr( $base, -4 ) ) {
			return true;
		}
		if ( in_array( $base, array( '.user.ini', 'php.ini', 'web.config', '.htpasswd', '.my.cnf', 'auth.json' ), true ) ) {
			return true;
		}
		return in_array( Paths::ext( $base ), array( 'ini', 'env', 'cnf', 'conf', 'pem', 'key' ), true );
	}

	/* ------------------------------------------------------------------ */
	/* Store and read                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Copies a file when it qualifies (copies on, copyable name, at most
	 * snapshot_max_kb, not binary). Files that hold secrets are stored
	 * redacted (see the class comment). When the copy exists nothing is read;
	 * its time is refreshed so prune() keeps it for another GRACE period.
	 *
	 * @param string $abs Absolute path.
	 * @param string $sha Known sha256 of the content ('' to compute it).
	 * @return bool True when a copy of $sha (or of the current content when $sha is empty) exists afterwards.
	 */
	public function store( $abs, $sha = '' ) {
		$abs = (string) $abs;
		$sha = strtolower( (string) $sha );
		if ( ! $this->enabled() || ! self::is_diffable_name( $abs ) ) {
			return false;
		}
		if ( self::is_sha( $sha ) && $this->has( $sha ) ) {
			$this->refresh( $sha, $abs );
			if ( $this->has( $sha ) ) {
				return true;
			}
		}
		if ( ! @is_file( $abs ) || ! @is_readable( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$max  = $this->max_bytes();
		$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > $max ) {
			return false;
		}
		$content = @file_get_contents( $abs, false, null, 0, $max + 1 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		if ( ! is_string( $content ) || strlen( $content ) > $max || self::is_binary( $content ) ) {
			return false;
		}
		$real = hash( 'sha256', $content );
		if ( $this->has( $real ) ) {
			$this->refresh( $real, $abs );
		}
		if ( ! $this->has( $real ) ) {
			$payload = $this->payload( $real, $content, $abs );
			if ( null === $payload || ! $this->write( $real, $payload ) ) {
				return false;
			}
		}
		// The file changed after it was fingerprinted: that version is kept too,
		// but the one asked for is still missing.
		return '' === $sha || hash_equals( $sha, $real );
	}

	/**
	 * Copies a file that is trusted now, unless it matches an official
	 * WordPress.org checksum (that original can be downloaded when needed).
	 *
	 * @param string     $abs    Path.
	 * @param string     $sha    Known sha256.
	 * @param array|null $verify Scanner::verify_details() result.
	 * @return bool
	 */
	public function store_trusted( $abs, $sha, $verify = null ) {
		if ( is_array( $verify ) && isset( $verify['verdict'], $verify['source'] ) && 'match' === $verify['verdict'] && in_array( $verify['source'], array( 'core', 'plugin' ), true ) ) {
			return false;
		}
		return $this->store( $abs, $sha );
	}

	/**
	 * Stores content that did not come from a file on this site (a verified
	 * official original). Not bound to the "snapshots" setting: it is a cache.
	 *
	 * @param string $content Content.
	 * @return string sha256, '' when it was not stored.
	 */
	public function put_content( $content ) {
		$content = (string) $content;
		if ( ! function_exists( 'gzencode' ) || strlen( $content ) > self::HARD_MAX || self::is_binary( $content ) ) {
			return '';
		}
		$sha = hash( 'sha256', $content );
		return $this->write( $sha, $content ) ? $sha : '';
	}

	/**
	 * @param string $sha sha256.
	 * @return bool
	 */
	public function has( $sha ) {
		return self::is_sha( $sha ) && @is_file( $this->path_for( $sha ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Text of a stored version (the redacted text for a copy stored redacted).
	 *
	 * @param string $sha sha256.
	 * @return string|null Null when missing, unreadable or corrupt.
	 */
	public function get( $sha ) {
		$entry = $this->get_entry( $sha );
		return null === $entry ? null : $entry['text'];
	}

	/**
	 * A stored version, checked against its sha256.
	 *
	 * @param string $sha sha256.
	 * @return array|null { text: string, redacted: bool, found: array (name => fingerprint
	 *                    of the hidden values, Diff::redact()), key: string (Diff::fingerprint_key_id()
	 *                    when they were taken) }, null when missing, unreadable or corrupt.
	 */
	public function get_entry( $sha ) {
		$sha = strtolower( (string) $sha );
		if ( ! self::is_sha( $sha ) || ! function_exists( 'gzdecode' ) ) {
			return null;
		}
		$path = $this->path_for( $sha );
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 2 * self::HARD_MAX ) {
			return null;
		}
		$gz = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		if ( ! is_string( $gz ) ) {
			return null;
		}
		$content = @gzdecode( $gz, 2 * self::HARD_MAX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( is_string( $content ) ) {
			$entry = self::parse_redacted( $content, $sha );
			if ( null !== $entry ) {
				return $entry;
			}
			// A file of the site may itself start with the marker: then it is a plain copy.
			if ( strlen( $content ) <= self::HARD_MAX && hash_equals( $sha, hash( 'sha256', $content ) ) ) {
				return array(
					'text'     => $content,
					'redacted' => false,
					'found'    => array(),
					'key'      => '',
				);
			}
		}
		Fs::delete( $path ); // corrupt or truncated copy.
		return null;
	}

	/**
	 * Reads a copy stored redacted.
	 *
	 * @param string $content Decompressed copy.
	 * @param string $sha     sha256 of the real content it stands for.
	 * @return array|null get_entry() shape, null when it is not a valid redacted copy of $sha.
	 */
	private static function parse_redacted( $content, $sha ) {
		$magic = strlen( self::REDACTED_MAGIC );
		if ( 0 !== strncmp( $content, self::REDACTED_MAGIC, $magic ) ) {
			return null;
		}
		$eol = strpos( $content, "\n", $magic );
		if ( false === $eol || $eol - $magic > 262144 ) {
			return null;
		}
		$head = json_decode( (string) substr( $content, $magic, $eol - $magic ), true );
		$text = (string) substr( $content, $eol + 1 );
		if ( ! is_array( $head ) || ! isset( $head['sha256'], $head['body'] ) || ! is_string( $head['sha256'] ) || ! is_string( $head['body'] )
			|| ! hash_equals( $sha, strtolower( $head['sha256'] ) ) || ! hash_equals( strtolower( $head['body'] ), hash( 'sha256', $text ) ) ) {
			return null;
		}
		$found = array();
		foreach ( isset( $head['found'] ) && is_array( $head['found'] ) ? $head['found'] : array() as $name => $print ) {
			if ( is_string( $print ) ) {
				$found[ (string) $name ] = $print;
			}
		}
		return array(
			'text'     => $text,
			'redacted' => true,
			'found'    => $found,
			'key'      => isset( $head['key'] ) && is_string( $head['key'] ) ? $head['key'] : '',
		);
	}

	/**
	 * What is written for a file: the content itself, or for a file that
	 * holds secrets, the redacted copy (see the class comment).
	 *
	 * @param string $sha     sha256 of $content.
	 * @param string $content Content.
	 * @param string $name    File name or path.
	 * @return string|null Null when a redacted copy could not be built (nothing is stored then).
	 */
	private function payload( $sha, $content, $name ) {
		$secret = self::is_secret_name( $name );
		if ( ! $secret && 0 === preg_match( self::SECRET_HINT, $content ) ) {
			return $content;
		}
		$found = array();
		$text  = Diff::redact( $content, basename( wp_normalize_path( (string) $name ) ), $found );
		if ( ! $found && ! $secret ) {
			return $content;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- exact bytes, no WordPress filters.
		$head = json_encode(
			array(
				'sha256' => $sha,
				'body'   => hash( 'sha256', $text ),
				'key'    => Diff::fingerprint_key_id(),
				'found'  => (object) $found,
			),
			JSON_UNESCAPED_SLASHES | ( defined( 'JSON_INVALID_UTF8_SUBSTITUTE' ) ? JSON_INVALID_UTF8_SUBSTITUTE : 0 )
		);
		if ( ! is_string( $head ) || false !== strpos( $head, "\n" ) ) {
			return null;
		}
		return self::REDACTED_MAGIC . $head . "\n" . $text;
	}

	/**
	 * An existing copy is needed again: its time is refreshed (prune() keeps
	 * it another GRACE period), and a plain copy of a file that holds secrets,
	 * made by an earlier version of the plugin, is replaced by a redacted one.
	 *
	 * @param string $sha  sha256.
	 * @param string $name File name or path ('' when unknown).
	 */
	private function refresh( $sha, $name = '' ) {
		Fs::touch( $this->path_for( $sha ) );
		if ( '' !== (string) $name && self::is_secret_name( $name ) ) {
			$this->harden( $sha, $name );
		}
	}

	/**
	 * Replaces a plain copy of a file that holds secrets with a redacted one.
	 *
	 * @param string $sha  sha256.
	 * @param string $name File name or path.
	 * @return bool Whether a plain copy was replaced.
	 */
	private function harden( $sha, $name ) {
		$entry = $this->get_entry( $sha );
		if ( null === $entry || $entry['redacted'] ) {
			return false;
		}
		$payload = $this->payload( strtolower( (string) $sha ), $entry['text'], $name );
		if ( null === $payload ) {
			// Never keep the plain copy of a secret file.
			Fs::delete( $this->path_for( $sha ) );
			return true;
		}
		return $payload !== $entry['text'] && $this->write( $sha, $payload, true );
	}

	/**
	 * When a version was first stored (unix time, 0 when missing).
	 *
	 * @param string $sha sha256.
	 * @return int
	 */
	public function stored_at( $sha ) {
		if ( ! self::is_sha( $sha ) ) {
			return 0;
		}
		$time = @filemtime( $this->path_for( $sha ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return false === $time ? 0 : (int) $time;
	}

	/**
	 * Writes one compressed copy atomically (temp file + rename).
	 *
	 * @param string $sha     sha256 the copy stands for.
	 * @param string $content What to store (payload()).
	 * @param bool   $replace Replace an existing copy.
	 * @return bool
	 */
	private function write( $sha, $content, $replace = false ) {
		$path = $this->path_for( $sha );
		if ( ! $replace && @is_file( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Fs::touch( $path ); // needed again: keep it past the next prune().
			return true;
		}
		if ( ! $replace && $this->is_full() ) {
			// The store is at its limit: no new copy until enforce_cap() made room.
			$this->count_usage( 'refused' );
			return false;
		}
		if ( ! $this->ensure_root() ) {
			$this->count_usage( 'failures' );
			return false;
		}
		$dir = dirname( $path );
		if ( ! @is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$this->count_usage( 'failures' );
			return false;
		}
		$gz = gzencode( $content, 6 );
		if ( false === $gz ) {
			return false;
		}
		$tmp = $dir . '/.' . substr( basename( $path, '.gz' ), 0, 12 ) . '-' . substr( md5( uniqid( 'wpcs', true ) ), 0, 8 ) . '.tmp';
		if ( false === @file_put_contents( $tmp, $gz ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
			Fs::delete( $tmp );
			$this->count_usage( 'failures' );
			return false;
		}
		Fs::chmod( $tmp, 0600 );
		if ( ! Fs::replace( $tmp, $path ) ) {
			if ( $replace && Fs::delete( $path ) && Fs::replace( $tmp, $path ) ) { // Windows does not rename over a file.
				return true;
			}
			Fs::delete( $tmp );
			$exists = @is_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- written by another process meanwhile.
			if ( ! $exists ) {
				$this->count_usage( 'failures' );
			}
			return ! $replace && $exists;
		}
		if ( ! $replace ) {
			$this->count_usage( 'added', strlen( $gz ) );
		}
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Limits and usage                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * @return int Most stored copies.
	 */
	public function max_files() {
		return max( 1000, (int) wpcybersec()->settings->get( 'snapshot_max_files', 20000 ) );
	}

	/**
	 * @return int Most bytes on disk.
	 */
	public function max_total_bytes() {
		return max( 10, (int) wpcybersec()->settings->get( 'snapshot_max_mb', 200 ) ) * MB_IN_BYTES;
	}

	/**
	 * Numbers for the dashboard and the settings page.
	 *
	 * @return array { enabled: bool, files: int, bytes: int, max_files: int, max_bytes: int,
	 *                 percent: float (the fuller of the two limits), full: bool, refused: int
	 *                 (copies not taken because the store was full, since the last count),
	 *                 failures: int (copies that could not be written), last_failure: int (unix),
	 *                 counted_at: int (unix time of the last exact count, 0 = estimate) }
	 */
	public function usage() {
		$usage     = $this->load_usage();
		$max_files = $this->max_files();
		$max_bytes = $this->max_total_bytes();
		$percent   = max( $usage['files'] / $max_files, $usage['bytes'] / $max_bytes ) * 100;
		return array(
			'enabled'      => $this->enabled(),
			'files'        => (int) $usage['files'],
			'bytes'        => (int) $usage['bytes'],
			'max_files'    => $max_files,
			'max_bytes'    => $max_bytes,
			'percent'      => round( min( 100.0, $percent ), 1 ),
			'full'         => $this->is_full(),
			'refused'      => (int) $usage['refused'],
			'failures'     => (int) $usage['failures'],
			'last_failure' => (int) $usage['last_failure'],
			'counted_at'   => (int) $usage['at'],
		);
	}

	/**
	 * Whether a new copy would go over a limit.
	 *
	 * @return bool
	 */
	public function is_full() {
		$usage = $this->load_usage();
		return $usage['files'] >= $this->max_files() || $usage['bytes'] >= $this->max_total_bytes();
	}

	/**
	 * Deletes the least recently used copies (oldest file time; a copy is
	 * touched whenever it is needed again) until both totals are under
	 * CAP_TARGET of their limits. Recounts first when the totals are older
	 * than a day. Two passes over the store: an hourly histogram of file
	 * times picks the cut-off, then older copies are deleted, so memory stays
	 * small however many copies there are.
	 *
	 * @param float $seconds Time budget (the rest is done next time).
	 * @return int Copies deleted.
	 */
	public function enforce_cap( $seconds = 5.0 ) {
		$usage = $this->load_usage();
		if ( (int) $usage['at'] < time() - DAY_IN_SECONDS ) {
			$this->stats( true ); // Exact totals (also saved as usage).
			$usage = $this->load_usage();
		}
		if ( ! $this->is_full() && $usage['files'] < $this->max_files() * 0.98 && $usage['bytes'] < $this->max_total_bytes() * 0.98 ) {
			return 0;
		}
		$deadline   = microtime( true ) + max( 1.0, (float) $seconds );
		$need_files = max( 0, (int) $usage['files'] - (int) floor( $this->max_files() * self::CAP_TARGET ) );
		$need_bytes = max( 0, (int) $usage['bytes'] - (int) floor( $this->max_total_bytes() * self::CAP_TARGET ) );
		if ( ! $need_files && ! $need_bytes ) {
			return 0;
		}

		// Pass 1: copies and bytes per hour of last use.
		$hours = array();
		foreach ( $this->copy_files() as $file ) {
			$mtime = (int) @filemtime( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$size  = (int) @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$hour  = (int) floor( $mtime / HOUR_IN_SECONDS );
			if ( ! isset( $hours[ $hour ] ) ) {
				$hours[ $hour ] = array( 0, 0 );
			}
			++$hours[ $hour ][0];
			$hours[ $hour ][1] += $size;
		}
		ksort( $hours );
		$cut   = null;
		$files = 0;
		$bytes = 0;
		foreach ( $hours as $hour => $sum ) {
			if ( $files + $sum[0] >= $need_files && $bytes + $sum[1] >= $need_bytes ) {
				$cut = $hour; // Only part of this hour has to go.
				break;
			}
			$files += $sum[0];
			$bytes += $sum[1];
		}
		if ( null === $cut ) {
			return 0;
		}
		// Still to delete from the cut-off hour itself, after every older copy.
		$rest_files = $need_files - $files;
		$rest_bytes = $need_bytes - $bytes;

		// Pass 2: delete every copy last used before the cut-off hour, and
		// from that hour only as many as are still needed.
		$deleted = 0;
		$freed   = 0;
		foreach ( $this->copy_files() as $file ) {
			if ( microtime( true ) >= $deadline ) {
				break;
			}
			$hour = (int) floor( (int) @filemtime( $file ) / HOUR_IN_SECONDS ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $hour > $cut || ( $hour === $cut && $rest_files <= 0 && $rest_bytes <= 0 ) ) {
				continue;
			}
			$size = (int) @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( Fs::delete( $file ) ) {
				++$deleted;
				$freed += $size;
				if ( $hour === $cut ) {
					--$rest_files;
					$rest_bytes -= $size;
				}
			}
		}
		if ( $deleted ) {
			$this->usage['files']   = max( 0, (int) $this->usage['files'] - $deleted );
			$this->usage['bytes']   = max( 0, (int) $this->usage['bytes'] - $freed );
			$this->usage['refused'] = 0;
			$this->save_usage();
			Network::delete_transient( self::STATS_TRANSIENT );
			wpcybersec()->logger->log(
				'snapshots_capped',
				sprintf(
					/* translators: 1: number of files, 2: file count limit, 3: size limit */
					_n( 'Deleted %1$s stored file copy (the oldest) to stay under the limits of %2$s copies and %3$s.', 'Deleted %1$s stored file copies (the oldest) to stay under the limits of %2$s copies and %3$s.', $deleted, 'qartvelo-guard' ),
					number_format_i18n( $deleted ),
					number_format_i18n( $this->max_files() ),
					size_format( $this->max_total_bytes() )
				),
				array(
					'deleted' => $deleted,
					'freed'   => $freed,
				)
			);
		}
		return $deleted;
	}

	/**
	 * @return array USAGE_OPTION with every key.
	 */
	private function load_usage() {
		if ( null === $this->usage ) {
			$saved       = Network::get_option( self::USAGE_OPTION, array() );
			$this->usage = array_merge(
				array(
					'files'        => 0,
					'bytes'        => 0,
					'at'           => 0,
					'failures'     => 0,
					'refused'      => 0,
					'last_failure' => 0,
				),
				is_array( $saved ) ? $saved : array()
			);
			if ( ! is_array( $saved ) || ! $saved ) {
				// First use: start from the cached count when there is one (an
				// exact count runs in enforce_cap(), never in the middle of a scan).
				$cached = Network::get_transient( self::STATS_TRANSIENT );
				if ( is_array( $cached ) && isset( $cached['files'], $cached['bytes'] ) ) {
					$this->usage['files'] = (int) $cached['files'];
					$this->usage['bytes'] = (int) $cached['bytes'];
				}
			}
		}
		return $this->usage;
	}

	/**
	 * @param string $what  added | refused | failures.
	 * @param int    $bytes Size of an added copy.
	 */
	private function count_usage( $what, $bytes = 0 ) {
		$this->load_usage();
		if ( 'added' === $what ) {
			++$this->usage['files'];
			$this->usage['bytes'] += (int) $bytes;
		} else {
			++$this->usage[ $what ];
			if ( 'failures' === $what ) {
				$this->usage['last_failure'] = time();
			}
		}
		++$this->usage_dirty;
		if ( $this->usage_dirty >= 50 ) {
			$this->save_usage();
		} elseif ( ! $this->usage_hooked ) {
			$this->usage_hooked = true;
			register_shutdown_function( array( $this, 'save_usage' ) );
		}
	}

	/**
	 * Saves the running totals (also at the end of the request).
	 */
	public function save_usage() {
		if ( null === $this->usage || 0 === $this->usage_dirty ) {
			return;
		}
		$this->usage_dirty = 0;
		Network::update_option( self::USAGE_OPTION, $this->usage, false );
	}

	/* ------------------------------------------------------------------ */
	/* Paths and key                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Folder of the copies (no trailing slash). One folder for a whole
	 * multisite network, like the manifest (older versions kept a
	 * snapshots/site-<id>/ folder per site; Network removes those).
	 *
	 * @return string
	 */
	public function root() {
		return wpcybersec()->storage->path( self::DIR );
	}

	/**
	 * File name stem for a version (the keyed hash, not the sha256 itself).
	 *
	 * @param string $sha sha256.
	 * @return string 64 hex chars.
	 */
	public function name_for( $sha ) {
		return hash_hmac( 'sha256', strtolower( (string) $sha ), $this->key() );
	}

	/**
	 * @param string $sha sha256.
	 * @return string Absolute path of the copy.
	 */
	public function path_for( $sha ) {
		$name = $this->name_for( $sha );
		return $this->root() . '/' . substr( $name, 0, 2 ) . '/' . substr( $name, 2, 2 ) . '/' . $name . '.gz';
	}

	/**
	 * Random key (one per site, or per multisite network), created on first use.
	 *
	 * @return string
	 */
	private function key() {
		if ( null !== $this->key ) {
			return $this->key;
		}
		$key = Network::get_option( self::KEY_OPTION, '' );
		if ( ! is_string( $key ) || ! preg_match( '/^[a-f0-9]{64}$/', $key ) ) {
			try {
				$key = bin2hex( random_bytes( 32 ) );
			} catch ( \Throwable $e ) {
				$key = hash( 'sha256', wp_generate_password( 64, true, true ) . uniqid( '', true ) );
			}
			if ( ! Network::add_option( self::KEY_OPTION, $key, '', 'no' ) ) {
				// Another request created it first: use that one.
				Network::flush_option_cache( self::KEY_OPTION );
				$stored = Network::get_option( self::KEY_OPTION, '' );
				if ( is_string( $stored ) && preg_match( '/^[a-f0-9]{64}$/', $stored ) ) {
					$key = $stored;
				} else {
					Network::update_option( self::KEY_OPTION, $key, false );
				}
			}
		}
		$this->key = $key;
		return $key;
	}

	/**
	 * Creates the folder and its deny files once per request.
	 *
	 * @return bool
	 */
	private function ensure_root() {
		if ( $this->ready ) {
			return true;
		}
		$storage = wpcybersec()->storage;
		if ( is_wp_error( $storage->ensure() ) ) {
			return false;
		}
		$root = $this->root();
		if ( ! @is_dir( $root ) && ! wp_mkdir_p( $root ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$storage->protect( $root );
		if ( self::DIR !== basename( $root ) ) {
			$storage->protect( dirname( $root ) );
		}
		$this->ready = true;
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Backfill (copies of files trusted before copies were taken)         */
	/* ------------------------------------------------------------------ */

	/**
	 * Whether scans should also copy unchanged trusted files (once, after the
	 * feature was switched on or the size limit raised).
	 *
	 * @return bool
	 */
	public function needs_backfill() {
		list( $done ) = $this->backfill_state();
		return $this->enabled() && ! $done;
	}

	/**
	 * Generation of the backfill (raised by every reset). A scan remembers it
	 * when it starts and passes it to backfill_done().
	 *
	 * @return int
	 */
	public function backfill_generation() {
		list( , $generation ) = $this->backfill_state();
		return $generation;
	}

	/**
	 * A whole-site scan copied every trusted file. Ignored when the backfill
	 * was reset after that scan started (copies deleted, limit raised).
	 *
	 * @param int|null $generation backfill_generation() when the scan started (null: any).
	 * @return bool Whether it was marked done.
	 */
	public function backfill_done( $generation = null ) {
		Network::flush_option_cache( self::BACKFILL_OPTION );
		list( , $current ) = $this->backfill_state();
		if ( null !== $generation && (int) $generation !== $current ) {
			return false;
		}
		Network::update_option( self::BACKFILL_OPTION, 'done:' . $current, false );
		return true;
	}

	/**
	 * The next scan copies unchanged trusted files again.
	 */
	public function reset_backfill() {
		Network::flush_option_cache( self::BACKFILL_OPTION );
		list( , $generation ) = $this->backfill_state();
		Network::update_option( self::BACKFILL_OPTION, 'pending:' . ( $generation + 1 ), false );
	}

	/**
	 * @return array { 0: bool done, 1: int generation }
	 */
	private function backfill_state() {
		$value = Network::get_option( self::BACKFILL_OPTION, '' );
		if ( is_string( $value ) && preg_match( '/^(done|pending):(\d{1,9})$/', $value, $m ) ) {
			return array( 'done' === $m[1], (int) $m[2] );
		}
		if ( 'done' === $value ) {
			return array( true, 0 ); // Written by older versions.
		}
		return array( false, 0 );
	}

	/* ------------------------------------------------------------------ */
	/* Housekeeping                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Number and total size of the stored copies (cached for an hour).
	 *
	 * @param bool $fresh Recount now.
	 * @return array { files: int, bytes: int }
	 */
	public function stats( $fresh = false ) {
		if ( ! $fresh ) {
			$cached = Network::get_transient( self::STATS_TRANSIENT );
			if ( is_array( $cached ) && isset( $cached['files'], $cached['bytes'] ) ) {
				return array(
					'files' => (int) $cached['files'],
					'bytes' => (int) $cached['bytes'],
				);
			}
		}
		$stats = array(
			'files' => 0,
			'bytes' => 0,
		);
		foreach ( $this->copy_files() as $file ) {
			++$stats['files'];
			$size            = @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$stats['bytes'] += false === $size ? 0 : (int) $size;
			if ( $stats['files'] >= 500000 ) {
				break;
			}
		}
		Network::set_transient( self::STATS_TRANSIENT, $stats, HOUR_IN_SECONDS );
		$this->load_usage();
		$this->usage['files'] = $stats['files'];
		$this->usage['bytes'] = $stats['bytes'];
		$this->usage['at']    = time();
		++$this->usage_dirty;
		$this->save_usage();
		return $stats;
	}

	/**
	 * Deletes every stored copy. While copies are on, the next whole-site scan
	 * copies the trusted files again.
	 *
	 * @return int Files deleted.
	 */
	public function clear() {
		$root    = $this->root();
		$deleted = 0;
		if ( preg_match( '/^(?:' . self::DIR . '|site-\d+)$/', basename( $root ) ) && @is_dir( $root ) && ! is_link( $root ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			foreach ( $this->top_dirs( $root ) as $top ) {
				$deleted += $this->delete_tree( $root . '/' . $top );
			}
		}
		Network::delete_transient( self::STATS_TRANSIENT );
		Network::delete_option( self::CURSOR_OPTION );
		$this->load_usage();
		$this->usage['files']   = 0;
		$this->usage['bytes']   = 0;
		$this->usage['refused'] = 0;
		$this->usage['at']      = time();
		++$this->usage_dirty;
		$this->save_usage();
		$this->reset_backfill();
		return $deleted;
	}

	/**
	 * Deletes copies no manifest row and no file/threat report refers to (its
	 * sha256, details.previous_sha256 or details.base_sha256). Runs daily from
	 * 'wpcybersec_maintenance'; a large store is walked over several runs.
	 *
	 * @param float $seconds   Time budget.
	 * @param int   $max_files Files to look at in this run.
	 * @return array { checked: int, deleted: int, complete: bool, hardened: int }
	 */
	public function prune( $seconds = self::PRUNE_SECONDS, $max_files = self::PRUNE_FILES ) {
		$result = array(
			'checked'  => 0,
			'deleted'  => 0,
			'complete' => true,
			'hardened' => 0,
		);
		$root = $this->root();
		if ( ! @is_dir( $root ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Network::delete_option( self::CURSOR_OPTION );
			return $result;
		}

		$deadline = microtime( true ) + max( 1.0, (float) $seconds );
		$secret   = array();
		$keep     = $this->referenced_names( $secret );
		$cursor   = (string) Network::get_option( self::CURSOR_OPTION, '' );

		// Plain copies of wp-config.php and other secret files made by an
		// earlier version of the plugin are replaced with redacted ones.
		foreach ( array_slice( $secret, 0, self::HARDEN_PER_RUN, true ) as $sha => $name ) {
			if ( $this->harden( (string) $sha, $name ) ) {
				++$result['hardened'];
			}
		}
		$cutoff  = time() - self::GRACE;
		$tmp_cut = time() - HOUR_IN_SECONDS;

		foreach ( $this->top_dirs( $root ) as $top ) {
			if ( '' !== $cursor && strcmp( $top, $cursor ) <= 0 ) {
				continue;
			}
			foreach ( $this->top_dirs( $root . '/' . $top ) as $sub ) {
				$dir     = $root . '/' . $top . '/' . $sub;
				$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$left    = 0;
				foreach ( (array) $entries as $entry ) {
					if ( '.' === $entry || '..' === $entry || '' === (string) $entry ) {
						continue;
					}
					$file = $dir . '/' . $entry;
					++$result['checked'];
					$mtime = (int) @filemtime( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
					if ( '.tmp' === substr( $entry, -4 ) ) {
						if ( $mtime < $tmp_cut && Fs::delete( $file ) ) {
							continue;
						}
					} elseif ( preg_match( '/^([a-f0-9]{64})\.gz$/', $entry, $m ) && ! isset( $keep[ substr( $m[1], 0, 32 ) ] ) && $mtime < $cutoff ) {
						if ( Fs::delete( $file ) ) {
							++$result['deleted'];
							continue;
						}
					}
					++$left;
				}
				if ( 0 === $left ) {
					Fs::rmdir( $dir );
				}
			}
			Fs::rmdir( $root . '/' . $top ); // only succeeds when empty.
			$cursor = $top;
			if ( $result['checked'] >= $max_files || microtime( true ) >= $deadline ) {
				$result['complete'] = false;
				break;
			}
		}

		if ( $result['complete'] ) {
			Network::delete_option( self::CURSOR_OPTION );
		} else {
			Network::update_option( self::CURSOR_OPTION, $cursor, false );
		}
		if ( $result['deleted'] ) {
			Network::delete_transient( self::STATS_TRANSIENT );
			$this->load_usage();
			// Sizes of pruned copies are not known here: the exact count in
			// enforce_cap() corrects the bytes; the file count is exact.
			$this->usage['files'] = max( 0, (int) $this->usage['files'] - (int) $result['deleted'] );
			$this->usage['at']    = 0;
			++$this->usage_dirty;
			$this->save_usage();
			wpcybersec()->logger->log(
				'snapshots_pruned',
				sprintf(
					/* translators: %s: number of files */
					_n( 'Deleted %s stored file copy that no report or trusted file needs any more.', 'Deleted %s stored file copies that no report or trusted file needs any more.', $result['deleted'], 'qartvelo-guard' ),
					number_format_i18n( $result['deleted'] )
				),
				$result
			);
		}
		// Still over a limit after the unreferenced copies went: drop the oldest.
		$left = $deadline - microtime( true );
		if ( $left > 1.0 ) {
			$result['capped'] = $this->enforce_cap( $left );
		}
		return $result;
	}

	/**
	 * Name prefixes (32 hex chars of the keyed name) of every version still
	 * referenced by the manifest or by a file/threat report.
	 *
	 * @param array $secret Receives sha256 => file name of the versions of files that hold secrets.
	 * @return array prefix => true
	 */
	private function referenced_names( array &$secret = array() ) {
		global $wpdb;
		$keep = array();

		$table = Store::table( 'manifest' );
		$last  = '';
		do {
			$rows = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT path_hash, path, sha256 FROM %i WHERE path_hash > %s ORDER BY path_hash LIMIT 5000', $table, $last ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
			foreach ( $rows as $row ) {
				$last = (string) $row['path_hash'];
				if ( self::is_sha( $row['sha256'] ) && self::is_diffable_name( (string) $row['path'] ) ) {
					$keep[ substr( $this->name_for( $row['sha256'] ), 0, 32 ) ] = true;
					if ( self::is_secret_name( (string) $row['path'] ) ) {
						$secret[ strtolower( (string) $row['sha256'] ) ] = basename( (string) $row['path'] );
					}
				}
			}
		} while ( count( $rows ) >= 5000 );

		$table   = Store::table( 'items' );
		$last_id = 0;
		do {
			$rows = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT id, path, sha256, details FROM %i WHERE id > %d AND type IN (%s, %s) ORDER BY id LIMIT 1000', $table, $last_id, Store::TYPE_FILE, Store::TYPE_THREAT ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
			foreach ( $rows as $row ) {
				$last_id = (int) $row['id'];
				$shas    = array( (string) $row['sha256'] );
				$details = json_decode( (string) $row['details'], true );
				if ( is_array( $details ) ) {
					foreach ( array( 'previous_sha256', 'base_sha256' ) as $key ) {
						if ( ! empty( $details[ $key ] ) ) {
							$shas[] = (string) $details[ $key ];
						}
					}
				}
				$path = isset( $row['path'] ) ? (string) $row['path'] : '';
				foreach ( $shas as $sha ) {
					if ( self::is_sha( $sha ) ) {
						$keep[ substr( $this->name_for( $sha ), 0, 32 ) ] = true;
						if ( '' !== $path && self::is_secret_name( $path ) ) {
							$secret[ strtolower( $sha ) ] = basename( $path );
						}
					}
				}
			}
		} while ( count( $rows ) >= 1000 );

		return $keep;
	}

	/**
	 * Two-hex-digit folder names inside a folder, sorted.
	 *
	 * @param string $dir Folder.
	 * @return string[]
	 */
	private function top_dirs( $dir ) {
		$out = array();
		foreach ( (array) @scandir( $dir ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( preg_match( '/^[a-f0-9]{2}$/', (string) $entry ) && @is_dir( $dir . '/' . $entry ) && ! is_link( $dir . '/' . $entry ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$out[] = (string) $entry;
			}
		}
		sort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * Every stored copy (generator over the two folder levels).
	 *
	 * @return \Generator|string[]
	 */
	private function copy_files() {
		$root = $this->root();
		if ( ! @is_dir( $root ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return;
		}
		foreach ( $this->top_dirs( $root ) as $top ) {
			foreach ( $this->top_dirs( $root . '/' . $top ) as $sub ) {
				$dir = $root . '/' . $top . '/' . $sub;
				foreach ( (array) @scandir( $dir ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					if ( '.gz' === substr( (string) $entry, -3 ) ) {
						yield $dir . '/' . $entry;
					}
				}
			}
		}
	}

	/**
	 * Recursive delete that never follows symlinks.
	 *
	 * @param string $path File or folder.
	 * @return int Files deleted.
	 */
	private function delete_tree( $path ) {
		if ( is_link( $path ) || @is_file( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return Fs::delete( $path ) ? 1 : 0;
		}
		if ( ! @is_dir( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return 0;
		}
		$count = 0;
		foreach ( (array) @scandir( $path ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( '.' === $entry || '..' === $entry || '' === (string) $entry ) {
				continue;
			}
			$count += $this->delete_tree( $path . '/' . $entry );
		}
		Fs::rmdir( $path );
		return $count;
	}
}
