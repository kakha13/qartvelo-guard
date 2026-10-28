<?php
/**
 * Reinstall a clean WordPress core when many core files are damaged.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * When a scan finds many changed, infected, extra or missing files in the
 * WordPress core, replacing all of core with the official release is faster
 * and safer than reviewing them one by one. This class:
 *
 *   damage()        counts open items in core paths (one indexed query on the
 *                   items table, only on pages that show the result) plus the
 *                   missing core files of the last scan, and says whether to
 *                   suggest a reinstall (THRESHOLD, filter
 *                   wpcybersec_core_damage_threshold; any extra executable
 *                   file inside wp-admin/ or wp-includes/ always counts);
 *   manual_steps()  the by-hand way: back up, download the no-content zip of
 *                   this exact version, delete wp-admin, wp-includes and the
 *                   core root files listed in the official checksums, upload
 *                   and extract, scan (hosting panel's file manager named
 *                   when known; an SSH block and a WP-CLI note as other ways;
 *                   Composer and host-managed core get their own advice);
 *   the one-click reinstall (only with the direct filesystem method and a
 *                   standard layout): download, extract into a folder on the
 *                   same filesystem as ABSPATH, verify EVERY file against
 *                   get_core_checksums( version, 'en_US' ), then in one short
 *                   request: maintenance mode, wp-admin and wp-includes renamed
 *                   into a backup folder and the clean ones renamed in, root
 *                   files copied to the backup and replaced atomically,
 *                   maintenance off, version.php and a loopback request
 *                   checked, automatic rollback on any failure. Afterwards the
 *                   core items are resolved, the new files trusted in the
 *                   manifest and a quick scan started. The backup is kept for
 *                   KEEP_DAYS days with "Restore the previous core".
 *
 * State: option STATE_OPTION (not autoloaded) for the job, BACKUPS_OPTION for
 * the kept backups. Every step is logged.
 */
class Core_Repair {

	/** Open core items (plus missing core files) from which a reinstall is suggested. */
	const THRESHOLD = 5;

	/** Job state (not autoloaded). */
	const STATE_OPTION = 'wpcybersec_core_reinstall';

	/** Kept backups of replaced cores (not autoloaded). */
	const BACKUPS_OPTION = 'wpcybersec_core_backups';

	/** Days a backup of the previous core is kept. */
	const KEEP_DAYS = 7;

	/** The official package without wp-content. */
	const PACKAGE_URL = 'https://downloads.wordpress.org/release/wordpress-%s-no-content.zip';

	/** Marker file in every backup folder (JSON). */
	const MARKER = '.wpcybersec-core-backup';

	/** Text in a .maintenance file this plugin wrote. */
	const MAINT_TAG = 'Qartvelo Guard';

	/** Core folders, in the order they are swapped. */
	const DIRS = array( 'wp-includes', 'wp-admin' );

	/** Server configuration names that are disabled inside a backup. */
	const CONFIG_NAMES = array( '.htaccess', '.htpasswd', '.user.ini', 'php.ini', 'web.config' );

	/** Suffix of a disabled configuration file inside a backup. */
	const OFF_SUFFIX = '.wpcs-off';

	/** Seconds after which an unfinished swap is rolled back by the next request. */
	const STALE = 300;

	/** Seconds one extract or verify request works. */
	const BUDGET = 8.0;

	/** Root files of WordPress when the checksums cannot be loaded. */
	const ROOT_FALLBACK = array( 'index.php', 'license.txt', 'readme.html', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php' );

	/** @var array|null damage() result for this request. */
	private $damage = null;

	/** @var array|null auto_status() result for this request. */
	private $auto = null;

	/** @var array|null Swap in progress in this request { plan, journal, done }. */
	private $swapping = null;

	public function register() {
		foreach ( array( 'core_reinstall', 'core_restore', 'core_maintenance' ) as $endpoint ) {
			add_action( 'wp_ajax_wpcybersec_' . $endpoint, array( $this, 'ajax_' . $endpoint ) );
		}
		add_action( 'wpcybersec_maintenance', array( $this, 'prune' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Detection                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * How many open items in core paths there are, and whether a reinstall
	 * should be suggested. Only reads what the scanner stored: open file and
	 * threat items under wp-admin/, wp-includes/ and the WordPress root (one
	 * query, skipped while nothing is open) and the missing core file count of
	 * the last whole-site scan. Call it only on pages that show the result.
	 *
	 * @return array { modified, threats, unknown, unknown_exec, missing, total, show, ids, threshold, version }
	 */
	public function damage() {
		if ( null !== $this->damage ) {
			return $this->damage;
		}
		$out  = array(
			'modified'     => 0,
			'threats'      => 0,
			'unknown'      => 0,
			'unknown_exec' => 0,
			'missing'      => 0,
			'total'        => 0,
			'show'         => false,
			'ids'          => array(),
			'threshold'    => self::threshold(),
			'version'      => '',
		);
		$plugin = wpcybersec();
		$last   = $plugin->scan_job ? $plugin->scan_job->last_result() : array();
		if ( isset( $last['missing_core'] ) && (int) $last['missing_core'] > 0 ) {
			$out['missing'] = (int) $last['missing_core'];
		}
		$counts = $plugin->store->counts();
		if ( (int) $counts['pending'] + (int) $counts['threats'] > 0 ) {
			$seen = array();
			foreach ( $this->core_items() as $item ) {
				$kind = self::classify( $item );
				if ( '' === $kind['kind'] || isset( $seen[ $kind['rel'] ] ) ) {
					continue;
				}
				$seen[ $kind['rel'] ] = true;
				$out['ids'][]         = (int) $item['id'];
				switch ( $kind['kind'] ) {
					case 'modified':
						++$out['modified'];
						break;
					case 'unknown':
						++$out['unknown'];
						if ( $kind['exec'] ) {
							++$out['unknown_exec'];
						}
						break;
					default:
						++$out['threats'];
				}
			}
		}
		$out['total']   = $out['modified'] + $out['threats'] + $out['unknown'] + $out['missing'];
		$out['show']    = $out['total'] >= $out['threshold'] || $out['unknown_exec'] > 0;
		$out['version'] = $plugin->scanner ? (string) $plugin->scanner->installed_wp_version() : '';
		$this->damage   = $out;
		return $out;
	}

	/**
	 * Forgets the damage() result of this request.
	 */
	public function reset() {
		$this->damage = null;
		$this->auto   = null;
	}

	/**
	 * Number of open core items (plus missing files) from which a reinstall is suggested.
	 *
	 * @return int
	 */
	public static function threshold() {
		/**
		 * Filters how many damaged core files make the plugin suggest a core reinstall.
		 *
		 * @param int $threshold Default THRESHOLD (5).
		 */
		return max( 1, (int) apply_filters( 'wpcybersec_core_damage_threshold', self::THRESHOLD ) );
	}

	/**
	 * Open file and threat items whose file is in wp-admin/, wp-includes/ or
	 * the top of the WordPress folder (still in place, not held).
	 *
	 * @return array[] Decoded items.
	 */
	private function core_items() {
		global $wpdb;
		$table = Store::table( 'items' );
		$or    = array();
		$args  = array( Store::TYPE_FILE, Store::TYPE_THREAT, Store::STATUS_PENDING, Store::SOURCE_DATABASE );
		foreach ( self::roots() as $root ) {
			$like  = $wpdb->esc_like( $root );
			$or[]  = '(original_path LIKE %s OR original_path LIKE %s OR (original_path LIKE %s AND original_path NOT LIKE %s))';
			$args[] = $like . 'wp-admin/%';
			$args[] = $like . 'wp-includes/%';
			$args[] = $like . '%';
			$args[] = $like . '%/%';
		}
		$sql = "SELECT id, type, status, severity, path, original_path, quarantine_path, sha256, size, mime, source, user_id, ip, details, created_at, updated_at, decided_by, decided_at FROM {$table} WHERE type IN (%s, %s) AND status = %s AND quarantine_path = '' AND source <> %s AND (" . implode( ' OR ', $or ) . ') ORDER BY id ASC LIMIT 5000';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin table from Store::table(), fixed conditions with placeholders.
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A );
		return array_map( array( Store::class, 'decode_item' ), is_array( $rows ) ? $rows : array() );
	}

	/**
	 * What an open item says about core.
	 *
	 * @param array $item Decoded item.
	 * @return array { kind: modified|threat|unknown|'', rel, exec }
	 */
	public static function classify( array $item ) {
		$out = array(
			'kind' => '',
			'rel'  => '',
			'exec' => false,
		);
		$abs = '' !== (string) $item['original_path'] ? (string) $item['original_path'] : Paths::abs( (string) $item['path'] );
		$rel = self::core_rel( $abs );
		if ( '' === $rel ) {
			return $out;
		}
		$out['rel'] = $rel;
		$details    = is_array( $item['details'] ) ? $item['details'] : array();
		$sigs       = array();
		foreach ( isset( $details['hits'] ) ? (array) $details['hits'] : array() as $hit ) {
			if ( is_array( $hit ) && isset( $hit['sig'] ) ) {
				$sigs[ (string) $hit['sig'] ] = true;
			}
		}
		$verified = isset( $details['verified'] ) ? (string) $details['verified'] : '';
		$checksum = isset( $details['checksum'] ) ? (string) $details['checksum'] : '';
		$in_dir   = 1 === preg_match( '~^wp-(?:admin|includes)/~', $rel );

		if ( $in_dir && ( isset( $sigs['core_unknown_file'] ) || isset( $sigs['core_unknown_config'] ) || ( 'core' === $verified && 'unknown_file' === $checksum ) ) ) {
			$out['kind'] = 'unknown';
			$out['exec'] = isset( $sigs['core_unknown_file'] ) || Paths::is_executable( $rel );
			return $out;
		}
		if ( 'core' === $verified && 'mismatch' === $checksum ) {
			// A localized version.php is compared without its $wp_local_package line; never count it.
			$out['kind'] = 'wp-includes/version.php' === $rel && self::is_localized() ? '' : 'modified';
			return $out;
		}
		// Root core file names are stable across versions: no checksum lookup on page loads.
		if ( Store::TYPE_THREAT === (string) $item['type'] && ( $in_dir || in_array( $rel, self::ROOT_FALLBACK, true ) ) ) {
			$out['kind'] = 'threat';
		}
		return $out;
	}

	/**
	 * Path relative to ABSPATH ('' when outside it).
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	public static function core_rel( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		foreach ( self::roots() as $root ) {
			if ( 0 === strpos( $abs, $root ) ) {
				return substr( $abs, strlen( $root ) );
			}
		}
		return '';
	}

	/**
	 * ABSPATH as given and resolved, with a trailing slash.
	 *
	 * @return string[]
	 */
	private static function roots() {
		$roots = array( trailingslashit( wp_normalize_path( ABSPATH ) ) );
		$real  = realpath( ABSPATH );
		if ( $real ) {
			$roots[] = trailingslashit( wp_normalize_path( $real ) );
		}
		return array_values( array_unique( $roots ) );
	}

	/**
	 * Whether the installed core is a localized package ($wp_local_package).
	 *
	 * @return bool
	 */
	public static function is_localized() {
		$scanner = wpcybersec()->scanner;
		return $scanner && 'en_US' !== $scanner->package_locale();
	}

	/**
	 * The official core checksums of a version, en_US (what the no-content
	 * package is), without the bundled wp-content files.
	 *
	 * @param string $version Version.
	 * @return array|false path => md5
	 */
	public static function checksums( $version ) {
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$sums = get_core_checksums( (string) $version, 'en_US' );
		if ( ! is_array( $sums ) || ! $sums ) {
			return false;
		}
		$out = array();
		foreach ( $sums as $path => $md5 ) {
			$path = ltrim( wp_normalize_path( (string) $path ), '/' );
			if ( '' === $path || 0 === strpos( $path, 'wp-content/' ) || ! is_string( $md5 ) || ! preg_match( '~^[a-f0-9]{32}$~i', $md5 ) || false !== strpos( $path, '..' ) ) {
				continue;
			}
			$out[ $path ] = strtolower( $md5 );
		}
		ksort( $out );
		return $out ? $out : false;
	}

	/**
	 * Core files at the top of the WordPress folder, from the checksums of the
	 * installed version (a fixed list when they cannot be loaded).
	 *
	 * @param array|null $map checksums() result, or null for the scanner's map.
	 * @return string[]
	 */
	public static function root_files( $map = null ) {
		if ( null === $map ) {
			$scanner = wpcybersec()->scanner;
			$map     = $scanner && wpcybersec()->settings->get( 'use_checksums', true ) ? $scanner->core_map() : false;
		}
		$names = array();
		if ( is_array( $map ) ) {
			foreach ( array_keys( $map ) as $path ) {
				if ( false === strpos( (string) $path, '/' ) ) {
					$names[] = (string) $path;
				}
			}
		}
		$names = $names ? $names : self::ROOT_FALLBACK;
		sort( $names );
		return $names;
	}

	/* ------------------------------------------------------------------ */
	/* Where and whether the one-click reinstall can run                   */
	/* ------------------------------------------------------------------ */

	/**
	 * How WordPress core is installed: standard, composer (Bedrock, a Composer
	 * package), symlink (wp-admin or wp-includes is a link) or custom (WPINC
	 * renamed).
	 *
	 * @return string
	 */
	public static function layout() {
		$abs = trailingslashit( wp_normalize_path( ABSPATH ) );
		if ( defined( 'WPINC' ) && 'wp-includes' !== WPINC ) {
			return 'custom';
		}
		foreach ( self::DIRS as $dir ) {
			if ( @is_link( $abs . $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return 'symlink';
			}
		}
		if ( false !== strpos( $abs, '/vendor/' ) ) {
			return 'composer';
		}
		if ( '' !== self::composer_package() ) {
			return 'composer';
		}
		$home = Paths::home_dir();
		if ( '' !== $home && 'web' === basename( untrailingslashit( $home ) ) && trailingslashit( wp_normalize_path( $home ) ) . 'wp/' === $abs ) {
			return 'composer';
		}
		return 'standard';
	}

	/**
	 * The Composer package that installs core, read from a composer.json one
	 * or two folders above ABSPATH ('' when none).
	 *
	 * @return string Package name, or "composer" when only the layout says so.
	 */
	public static function composer_package() {
		$abs = untrailingslashit( wp_normalize_path( ABSPATH ) );
		foreach ( array( dirname( $abs ), dirname( dirname( $abs ) ) ) as $dir ) {
			$file = trailingslashit( $dir ) . 'composer.json';
			if ( ! Storage::path_allowed( $file ) || ! @is_file( $file ) || @filesize( $file ) > 262144 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			$json = (string) @file_get_contents( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
			if ( preg_match( '~"(roots/wordpress(?:-no-content)?|johnpbloch/wordpress(?:-core)?|wordpress/core-implementation|roots/bedrock)"~', $json, $m ) ) {
				return 'roots/bedrock' === $m[1] ? 'roots/wordpress' : $m[1];
			}
		}
		return '';
	}

	/**
	 * Whether the one-click reinstall may run here, and why not.
	 *
	 * @param bool $live Also run the checks that cost a request (web access to the data folder).
	 * @return array { ok: bool, reason: string, code: string }
	 */
	public function auto_status( $live = false ) {
		if ( null !== $this->auto && ! $live ) {
			return $this->auto;
		}
		$result = $this->auto_check( $live );
		if ( ! $live ) {
			$this->auto = $result;
		}
		return $result;
	}

	/**
	 * @param bool $live See auto_status().
	 * @return array
	 */
	private function auto_check( $live ) {
		$no = static function ( $code, $reason ) {
			return array(
				'ok'     => false,
				'reason' => $reason,
				'code'   => $code,
			);
		};
		$plugin = wpcybersec();
		if ( Install_Gate::mods_disallowed() ) {
			return $no( 'file_mods', __( 'DISALLOW_FILE_MODS is set in wp-config.php, so WordPress may not change its own files. Use the steps by hand, or remove that line for the reinstall.', 'qartvelo-guard' ) );
		}
		if ( $plugin->settings->get( 'freeze_mods', false ) && $plugin->install_gate && ! $plugin->install_gate->is_unlocked() ) {
			return $no( 'freeze', __( 'The freeze lock is on, so the plugin does not change files. Unlock file changes for a few minutes on the Dashboard (Protection > Freeze lock), then try again.', 'qartvelo-guard' ) );
		}
		switch ( self::layout() ) {
			case 'composer':
				return $no( 'composer', __( 'WordPress core is installed with Composer here. Reinstall it with Composer (see the steps), not by replacing files.', 'qartvelo-guard' ) );
			case 'symlink':
				return $no( 'symlink', __( 'wp-admin or wp-includes is a symbolic link on this server, so the folders cannot be swapped safely from WordPress.', 'qartvelo-guard' ) );
			case 'custom':
				return $no( 'custom', __( 'This site renames the wp-includes folder (WPINC), which the official package does not.', 'qartvelo-guard' ) );
		}
		$host = $plugin->hosting ? $plugin->hosting->manages_core() : '';
		if ( '' !== $host ) {
			/* translators: %s: host name */
			return $no( 'managed', sprintf( __( '%s manages WordPress core for this site. Ask its support, or use its restore tools.', 'qartvelo-guard' ), $host ) );
		}
		if ( ! class_exists( 'ZipArchive' ) ) {
			return $no( 'zip', __( 'PHP\'s zip extension (ZipArchive) is missing on this server, so the package cannot be unpacked from WordPress.', 'qartvelo-guard' ) );
		}
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( 'direct' !== get_filesystem_method( array(), ABSPATH, false ) ) {
			return $no( 'fs', __( 'WordPress cannot write its own files directly on this server (updates would ask for FTP details), so the plugin does not replace core here.', 'qartvelo-guard' ) );
		}
		$abs = untrailingslashit( wp_normalize_path( ABSPATH ) );
		foreach ( array_merge( array( $abs ), array_map( static function ( $d ) use ( $abs ) {
			return $abs . '/' . $d;
		}, self::DIRS ) ) as $dir ) {
			if ( @is_dir( $dir ) && ! Fs::is_writable( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				/* translators: %s: folder path */
				return $no( 'writable', sprintf( __( 'PHP cannot write to %s.', 'qartvelo-guard' ), $dir ) );
			}
		}
		$places = $this->places( $live );
		if ( is_wp_error( $places ) ) {
			return $no( 'places', $places->get_error_message() );
		}
		return array(
			'ok'     => true,
			'reason' => '',
			'code'   => '',
		);
	}

	/**
	 * Folders for the unpacked package and the backup, both on the same
	 * filesystem as ABSPATH (renames between them are one step) and never in
	 * a folder the scan walks. The backup holds the old, possibly infected
	 * files, so it must not be reachable from the web: the plugin's data
	 * folder when it is outside the web root, or inside it on Apache /
	 * LiteSpeed Enterprise (its deny-all .htaccess) or when the live test says
	 * it is blocked; else a hidden folder next to the WordPress folder.
	 *
	 * @param bool $live Run the web access test when it decides.
	 * @return array|\WP_Error { stage: folder, backup: folder (parent of the backup folders), sibling: bool }
	 */
	private function places( $live = false ) {
		$storage = wpcybersec()->storage;
		$abs     = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$data    = $storage ? untrailingslashit( wp_normalize_path( (string) $storage->data_dir() ) ) : '';
		$stage   = '';
		$backup  = '';
		$sibling = false;

		$data_ok = '' !== $data && @is_dir( $data ) && Fs::is_writable( $data ) && Fs::same_device( $data, $abs ) // phpcs:ignore WordPress.PHP.NoSilencedErrors
			&& ! Storage::is_within( $data, $abs . '/wp-admin' ) && ! Storage::is_within( $data, $abs . '/wp-includes' );
		if ( $data_ok ) {
			$stage = $data . '/core-stage';
			if ( ! $storage->is_in_webroot( $data ) || $this->data_protected( $data, $live ) ) {
				$backup = $data . '/core-backup';
			}
		}
		$parent     = wp_normalize_path( dirname( $abs ) );
		$probe      = $parent . '/.wpcybersec-core-backup-probe';
		$sibling_ok = $parent !== $abs && Storage::path_allowed( $probe ) && @is_dir( $parent ) && Fs::is_writable( $parent ) && Fs::same_device( $parent, $abs ) // phpcs:ignore WordPress.PHP.NoSilencedErrors
			&& ! $storage->is_in_webroot( $probe ) && ! Paths::in_scope( $probe );
		if ( '' === $stage && $sibling_ok ) {
			$stage = $parent . '/.wpcybersec-core-stage';
		}
		if ( '' === $backup && $sibling_ok ) {
			$backup  = $parent;
			$sibling = true;
		}
		if ( '' === $stage ) {
			return new \WP_Error( 'wpcybersec_core_place', __( 'There is no folder on the same disk as WordPress where the plugin may unpack the package (its data folder is on another disk or not writable).', 'qartvelo-guard' ) );
		}
		if ( '' === $backup ) {
			return new \WP_Error( 'wpcybersec_core_place', __( 'The old core files would have to be kept inside the public website folder, where a backdoor among them could still be opened from the web (the data folder is not blocked from web access on this server). Move the data folder outside the web root (Settings > Advanced), or use the steps by hand.', 'qartvelo-guard' ) );
		}
		return array(
			'stage'   => $stage,
			'backup'  => $backup,
			'sibling' => $sibling,
		);
	}

	/**
	 * Whether files in the data folder inside the web root cannot be opened
	 * from the web.
	 *
	 * @param string $data Data folder.
	 * @param bool   $live Run the web access test (once an hour at most).
	 * @return bool
	 */
	private function data_protected( $data, $live ) {
		$plugin = wpcybersec();
		$web    = '';
		if ( $plugin->hosting ) {
			try {
				$info = $plugin->hosting->current();
				$web  = isset( $info['web_server'] ) ? (string) $info['web_server'] : '';
			} catch ( \Throwable $e ) {
				$web = '';
			}
		}
		$htaccess = (string) @file_get_contents( $data . '/.htaccess', false, null, 0, 4096 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
		if ( in_array( $web, array( 'apache', 'litespeed' ), true ) && false !== stripos( $htaccess, 'Require all denied' ) ) {
			return true;
		}
		if ( $plugin->sysadmin && method_exists( $plugin->sysadmin, 'probe_quarantine_web' ) && ( $live || 'nginx' !== $web ) ) {
			try {
				$probe = $plugin->sysadmin->probe_quarantine_web( false );
				return isset( $probe['result'] ) && 'blocked' === $probe['result'];
			} catch ( \Throwable $e ) {
				return false;
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* By hand                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Address of the no-content package of a version: the core update offer
	 * when it has one for exactly this version, else the release folder.
	 *
	 * @param string $version Version.
	 * @return string
	 */
	public static function package_url( $version ) {
		$version = (string) $version;
		$offers  = get_site_transient( 'update_core' );
		if ( is_object( $offers ) && ! empty( $offers->updates ) ) {
			foreach ( (array) $offers->updates as $offer ) {
				if ( is_object( $offer ) && isset( $offer->version, $offer->locale, $offer->packages ) && $version === (string) $offer->version && 'en_US' === (string) $offer->locale ) {
					$url = is_object( $offer->packages ) && ! empty( $offer->packages->no_content ) ? (string) $offer->packages->no_content : '';
					if ( preg_match( '~^https://downloads\.(?:wordpress|w)\.org/release/wordpress-[0-9a-z.\-]+-no-content\.zip$~i', $url ) ) {
						return $url;
					}
				}
			}
		}
		return sprintf( self::PACKAGE_URL, rawurlencode( $version ) );
	}

	/**
	 * Every step of the reinstall by hand, in the { text, code } shape of
	 * Hosting::steps() (an "other ways" marker before the SSH block). Uses
	 * the hosting detection, so call it only on pages that show the steps.
	 *
	 * @return array[]
	 */
	public function manual_steps() {
		$plugin  = wpcybersec();
		$version = $plugin->scanner ? (string) $plugin->scanner->installed_wp_version() : '';
		$abs     = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$hosting = $plugin->hosting;
		$host    = '';
		$fm      = null;
		if ( $hosting ) {
			try {
				$host = $hosting->manages_core();
				$fm   = $hosting->file_manager();
			} catch ( \Throwable $e ) {
				$host = '';
				$fm   = null;
			}
		}
		$after = self::after_steps();

		if ( 'composer' === self::layout() ) {
			$package = self::composer_package();
			$package = '' !== $package ? $package : 'roots/wordpress';
			$project = wp_normalize_path( dirname( '' !== Paths::home_dir() ? untrailingslashit( Paths::home_dir() ) : $abs ) );
			return array_merge(
				array(
					array( 'text' => __( 'WordPress core is installed with Composer on this site (Bedrock or a similar setup). Do not delete files by hand: reinstall the core package with Composer, which downloads a clean copy of the version in composer.lock.', 'qartvelo-guard' ) ),
					array(
						'text' => __( 'Take a backup of the database and the files first. Then, in the project folder:', 'qartvelo-guard' ),
						'code' => 'cd ' . Sysadmin_Tools::shell_arg( $project ) . "\ncomposer reinstall " . $package,
					),
					array(
						'text' => __( 'With Composer older than 2.1 (no reinstall command), delete the core folder and install again:', 'qartvelo-guard' ),
						'code' => 'rm -rf ' . Sysadmin_Tools::shell_arg( $abs ) . "\ncomposer install",
					),
					array(
						'text' => __( 'Check the result and run a full scan in Qartvelo Guard (Dashboard > Full malware scan):', 'qartvelo-guard' ),
						'code' => Sysadmin_Tools::wp_cli() . ' core verify-checksums',
					),
				),
				$after
			);
		}
		if ( '' !== $host ) {
			return array_merge(
				array(
					/* translators: %s: host name */
					array( 'text' => sprintf( __( '%s manages WordPress core for this site, so its files cannot (or should not) be replaced by hand. Ask its support to reinstall a clean WordPress core, or restore the site from a backup taken before the infection with the host\'s own backup tools.', 'qartvelo-guard' ), $host ) ),
					array( 'text' => __( 'Afterwards run a full scan in Qartvelo Guard (Dashboard > Full malware scan).', 'qartvelo-guard' ) ),
				),
				$after
			);
		}

		$url    = self::package_url( $version );
		$roots  = self::root_files();
		$fm_txt = $fm ? $fm['name'] : __( 'your hosting file manager or an SFTP program (FileZilla, Cyberduck, WinSCP)', 'qartvelo-guard' );
		$steps  = array();

		$steps[] = array( 'text' => __( 'Take a full backup first: the database and every file (your host\'s backup tool or a backup plugin). Keep it until the site has been checked.', 'qartvelo-guard' ) );
		$steps[] = array(
			/* translators: %s: WordPress version */
			'text' => sprintf( __( 'Download the clean WordPress %s package without wp-content (the "no-content" zip, about 25 MB):', 'qartvelo-guard' ), $version ),
			'code' => $url,
		);
		if ( self::is_localized() || 'en_US' !== get_locale() ) {
			$steps[] = array( 'text' => __( 'This site is not in English: that is fine. The no-content package is English, but the language files live in wp-content/languages, which stays untouched, so the site keeps its language. Its wp-includes/version.php is the English one, which is correct.', 'qartvelo-guard' ) );
		}
		if ( $fm ) {
			/* translators: 1: file manager steps, 2: WordPress folder */
			$steps[] = array( 'text' => sprintf( __( '%1$s Go to the WordPress folder: %2$s', 'qartvelo-guard' ), $fm['open'], $abs ) );
		} else {
			/* translators: 1: file manager name, 2: WordPress folder */
			$steps[] = array( 'text' => sprintf( __( 'Open %1$s and go to the WordPress folder: %2$s', 'qartvelo-guard' ), $fm_txt, $abs ) );
		}
		/* translators: %s: upload hint */
		$steps[] = array( 'text' => sprintf( __( 'Upload the zip into the WordPress folder before you delete anything, so the site is down for a minute only. %s', 'qartvelo-guard' ), $fm ? $fm['upload'] : __( 'With SFTP, extract the zip on your computer instead and upload the contents of its "wordpress" folder in the move step below.', 'qartvelo-guard' ) ) );
		$steps[] = array(
			'text' => __( 'Turn on maintenance mode (the "Turn on maintenance mode" button here writes it for you; WordPress lifts it by itself after 10 minutes), or create a file named .maintenance in the WordPress folder with this line:', 'qartvelo-guard' ),
			'code' => '<?php $upgrading = time();',
		);
		$steps[] = array(
			'text' => __( 'Delete these two folders completely:', 'qartvelo-guard' ),
			'code' => "wp-admin\nwp-includes",
		);
		$steps[] = array(
			/* translators: %s: WordPress version */
			'text' => sprintf( __( 'In the WordPress folder delete exactly these files (the core files of WordPress %s, nothing else):', 'qartvelo-guard' ), $version ),
			'code' => implode( "\n", $roots ),
		);
		$keep    = $this->kept_entries( $roots );
		$steps[] = array(
			'text' => __( 'Do NOT delete anything else: wp-config.php, the wp-content folder (plugins, themes, uploads, languages), .htaccess, .user.ini, php.ini, robots.txt, the guard file wpcybersec-guard.php and files of other plugins (for example wordfence-waf.php) stay. Unknown PHP files in the WordPress folder are listed in Reports for a separate review. In this folder that means keeping:', 'qartvelo-guard' ),
			'code' => $keep ? implode( "\n", $keep ) : 'wp-config.php' . "\n" . 'wp-content',
		);
		$steps[] = array( 'text' => $fm ? $fm['extract'] . ' ' . __( 'It creates a folder named "wordpress".', 'qartvelo-guard' ) : __( 'Extract the zip in the WordPress folder. It creates a folder named "wordpress".', 'qartvelo-guard' ) );
		$steps[] = array( 'text' => ( $fm ? $fm['move'] : __( 'Move everything inside the "wordpress" folder one folder up, into the WordPress folder (with SFTP: upload the contents of the extracted "wordpress" folder there).', 'qartvelo-guard' ) ) . ' ' . __( 'wp-admin and wp-includes must end up directly in the WordPress folder, next to wp-config.php.', 'qartvelo-guard' ) );
		$steps[] = array( 'text' => __( 'Delete the zip file, the empty "wordpress" folder and the .maintenance file.', 'qartvelo-guard' ) );
		$steps[] = array( 'text' => __( 'Open the site and log in again, then run a full scan in Qartvelo Guard (Dashboard > Full malware scan). The core reports close by themselves.', 'qartvelo-guard' ) );
		$steps   = array_merge( $steps, $after );

		$steps[] = Hosting::other_ways();
		$steps[] = array(
			'text' => __( 'With SSH: this block checks that it runs in the WordPress folder, downloads the package, compares it with the checksum published next to it, deletes only the core folders and files listed above, copies the clean ones in and cleans up. Paste it as it is (it runs in a subshell, so an error does not close your session):', 'qartvelo-guard' ),
			'code' => $this->ssh_block( $version, $roots ),
		);
		$wpcli = __( 'With WP-CLI, check the result afterwards (it lists every core file that still differs):', 'qartvelo-guard' );
		if ( version_compare( $version, '7.0', '>=' ) ) {
			$wpcli .= ' ' . __( 'Do not use "wp core download --force" for this on WordPress 7.x: it unpacks the .tar.gz package, whose long file paths in wp-includes/php-ai-client get cut, so files go missing.', 'qartvelo-guard' );
		}
		$steps[] = array(
			'text' => $wpcli,
			'code' => Sysadmin_Tools::wp_cli() . ' core verify-checksums',
		);
		return $steps;
	}

	/**
	 * Steps after any core reinstall.
	 *
	 * @return array[]
	 */
	public static function after_steps() {
		return array(
			array(
				'text' => __( 'Afterwards change the password of every administrator account (Users), and replace the secret keys and salts in wp-config.php with new ones (everyone has to log in again). New keys: https://api.wordpress.org/secret-key/1.1/salt/ or with WP-CLI:', 'qartvelo-guard' ),
				'code' => Sysadmin_Tools::wp_cli() . ' config shuffle-salts',
			),
			array( 'text' => __( 'A core reinstall does not clean plugins, themes or uploads: review the remaining reports, update every plugin and theme, and delete the ones you do not use.', 'qartvelo-guard' ) ),
		);
	}

	/**
	 * What stays at the top of the WordPress folder (everything that is not a
	 * core folder or core file), at most 40 names.
	 *
	 * @param string[] $roots Core root files.
	 * @return string[]
	 */
	private function kept_entries( array $roots ) {
		$entries = @scandir( ABSPATH ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$out     = array();
		foreach ( is_array( $entries ) ? $entries : array() as $entry ) {
			if ( '.' === $entry || '..' === $entry || in_array( $entry, self::DIRS, true ) || in_array( $entry, $roots, true ) ) {
				continue;
			}
			$out[] = $entry . ( @is_dir( ABSPATH . $entry ) ? '/' : '' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		sort( $out );
		if ( count( $out ) > 40 ) {
			$out   = array_slice( $out, 0, 40 );
			$out[] = '...';
		}
		return $out;
	}

	/**
	 * The SSH alternative: one block to paste.
	 *
	 * @param string   $version Version.
	 * @param string[] $roots   Core root files.
	 * @return string
	 */
	public function ssh_block( $version, array $roots ) {
		$abs     = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$config  = Config_Editor::path();
		$cfg     = ( '' !== $config && wp_normalize_path( dirname( $config ) ) !== $abs ) ? '../wp-config.php' : 'wp-config.php';
		$content = defined( 'WP_CONTENT_DIR' ) ? untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) : $abs . '/wp-content';
		$content = $abs . '/wp-content' === $content ? 'wp-content' : Sysadmin_Tools::shell_arg( $content );
		$names   = implode( ' ', array_map( array( Sysadmin_Tools::class, 'shell_arg' ), $roots ) );
		$lines   = array(
			'(',
			'set -e',
			'cd ' . Sysadmin_Tools::shell_arg( $abs ),
			'if [ ! -f ' . $cfg . ' ] || [ ! -d ' . $content . ' ]; then echo "Stopped: ' . $cfg . ' or wp-content is missing here, so this is not the WordPress folder."; exit 1; fi',
			'command -v curl >/dev/null || { echo "Stopped: curl is not installed."; exit 1; }',
			"VER='" . preg_replace( '~[^0-9A-Za-z.\-]~', '', (string) $version ) . "'",
			'URL="https://downloads.wordpress.org/release/wordpress-$VER-no-content.zip"',
			'TMP=$(mktemp -d)',
			'curl -fsSL -o "$TMP/wp.zip" "$URL"',
			'SUM=$(curl -fsSL "$URL.sha1")',
			'GOT=$( (sha1sum "$TMP/wp.zip" 2>/dev/null || shasum -a 1 "$TMP/wp.zip") | cut -d" " -f1 )',
			'if [ -z "$SUM" ] || [ "$GOT" != "$SUM" ]; then echo "Stopped: the download does not match its published checksum."; rm -rf "$TMP"; exit 1; fi',
			'if command -v unzip >/dev/null; then unzip -q "$TMP/wp.zip" -d "$TMP"; else php -r \'$z = new ZipArchive(); exit( true === $z->open( $argv[1] ) && $z->extractTo( $argv[2] ) ? 0 : 1 );\' "$TMP/wp.zip" "$TMP"; fi',
			'if [ ! -f "$TMP/wordpress/wp-includes/version.php" ] || [ ! -f "$TMP/wordpress/wp-admin/index.php" ]; then echo "Stopped: the package could not be unpacked."; rm -rf "$TMP"; exit 1; fi',
			'OWNER=$(stat -c "%u:%g" ' . $content . ' 2>/dev/null || stat -f "%u:%g" ' . $content . ')',
			'echo "<?php \$upgrading = $(date +%s);" > .maintenance',
			'rm -rf wp-admin wp-includes',
			'rm -f ' . $names,
			'cp -R "$TMP/wordpress/." .',
			'if [ "$(id -u)" = "0" ]; then chown -R "$OWNER" wp-admin wp-includes ' . $names . '; fi',
			'rm -f .maintenance',
			'rm -rf "$TMP"',
			'echo "Done: the WordPress core files were replaced. Now run a full scan in Qartvelo Guard."',
			')',
		);
		return implode( "\n", $lines );
	}

	/**
	 * Writes ABSPATH/.maintenance (WordPress shows its maintenance page for up
	 * to 10 minutes). An existing file of someone else is left alone.
	 *
	 * @return string written | existing | failed
	 */
	public function maintenance_on() {
		$file = ABSPATH . '.maintenance';
		if ( @is_file( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$code = (string) @file_get_contents( $file, false, null, 0, 4096 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
			if ( false === strpos( $code, self::MAINT_TAG ) ) {
				return 'existing';
			}
		}
		$code = '<?php $upgrading = ' . time() . '; // ' . self::MAINT_TAG . ": WordPress core is being replaced. Delete this file if it is still here after 10 minutes.\n";
		$tmp  = ABSPATH . '.wpcs-maint-' . strtolower( wp_generate_password( 8, false, false ) ) . '.tmp';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- WordPress only reads .maintenance from ABSPATH; temporary file next to it for an atomic replace, on the admin's request.
		if ( strlen( $code ) !== (int) @file_put_contents( $tmp, $code ) || ! Fs::replace( $tmp, $file ) ) {
			Fs::delete( $tmp );
			return 'failed';
		}
		return 'written';
	}

	/**
	 * Removes the .maintenance file this plugin wrote.
	 */
	public function maintenance_off() {
		$file = ABSPATH . '.maintenance';
		$code = (string) @file_get_contents( $file, false, null, 0, 4096 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
		if ( '' !== $code && false !== strpos( $code, self::MAINT_TAG ) ) {
			Fs::delete( $file );
		}
	}

	/* ------------------------------------------------------------------ */
	/* One-click reinstall: job                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * The job state (empty array when none).
	 *
	 * @return array
	 */
	public function state() {
		$state = Network::get_option( self::STATE_OPTION, array() );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * @param array $state State.
	 */
	private function save( array $state ) {
		$state['updated_at'] = time();
		Network::update_option( self::STATE_OPTION, $state, false );
	}

	/**
	 * Whether a job is between start and the end of the swap.
	 *
	 * @param array|null $state State.
	 * @return bool
	 */
	public function is_active( $state = null ) {
		$state = is_array( $state ) ? $state : $this->state();
		return isset( $state['step'] ) && in_array( $state['step'], array( 'download', 'extract', 'verify', 'ready', 'swap', 'finish' ), true );
	}

	/**
	 * Starts a reinstall: checks, then downloads the package.
	 *
	 * @return array|\WP_Error State.
	 */
	public function start() {
		$this->recover();
		$state = $this->state();
		if ( $this->is_active( $state ) && isset( $state['step'] ) && in_array( $state['step'], array( 'swap', 'finish' ), true ) ) {
			// Another request is exchanging the files right now: its work folder must not be removed under it.
			return new \WP_Error( 'wpcybersec_core_busy', __( 'A core reinstall is swapping the files right now. Wait a minute, then look at its status again.', 'qartvelo-guard' ) );
		}
		if ( $this->is_active( $state ) && (int) $state['updated_at'] > time() - 15 * MINUTE_IN_SECONDS ) {
			return $state; // Resume the job that is already there.
		}
		if ( $this->is_active( $state ) ) {
			$this->cleanup( $state );
		}
		$auto = $this->auto_status( true );
		if ( ! $auto['ok'] ) {
			return new \WP_Error( 'wpcybersec_core_' . $auto['code'], $auto['reason'] );
		}
		if ( $this->scan_running() ) {
			return new \WP_Error( 'wpcybersec_core_scan', __( 'A scan is running. Wait until it has finished, then start the reinstall.', 'qartvelo-guard' ) );
		}
		$plugin  = wpcybersec();
		$version = (string) $plugin->scanner->installed_wp_version();
		if ( ! preg_match( '~^\d+\.\d+(?:\.\d+)?$~', $version ) ) {
			/* translators: %s: version */
			return new \WP_Error( 'wpcybersec_core_version', sprintf( __( 'The installed WordPress version (%s) is not a release version, so there is no official package for it.', 'qartvelo-guard' ), '' !== $version ? $version : '?' ) );
		}
		$map = self::checksums( $version );
		if ( ! $map ) {
			/* translators: %s: WordPress version */
			return new \WP_Error( 'wpcybersec_core_checksums', sprintf( __( 'The official checksums of WordPress %s could not be loaded from wordpress.org, so the package could not be verified. Try again later.', 'qartvelo-guard' ), $version ) );
		}
		$places = $this->places( true );
		if ( is_wp_error( $places ) ) {
			return $places;
		}
		$id    = gmdate( 'Ymd-His' ) . '-' . strtolower( wp_generate_password( 6, false, false ) );
		$stage = $places['stage'] . '/' . $id;
		if ( ! Fs::mkdir( $stage, 0700 ) ) {
			/* translators: %s: folder path */
			return new \WP_Error( 'wpcybersec_core_stage', sprintf( __( 'Could not create the folder %s.', 'qartvelo-guard' ), $stage ) );
		}
		$plugin->storage->protect( $places['stage'] );
		$plugin->storage->protect( $stage );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- the verified checksum list next to the package, read back by later steps.
		if ( false === @file_put_contents( $stage . '/checksums.json', wp_json_encode( $map ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Fs::delete_tree( $stage );
			return new \WP_Error( 'wpcybersec_core_stage', __( 'Could not write into the folder for the package.', 'qartvelo-guard' ) );
		}
		$state = array(
			'id'          => $id,
			'step'        => 'download',
			'version'     => $version,
			'locale'      => $plugin->scanner->package_locale(),
			'url'         => self::package_url( $version ),
			'zip'         => '',
			'stage'       => $stage,
			'backup_root' => $places['backup'],
			'sibling'     => ! empty( $places['sibling'] ),
			'cursor'      => 0,
			'total'       => 0,
			'summary'     => array(),
			'journal'     => array(),
			'message'     => '',
			'started_at'  => time(),
			'user'        => get_current_user_id(),
		);
		$this->save( $state );
		/* translators: 1: WordPress version, 2: package address */
		$this->log( 'core_reinstall_started', sprintf( __( 'Started reinstalling WordPress %1$s from %2$s.', 'qartvelo-guard' ), $version, $state['url'] ), array( 'job' => $id ) );
		return $this->download( $state );
	}

	/**
	 * Continues the download, extract and verify steps (and the finish after a swap).
	 *
	 * @return array|\WP_Error State.
	 */
	public function tick() {
		$this->recover();
		$state = $this->state();
		if ( ! $this->is_active( $state ) ) {
			return $state;
		}
		switch ( $state['step'] ) {
			case 'download':
				return $this->download( $state );
			case 'extract':
				return $this->extract( $state );
			case 'verify':
				return $this->verify( $state );
			case 'finish':
				return $this->finish( $state );
		}
		return $state;
	}

	/**
	 * @param array $state State.
	 * @return array|\WP_Error
	 */
	private function download( array $state ) {
		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 300 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- the core package is about 25 MB; a slow host must not stop the download half way.
		}
		$tmp = download_url( $state['url'], 300 );
		if ( is_wp_error( $tmp ) ) {
			/* translators: %s: error message */
			return $this->fail( $state, sprintf( __( 'The package could not be downloaded: %s', 'qartvelo-guard' ), $tmp->get_error_message() ) );
		}
		$zip = $state['stage'] . '/package.zip';
		if ( ! Fs::move( $tmp, $zip ) ) {
			Fs::delete( $tmp );
			return $this->fail( $state, __( 'The downloaded package could not be stored in the work folder.', 'qartvelo-guard' ) );
		}
		// The release folder publishes a .sha1 next to every package: compare when it answers.
		$sha1 = wp_remote_get( $state['url'] . '.sha1', array( 'timeout' => 15 ) );
		$want = is_wp_error( $sha1 ) || 200 !== (int) wp_remote_retrieve_response_code( $sha1 ) ? '' : strtolower( trim( (string) wp_remote_retrieve_body( $sha1 ) ) );
		if ( preg_match( '~^[a-f0-9]{40}$~', $want ) && ! hash_equals( $want, (string) sha1_file( $zip ) ) ) {
			return $this->fail( $state, __( 'The downloaded package does not match the checksum wordpress.org publishes for it. Nothing was changed.', 'qartvelo-guard' ) );
		}
		$state['zip']    = $zip;
		$state['step']   = 'extract';
		$state['cursor'] = 0;
		$this->save( $state );
		return $state;
	}

	/**
	 * Unpacks the package into the work folder, a batch per request.
	 *
	 * @param array $state State.
	 * @return array|\WP_Error
	 */
	private function extract( array $state ) {
		$zip = new \ZipArchive();
		if ( true !== $zip->open( $state['zip'] ) ) {
			return $this->fail( $state, __( 'The downloaded package is not a valid zip file.', 'qartvelo-guard' ) );
		}
		$total = (int) $zip->numFiles;
		$end   = microtime( true ) + self::BUDGET;
		$i     = (int) $state['cursor'];
		$dest  = $state['stage'] . '/files';
		if ( 0 === $i ) {
			// Every name is checked before anything is written: one folder named
			// "wordpress", no "..", no absolute paths, no wp-content.
			for ( $n = 0; $n < $total; $n++ ) {
				$name = (string) $zip->getNameIndex( $n );
				if ( ! self::safe_entry( $name ) ) {
					$zip->close();
					/* translators: %s: name inside the zip */
					return $this->fail( $state, sprintf( __( 'The package contains an unexpected entry (%s). Nothing was changed.', 'qartvelo-guard' ), Signatures::clean_snippet( $name ) ) );
				}
			}
			if ( ! Fs::mkdir( $dest, 0700 ) ) {
				$zip->close();
				return $this->fail( $state, __( 'Could not create the folder for the unpacked files.', 'qartvelo-guard' ) );
			}
		}
		while ( $i < $total && microtime( true ) < $end ) {
			$batch = array();
			for ( $n = 0; $n < 200 && $i < $total; $n++, $i++ ) {
				$name = (string) $zip->getNameIndex( $i );
				if ( '/' !== substr( $name, -1 ) ) {
					$batch[] = $name;
				}
			}
			if ( $batch && ! $zip->extractTo( $dest, $batch ) ) {
				$zip->close();
				return $this->fail( $state, __( 'The package could not be unpacked (disk full or no permission).', 'qartvelo-guard' ) );
			}
		}
		$zip->close();
		$state['cursor'] = $i;
		$state['total']  = $total;
		if ( $i >= $total ) {
			$state['step']   = 'verify';
			$state['cursor'] = 0;
		}
		$this->save( $state );
		return $state;
	}

	/**
	 * A name inside the package that may be unpacked.
	 *
	 * @param string $name Entry name.
	 * @return bool
	 */
	private static function safe_entry( $name ) {
		if ( '' === $name || 0 !== strpos( $name, 'wordpress/' ) || false !== strpos( $name, '\\' ) || false !== strpos( $name, "\0" ) ) {
			return false;
		}
		if ( 0 === strpos( $name, 'wordpress/wp-content/' ) || 'wordpress/wp-content' === rtrim( $name, '/' ) ) {
			return false;
		}
		foreach ( explode( '/', $name ) as $part ) {
			if ( '..' === $part || '.' === $part ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Verifies every unpacked file against the official md5 checksums, and
	 * that nothing else was unpacked. Any difference stops the job with
	 * nothing changed.
	 *
	 * @param array $state State.
	 * @return array|\WP_Error
	 */
	private function verify( array $state ) {
		$map = $this->stage_map( $state );
		if ( ! $map ) {
			return $this->fail( $state, __( 'The checksum list of the job is missing.', 'qartvelo-guard' ) );
		}
		$base  = $state['stage'] . '/files/wordpress/';
		$keys  = array_keys( $map );
		$end   = microtime( true ) + self::BUDGET;
		$i     = (int) $state['cursor'];
		$count = count( $keys );
		while ( $i < $count && microtime( true ) < $end ) {
			$path = $keys[ $i ];
			$file = $base . $path;
			if ( ! @is_file( $file ) || @is_link( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				/* translators: %s: file path */
				return $this->fail( $state, sprintf( __( 'The package is missing %s. Nothing was changed.', 'qartvelo-guard' ), $path ) );
			}
			if ( ! hash_equals( $map[ $path ], (string) md5_file( $file ) ) ) {
				/* translators: %s: file path */
				return $this->fail( $state, sprintf( __( '%s in the package does not match the official checksum. Nothing was changed.', 'qartvelo-guard' ), $path ) );
			}
			++$i;
		}
		$state['cursor'] = $i;
		$state['total']  = $count;
		if ( $i < $count ) {
			$this->save( $state );
			return $state;
		}
		// Nothing more than the listed files may have been unpacked.
		$found = self::list_files( untrailingslashit( $base ) );
		$extra = array_diff( $found, $keys );
		if ( $extra ) {
			/* translators: %s: file path */
			return $this->fail( $state, sprintf( __( 'The package contains %s, which is not in the official checksum list. Nothing was changed.', 'qartvelo-guard' ), Signatures::clean_snippet( (string) reset( $extra ) ) ) );
		}
		foreach ( self::DIRS as $dir ) {
			if ( ! @is_dir( $base . $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				/* translators: %s: folder */
				return $this->fail( $state, sprintf( __( 'The package has no %s folder.', 'qartvelo-guard' ), $dir ) );
			}
		}
		$state['summary'] = $this->summary( $map );
		$state['step']    = 'ready';
		$this->save( $state );
		/* translators: 1: number of files, 2: WordPress version */
		$this->log( 'core_package_verified', sprintf( __( 'Verified all %1$s files of the WordPress %2$s package against the official checksums.', 'qartvelo-guard' ), number_format_i18n( $count ), $state['version'] ), array( 'job' => $state['id'] ) );
		return $state;
	}

	/**
	 * What the swap will do, for the confirmation.
	 *
	 * @param array $map Checksums.
	 * @return array { files, root, unknown, unknown_list, configs }
	 */
	private function summary( array $map ) {
		$abs     = trailingslashit( wp_normalize_path( ABSPATH ) );
		$unknown = array();
		$configs = array();
		foreach ( self::DIRS as $dir ) {
			foreach ( self::list_files( $abs . $dir, $dir . '/' ) as $rel ) {
				if ( ! isset( $map[ $rel ] ) ) {
					$unknown[] = $rel;
					if ( in_array( strtolower( basename( $rel ) ), self::CONFIG_NAMES, true ) ) {
						$configs[] = $rel;
					}
				}
			}
		}
		return array(
			'files'        => count( $map ),
			'root'         => self::root_files( $map ),
			'unknown'      => count( $unknown ),
			'unknown_list' => array_slice( $unknown, 0, 200 ),
			'configs'      => array_slice( $configs, 0, 50 ),
		);
	}

	/**
	 * Every file under a folder (symlinks listed, never followed), as paths
	 * relative to it with $prefix in front.
	 *
	 * @param string $dir    Folder.
	 * @param string $prefix Prefix for the names.
	 * @return string[]
	 */
	private static function list_files( $dir, $prefix = '' ) {
		$out     = array();
		$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		foreach ( is_array( $entries ) ? $entries : array() as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path = $dir . '/' . $entry;
			if ( ! @is_link( $path ) && @is_dir( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$out = array_merge( $out, self::list_files( $path, $prefix . $entry . '/' ) );
			} else {
				$out[] = $prefix . $entry;
			}
		}
		return $out;
	}

	/**
	 * Checksums saved with the job.
	 *
	 * @param array $state State.
	 * @return array
	 */
	private function stage_map( array $state ) {
		$json = (string) @file_get_contents( $state['stage'] . '/checksums.json' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
		$map  = json_decode( $json, true );
		return is_array( $map ) ? $map : array();
	}

	/**
	 * The short request that replaces core: maintenance on, folders and root
	 * files swapped, maintenance off, checks, rollback on any failure.
	 *
	 * @return array|\WP_Error State.
	 */
	public function swap() {
		$this->recover();
		$state = $this->state();
		if ( ! isset( $state['step'] ) || 'ready' !== $state['step'] ) {
			return new \WP_Error( 'wpcybersec_core_step', __( 'The package is not ready yet. Start the reinstall again.', 'qartvelo-guard' ) );
		}
		$this->reset();
		$auto = $this->auto_status();
		if ( ! $auto['ok'] ) {
			return $this->fail( $state, $auto['reason'] );
		}
		if ( $this->scan_running() ) {
			return new \WP_Error( 'wpcybersec_core_scan', __( 'A scan is running. Wait until it has finished, then confirm again.', 'qartvelo-guard' ) );
		}
		$map  = $this->stage_map( $state );
		$src  = $state['stage'] . '/files/wordpress/';
		$name = $state['sibling'] ? '.wpcybersec-core-backup-' . $state['id'] : $state['id'];
		$bak  = untrailingslashit( $state['backup_root'] ) . '/' . $name;
		if ( ! $map || ! @is_dir( $src . 'wp-admin' ) || ! @is_dir( $src . 'wp-includes' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $this->fail( $state, __( 'The unpacked package is gone. Start the reinstall again.', 'qartvelo-guard' ) );
		}
		if ( ! Fs::mkdir( $bak . '/root', 0700 ) ) {
			/* translators: %s: folder path */
			return $this->fail( $state, sprintf( __( 'Could not create the backup folder %s.', 'qartvelo-guard' ), $bak ) );
		}
		if ( ! $state['sibling'] ) {
			wpcybersec()->storage->protect( untrailingslashit( $state['backup_root'] ) );
		}
		wpcybersec()->storage->protect( $bak );
		$roots = self::root_files( $map );
		$added = array();
		foreach ( $roots as $file ) {
			if ( ! @file_exists( ABSPATH . $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$added[] = $file;
			}
		}
		$marker = array(
			'id'      => $state['id'],
			'abspath' => wp_normalize_path( ABSPATH ),
			'version' => $state['version'],
			'locale'  => $state['locale'],
			'at'      => time(),
			'added'   => $added,
			'configs' => array(),
		);
		$this->write_marker( $bak, $marker );

		$plan = array(
			'src'      => $src,
			'src_root' => $src,
			'aside'    => trailingslashit( $bak ),
			'files'    => $roots,
			'remove'   => array(),
		);
		$state['step']    = 'swap';
		$state['backup']  = $bak;
		$state['plan']    = $plan;
		$state['journal'] = array();
		$this->save( $state );

		$result = $this->exchange( $plan, $state, $state['version'] );
		if ( is_wp_error( $result ) ) {
			$data = $result->get_error_data();
			$keep = ! empty( $data['problems'] );
			if ( ! $keep ) {
				Fs::delete_tree( $bak ); // Only the root file copies are left in it.
			}
			// When something could not be put back, the backup and the package stay for a repair by hand.
			return $this->fail( $state, $result->get_error_message(), $keep );
		}
		$state = $this->state();

		// The old folders are in the backup now: server configuration files in them
		// (an attacker's .htaccess could open the backup to the web) are switched off.
		$marker['configs'] = $this->disable_configs( $bak );
		$this->write_marker( $bak, $marker );

		$this->remember_backup( $state, $marker );
		/* translators: 1: WordPress version, 2: backup folder */
		$this->log( 'core_reinstalled', sprintf( __( 'Replaced WordPress core with the verified official %1$s files. The previous core is kept in %2$s for 7 days.', 'qartvelo-guard' ), $state['version'], self::display_path( $bak ) ), array( 'job' => $state['id'] ) );
		$state['step']   = 'finish';
		$state['cursor'] = 0;
		$this->save( $state );
		return $this->finish( $state );
	}

	/**
	 * Swaps wp-admin, wp-includes and the root files, checks the site and rolls
	 * back on any failure. Maintenance mode is on during the swap and off in
	 * every case afterwards.
	 *
	 * @param array  $plan    { src, src_root, aside, files, remove }.
	 * @param array  $state   Job state (the journal is saved in it).
	 * @param string $version Version wp-includes/version.php must report afterwards ('' to skip).
	 * @return true|\WP_Error
	 */
	private function exchange( array $plan, array $state, $version ) {
		// Everything this request still needs from wp-admin is loaded before it moves.
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';
		Fs::direct();
		$pre = $this->loopback();

		$maint          = $this->maintenance_on();
		$this->swapping = array(
			'plan'    => $plan,
			'journal' => array(),
			'done'    => false,
			'state'   => $state,
		);
		register_shutdown_function( array( $this, 'shutdown_guard' ) );

		$error = $this->apply_plan( $plan, $state );
		self::opcache_reset();
		if ( '' === $error ) {
			$this->maintenance_off();
			$check = $this->post_check( $version, $pre );
			if ( ! $check['ok'] ) {
				$error = $check['message'];
			}
		}
		if ( '' !== $error ) {
			$this->maintenance_on();
			$this->journal( null, $state ); // Still alive: the loopback checks took a while, and a status poll must not roll this job back.
			$problems = $this->rollback( $this->swapping['journal'], $plan );
			self::opcache_reset();
			$this->maintenance_off();
			$this->swapping['done'] = true;
			$this->journal( null, $state );
			$after                  = $this->loopback();
			$message                = sprintf(
				/* translators: 1: what failed, 2: HTTP status of the home page after the rollback */
				__( 'The reinstall was undone: %1$s The previous core files are back (home page answers HTTP %2$s).', 'qartvelo-guard' ),
				$error,
				$after > 0 ? (string) $after : '-'
			);
			if ( $problems ) {
				$message .= ' ' . __( 'Some files could not be put back:', 'qartvelo-guard' ) . ' ' . implode( '; ', $problems );
			}
			$this->log( 'core_reinstall_rolled_back', $message, array( 'job' => isset( $state['id'] ) ? $state['id'] : '' ) );
			return new \WP_Error( 'wpcybersec_core_rollback', $message, array( 'problems' => $problems ) );
		}
		if ( 'existing' === $maint ) {
			$this->log( 'core_maintenance_kept', __( 'A .maintenance file that was already there was left in place.', 'qartvelo-guard' ) );
		}
		$this->swapping['done'] = true;
		return true;
	}

	/**
	 * Moves the folders and files of a plan into place, recording each step.
	 *
	 * @param array $plan  Plan.
	 * @param array $state State.
	 * @return string '' when done, else what failed.
	 */
	private function apply_plan( array $plan, array $state ) {
		$abs   = trailingslashit( wp_normalize_path( ABSPATH ) );
		$aside = $plan['aside'];
		foreach ( self::DIRS as $dir ) {
			if ( @file_exists( $abs . $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( ! Fs::rename( $abs . $dir, $aside . $dir ) ) {
					/* translators: %s: folder */
					return sprintf( __( 'Could not move the current %s folder into the backup.', 'qartvelo-guard' ), $dir );
				}
				$this->journal( array( 'dir_out', $dir ), $state );
			}
			if ( ! Fs::rename( $plan['src'] . $dir, $abs . $dir ) ) {
				/* translators: %s: folder */
				return sprintf( __( 'Could not move the new %s folder into place.', 'qartvelo-guard' ), $dir );
			}
			$this->journal( array( 'dir_in', $dir ), $state );
		}
		foreach ( $plan['files'] as $file ) {
			$target = $abs . $file;
			$had    = @is_file( $target ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $had && ! Fs::copy( $target, $aside . 'root/' . $file ) ) {
				/* translators: %s: file name */
				return sprintf( __( 'Could not copy %s into the backup.', 'qartvelo-guard' ), $file );
			}
			if ( ! self::put_file( $plan['src_root'] . $file, $target ) ) {
				/* translators: %s: file name */
				return sprintf( __( 'Could not replace %s.', 'qartvelo-guard' ), $file );
			}
			$this->journal( array( 'file_in', $file, $had ), $state ); // Saved at once, like the folder steps, so recover() can undo it after a hard kill.
		}
		foreach ( $plan['remove'] as $file ) {
			if ( @is_file( $abs . $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( ! Fs::rename( $abs . $file, $aside . 'root/' . $file ) ) {
					/* translators: %s: file name */
					return sprintf( __( 'Could not move %s aside.', 'qartvelo-guard' ), $file );
				}
				$this->journal( array( 'file_removed', $file ), $state );
			}
		}
		$this->journal( null, $state );
		return '';
	}

	/**
	 * Records a step of the swap (saved, so a request that dies can be undone later).
	 *
	 * @param array|null $entry Step, or null to only save.
	 * @param array      $state State.
	 */
	private function journal( $entry, array $state ) {
		if ( null !== $entry ) {
			$this->swapping['journal'][] = $entry;
		}
		$state['journal'] = $this->swapping['journal'];
		$state['plan']    = $this->swapping['plan'];
		$this->save( $state );
	}

	/**
	 * Copies a file next to the target and renames it over the target, so the
	 * file is never missing or half written.
	 *
	 * @param string $from Source.
	 * @param string $to   Target.
	 * @return bool
	 */
	private static function put_file( $from, $to ) {
		$tmp = dirname( $to ) . '/.wpcs-core-' . strtolower( wp_generate_password( 10, false, false ) ) . '.tmp';
		if ( ! Fs::copy( $from, $tmp ) ) {
			Fs::delete( $tmp );
			return false;
		}
		$perms = @fileperms( @is_file( $to ) ? $to : $from ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $perms ) {
			Fs::chmod( $tmp, $perms & 0777 );
		}
		if ( ! Fs::replace( $tmp, $to ) ) {
			Fs::delete( $tmp );
			return false;
		}
		return true;
	}

	/**
	 * Undoes the recorded steps, newest first.
	 *
	 * @param array[] $journal Steps.
	 * @param array   $plan    Plan.
	 * @return string[] Problems (empty when everything is back).
	 */
	private function rollback( array $journal, array $plan ) {
		$abs      = trailingslashit( wp_normalize_path( ABSPATH ) );
		$aside    = $plan['aside'];
		$problems = array();
		foreach ( array_reverse( $journal ) as $step ) {
			$what = isset( $step[0] ) ? (string) $step[0] : '';
			$name = isset( $step[1] ) ? (string) $step[1] : '';
			if ( '' === $name ) {
				continue;
			}
			switch ( $what ) {
				case 'dir_in':
					if ( ! Fs::rename( $abs . $name, $plan['src'] . $name ) ) {
						$problems[] = $name;
					}
					break;
				case 'dir_out':
					if ( ! Fs::rename( $aside . $name, $abs . $name ) ) {
						$problems[] = $name;
					}
					break;
				case 'file_in':
					if ( ! empty( $step[2] ) ) {
						if ( ! self::put_file( $aside . 'root/' . $name, $abs . $name ) ) {
							$problems[] = $name;
						}
					} elseif ( ! Fs::delete( $abs . $name ) ) {
						$problems[] = $name;
					}
					break;
				case 'file_removed':
					if ( ! Fs::rename( $aside . 'root/' . $name, $abs . $name ) ) {
						$problems[] = $name;
					}
					break;
			}
		}
		clearstatcache();
		return $problems;
	}

	/**
	 * Shutdown function of a swap request: when PHP stops in the middle (a
	 * fatal error, max_execution_time), the recorded steps are undone.
	 */
	public function shutdown_guard() {
		if ( ! is_array( $this->swapping ) || ! empty( $this->swapping['done'] ) ) {
			return;
		}
		$this->swapping['done'] = true;
		$problems               = $this->rollback( $this->swapping['journal'], $this->swapping['plan'] );
		self::opcache_reset();
		$this->maintenance_off();
		$state = $this->swapping['state'];
		$error = error_get_last();
		$this->fail(
			$state,
			/* translators: %s: PHP error */
			sprintf( __( 'The request stopped during the swap (%s), so the previous core was put back.', 'qartvelo-guard' ), is_array( $error ) ? Signatures::clean_snippet( (string) $error['message'] ) : '-' ) . ( $problems ? ' ' . implode( '; ', $problems ) : '' ),
			(bool) $problems
		);
	}

	/**
	 * A swap whose request died without its shutdown function (killed) is
	 * undone by the next request that looks at the job.
	 */
	public function recover() {
		$state = $this->state();
		if ( ! isset( $state['step'] ) || 'swap' !== $state['step'] || (int) $state['updated_at'] > time() - self::STALE || empty( $state['plan'] ) ) {
			return;
		}
		$problems = $this->rollback( isset( $state['journal'] ) ? (array) $state['journal'] : array(), (array) $state['plan'] );
		self::opcache_reset();
		$this->maintenance_off();
		$this->fail( $state, __( 'A reinstall stopped in the middle of the swap; the previous core was put back.', 'qartvelo-guard' ) . ( $problems ? ' ' . implode( '; ', $problems ) : '' ), (bool) $problems );
	}

	/**
	 * After the swap: version.php loads and reports the version, and the home
	 * page still answers (no HTTP 5xx; an answer when it answered before).
	 *
	 * @param string $version Expected version ('' to skip).
	 * @param int    $pre     HTTP status of the home page before the swap (0 = no answer).
	 * @return array { ok, message, code, pre, version }
	 */
	private function post_check( $version, $pre ) {
		clearstatcache();
		$file  = ABSPATH . 'wp-includes/version.php';
		$found = '';
		if ( @is_file( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$found = ( static function ( $path ) {
				$wp_version = '';
				include $path;
				return (string) $wp_version;
			} )( $file );
		}
		$code   = $this->loopback();
		$errors = array();
		if ( '' !== (string) $version && $found !== (string) $version ) {
			/* translators: 1: version found, 2: expected version */
			$errors[] = sprintf( __( 'wp-includes/version.php reports %1$s instead of %2$s.', 'qartvelo-guard' ), '' !== $found ? $found : '?', $version );
		}
		if ( $code >= 500 ) {
			/* translators: %d: HTTP status */
			$errors[] = sprintf( __( 'The home page answered HTTP %d.', 'qartvelo-guard' ), $code );
		} elseif ( $code <= 0 && $pre > 0 && $pre < 500 ) {
			$errors[] = __( 'The home page did not answer.', 'qartvelo-guard' );
		}
		$result = array(
			'ok'      => ! $errors,
			'message' => implode( ' ', $errors ),
			'code'    => $code,
			'pre'     => (int) $pre,
			'version' => $found,
		);
		/**
		 * Filters whether the site works after the core swap (false rolls it back).
		 *
		 * @param bool  $ok     Result of the built-in checks.
		 * @param array $result { ok, message, code, pre, version }.
		 */
		$ok = (bool) apply_filters( 'wpcybersec_core_reinstall_check', $result['ok'], $result );
		if ( ! $ok && $result['ok'] ) {
			$result['message'] = __( 'A check added by a filter failed.', 'qartvelo-guard' );
		}
		$result['ok'] = $ok;
		return $result;
	}

	/**
	 * HTTP status of the home page (0 when it does not answer).
	 *
	 * @return int
	 */
	private function loopback() {
		$url      = add_query_arg( 'wpcs_core_check', strtolower( wp_generate_password( 8, false, false ) ), Network::home_url( '/' ) );
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 20,
				'redirection' => 3,
				/** This filter is documented in wp-includes/class-wp-http-streams.php */
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter.
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		return is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
	}

	/**
	 * Clears the opcode cache, so PHP runs the new files right away even with
	 * opcache.validate_timestamps off.
	 */
	private static function opcache_reset() {
		clearstatcache();
		if ( function_exists( 'opcache_reset' ) ) {
			@opcache_reset(); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
	}

	/**
	 * Renames server configuration files inside the backed up folders.
	 *
	 * @param string $bak Backup folder.
	 * @return string[] Disabled files, relative to the backup folder.
	 */
	private function disable_configs( $bak ) {
		$out = array();
		foreach ( self::DIRS as $dir ) {
			foreach ( self::list_files( $bak . '/' . $dir, $dir . '/' ) as $rel ) {
				if ( in_array( strtolower( basename( $rel ) ), self::CONFIG_NAMES, true ) && Fs::rename( $bak . '/' . $rel, $bak . '/' . $rel . self::OFF_SUFFIX ) ) {
					$out[] = $rel;
				}
			}
		}
		return $out;
	}

	/**
	 * Puts the disabled configuration files of a backup back.
	 *
	 * @param string $bak    Backup folder.
	 * @param array  $marker Marker.
	 */
	private function enable_configs( $bak, array $marker ) {
		foreach ( isset( $marker['configs'] ) ? (array) $marker['configs'] : array() as $rel ) {
			$rel = (string) $rel;
			if ( '' !== $rel && false === strpos( $rel, '..' ) ) {
				Fs::rename( $bak . '/' . $rel . self::OFF_SUFFIX, $bak . '/' . $rel );
			}
		}
	}

	/**
	 * After a successful swap: closes the core reports, trusts the new files,
	 * lists the extra files that went into the backup, cleans up and starts a
	 * quick scan.
	 *
	 * @param array $state State.
	 * @return array State.
	 */
	private function finish( array $state ) {
		$plugin = wpcybersec();
		$map    = $this->stage_map( $state );
		$abs    = trailingslashit( wp_normalize_path( ABSPATH ) );
		$bak    = (string) $state['backup'];
		if ( $plugin->scanner ) {
			$plugin->scanner->reset_caches();
		}
		$this->reset();

		// 1. Reports about core files.
		$resolved = 0;
		$removed  = 0;
		foreach ( $this->core_items() as $item ) {
			$kind = self::classify( $item );
			$rel  = $kind['rel'];
			if ( '' === $rel ) {
				continue;
			}
			$in_dir = 1 === preg_match( '~^wp-(?:admin|includes)/~', $rel );
			if ( isset( $map[ $rel ] ) ) {
				$resolution = 'core_reinstalled';
				++$resolved;
			} elseif ( $in_dir && ! @file_exists( $abs . $rel ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$resolution = 'removed_with_core';
				++$removed;
			} else {
				continue;
			}
			$plugin->store->item_update(
				(int) $item['id'],
				array(
					'status'     => Store::STATUS_RESOLVED,
					'decided_by' => (int) $state['user'],
					'decided_at' => Store::now(),
					'details'    => array(
						'resolution'  => $resolution,
						'core_backup' => $state['id'],
					),
				)
			);
		}
		if ( $resolved ) {
			/* translators: %s: number of reports */
			$this->log( 'core_items_resolved', sprintf( _n( 'Closed %s report about a core file: it was replaced by the official file.', 'Closed %s reports about core files: they were replaced by the official files.', $resolved, 'qartvelo-guard' ), number_format_i18n( $resolved ) ), array( 'job' => $state['id'] ) );
		}
		if ( $removed ) {
			/* translators: %s: number of reports */
			$this->log( 'core_items_removed', sprintf( _n( 'Closed %s report about an extra file in wp-admin or wp-includes: removed with the old core (kept in the backup).', 'Closed %s reports about extra files in wp-admin or wp-includes: removed with the old core (kept in the backup).', $removed, 'qartvelo-guard' ), number_format_i18n( $removed ) ), array( 'job' => $state['id'] ) );
		}

		// 2. Extra files that sat in the old folders.
		$extra = array();
		foreach ( self::DIRS as $dir ) {
			foreach ( self::list_files( $bak . '/' . $dir, $dir . '/' ) as $rel ) {
				$rel = preg_replace( '~' . preg_quote( self::OFF_SUFFIX, '~' ) . '$~', '', $rel );
				if ( ! isset( $map[ $rel ] ) ) {
					$extra[] = $rel;
				}
			}
		}
		if ( $extra ) {
			$this->log(
				'core_unknown_moved',
				sprintf(
					/* translators: 1: number of files, 2: list of files */
					_n( '%1$s file that is not part of WordPress was in wp-admin or wp-includes and is now only in the backup: %2$s', '%1$s files that are not part of WordPress were in wp-admin or wp-includes and are now only in the backup: %2$s', count( $extra ), 'qartvelo-guard' ),
					number_format_i18n( count( $extra ) ),
					implode( ', ', array_slice( $extra, 0, 50 ) ) . ( count( $extra ) > 50 ? ', ...' : '' )
				),
				array(
					'job'   => $state['id'],
					'files' => array_slice( $extra, 0, 200 ),
				)
			);
		}

		// 3. The manifest: the new core files are trusted, rows of files that left are dropped.
		$store = $plugin->store;
		foreach ( self::DIRS as $dir ) {
			$store->manifest_delete_prefix( trailingslashit( Paths::rel( $abs . $dir ) ) );
		}
		$rows = array();
		foreach ( array_keys( $map ) as $rel ) {
			$file = $abs . $rel;
			$size = (int) @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$sha  = Scan_Job::fingerprint( $file, $size );
			if ( '' === $sha ) {
				continue;
			}
			$rows[] = array(
				'path'   => Paths::rel( $file ),
				'sha256' => $sha,
				'size'   => $size,
				'mtime'  => (int) @filemtime( $file ), // phpcs:ignore WordPress.PHP.NoSilencedErrors
				'state'  => Store::STATE_TRUSTED,
				'run_id' => 'core',
			);
			if ( count( $rows ) >= 500 ) {
				$store->manifest_upsert_many( $rows );
				$rows = array();
			}
		}
		if ( $rows ) {
			$store->manifest_upsert_many( $rows );
		}

		// 4. The missing core count of the last scan is out of date now.
		$this->refresh_missing();

		// 5. Clean up and scan.
		Fs::delete_tree( $state['stage'] );
		$this->prune_stage_root( $state['stage'] );
		$scan = '';
		if ( $plugin->scan_job ) {
			$started = $plugin->scan_job->start(
				array(
					'mode'    => 'incremental',
					'malware' => true,
					'trigger' => 'update',
				)
			);
			$scan = is_wp_error( $started ) ? '' : (string) $started;
		}
		Store::flush_counts();
		$state['step']    = 'done';
		$state['plan']    = array();
		$state['journal'] = array();
		$state['result']  = array(
			'resolved' => $resolved,
			'removed'  => $removed,
			'extra'    => count( $extra ),
			'configs'  => isset( $state['summary']['configs'] ) ? (array) $state['summary']['configs'] : array(),
			'backup'   => $state['id'],
			'scan'     => $scan,
		);
		$state['message'] = sprintf(
			/* translators: 1: WordPress version, 2: number of closed reports, 3: number of extra files */
			__( 'WordPress %1$s core was replaced with the verified official files. %2$s reports were closed and %3$s extra files from wp-admin and wp-includes went into the backup. A quick scan was started.', 'qartvelo-guard' ),
			$state['version'],
			number_format_i18n( $resolved + $removed ),
			number_format_i18n( count( $extra ) )
		);
		$this->save( $state );
		return $state;
	}

	/**
	 * Updates the missing core file count of the last scan.
	 */
	private function refresh_missing() {
		$plugin = wpcybersec();
		if ( ! $plugin->scan_job || ! $plugin->scanner ) {
			return;
		}
		$last = $plugin->scan_job->last_result();
		if ( $last && isset( $last['missing_core'] ) ) {
			$last['missing_core'] = (int) $plugin->scanner->missing_core_count();
			Network::update_option( Scan_Job::LAST_OPTION, $last, false );
		}
	}

	/**
	 * Stops a job before the swap and removes its files.
	 *
	 * @return array State.
	 */
	public function cancel() {
		$state = $this->state();
		if ( isset( $state['step'] ) && in_array( $state['step'], array( 'swap', 'finish' ), true ) ) {
			return $state; // Too late: the swap decides by itself.
		}
		$this->cleanup( $state );
		Network::delete_option( self::STATE_OPTION );
		if ( $this->is_active( $state ) ) {
			$this->log( 'core_reinstall_cancelled', __( 'Cancelled the core reinstall before anything was changed.', 'qartvelo-guard' ) );
		}
		return array();
	}

	/**
	 * Forgets a finished or failed job (its message was shown).
	 */
	public function dismiss() {
		$state = $this->state();
		if ( ! $this->is_active( $state ) ) {
			$this->cleanup( $state );
			Network::delete_option( self::STATE_OPTION );
		}
	}

	/**
	 * Removes the work folder of a job.
	 *
	 * @param array $state State.
	 */
	private function cleanup( array $state ) {
		if ( ! empty( $state['stage'] ) && false !== strpos( (string) $state['stage'], 'core-stage' ) ) {
			Fs::delete_tree( (string) $state['stage'] );
			$this->prune_stage_root( (string) $state['stage'] );
		}
	}

	/**
	 * Removes the parent of the work folders when it holds nothing but its protection files.
	 *
	 * @param string $stage Work folder of a job.
	 */
	private function prune_stage_root( $stage ) {
		$root    = dirname( (string) $stage );
		$entries = @scandir( $root ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $entries ) || false === strpos( basename( $root ), 'core-stage' ) ) {
			return;
		}
		$left = array_diff( $entries, array( '.', '..', '.htaccess', 'index.php', 'web.config' ) );
		if ( ! $left ) {
			Fs::delete_tree( $root );
		}
	}

	/**
	 * Marks the job failed (nothing changed, or everything rolled back).
	 *
	 * @param array  $state   State.
	 * @param string $message Why.
	 * @param bool   $keep    Keep the work folder (something could not be put back).
	 * @return \WP_Error
	 */
	private function fail( array $state, $message, $keep = false ) {
		if ( ! $keep ) {
			$this->cleanup( $state );
		}
		$state['step']    = 'failed';
		$state['message'] = (string) $message;
		$state['plan']    = array();
		$state['journal'] = array();
		$this->save( $state );
		/* translators: %s: reason */
		$this->log( 'core_reinstall_failed', sprintf( __( 'Core reinstall stopped: %s', 'qartvelo-guard' ), $message ), array( 'job' => isset( $state['id'] ) ? $state['id'] : '' ) );
		return new \WP_Error( 'wpcybersec_core_failed', (string) $message );
	}

	/**
	 * @return bool
	 */
	private function scan_running() {
		$job = wpcybersec()->scan_job;
		if ( ! $job ) {
			return false;
		}
		$status = $job->status();
		return isset( $status['state'] ) && in_array( $status['state'], array( 'enumerating', 'processing', 'finishing' ), true ) && ! $job->is_stalled();
	}

	/* ------------------------------------------------------------------ */
	/* Backups                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $dir    Backup folder.
	 * @param array  $marker Marker data.
	 */
	private function write_marker( $dir, array $marker ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors -- small JSON marker in the plugin's own backup folder.
		@file_put_contents( $dir . '/' . self::MARKER, wp_json_encode( $marker ) );
	}

	/**
	 * @param string $dir Backup folder.
	 * @return array Marker, empty when missing.
	 */
	private function read_marker( $dir ) {
		$json = (string) @file_get_contents( $dir . '/' . self::MARKER ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
		$data = json_decode( $json, true );
		return is_array( $data ) ? $data : array();
	}

	/**
	 * Kept backups, newest first.
	 *
	 * @return array[] { id, dir, at, version, extra, user }
	 */
	public function backups() {
		$list = Network::get_option( self::BACKUPS_OPTION, array() );
		$out  = array();
		foreach ( is_array( $list ) ? $list : array() as $entry ) {
			if ( is_array( $entry ) && ! empty( $entry['id'] ) && ! empty( $entry['dir'] ) ) {
				$out[] = $entry;
			}
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return (int) $b['at'] - (int) $a['at'];
			}
		);
		return $out;
	}

	/**
	 * @param array $state  State.
	 * @param array $marker Marker.
	 */
	private function remember_backup( array $state, array $marker ) {
		$list   = $this->backups();
		$list[] = array(
			'id'      => $state['id'],
			'dir'     => $state['backup'],
			'at'      => time(),
			'version' => $state['version'],
			'extra'   => isset( $state['summary']['unknown'] ) ? (int) $state['summary']['unknown'] : 0,
			'configs' => count( (array) $marker['configs'] ),
			'user'    => (int) $state['user'],
		);
		Network::update_option( self::BACKUPS_OPTION, array_values( $list ), false );
	}

	/**
	 * @param string $id Backup id.
	 */
	private function forget_backup( $id ) {
		$list = array_values(
			array_filter(
				$this->backups(),
				static function ( $entry ) use ( $id ) {
					return (string) $entry['id'] !== (string) $id;
				}
			)
		);
		if ( $list ) {
			Network::update_option( self::BACKUPS_OPTION, $list, false );
		} else {
			Network::delete_option( self::BACKUPS_OPTION );
		}
	}

	/**
	 * A backup entry whose folder still exists and belongs to this site.
	 *
	 * @param string $id Backup id.
	 * @return array|null { entry, marker }
	 */
	private function find_backup( $id ) {
		foreach ( $this->backups() as $entry ) {
			if ( (string) $entry['id'] !== (string) $id ) {
				continue;
			}
			$marker = $this->read_marker( (string) $entry['dir'] );
			if ( isset( $marker['id'], $marker['abspath'] ) && (string) $marker['id'] === (string) $id && wp_normalize_path( (string) $marker['abspath'] ) === wp_normalize_path( ABSPATH ) ) {
				return array(
					'entry'  => $entry,
					'marker' => $marker,
				);
			}
			return null;
		}
		return null;
	}

	/**
	 * Puts the core from before a reinstall back (the replaced, clean core is
	 * deleted afterwards). Same checks and rollback as the reinstall.
	 *
	 * @param string $id Backup id.
	 * @return array|\WP_Error { message, scan }
	 */
	public function restore( $id ) {
		$this->recover();
		$found = $this->find_backup( (string) $id );
		if ( ! $found ) {
			return new \WP_Error( 'wpcybersec_core_backup', __( 'This backup no longer exists.', 'qartvelo-guard' ) );
		}
		$this->reset();
		$auto = $this->auto_status();
		if ( ! $auto['ok'] && ! in_array( $auto['code'], array( 'places' ), true ) ) {
			return new \WP_Error( 'wpcybersec_core_' . $auto['code'], $auto['reason'] );
		}
		if ( $this->scan_running() ) {
			return new \WP_Error( 'wpcybersec_core_scan', __( 'A scan is running. Wait until it has finished, then try again.', 'qartvelo-guard' ) );
		}
		if ( $this->is_active() ) {
			return new \WP_Error( 'wpcybersec_core_busy', __( 'A core reinstall is in progress.', 'qartvelo-guard' ) );
		}
		$bak    = untrailingslashit( (string) $found['entry']['dir'] );
		$marker = $found['marker'];
		foreach ( self::DIRS as $dir ) {
			if ( ! @is_dir( $bak . '/' . $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				/* translators: %s: folder */
				return new \WP_Error( 'wpcybersec_core_backup', sprintf( __( 'The backup has no %s folder, so it cannot be restored.', 'qartvelo-guard' ), $dir ) );
			}
		}
		$replaced = $bak . '/replaced';
		if ( ! Fs::mkdir( $replaced . '/root', 0700 ) ) {
			return new \WP_Error( 'wpcybersec_core_backup', __( 'Could not create a folder inside the backup.', 'qartvelo-guard' ) );
		}
		$this->enable_configs( $bak, $marker );
		$files = array();
		foreach ( self::list_files( $bak . '/root' ) as $name ) {
			if ( false === strpos( $name, '/' ) ) {
				$files[] = $name;
			}
		}
		$plan  = array(
			'src'      => trailingslashit( $bak ),
			'src_root' => trailingslashit( $bak ) . 'root/',
			'aside'    => trailingslashit( $replaced ),
			'files'    => $files,
			'remove'   => array_values( array_diff( isset( $marker['added'] ) ? (array) $marker['added'] : array(), $files ) ),
		);
		$state = array(
			'id'      => 'restore-' . $id,
			'step'    => 'swap',
			'plan'    => $plan,
			'journal' => array(),
			'user'    => get_current_user_id(),
		);
		$this->save( $state );
		$result = $this->exchange( $plan, $state, '' );
		if ( is_wp_error( $result ) ) {
			Network::delete_option( self::STATE_OPTION );
			$data = $result->get_error_data();
			if ( empty( $data['problems'] ) ) {
				$this->disable_configs( $bak );
				Fs::delete_tree( $replaced );
			}
			return $result;
		}
		Network::delete_option( self::STATE_OPTION );

		// The restored files are judged again by the next scan.
		$plugin = wpcybersec();
		$abs    = trailingslashit( wp_normalize_path( ABSPATH ) );
		foreach ( self::DIRS as $dir ) {
			$plugin->store->manifest_delete_prefix( trailingslashit( Paths::rel( $abs . $dir ) ) );
		}
		$hashes = array();
		foreach ( array_merge( $files, $plan['remove'] ) as $name ) {
			$hashes[] = Paths::hash( Paths::rel( $abs . $name ) );
		}
		$plugin->store->manifest_delete( $hashes );
		if ( $plugin->scanner ) {
			$plugin->scanner->reset_caches();
		}
		$this->refresh_missing();
		Fs::delete_tree( $bak );
		$this->forget_backup( $id );
		$scan = '';
		if ( $plugin->scan_job ) {
			$started = $plugin->scan_job->start(
				array(
					'mode'    => 'incremental',
					'malware' => true,
					'trigger' => 'update',
				)
			);
			$scan = is_wp_error( $started ) ? '' : (string) $started;
		}
		$message = __( 'The previous WordPress core was put back and the replaced files were deleted. A quick scan was started; it reports the old core files again.', 'qartvelo-guard' );
		$this->log( 'core_restored_previous', $message, array( 'backup' => $id ) );
		return array(
			'message' => $message,
			'scan'    => $scan,
		);
	}

	/**
	 * Daily: deletes backups older than KEEP_DAYS and work folders of jobs
	 * that were left behind.
	 */
	public function prune() {
		foreach ( $this->backups() as $entry ) {
			if ( (int) $entry['at'] > time() - self::KEEP_DAYS * DAY_IN_SECONDS ) {
				continue;
			}
			$marker = $this->read_marker( (string) $entry['dir'] );
			if ( isset( $marker['id'] ) && (string) $marker['id'] === (string) $entry['id'] ) {
				Fs::delete_tree( (string) $entry['dir'] );
			}
			$this->forget_backup( (string) $entry['id'] );
			/* translators: %s: date */
			$this->log( 'core_backup_deleted', sprintf( __( 'Deleted the backup of the previous WordPress core from %s (kept for 7 days).', 'qartvelo-guard' ), gmdate( 'Y-m-d H:i', (int) $entry['at'] ) . ' UTC' ), array( 'backup' => $entry['id'] ) );
		}
		// A job nobody finished (or its message nobody read) is forgotten after a day; never one in the swap.
		$state   = $this->state();
		$updated = isset( $state['updated_at'] ) ? (int) $state['updated_at'] : 0;
		if ( $state && $updated < time() - DAY_IN_SECONDS && ( ! isset( $state['step'] ) || 'swap' !== $state['step'] ) ) {
			$this->cleanup( $state );
			Network::delete_option( self::STATE_OPTION );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Output helpers                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * A folder for messages: the data folder is never named in full.
	 *
	 * @param string $dir Folder.
	 * @return string
	 */
	public static function display_path( $dir ) {
		$data = wpcybersec()->storage ? untrailingslashit( wp_normalize_path( (string) wpcybersec()->storage->data_dir() ) ) : '';
		$dir  = wp_normalize_path( (string) $dir );
		if ( '' !== $data && 0 === strpos( $dir, $data . '/' ) ) {
			return '[' . __( 'plugin data folder', 'qartvelo-guard' ) . ']/' . substr( $dir, strlen( $data ) + 1 );
		}
		return $dir;
	}

	/**
	 * The text of the confirmation before the swap.
	 *
	 * @param array $state State (step ready).
	 * @return array { title, verdict, text, confirm }
	 */
	public static function confirm_text( array $state ) {
		$sum   = isset( $state['summary'] ) ? (array) $state['summary'] : array();
		$extra = isset( $sum['unknown'] ) ? (int) $sum['unknown'] : 0;
		$text  = sprintf(
			/* translators: 1: number of files, 2: number of root files, 3: number of extra files */
			__( 'All %1$s files of the package match the official checksums. The site goes into maintenance mode for a few seconds; wp-admin, wp-includes and the %2$s core files in the WordPress folder are swapped for the official ones; %3$s extra files in wp-admin and wp-includes go into the backup with the old folders. wp-config.php, wp-content, .htaccess and every other file stay as they are. If the site does not answer afterwards, everything is put back automatically.', 'qartvelo-guard' ),
			number_format_i18n( isset( $sum['files'] ) ? (int) $sum['files'] : 0 ),
			number_format_i18n( isset( $sum['root'] ) ? count( (array) $sum['root'] ) : 0 ),
			number_format_i18n( $extra )
		);
		if ( ! empty( $sum['configs'] ) ) {
			/* translators: %s: list of files */
			$text .= ' ' . sprintf( __( 'Server configuration files you may have added there go into the backup too (put them back by hand if you need them): %s.', 'qartvelo-guard' ), implode( ', ', (array) $sum['configs'] ) );
		}
		return array(
			/* translators: %s: WordPress version */
			'title'   => sprintf( __( 'Reinstall WordPress %s core now?', 'qartvelo-guard' ), (string) $state['version'] ),
			'verdict' => __( 'The previous core is kept as a backup for 7 days and can be restored with one click.', 'qartvelo-guard' ),
			'text'    => $text,
			'confirm' => __( 'Reinstall now', 'qartvelo-guard' ),
		);
	}

	/**
	 * The job as the browser sees it.
	 *
	 * @param array $state State.
	 * @return array
	 */
	public static function public_state( array $state ) {
		$step    = isset( $state['step'] ) ? (string) $state['step'] : '';
		$labels  = array(
			'download' => __( 'Downloading the official package', 'qartvelo-guard' ),
			'extract'  => __( 'Unpacking', 'qartvelo-guard' ),
			'verify'   => __( 'Checking every file against the official checksums', 'qartvelo-guard' ),
			'ready'    => __( 'Ready: every file verified', 'qartvelo-guard' ),
			'swap'     => __( 'Replacing core', 'qartvelo-guard' ),
			'finish'   => __( 'Closing reports and trusting the new files', 'qartvelo-guard' ),
			'done'     => __( 'Done', 'qartvelo-guard' ),
			'failed'   => __( 'Stopped', 'qartvelo-guard' ),
		);
		$weights = array(
			'download' => 5,
			'extract'  => 20,
			'verify'   => 60,
			'ready'    => 85,
			'swap'     => 90,
			'finish'   => 95,
			'done'     => 100,
			'failed'   => 100,
		);
		$percent = isset( $weights[ $step ] ) ? $weights[ $step ] : 0;
		$total   = isset( $state['total'] ) ? (int) $state['total'] : 0;
		if ( $total > 0 && in_array( $step, array( 'extract', 'verify' ), true ) ) {
			$span    = 'extract' === $step ? 40 : 25;
			$percent = $weights[ $step ] + (int) floor( $span * min( 1, ( isset( $state['cursor'] ) ? (int) $state['cursor'] : 0 ) / $total ) );
		}
		$out = array(
			'step'    => $step,
			'label'   => isset( $labels[ $step ] ) ? $labels[ $step ] : '',
			'percent' => min( 100, $percent ),
			'message' => isset( $state['message'] ) ? (string) $state['message'] : '',
			'version' => isset( $state['version'] ) ? (string) $state['version'] : '',
		);
		if ( 'ready' === $step ) {
			$out['confirm'] = self::confirm_text( $state );
		}
		if ( 'done' === $step && isset( $state['result'] ) ) {
			$out['result'] = $state['result'];
		}
		return $out;
	}

	/**
	 * @param string $event   Event.
	 * @param string $message Message.
	 * @param array  $context Context.
	 */
	private function log( $event, $message, array $context = array() ) {
		if ( wpcybersec()->logger ) {
			wpcybersec()->logger->log( $event, $message, $context );
		}
	}

	/* ------------------------------------------------------------------ */
	/* AJAX                                                                */
	/* ------------------------------------------------------------------ */

	/**
	 * Nonce + capability gate.
	 */
	private function guard() {
		if ( ! check_ajax_referer( Ajax::NONCE, '_ajax_nonce', false ) ) {
			wp_send_json_error( array( 'message' => __( 'Your session expired. Reload the page and try again.', 'qartvelo-guard' ) ), 403 );
		}
		if ( ! Admin\Admin::can() ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'qartvelo-guard' ) ), 403 );
		}
	}

	/**
	 * @param string $key Request key.
	 * @return string
	 */
	private function param( $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
		return isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '';
	}

	/**
	 * AJAX core_reinstall: do=start|tick|swap|cancel|status|dismiss.
	 */
	public function ajax_core_reinstall() {
		$this->guard();
		$do = $this->param( 'do' );
		switch ( $do ) {
			case 'start':
				$result = $this->start();
				break;
			case 'tick':
				$result = $this->tick();
				break;
			case 'swap':
				$result = $this->swap();
				break;
			case 'cancel':
				$result = $this->cancel();
				break;
			case 'dismiss':
				$this->dismiss();
				$result = array();
				break;
			default:
				$this->recover();
				$result = $this->state();
		}
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		$out = self::public_state( (array) $result );
		if ( 'done' === $out['step'] && wpcybersec()->scan_job ) {
			$out['scan'] = wpcybersec()->scan_job->status();
		}
		wp_send_json_success( $out );
	}

	/**
	 * AJAX core_restore: id=<backup id>.
	 */
	public function ajax_core_restore() {
		$this->guard();
		$result = $this->restore( $this->param( 'id' ) );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		wp_send_json_success( $result );
	}

	/**
	 * AJAX core_maintenance: writes .maintenance for the steps by hand.
	 */
	public function ajax_core_maintenance() {
		$this->guard();
		$result = $this->maintenance_on();
		if ( 'failed' === $result ) {
			wp_send_json_error( array( 'message' => __( 'Could not write the .maintenance file. Create it by hand with the line shown in the steps.', 'qartvelo-guard' ) ) );
		}
		$this->log( 'core_maintenance_on', __( 'Turned on maintenance mode for a core reinstall by hand (.maintenance in the WordPress folder; WordPress lifts it after 10 minutes).', 'qartvelo-guard' ) );
		wp_send_json_success(
			array(
				'message' => 'existing' === $result
					? __( 'A .maintenance file was already there; it was left as it is.', 'qartvelo-guard' )
					: __( 'Maintenance mode is on: visitors and this admin see the maintenance message until .maintenance is deleted or 10 minutes have passed. Keep this page open for the steps.', 'qartvelo-guard' ),
			)
		);
	}
}
