<?php
/**
 * Damaged WordPress core: detection, the reinstall by WordPress's own updater, the steps by hand.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * When a scan finds changed, infected or missing files in the WordPress core,
 * a clean copy of every core file is faster and safer than reviewing them one
 * by one. The plugin never creates or overwrites a file in wp-admin,
 * wp-includes or among the core files of the WordPress folder itself (it
 * only moves a reported file that is not critical out, into quarantine, when
 * an administrator or the automatic quarantine decides so, and does not put
 * it back there): the reinstall is done by WordPress's own
 * Core_Upgrader, the code behind Dashboard > Updates > "Re-install version X".
 * This class:
 *
 *   damage()        counts open items in core paths (one indexed query on the
 *                   items table, only on pages that show the result) plus the
 *                   missing core files of the last scan, and says whether to
 *                   suggest a reinstall: from one changed, infected or missing
 *                   core file on (THRESHOLD, filter
 *                   wpcybersec_core_damage_threshold), and always for an extra
 *                   executable file inside wp-admin/ or wp-includes/;
 *   reinstall()     checks that WordPress may update itself here
 *                   (auto_status()), takes the offer of the installed version
 *                   and locale from the core update data (or builds the same
 *                   object) with the response "reinstall", and runs
 *                   Core_Upgrader::upgrade() with it. WordPress downloads its
 *                   package, turns its own maintenance mode on and off and
 *                   overwrites its own files. Afterwards the reports about
 *                   files that match the official checksums again are closed
 *                   and a quick scan is started. A reinstall only overwrites
 *                   files: files that are not part of WordPress stay where they
 *                   are and stay reported, for the usual per-file decisions;
 *   manual_steps()  the by-hand way: back up, download the no-content zip of
 *                   this exact version, delete wp-admin, wp-includes and the
 *                   core root files listed in the official checksums, upload
 *                   and extract, scan (hosting panel's file manager named
 *                   when known; an SSH block and a WP-CLI note as other ways;
 *                   Composer and host-managed core get their own advice).
 *
 * State: option RESULT_OPTION (not autoloaded) holds the outcome of the last
 * reinstall until it is dismissed or a day old. prune() also removes what the
 * plugin's own core swap of versions up to 1.1.4 left behind (expired backups
 * of a replaced core, its work folder and its two options); nothing restores them.
 */
class Core_Repair {

	/** Changed, infected or missing core files from which a reinstall is suggested. */
	const THRESHOLD = 1;

	/** Outcome of the last reinstall { ok, message, version, closed, extra, at, user } (not autoloaded). */
	const RESULT_OPTION = 'wpcybersec_core_result';

	/** Job state of the plugin's own core swap in versions up to 1.1.4: only deleted. */
	const LEGACY_STATE_OPTION = 'wpcybersec_core_reinstall';

	/** Backups of a replaced core that versions up to 1.1.4 kept: only deleted when expired. */
	const LEGACY_BACKUPS_OPTION = 'wpcybersec_core_backups';

	/** Days such a backup is kept before prune() deletes it. */
	const LEGACY_KEEP_DAYS = 7;

	/** Marker file in every such backup folder (JSON). */
	const LEGACY_MARKER = '.wpcybersec-core-backup';

	/** Release folder of wordpress.org (packages of every version and locale). */
	const RELEASE_URL = 'https://downloads.wordpress.org/release/';

	/** The official package without wp-content. */
	const PACKAGE_URL = 'https://downloads.wordpress.org/release/wordpress-%s-no-content.zip';

	/** Core folders. */
	const DIRS = array( 'wp-includes', 'wp-admin' );

	/** Root files of WordPress when the checksums cannot be loaded. */
	const ROOT_FALLBACK = array( 'index.php', 'license.txt', 'readme.html', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php' );

	/** @var array|null damage() result for this request. */
	private $damage = null;

	/** @var array|null auto_status() result for this request. */
	private $auto = null;

	public function register() {
		add_action( 'wp_ajax_wpcybersec_core_reinstall', array( $this, 'ajax_core_reinstall' ) );
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
	 * "repairable" is what a reinstall puts right (changed, infected and
	 * missing core files); "unknown" files are not part of WordPress and are
	 * not removed by a reinstall.
	 *
	 * @return array { modified, threats, unknown, unknown_exec, missing, repairable, total, show, ids, threshold, version }
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
			'repairable'   => 0,
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
		$out['repairable'] = $out['modified'] + $out['threats'] + $out['missing'];
		$out['total']      = $out['repairable'] + $out['unknown'];
		$out['show']       = $out['repairable'] >= $out['threshold'] || $out['unknown_exec'] > 0;
		$out['version']    = $plugin->scanner ? (string) $plugin->scanner->installed_wp_version() : '';
		$this->damage      = $out;
		return $out;
	}

	/**
	 * Forgets the damage() and auto_status() results of this request.
	 */
	public function reset() {
		$this->damage = null;
		$this->auto   = null;
	}

	/**
	 * Number of changed, infected or missing core files from which a reinstall is suggested.
	 *
	 * @return int
	 */
	public static function threshold() {
		/**
		 * Filters how many damaged core files make the plugin suggest a core reinstall.
		 *
		 * @param int $threshold Default THRESHOLD (1).
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
		$found = array();
		// One fixed statement per root (the WordPress folder as given and resolved, usually the same folder).
		foreach ( self::roots() as $root ) {
			$like = $wpdb->esc_like( $root );
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, type, status, severity, path, original_path, quarantine_path, sha256, size, mime, source, user_id, ip, details, created_at, updated_at, decided_by, decided_at FROM %i WHERE type IN (%s, %s) AND status = %s AND quarantine_path = '' AND source <> %s AND ( original_path LIKE %s OR original_path LIKE %s OR ( original_path LIKE %s AND original_path NOT LIKE %s ) ) ORDER BY id ASC LIMIT 5000", $table, Store::TYPE_FILE, Store::TYPE_THREAT, Store::STATUS_PENDING, Store::SOURCE_DATABASE, $like . 'wp-admin/%', $like . 'wp-includes/%', $like . '%', $like . '%/%' ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
			foreach ( is_array( $rows ) ? $rows : array() as $row ) {
				$found[ (int) $row['id'] ] = $row;
			}
		}
		// The same rows as one statement over every root: the oldest 5000, by id.
		ksort( $found, SORT_NUMERIC );
		return array_map( array( Store::class, 'decode_item' ), array_slice( array_values( $found ), 0, 5000 ) );
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
	 * Path relative to the WordPress folder ('' when outside it).
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
	 * The WordPress folder as given and resolved, with a trailing slash.
	 *
	 * @return string[]
	 */
	private static function roots() {
		$roots = array( Paths::wp_root() );
		$real  = realpath( Paths::wp_root() );
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
	 * What a reinstall does to translation files on a localized package: the
	 * package is the full one (localized releases have no "no-content" build),
	 * and update_core() copies its wp-content/languages over the files that are
	 * there. One sentence for the card, the confirmation and the report.
	 *
	 * @return string
	 */
	public static function languages_text() {
		return __( 'This site was installed from a localized WordPress package, so WordPress\'s own translation files in wp-content/languages are replaced by those of the package; WordPress then offers newer translations again under Dashboard > Updates.', 'qartvelo-guard' );
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
	/* How core is installed, and whether WordPress may reinstall it here  */
	/* ------------------------------------------------------------------ */

	/**
	 * How WordPress core is installed: standard, composer (Bedrock, a Composer
	 * package), symlink (wp-admin or wp-includes is a link) or custom (WPINC
	 * renamed).
	 *
	 * @return string
	 */
	public static function layout() {
		$abs = Paths::wp_root();
		if ( 'wp-includes' !== WPINC ) {
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
	 * or two folders above the WordPress folder ('' when none).
	 *
	 * @return string Package name, or "composer" when only the layout says so.
	 */
	public static function composer_package() {
		$abs = untrailingslashit( Paths::wp_root() );
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
	 * Whether WordPress may reinstall its core here from the plugin, and why not.
	 *
	 * @return array { ok: bool, reason: string, code: string }
	 */
	public function auto_status() {
		if ( null === $this->auto ) {
			$this->auto = $this->auto_check();
		}
		return $this->auto;
	}

	/**
	 * @return array See auto_status().
	 */
	private function auto_check() {
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
			return $no( 'freeze', __( 'The freeze lock is on, so WordPress may not change files. Unlock file changes for a few minutes on the Dashboard (Protection > Freeze lock), then try again.', 'qartvelo-guard' ) );
		}
		if ( ! wp_is_file_mod_allowed( 'capability_update_core' ) ) {
			return $no( 'file_mods', __( 'File changes are switched off on this site (the file_mod_allowed filter), so WordPress may not reinstall itself. Use the steps by hand.', 'qartvelo-guard' ) );
		}
		switch ( self::layout() ) {
			case 'composer':
				return $no( 'composer', __( 'WordPress core is installed with Composer here. Reinstall it with Composer (see the steps), not with the WordPress updater.', 'qartvelo-guard' ) );
			case 'symlink':
				return $no( 'symlink', __( 'wp-admin or wp-includes is a symbolic link on this server (a shared or managed core), so it is not reinstalled from WordPress.', 'qartvelo-guard' ) );
			case 'custom':
				return $no( 'custom', __( 'This site renames the wp-includes folder (WPINC), which the official package does not.', 'qartvelo-guard' ) );
		}
		$host = $plugin->hosting ? $plugin->hosting->manages_core() : '';
		if ( '' !== $host ) {
			/* translators: %s: host name */
			return $no( 'managed', sprintf( __( '%s manages WordPress core for this site. Ask its support, or use its restore tools.', 'qartvelo-guard' ), $host ) );
		}
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( 'direct' !== get_filesystem_method( array(), Paths::wp_root(), false ) ) {
			return $no( 'fs', self::credentials_text() );
		}
		return array(
			'ok'     => true,
			'reason' => '',
			'code'   => '',
		);
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
		$abs     = untrailingslashit( Paths::wp_root() );
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
			'text' => __( 'Turn on maintenance mode: create a file named .maintenance in the WordPress folder with this line (WordPress lifts it by itself after 10 minutes):', 'qartvelo-guard' ),
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
		$abs     = Paths::wp_root();
		$entries = @scandir( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$out     = array();
		foreach ( is_array( $entries ) ? $entries : array() as $entry ) {
			if ( '.' === $entry || '..' === $entry || in_array( $entry, self::DIRS, true ) || in_array( $entry, $roots, true ) ) {
				continue;
			}
			$out[] = $entry . ( @is_dir( $abs . $entry ) ? '/' : '' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
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
		$abs     = untrailingslashit( Paths::wp_root() );
		$config  = Config_Editor::path();
		$cfg     = ( '' !== $config && wp_normalize_path( dirname( $config ) ) !== $abs ) ? '../wp-config.php' : 'wp-config.php';
		// The commands run inside the WordPress folder: wp-content by its name there when it is directly inside, else by its full path.
		$content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
		$content = Sysadmin_Tools::shell_arg( dirname( $content ) === $abs ? basename( $content ) : $content );
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

	/* ------------------------------------------------------------------ */
	/* Reinstall by WordPress's own updater                                */
	/* ------------------------------------------------------------------ */

	/**
	 * Why WordPress's updater cannot be started from here when it would ask for FTP details.
	 *
	 * @return string
	 */
	private static function credentials_text() {
		return __( 'WordPress cannot write its own files directly on this server: it asks for FTP details when it updates. The plugin does not ask for them. Open Dashboard > Updates and press "Re-install" there; WordPress asks for the details itself.', 'qartvelo-guard' );
	}

	/**
	 * Dashboard > Updates (Network Admin on multisite).
	 *
	 * @return string
	 */
	public static function updates_url() {
		return network_admin_url( 'update-core.php' );
	}

	/**
	 * Whether an address is a package in the release folder of wordpress.org.
	 *
	 * @param mixed $url Address.
	 * @return bool
	 */
	private static function is_release_url( $url ) {
		return is_string( $url ) && false === strpos( $url, '..' ) && 1 === preg_match( '~^https://downloads\.(?:wordpress|w)\.org/release/[0-9A-Za-z_./\-]+\.zip$~', $url );
	}

	/**
	 * The update offer that makes Core_Upgrader reinstall a version: the offer
	 * WordPress itself holds for exactly this version and locale
	 * (find_core_update(), what wp-admin/update-core.php uses for its
	 * "Re-install" button), or the same object built from the release folder
	 * of wordpress.org when the site is not on the newest release and so has no
	 * such offer. The response is "reinstall", as do_core_upgrade( true ) sets it.
	 *
	 * @param string $version Installed version.
	 * @param string $locale  Locale of the installed package (Scanner::package_locale()).
	 * @return object
	 */
	public static function offer( $version, $locale ) {
		$version = (string) $version;
		$locale  = '' !== (string) $locale ? (string) $locale : 'en_US';
		if ( ! function_exists( 'find_core_update' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$found = find_core_update( $version, $locale );
		if ( is_object( $found ) && isset( $found->packages ) && is_object( $found->packages ) ) {
			$official = isset( $found->packages->full ) && self::is_release_url( $found->packages->full );
			foreach ( get_object_vars( $found->packages ) as $package ) {
				if ( is_string( $package ) && '' !== $package && ! self::is_release_url( $package ) ) {
					$official = false;
				}
			}
			if ( $official ) {
				$offer           = clone $found;
				$offer->packages = clone $found->packages;
				$offer->response = 'reinstall';
				return $offer;
			}
		}
		$base = self::RELEASE_URL . ( 'en_US' === $locale ? '' : rawurlencode( $locale ) . '/' ) . 'wordpress-' . rawurlencode( $version );
		return (object) array(
			'response'        => 'reinstall',
			'download'        => $base . '.zip',
			'locale'          => $locale,
			'packages'        => (object) array(
				'full'        => $base . '.zip',
				// Localized releases are published as the full package only.
				'no_content'  => 'en_US' === $locale ? $base . '-no-content.zip' : false,
				'new_bundled' => false,
				'partial'     => false,
				'rollback'    => false,
			),
			'current'         => $version,
			'version'         => $version,
			'php_version'     => isset( $GLOBALS['required_php_version'] ) ? (string) $GLOBALS['required_php_version'] : '',
			'mysql_version'   => isset( $GLOBALS['required_mysql_version'] ) ? (string) $GLOBALS['required_mysql_version'] : '',
			'new_bundled'     => '',
			'partial_version' => '',
		);
	}

	/**
	 * Reinstalls the installed WordPress version with WordPress's own updater
	 * (Core_Upgrader, the code behind Dashboard > Updates > "Re-install"). The
	 * plugin writes no core file itself: WordPress downloads its package,
	 * turns its maintenance mode on and off and overwrites its own files.
	 * wp-config.php, plugins, themes and uploads are not part of that. On a
	 * localized package (the full one) update_core() also copies the package's
	 * wp-content/languages over WordPress's own translation files;
	 * Install_Gate re-trusts that folder with the core folders. Files that are
	 * not part of WordPress are not removed: they stay reported.
	 *
	 * Call it only after the capability and the nonce were checked (the AJAX
	 * handler here) or from WP-CLI.
	 *
	 * @return array|\WP_Error { ok, message, version, closed, extra, scan, at, user }
	 */
	public function reinstall() {
		$this->reset();
		$auto = $this->auto_status();
		if ( ! $auto['ok'] ) {
			return new \WP_Error( 'wpcybersec_core_' . $auto['code'], $auto['reason'] );
		}
		if ( $this->scan_running() ) {
			return new \WP_Error( 'wpcybersec_core_scan', __( 'A scan is running. Wait until it has finished, then start the reinstall.', 'qartvelo-guard' ) );
		}
		$plugin  = wpcybersec();
		$version = $plugin->scanner ? (string) $plugin->scanner->installed_wp_version() : '';
		if ( ! preg_match( '~^\d+\.\d+(?:\.\d+)?$~', $version ) ) {
			/* translators: %s: version */
			return new \WP_Error( 'wpcybersec_core_version', sprintf( __( 'The installed WordPress version (%s) is not a release version, so there is no official package for it.', 'qartvelo-guard' ), '' !== $version ? $version : '?' ) );
		}
		$locale = (string) $plugin->scanner->package_locale();
		$offer  = self::offer( $version, $locale );

		if ( ! class_exists( 'Core_Upgrader', false ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		}
		$upgrader = new \Core_Upgrader( new \WP_Ajax_Upgrader_Skin() );
		// The updater's progress messages go to its skin; anything printed on the way must not reach an AJAX answer.
		$level = ob_get_level();
		ob_start();
		try {
			$result = $upgrader->upgrade( $offer );
		} catch ( \Throwable $e ) {
			$result = new \WP_Error( 'wpcybersec_core_exception', $e->getMessage() );
		}
		while ( ob_get_level() > $level ) {
			ob_end_clean();
		}

		if ( ! is_string( $result ) || '' === $result ) {
			$error = self::credentials_text(); // false: WordPress could not connect to the filesystem without asking for details.
			if ( is_wp_error( $result ) ) {
				$error = (string) $result->get_error_message();
				$data  = $result->get_error_data();
				if ( is_string( $data ) && '' !== $data ) {
					$error .= ' (' . $data . ')';
				}
				// The updater's own text: plain, and never longer than a short paragraph.
				$error = wp_html_excerpt( $error, 600, '...' );
			}
			/* translators: 1: WordPress version, 2: error message of the WordPress updater */
			$message = sprintf( __( 'WordPress could not reinstall its %1$s core: %2$s', 'qartvelo-guard' ), $version, $error );
			$this->remember( false, $message, $version, 0, 0 );
			$this->log( 'core_reinstall_failed', $message, array( 'version' => $version ) );
			return new \WP_Error( 'wpcybersec_core_failed', $message );
		}

		// What the plugin remembers about core is out of date now.
		$this->reset();
		if ( $plugin->scanner ) {
			$plugin->scanner->reset_caches();
			// A remembered "checksums could not be loaded" must not keep the scan from verifying the new files.
			$key = Scanner::CORE_TRANSIENT . md5( $version . '|' . $locale );
			if ( ! is_array( get_site_transient( $key ) ) ) {
				delete_site_transient( $key );
			}
		}
		$closed = $this->close_repaired();
		$this->refresh_missing();
		Store::flush_counts();
		$this->reset();
		$damage = $this->damage();
		$extra  = (int) $damage['unknown'];

		// The usual quick scan judges every replaced file again.
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

		$message = sprintf(
			/* translators: %s: WordPress version */
			__( 'WordPress reinstalled its %s core from the official package (the same as Dashboard > Updates > Re-install).', 'qartvelo-guard' ),
			$version
		);
		if ( $closed ) {
			/* translators: %s: number of reports */
			$message .= ' ' . sprintf( _n( '%s report about a core file was closed: the file matches the official checksum again.', '%s reports about core files were closed: the files match the official checksums again.', $closed, 'qartvelo-guard' ), number_format_i18n( $closed ) );
		}
		$message .= ' ' . ( '' !== $scan ? __( 'A quick scan was started.', 'qartvelo-guard' ) : __( 'Run a quick scan now.', 'qartvelo-guard' ) );
		$this->log(
			'core_reinstalled',
			$message . ( $extra ? ' ' . self::extra_text( $extra, '' ) : '' ),
			array(
				'version' => $version,
				'locale'  => $locale,
				'closed'  => $closed,
				'extra'   => $extra,
			)
		);
		return array_merge( $this->remember( true, $message, $version, $closed, $extra ), array( 'scan' => $scan ) );
	}

	/**
	 * The sentence about files a reinstall does not remove.
	 *
	 * @param int    $count   Reported files in wp-admin or wp-includes that are not part of WordPress.
	 * @param string $context reports (the list is on the same page) | anything else.
	 * @return string '' when there are none.
	 */
	public static function extra_text( $count, $context = '' ) {
		$count = (int) $count;
		if ( $count <= 0 ) {
			return '';
		}
		if ( 'reports' === $context ) {
			/* translators: %s: number of files */
			return sprintf( _n( '%s file that is not part of WordPress is still in wp-admin or wp-includes: review it below.', '%s files that are not part of WordPress are still in wp-admin or wp-includes: review them below.', $count, 'qartvelo-guard' ), number_format_i18n( $count ) );
		}
		/* translators: %s: number of files */
		return sprintf( _n( '%s file that is not part of WordPress is still in wp-admin or wp-includes: review it in Reports.', '%s files that are not part of WordPress are still in wp-admin or wp-includes: review them in Reports.', $count, 'qartvelo-guard' ), number_format_i18n( $count ) );
	}

	/**
	 * Closes the open reports about core files that match their official
	 * checksum again (the resolution a scan gives a flagged file that verifies)
	 * and trusts those files in the manifest. Only reads files.
	 *
	 * @return int Reports closed.
	 */
	private function close_repaired() {
		$plugin = wpcybersec();
		if ( ! $plugin->scanner || ! $plugin->store ) {
			return 0;
		}
		$closed = 0;
		$seen   = array();
		foreach ( $this->core_items() as $item ) {
			$rel = (string) $item['path'];
			$abs = '' !== (string) $item['original_path'] ? wp_normalize_path( (string) $item['original_path'] ) : Paths::abs( $rel );
			if ( '' === $rel || isset( $seen[ $rel ] ) || '' === self::core_rel( $abs ) ) {
				continue;
			}
			$seen[ $rel ] = true;
			clearstatcache( true, $abs );
			if ( ! @is_file( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			$sha    = Scan_Job::fingerprint( $abs );
			$verify = '' !== $sha ? $plugin->scanner->verify_details( $rel, $sha ) : array();
			if ( ! isset( $verify['verdict'], $verify['source'] ) || 'match' !== $verify['verdict'] || 'core' !== $verify['source'] ) {
				continue;
			}
			$closed += (int) $plugin->store->items_resolve_open( $rel, 'now_trusted' );
			if ( $plugin->file_monitor ) {
				$plugin->file_monitor->trust_file( $abs, $sha );
			}
		}
		return $closed;
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
	/* Outcome of the last reinstall                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Saves the outcome for the card on the next page load.
	 *
	 * @param bool   $ok      Whether WordPress reinstalled its core.
	 * @param string $message What happened.
	 * @param string $version WordPress version.
	 * @param int    $closed  Reports closed.
	 * @param int    $extra   Reported files in wp-admin or wp-includes that are not part of WordPress.
	 * @return array The saved outcome.
	 */
	private function remember( $ok, $message, $version, $closed, $extra ) {
		$result = array(
			'ok'      => (bool) $ok,
			'message' => (string) $message,
			'version' => (string) $version,
			'closed'  => (int) $closed,
			'extra'   => (int) $extra,
			'at'      => time(),
			'user'    => get_current_user_id(),
		);
		Network::update_option( self::RESULT_OPTION, $result, false );
		return $result;
	}

	/**
	 * Outcome of the last reinstall (empty array when none, or dismissed).
	 *
	 * @return array { ok, message, version, closed, extra, at, user }
	 */
	public function last_result() {
		$result = Network::get_option( self::RESULT_OPTION, array() );
		return is_array( $result ) && isset( $result['ok'], $result['message'] ) ? $result : array();
	}

	/**
	 * Forgets the outcome (its message was read).
	 */
	public function dismiss() {
		Network::delete_option( self::RESULT_OPTION );
	}

	/* ------------------------------------------------------------------ */
	/* Leftovers of versions up to 1.1.4                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Daily: forgets an outcome nobody dismissed after a day, and removes what
	 * the plugin's own core swap of versions up to 1.1.4 left in its data
	 * folder (or next to the WordPress folder): backups of a replaced core once
	 * they are LEGACY_KEEP_DAYS old, the work folder of an unfinished job and
	 * the two options. Nothing is restored from them.
	 */
	public function prune() {
		$result = $this->last_result();
		if ( $result && ( ! isset( $result['at'] ) || (int) $result['at'] < time() - DAY_IN_SECONDS ) ) {
			$this->dismiss();
		}

		$state = Network::get_option( self::LEGACY_STATE_OPTION, null );
		if ( null !== $state ) {
			$stage = is_array( $state ) && ! empty( $state['stage'] ) ? wp_normalize_path( (string) $state['stage'] ) : '';
			if ( '' !== $stage && false !== strpos( $stage, 'core-stage' ) && self::is_own_place( $stage ) ) {
				Fs::delete_tree( $stage );
				self::remove_empty_parent( $stage, 'core-stage' );
			}
			Network::delete_option( self::LEGACY_STATE_OPTION );
		}

		$list = Network::get_option( self::LEGACY_BACKUPS_OPTION, null );
		if ( null === $list ) {
			return;
		}
		$keep = array();
		foreach ( is_array( $list ) ? $list : array() as $entry ) {
			if ( ! is_array( $entry ) || empty( $entry['id'] ) || empty( $entry['dir'] ) ) {
				continue;
			}
			if ( isset( $entry['at'] ) && (int) $entry['at'] > time() - self::LEGACY_KEEP_DAYS * DAY_IN_SECONDS ) {
				$keep[] = $entry;
				continue;
			}
			$dir    = wp_normalize_path( (string) $entry['dir'] );
			$marker = json_decode( (string) @file_get_contents( $dir . '/' . self::LEGACY_MARKER ), true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
			// Only a folder that carries the marker of this backup, in a place where the old versions put one.
			if ( is_array( $marker ) && isset( $marker['id'] ) && (string) $marker['id'] === (string) $entry['id'] && self::is_own_place( $dir ) ) {
				Fs::delete_tree( $dir );
				self::remove_empty_parent( $dir, 'core-backup' );
				/* translators: %s: folder */
				$this->log( 'core_backup_deleted', sprintf( __( 'Deleted the backup of a WordPress core that an older version of this plugin replaced (kept for 7 days): %s', 'qartvelo-guard' ), self::display_path( $dir ) ), array( 'backup' => (string) $entry['id'] ) );
			}
		}
		if ( $keep ) {
			Network::update_option( self::LEGACY_BACKUPS_OPTION, array_values( $keep ), false );
		} else {
			Network::delete_option( self::LEGACY_BACKUPS_OPTION );
		}
	}

	/**
	 * Removes the "core-stage" or "core-backup" folder of the data folder that
	 * held a deleted work or backup folder, once nothing but its protection
	 * files is left in it.
	 *
	 * @param string $dir  The folder that was just deleted.
	 * @param string $name Name the parent must have.
	 */
	private static function remove_empty_parent( $dir, $name ) {
		$root    = dirname( untrailingslashit( wp_normalize_path( (string) $dir ) ) );
		$entries = @scandir( $root ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( is_array( $entries ) && false !== strpos( basename( $root ), (string) $name ) && self::is_own_place( $root ) && ! array_diff( $entries, array( '.', '..', '.htaccess', 'index.php', 'web.config' ) ) ) {
			Fs::delete_tree( $root );
		}
	}

	/**
	 * Whether a folder is where versions up to 1.1.4 kept their core backups
	 * and work folders: inside the plugin's data folder, or (inside) a hidden
	 * ".wpcybersec-core-" folder next to the WordPress folder. Never the
	 * WordPress folder itself or anything inside it that is not the data folder.
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	private static function is_own_place( $dir ) {
		$dir  = untrailingslashit( wp_normalize_path( (string) $dir ) );
		$data = wpcybersec()->storage ? untrailingslashit( wp_normalize_path( (string) wpcybersec()->storage->data_dir() ) ) : '';
		if ( '' === $dir || false !== strpos( $dir . '/', '/../' ) || ! Storage::path_allowed( $dir ) ) {
			return false;
		}
		if ( '' !== $data && $dir !== $data && Storage::is_within( $dir, $data ) ) {
			return true;
		}
		$parent = untrailingslashit( wp_normalize_path( dirname( untrailingslashit( Paths::wp_root() ) ) ) );
		return 0 === strpos( $dir, $parent . '/.wpcybersec-core-' );
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
	 * The text of the confirmation before a reinstall (card, row link, WP-CLI).
	 *
	 * @param array $damage damage().
	 * @return array { title, verdict, text, confirm }
	 */
	public static function confirm_text( array $damage ) {
		// A localized package is the full one, and WordPress's updater copies its wp-content/languages too.
		$text = self::is_localized()
			? __( 'WordPress downloads its official package from wordpress.org and overwrites wp-admin, wp-includes and the core files in the WordPress folder with it, the same as Dashboard > Updates > Re-install. Visitors see the maintenance message for a moment. wp-config.php, .htaccess, plugins, themes and uploads are not touched.', 'qartvelo-guard' ) . ' ' . self::languages_text()
			: __( 'WordPress downloads its official package from wordpress.org and overwrites wp-admin, wp-includes and the core files in the WordPress folder with it, the same as Dashboard > Updates > Re-install. Visitors see the maintenance message for a moment. wp-config.php, wp-content (plugins, themes, uploads, languages), .htaccess and every other file stay as they are.', 'qartvelo-guard' );
		if ( ! empty( $damage['unknown'] ) ) {
			$text .= ' ' . sprintf(
				/* translators: %s: number of files */
				_n( 'A reinstall does not remove files that are not part of WordPress: %s such file in wp-admin or wp-includes stays reported for you to review.', 'A reinstall does not remove files that are not part of WordPress: %s such files in wp-admin or wp-includes stay reported for you to review.', (int) $damage['unknown'], 'qartvelo-guard' ),
				number_format_i18n( (int) $damage['unknown'] )
			);
		}
		if ( Network::active() ) {
			$text .= ' ' . __( 'All sites of the network share this core.', 'qartvelo-guard' );
		}
		return array(
			/* translators: %s: WordPress version */
			'title'   => sprintf( __( 'Reinstall WordPress %s core now?', 'qartvelo-guard' ), isset( $damage['version'] ) ? (string) $damage['version'] : '' ),
			'verdict' => __( 'The changed core files are overwritten and not kept. If you changed a core file on purpose, copy it first.', 'qartvelo-guard' ),
			'text'    => $text,
			'confirm' => __( 'Reinstall now', 'qartvelo-guard' ),
		);
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
	 * AJAX core_reinstall: do=run (one request: WordPress reinstalls its core)
	 * or do=dismiss (forgets the outcome shown on the card).
	 */
	public function ajax_core_reinstall() {
		$this->guard();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		if ( 'dismiss' === $do ) {
			$this->dismiss();
			wp_send_json_success( array() );
		}
		if ( 'run' !== $do ) {
			wp_send_json_error( array( 'message' => __( 'Unknown action.', 'qartvelo-guard' ) ), 400 );
		}
		// The capability WordPress itself asks for on Dashboard > Updates.
		if ( ! current_user_can( 'update_core' ) ) {
			wp_send_json_error( array( 'message' => __( 'Your account may not update WordPress on this site.', 'qartvelo-guard' ) ), 403 );
		}
		$result = $this->reinstall();
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		$out = array(
			'message' => trim( $result['message'] . ' ' . self::extra_text( $result['extra'], '' ) ),
			'version' => $result['version'],
			'extra'   => $result['extra'],
		);
		if ( wpcybersec()->scan_job ) {
			$out['scan'] = wpcybersec()->scan_job->status();
		}
		wp_send_json_success( $out );
	}
}
