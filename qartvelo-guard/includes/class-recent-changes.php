<?php
/**
 * Recent changes (incident mode): executable and config files modified in the
 * last days, whatever the baseline says, with what explains each change.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Changes are normally judged against the baseline. When a site was already
 * infected while the baseline was recorded, the infected files are part of
 * it and look normal. This view lists every executable or config file
 * (Paths::is_executable()) whose modification time, as the last scan saw it
 * (manifest mtime column), falls in the last 7, 14 or 30 days, and explains
 * each one:
 *
 *   update     the file changed while WordPress, a plugin or a theme was
 *              updated or installed (update marks, see remember_update())
 *   checksum   the file matches the official WordPress.org checksum
 *   allowed    an administrator allowed this exact content
 *   reported   an open report already exists for the file
 *   none       nothing explains it (shown highlighted)
 *
 * Update marks come from option UPDATES_OPTION (written by Install_Gate when an
 * update finishes, see remember_update()) and, for updates before that option
 * existed, from the "rebaselined" activity log events.
 *
 * Created on demand (new Recent_Changes()); not a service.
 */
class Recent_Changes {

	/** Option: list of { p: relative prefix, t: unix time, a: update|install }. */
	const UPDATES_OPTION = 'wpcybersec_update_marks';

	/** Marks kept at most, and for how long. */
	const MAX_MARKS = 600;
	const KEEP_DAYS = 45;

	/** A file written this long before (or after) an update mark counts as part of it. */
	const BEFORE = 3600;
	const AFTER  = 900;

	/** Manifest rows read at most for one listing. */
	const SCAN_CAP = 20000;

	/** Allowed day windows. */
	const WINDOWS = array( 7, 14, 30 );

	/** @var array|null Marks cache. */
	private $marks = null;

	/** @var array|null Plugin folder => name. */
	private $plugin_names = null;

	/* ------------------------------------------------------------------ */
	/* Update marks                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Remembers that files under these paths were just written by an update
	 * or install (called by Install_Gate on upgrader_process_complete).
	 *
	 * @param string[] $abs_paths Absolute folders or files.
	 * @param string   $action    update | install.
	 */
	public static function remember_update( array $abs_paths, $action = 'update' ) {
		$now   = time();
		$marks = Network::get_option( self::UPDATES_OPTION, array() );
		$marks = is_array( $marks ) ? $marks : array();
		foreach ( $abs_paths as $abs ) {
			$abs = wp_normalize_path( (string) $abs );
			if ( '' === $abs ) {
				continue;
			}
			$rel = Paths::rel( $abs );
			if ( '' === $rel || Paths::is_absolute( $rel ) ) {
				continue; // Outside the scanned folder.
			}
			$marks[] = array(
				'p' => @is_dir( $abs ) ? trailingslashit( $rel ) : $rel, // phpcs:ignore WordPress.PHP.NoSilencedErrors
				't' => $now,
				'a' => 'install' === $action ? 'install' : 'update',
			);
		}
		$cutoff = $now - self::KEEP_DAYS * DAY_IN_SECONDS;
		$marks  = array_values(
			array_filter(
				$marks,
				static function ( $mark ) use ( $cutoff ) {
					return is_array( $mark ) && isset( $mark['p'], $mark['t'] ) && (int) $mark['t'] >= $cutoff;
				}
			)
		);
		if ( count( $marks ) > self::MAX_MARKS ) {
			$marks = array_slice( $marks, -self::MAX_MARKS );
		}
		Network::update_option( self::UPDATES_OPTION, $marks, false );
	}

	/**
	 * Every known update mark: the option plus "rebaselined" log events.
	 *
	 * @return array[] Each { p, t, a }.
	 */
	public function marks() {
		if ( null !== $this->marks ) {
			return $this->marks;
		}
		$marks = Network::get_option( self::UPDATES_OPTION, array() );
		$marks = is_array( $marks ) ? array_values( array_filter( $marks, 'is_array' ) ) : array();

		$store = wpcybersec()->store;
		$log   = $store ? $store->log_query(
			array(
				'event'    => 'rebaselined',
				'per_page' => 500,
				'page'     => 1,
			)
		) : array( 'rows' => array() );
		$cutoff = time() - self::KEEP_DAYS * DAY_IN_SECONDS;
		foreach ( (array) $log['rows'] as $row ) {
			$time = strtotime( (string) $row['created_at'] . ' UTC' );
			if ( ! $time || $time < $cutoff ) {
				continue;
			}
			$context = isset( $row['context'] ) && is_array( $row['context'] ) ? $row['context'] : array();
			foreach ( array( 'dirs', 'files' ) as $key ) {
				foreach ( isset( $context[ $key ] ) ? (array) $context[ $key ] : array() as $abs ) {
					$rel = Paths::rel( (string) $abs );
					if ( '' === $rel || Paths::is_absolute( $rel ) ) {
						continue;
					}
					$marks[] = array(
						'p' => 'dirs' === $key ? trailingslashit( $rel ) : $rel,
						't' => (int) $time,
						'a' => 'update',
					);
				}
			}
		}
		$this->marks = $marks;
		return $marks;
	}

	/**
	 * The update that explains a file change, if any.
	 *
	 * @param string $rel   Relative path.
	 * @param int    $mtime Modification time.
	 * @return array|null { p, t, a } of the closest mark.
	 */
	public function update_for( $rel, $mtime ) {
		$best = null;
		foreach ( $this->marks() as $mark ) {
			$prefix = (string) $mark['p'];
			$match  = '/' === substr( $prefix, -1 ) ? 0 === strpos( $rel, $prefix ) : $rel === $prefix;
			if ( ! $match ) {
				continue;
			}
			$time = (int) $mark['t'];
			if ( $mtime < $time - self::BEFORE || $mtime > $time + self::AFTER ) {
				continue;
			}
			if ( null === $best || abs( $time - $mtime ) < abs( (int) $best['t'] - $mtime ) ) {
				$best = $mark;
			}
		}
		return $best;
	}

	/**
	 * Readable name of what an update mark covers: "WordPress",
	 * the plugin or theme name, or "Translations".
	 *
	 * @param string $prefix Relative prefix.
	 * @return array { kind: core|plugin|theme|translation|other, name }
	 */
	public function describe( $prefix ) {
		$abs  = Paths::abs( rtrim( (string) $prefix, '/' ) );
		$core = untrailingslashit( Paths::wp_root() );
		$roots = array(
			array( 'plugin', WP_PLUGIN_DIR ),
			array( 'theme', get_theme_root() ),
		);
		// Every theme folder WordPress knows (register_theme_directory()).
		global $wp_theme_directories;
		foreach ( is_array( $wp_theme_directories ) ? $wp_theme_directories : array() as $dir ) {
			$roots[] = array( 'theme', $dir );
		}
		foreach ( $roots as $entry ) {
			list( $kind, $root ) = $entry;
			$root = untrailingslashit( wp_normalize_path( (string) $root ) );
			if ( 0 === strpos( $abs, $root . '/' ) ) {
				$slug = strtok( substr( $abs, strlen( $root ) + 1 ), '/' );
				return array(
					'kind' => $kind,
					'name' => 'plugin' === $kind ? $this->plugin_name( (string) $slug ) : $this->theme_name( (string) $slug ),
				);
			}
		}
		if ( 0 === strpos( $abs . '/', untrailingslashit( wp_normalize_path( WP_LANG_DIR ) ) . '/' ) ) {
			return array(
				'kind' => 'translation',
				'name' => __( 'Translations', 'qartvelo-guard' ),
			);
		}
		$in_core = 0 === strpos( $abs . '/', $core . '/wp-admin/' ) || 0 === strpos( $abs . '/', $core . '/' . WPINC . '/' ) || dirname( $abs ) === $core;
		if ( $in_core ) {
			return array(
				'kind' => 'core',
				'name' => 'WordPress',
			);
		}
		return array(
			'kind' => 'other',
			'name' => basename( $abs ),
		);
	}

	/**
	 * @param string $slug Plugin folder (or single file).
	 * @return string
	 */
	private function plugin_name( $slug ) {
		if ( null === $this->plugin_names ) {
			$this->plugin_names = array();
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			foreach ( (array) get_plugins() as $file => $data ) {
				$folder = false === strpos( $file, '/' ) ? $file : dirname( $file );
				if ( ! isset( $this->plugin_names[ $folder ] ) && ! empty( $data['Name'] ) ) {
					$this->plugin_names[ $folder ] = (string) $data['Name'];
				}
			}
		}
		return isset( $this->plugin_names[ $slug ] ) ? $this->plugin_names[ $slug ] : $slug;
	}

	/**
	 * @param string $slug Theme folder.
	 * @return string
	 */
	private function theme_name( $slug ) {
		$theme = wp_get_theme( $slug );
		$name  = $theme->exists() ? (string) $theme->get( 'Name' ) : '';
		return '' !== $name ? $name : $slug;
	}

	/* ------------------------------------------------------------------ */
	/* Listing                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Executable and config files modified in the last $days days, newest first.
	 *
	 * @param array $args {
	 *     @type int    $days         7 | 14 | 30.
	 *     @type string $search       Path contains.
	 *     @type bool   $hide_updates Leave out files explained by an update mark.
	 *     @type int    $page         1-based.
	 *     @type int    $per_page     Rows per page.
	 * }
	 * @return array { rows: array[] (path, sha256, size, mtime, state), total: int, capped: bool, since: int }
	 */
	public function query( array $args ) {
		global $wpdb;
		$args  = array_merge(
			array(
				'days'         => 7,
				'search'       => '',
				'hide_updates' => false,
				'page'         => 1,
				'per_page'     => 50,
			),
			$args
		);
		$days  = in_array( (int) $args['days'], self::WINDOWS, true ) ? (int) $args['days'] : 7;
		$since = time() - $days * DAY_IN_SECONDS;
		$table = Store::table( 'manifest' );

		// Without a search the switch is 0, which makes the path condition true for every row.
		$by_search = '' !== (string) $args['search'] ? 1 : 0;
		$like      = $by_search ? '%' . $wpdb->esc_like( (string) $args['search'] ) . '%' : '';
		// Uses the mtime index: only the rows of the window are read.
		$rows   = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT path, sha256, size, mtime, state FROM %i WHERE mtime >= %d AND ( %d = 0 OR path LIKE %s ) ORDER BY mtime DESC LIMIT %d', $table, $since, $by_search, $like, self::SCAN_CAP + 1 ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		$capped = count( $rows ) > self::SCAN_CAP;
		if ( $capped ) {
			array_pop( $rows );
		}

		$list = array();
		foreach ( $rows as $row ) {
			$path = (string) $row['path'];
			if ( ! Paths::is_executable( $path ) || Paths::is_excluded( $path ) ) {
				continue;
			}
			if ( $args['hide_updates'] && $this->update_for( $path, (int) $row['mtime'] ) ) {
				continue;
			}
			$list[] = array(
				'path'   => $path,
				'sha256' => (string) $row['sha256'],
				'size'   => (int) $row['size'],
				'mtime'  => (int) $row['mtime'],
				'state'  => (string) $row['state'],
			);
		}

		$per_page = max( 1, (int) $args['per_page'] );
		$offset   = max( 0, ( (int) $args['page'] - 1 ) * $per_page );
		return array(
			'rows'   => array_slice( $list, $offset, $per_page ),
			'total'  => count( $list ),
			'capped' => $capped,
			'since'  => $since,
		);
	}

	/**
	 * What explains one change.
	 *
	 * @param array $row Row from query().
	 * @return array {
	 *     kind: update|checksum|allowed|reported|none, label: string,
	 *     item: array|null (open report), live_sha: string, changed: bool (file differs from what the scan saw), exists: bool
	 * }
	 */
	public function explain( array $row ) {
		$rel = (string) $row['path'];
		$abs = Paths::abs( $rel );
		$out = array(
			'kind'     => 'none',
			'label'    => __( 'Unexplained', 'qartvelo-guard' ),
			'item'     => null,
			'live_sha' => '',
			'changed'  => false,
			'exists'   => @is_file( $abs ), // phpcs:ignore WordPress.PHP.NoSilencedErrors
		);

		$store = wpcybersec()->store;
		foreach ( array( Store::TYPE_THREAT, Store::TYPE_FILE ) as $type ) {
			$open = $store->item_find_open( $type, $rel );
			if ( $open ) {
				$out['item'] = $open;
				break;
			}
		}

		$mark = $this->update_for( $rel, (int) $row['mtime'] );
		if ( $mark ) {
			$what         = $this->describe( (string) $mark['p'] );
			$out['kind']  = 'update';
			$out['label'] = 'core' === $what['kind']
				? ( 'install' === $mark['a'] ? __( 'WordPress install', 'qartvelo-guard' ) : __( 'WordPress update', 'qartvelo-guard' ) )
				: sprintf(
					'install' === $mark['a']
						/* translators: %s: plugin or theme name */
						? __( '%s install', 'qartvelo-guard' )
						/* translators: %s: plugin or theme name */
						: __( '%s update', 'qartvelo-guard' ),
					$what['name']
				);
			return $out;
		}

		$sha = (string) $row['sha256'];
		$md5 = '';
		if ( $out['exists'] && @is_readable( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$live = (string) @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( '' !== $live ) {
				$out['live_sha'] = $live;
				$out['changed']  = '' !== $sha && ! hash_equals( strtolower( $sha ), $live );
				$sha             = $live;
				$md5             = (string) @md5_file( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
		}

		$scanner = wpcybersec()->scanner;
		if ( '' !== $sha && $scanner && 'match' === $scanner->verify( $rel, $sha, $md5 ) ) {
			$out['kind']  = 'checksum';
			$out['label'] = __( 'Matches official checksum', 'qartvelo-guard' );
			return $out;
		}
		$allow = wpcybersec()->allowlist;
		if ( '' !== $sha && $allow && $allow->is_allowed_hash( strtolower( $sha ), true ) ) {
			$out['kind']  = 'allowed';
			$out['label'] = __( 'Allowed by an administrator', 'qartvelo-guard' );
			return $out;
		}
		if ( $out['exists'] && $scanner ) {
			if ( $scanner->is_own_bootstrap( $abs ) || self::only_own_block( $abs ) ) {
				$out['kind']  = 'plugin';
				$out['label'] = __( 'Written by this plugin', 'qartvelo-guard' );
				return $out;
			}
			if ( $scanner->is_inert_php( $abs, (int) @filesize( $abs ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$out['kind']  = 'inert';
				$out['label'] = __( 'Empty placeholder (no code)', 'qartvelo-guard' );
				return $out;
			}
		}
		if ( $out['item'] ) {
			$out['kind']  = 'reported';
			$out['label'] = __( 'Already reported', 'qartvelo-guard' );
		}
		return $out;
	}

	/**
	 * Whether a server config file (.htaccess, .user.ini) holds nothing but this
	 * plugin's own marked blocks. Any other line keeps it "Unexplained", so the
	 * marker cannot be used to hide added rules.
	 *
	 * @param string $abs File.
	 * @return bool
	 */
	private static function only_own_block( $abs ) {
		$base = strtolower( basename( $abs ) );
		if ( ! in_array( $base, array( '.htaccess', '.user.ini' ), true ) || (int) @filesize( $abs ) > 16384 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$text = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$names = implode( '|', array_map( static function ( $name ) {
			return preg_quote( $name, '~' );
		}, array( Guard_Manager::MARKER, Guard_Manager::LEGACY_MARKER, Sysadmin_Tools::MARKER, Sysadmin_Tools::LEGACY_MARKER ) ) );
		$rest  = preg_replace( '~^[#;] BEGIN (?:' . $names . ')\R.*?^[#;] END (?:' . $names . ')[ \t]*\R?~ms', '', $text, -1, $count );
		return $count > 0 && '' === trim( (string) $rest );
	}

	/* ------------------------------------------------------------------ */
	/* One file                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Validates a manifest key from a request: a file the manifest knows,
	 * covered by a whole-site scan (Paths::in_scope(), so files outside the
	 * scan root, whose key is their absolute path, work too), outside the
	 * plugin's data folder, and still there.
	 *
	 * @param string $rel Relative path.
	 * @return array|\WP_Error { rel, abs, row }
	 */
	public static function resolve( $rel ) {
		$rel = wp_normalize_path( trim( (string) $rel ) );
		$bad = new \WP_Error( 'wpcybersec_path', __( 'This file is not one the plugin monitors, so it cannot be shown here.', 'qartvelo-guard' ) );
		if ( '' === $rel || false !== strpos( $rel, "\0" ) || preg_match( '#(^|/)\.\.(/|$)#', $rel ) ) {
			return $bad;
		}
		// Keys outside the scan root are absolute paths; "/wp-content/x.php" may also mean a relative key.
		$row = wpcybersec()->store->manifest_get( $rel );
		if ( ! is_array( $row ) && '/' === substr( $rel, 0, 1 ) ) {
			$rel = ltrim( $rel, '/' );
			$row = '' !== $rel ? wpcybersec()->store->manifest_get( $rel ) : null;
		}
		if ( ! is_array( $row ) ) {
			return $bad;
		}
		$abs  = Paths::abs( $rel );
		$real = @realpath( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $real || ! @is_file( $real ) || ! Paths::in_scope( wp_normalize_path( $real ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new \WP_Error( 'wpcybersec_gone', __( 'This file no longer exists.', 'qartvelo-guard' ) );
		}
		if ( Storage::is_within( wp_normalize_path( $real ), wpcybersec()->storage->data_dir() ) ) {
			return $bad;
		}
		return array(
			'rel' => $rel,
			'abs' => $abs,
			'row' => $row,
		);
	}

	/**
	 * A file description shaped like an item (id 0), for Diff::for_item():
	 * the live file, its malware matches, and the last trusted version when
	 * the file changed after the last scan and a copy of it was kept.
	 *
	 * @param array $file resolve() result.
	 * @return array
	 */
	public static function file_item( array $file ) {
		$abs  = $file['abs'];
		$rel  = $file['rel'];
		$row  = $file['row'];
		$size = (int) @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$sha  = (string) @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		$hits    = array();
		$scanner = wpcybersec()->scanner;
		if ( $scanner && $size <= $scanner->max_bytes() ) {
			$hits = (array) $scanner->scan_file( $abs, $rel );
		}
		$details = array( 'hits' => array_values( $hits ) );
		$known   = strtolower( (string) $row['sha256'] );
		if ( Snapshots::is_sha( $known ) && '' !== $sha && ! hash_equals( $known, $sha ) && Store::STATE_TRUSTED === $row['state'] && wpcybersec()->snapshots->has( $known ) ) {
			$details['change']          = 'modified';
			$details['previous_sha256'] = $known;
		}
		return array(
			'id'              => 0,
			'type'            => Store::TYPE_FILE,
			'status'          => Store::STATUS_PENDING,
			'severity'        => $hits && $scanner ? $scanner->max_severity( $hits ) : 0,
			'path'            => $rel,
			'original_path'   => $abs,
			'quarantine_path' => '',
			'sha256'          => $sha,
			'size'            => $size,
			'mime'            => '',
			'source'          => 'review',
			'user_id'         => 0,
			'ip'              => '',
			'details'         => $details,
			'created_at'      => gmdate( 'Y-m-d H:i:s', (int) $row['mtime'] ),
			'updated_at'      => '',
			'decided_by'      => 0,
			'decided_at'      => null,
		);
	}

	/**
	 * "Report for review": a pending file item, so the normal Allow /
	 * Quarantine decisions apply. An open report of the same file is reused.
	 *
	 * @param string $rel Relative path.
	 * @return int|\WP_Error Item id.
	 */
	public static function report( $rel ) {
		$file = self::resolve( $rel );
		if ( is_wp_error( $file ) ) {
			return $file;
		}
		$store = wpcybersec()->store;
		foreach ( array( Store::TYPE_THREAT, Store::TYPE_FILE ) as $type ) {
			$open = $store->item_find_open( $type, $file['rel'] );
			if ( $open ) {
				return (int) $open['id'];
			}
		}

		$item = self::file_item( $file );
		$abs  = $file['abs'];
		if ( '' === (string) $item['sha256'] ) {
			return new \WP_Error( 'wpcybersec_read', __( 'The file could not be read.', 'qartvelo-guard' ) );
		}
		$snapshots = wpcybersec()->snapshots;
		if ( $snapshots ) {
			$snapshots->store( $abs, $item['sha256'] );
		}
		$details            = $item['details'];
		$details['context'] = 'recent_changes';
		if ( empty( $details['change'] ) ) {
			$details['change'] = 'modified';
		}
		$verify = wpcybersec()->scanner->verify_details( $file['rel'], $item['sha256'] );
		if ( '' !== $verify['source'] ) {
			$details['verified'] = $verify['source'];
			if ( '' !== $verify['reason'] ) {
				$details['checksum'] = $verify['reason'];
			}
		}
		$type = wp_check_filetype( basename( $abs ) );
		$id   = $store->item_insert(
			array(
				'type'          => Store::TYPE_FILE,
				'status'        => Store::STATUS_PENDING,
				'severity'      => max( Store::SEV_MEDIUM, (int) $item['severity'] ),
				'path'          => $file['rel'],
				'original_path' => $abs,
				'sha256'        => $item['sha256'],
				'size'          => (int) $item['size'],
				'mime'          => ! empty( $type['type'] ) ? (string) $type['type'] : '',
				'source'        => 'review',
				'user_id'       => get_current_user_id(),
				'details'       => $details,
			)
		);
		if ( ! $id ) {
			return new \WP_Error( 'wpcybersec_insert', __( 'The report could not be saved.', 'qartvelo-guard' ) );
		}
		// Known but no longer trusted until someone decides (like a file a scan reported).
		$store->manifest_set_state( $file['rel'], Store::STATE_PENDING );
		wpcybersec()->logger->log(
			'file_reported',
			/* translators: %s: relative path */
			sprintf( __( 'Recently changed file reported for review: %s', 'qartvelo-guard' ), $file['rel'] ),
			array(
				'item_id' => (int) $id,
				'path'    => $file['rel'],
				'sha256'  => $item['sha256'],
			)
		);
		return (int) $id;
	}
}
