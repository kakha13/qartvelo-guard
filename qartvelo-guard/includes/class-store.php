<?php
/**
 * Database access for items, manifest and activity log.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Tables (prefix = $wpdb->base_prefix . 'wpcybersec_', so every site of a
 * multisite network shares them; on a single site it equals $wpdb->prefix):
 *
 * items     Everything that needs or had an admin decision: held uploads,
 *           held installs, unknown files, malware threats (files and database
 *           content), new administrator accounts.
 * manifest  Known files: relative path -> sha256, size, mtime, state.
 * allowlist Approved hashes and installs (managed by Allowlist).
 * log       Activity log.
 *
 * All datetimes are UTC ("Y-m-d H:i:s").
 */
class Store {

	/* Item types. */
	const TYPE_UPLOAD  = 'upload';
	const TYPE_INSTALL = 'install';
	const TYPE_FILE    = 'file';
	const TYPE_THREAT  = 'threat';
	const TYPE_USER    = 'user';    // An account that gained administrator rights (User_Watch).

	/* Item sources that are not files. */
	const SOURCE_DATABASE = 'database'; // Threat found in the database (Db_Scanner); path "db:option:<name>" or "db:post:<id>".

	/* Item statuses. */
	const STATUS_PENDING     = 'pending';     // Waiting for an admin decision.
	const STATUS_APPROVED    = 'approved';    // Allowed (and remembered in the allowlist).
	const STATUS_DENIED      = 'denied';      // Rejected; held copy removed.
	const STATUS_IGNORED     = 'ignored';     // Threat marked safe (hash allowlisted).
	const STATUS_QUARANTINED = 'quarantined'; // Moved to quarantine by a decision.
	const STATUS_RESTORED    = 'restored';    // Put back without trusting.
	const STATUS_DELETED     = 'deleted';     // Permanently deleted.
	const STATUS_RESOLVED    = 'resolved';    // File gone or fixed outside the plugin.

	/* Severities. */
	const SEV_INFO     = 0;
	const SEV_MEDIUM   = 1;
	const SEV_HIGH     = 2;
	const SEV_CRITICAL = 3;

	/** Option caching counts() (Network::STATE_OPTIONS). */
	const COUNTS_OPTION = 'wpcybersec_counts';

	/** Seconds a cached count is trusted at most. */
	const COUNTS_TTL = 600;

	/** Shape of the cached counts (a different value counts again). */
	const COUNTS_FORMAT = 1;

	/** @var array|null counts() of this request. */
	private static $counts_cache = null;

	/* Manifest states. */
	const STATE_TRUSTED = 'trusted';
	const STATE_PENDING = 'pending';
	const STATE_THREAT  = 'threat';

	/**
	 * @param string $name items | manifest | allowlist | log.
	 * @return string Full table name.
	 */
	public static function table( $name ) {
		global $wpdb;
		return $wpdb->base_prefix . 'wpcybersec_' . $name;
	}

	/**
	 * @return string Current UTC datetime.
	 */
	public static function now() {
		return gmdate( 'Y-m-d H:i:s' );
	}

	/**
	 * Severity number to label.
	 *
	 * @param int $severity Severity.
	 * @return string
	 */
	public static function severity_label( $severity ) {
		$labels = array(
			self::SEV_INFO     => __( 'Info', 'qartvelo-guard' ),
			self::SEV_MEDIUM   => __( 'Medium', 'qartvelo-guard' ),
			self::SEV_HIGH     => __( 'High', 'qartvelo-guard' ),
			self::SEV_CRITICAL => __( 'Critical', 'qartvelo-guard' ),
		);
		return isset( $labels[ (int) $severity ] ) ? $labels[ (int) $severity ] : $labels[0];
	}

	/**
	 * Makes text safe for a utf8mb4 column. File names come straight from
	 * readdir() and may hold bytes that are not valid UTF-8 (Latin-1 legacy
	 * uploads, or a webshell named "x\xff.php" on purpose). wpdb refuses a whole
	 * query that contains such bytes, so every invalid byte becomes "?".
	 *
	 * @param string $text Raw text.
	 * @return string Valid UTF-8 (unchanged when it already was).
	 */
	public static function db_text( $text ) {
		$text = (string) $text;
		if ( '' === $text || 1 === @preg_match( '//u', $text ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $text;
		}
		$out = preg_replace_callback(
			'/[\x00-\x7F]+|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2}|(.)/s',
			static function ( $m ) {
				return isset( $m[1] ) ? '?' : $m[0];
			},
			$text
		);
		return is_string( $out ) ? $out : (string) preg_replace( '/[\x80-\xFF]/', '?', $text );
	}

	/* ------------------------------------------------------------------ */
	/* Items                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array $data Columns. details may be an array (stored as JSON).
	 * @return int New id, 0 on failure.
	 */
	public function item_insert( array $data ) {
		global $wpdb;
		$now  = self::now();
		$row  = array_merge(
			array(
				'type'            => self::TYPE_FILE,
				'status'          => self::STATUS_PENDING,
				'severity'        => 0,
				'path'            => '',
				'original_path'   => '',
				'quarantine_path' => '',
				'sha256'          => '',
				'size'            => 0,
				'mime'            => '',
				'source'          => '',
				'user_id'         => get_current_user_id(),
				'ip'              => self::client_ip(),
				'details'         => array(),
				'created_at'      => $now,
				'updated_at'      => $now,
				'decided_by'      => 0,
			),
			$data
		);
		if ( ! is_array( $row['details'] ) ) {
			$row['details'] = array();
		}
		// Keep the exact bytes of a path that is not valid UTF-8 (base64) so the
		// file can still be found, restored or deleted; the columns get a safe copy.
		foreach ( array( 'path', 'original_path', 'quarantine_path' ) as $col ) {
			$safe = self::db_text( $row[ $col ] );
			if ( $safe !== (string) $row[ $col ] ) {
				if ( 'original_path' === $col ) {
					$row['details']['raw_path'] = base64_encode( (string) $row[ $col ] ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
				} elseif ( 'quarantine_path' === $col ) {
					$row['details']['raw_quarantine_path'] = base64_encode( (string) $row[ $col ] ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
				}
				$row[ $col ] = $safe;
			}
		}
		$row['details'] = wp_json_encode( $row['details'] );
		$ok             = $wpdb->insert( self::table( 'items' ), $row ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$id             = $ok ? (int) $wpdb->insert_id : 0;
		if ( $id ) {
			self::flush_counts();
		}
		return $id;
	}

	/**
	 * @param int $id Item id.
	 * @return array|null Row with details decoded.
	 */
	public function item_get( $id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE id = %d', self::table( 'items' ), $id ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		return $row ? self::decode_item( $row ) : null;
	}

	/**
	 * @param int   $id   Item id.
	 * @param array $data Columns to change. details arrays are merged into the existing details.
	 * @return bool
	 */
	public function item_update( $id, array $data ) {
		global $wpdb;
		if ( isset( $data['details'] ) && is_array( $data['details'] ) ) {
			$current         = $this->item_get( $id );
			$data['details'] = wp_json_encode( array_merge( $current ? $current['details'] : array(), $data['details'] ) );
		}
		$data['updated_at'] = self::now();
		$ok                 = false !== $wpdb->update( self::table( 'items' ), $data, array( 'id' => (int) $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		if ( $ok && array_intersect_key( $data, array( 'status' => 1, 'type' => 1, 'quarantine_path' => 1 ) ) ) {
			self::flush_counts();
		}
		return $ok;
	}

	/**
	 * Lists items.
	 *
	 * @param array $args {
	 *     @type string|string[] $type      Item type(s).
	 *     @type string|string[] $status    Status(es).
	 *     @type bool            $held      Only items with a quarantine copy.
	 *     @type int             $min_severity Minimum severity.
	 *     @type string          $search    Matches path or sha256.
	 *     @type string          $orderby   id | created_at | severity | size | path. Default created_at.
	 *     @type string          $order     ASC | DESC. Default DESC.
	 *     @type int             $per_page  Default 20.
	 *     @type int             $page      1-based. Default 1.
	 * }
	 * @return array { rows: array[], total: int }
	 */
	public function items_query( array $args = array() ) {
		global $wpdb;
		$args = array_merge(
			array(
				'type'         => '',
				'status'       => '',
				'held'         => false,
				'min_severity' => 0,
				'search'       => '',
				'orderby'      => 'created_at',
				'order'        => 'DESC',
				'per_page'     => 20,
				'page'         => 1,
			),
			$args
		);

		$filter   = $this->items_filter( $args );
		$types    = $filter['types'];
		$statuses = $filter['statuses'];
		$orderby  = in_array( $args['orderby'], array( 'id', 'created_at', 'severity', 'size', 'path', 'updated_at' ), true ) ? $args['orderby'] : 'created_at';
		$per_page = max( 1, (int) $args['per_page'] );
		$offset   = max( 0, ( (int) $args['page'] - 1 ) * $per_page );
		$params   = array_merge( $filter['params'], array( $orderby, $per_page, $offset ) );

		// The table and the ORDER BY column are identifier placeholders; the direction is one of two fixed statements.
		$total = $this->items_total( $args );
		if ( 'ASC' === strtoupper( $args['order'] ) ) {
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE ( %d = 0 OR type IN (' . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ') ) AND ( %d = 0 OR status IN (' . implode( ',', array_fill( 0, count( $statuses ), '%s' ) ) . ") ) AND ( %d = 0 OR quarantine_path <> '' ) AND ( %d = 0 OR severity >= %d ) AND ( %d = 0 OR path LIKE %s OR sha256 LIKE %s ) ORDER BY %i ASC, id DESC LIMIT %d OFFSET %d", $params ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		} else {
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE ( %d = 0 OR type IN (' . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ') ) AND ( %d = 0 OR status IN (' . implode( ',', array_fill( 0, count( $statuses ), '%s' ) ) . ") ) AND ( %d = 0 OR quarantine_path <> '' ) AND ( %d = 0 OR severity >= %d ) AND ( %d = 0 OR path LIKE %s OR sha256 LIKE %s ) ORDER BY %i DESC, id DESC LIMIT %d OFFSET %d", $params ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		}

		return array(
			'rows'  => array_map( array( __CLASS__, 'decode_item' ), $rows ? $rows : array() ),
			'total' => $total,
		);
	}

	/**
	 * @param array $args Same filters as items_query().
	 * @return int
	 */
	public function items_count( array $args = array() ) {
		return $this->items_total(
			array_merge(
				array(
					'type'         => '',
					'status'       => '',
					'held'         => false,
					'min_severity' => 0,
					'search'       => '',
				),
				$args
			)
		);
	}

	/**
	 * @param array $args Filters of items_query(), every key present.
	 * @return int Rows that match.
	 */
	private function items_total( array $args ) {
		global $wpdb;
		$filter   = $this->items_filter( $args );
		$types    = $filter['types'];
		$statuses = $filter['statuses'];
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE ( %d = 0 OR type IN (' . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ') ) AND ( %d = 0 OR status IN (' . implode( ',', array_fill( 0, count( $statuses ), '%s' ) ) . ") ) AND ( %d = 0 OR quarantine_path <> '' ) AND ( %d = 0 OR severity >= %d ) AND ( %d = 0 OR path LIKE %s OR sha256 LIKE %s )", $filter['params'] ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * Counts used for menu badges and dashboard cards.
	 *
	 * Cached in the autoloaded option COUNTS_OPTION (a network option on
	 * multisite, see Network::STATE_OPTIONS), so the menu bubble, the admin
	 * bar and the "waiting for approval" notice cost no query on ordinary
	 * admin pages. Every change that can move a count (item_insert(),
	 * item_update() of status, type or quarantine_path, items_delete(), the
	 * network migration) calls flush_counts(); COUNTS_TTL bounds what a
	 * change made outside this class (or a race with a concurrent recount)
	 * could leave behind.
	 *
	 * @param bool $fresh Recount now.
	 * @return array { pending: int (uploads+installs+files+new administrators), threats: int (files and database), quarantined: int }
	 */
	public function counts( $fresh = false ) {
		$cached = $this->cached_counts( $fresh );
		return array(
			'pending'     => $cached['pending'],
			'threats'     => $cached['threats'],
			'quarantined' => $cached['quarantined'],
		);
	}

	/**
	 * Highest id among open items (pending uploads, installs, files, threats
	 * and administrators), from the same cache as counts().
	 *
	 * @return int 0 when nothing is open.
	 */
	public function newest_open_id() {
		$cached = $this->cached_counts( false );
		return $cached['newest'];
	}

	/**
	 * Forgets the cached counts (the next counts() call counts again). The
	 * marker always differs from what is stored, so the write is never skipped
	 * as "unchanged" by a long running process (a scan) whose cached copy of
	 * the option is out of date.
	 */
	public static function flush_counts() {
		self::$counts_cache = null;
		if ( function_exists( 'wp_installing' ) && wp_installing() ) {
			return;
		}
		Network::update_option( self::COUNTS_OPTION, array( 'stale' => uniqid( '', true ) ) );
	}

	/**
	 * @param bool $fresh Recount now.
	 * @return array { pending, threats, quarantined, newest, at }
	 */
	private function cached_counts( $fresh ) {
		if ( ! $fresh && null !== self::$counts_cache ) {
			return self::$counts_cache;
		}
		if ( ! $fresh ) {
			$stored = Network::get_option( self::COUNTS_OPTION, array() );
			if ( is_array( $stored ) && isset( $stored['v'], $stored['at'], $stored['pending'], $stored['threats'], $stored['quarantined'], $stored['newest'] )
				&& self::COUNTS_FORMAT === $stored['v'] && abs( time() - (int) $stored['at'] ) < self::COUNTS_TTL ) {
				self::$counts_cache = array(
					'pending'     => (int) $stored['pending'],
					'threats'     => (int) $stored['threats'],
					'quarantined' => (int) $stored['quarantined'],
					'newest'      => (int) $stored['newest'],
				);
				return self::$counts_cache;
			}
		}

		global $wpdb;
		$table   = self::table( 'items' );
		// One pass over the open and quarantined rows instead of three COUNT(*) queries and a MAX().
		// "pending" counts uploads, installs, files and new administrators; "newest" looks at those and at threats.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT
					SUM( status = %s AND type IN (%s, %s, %s, %s) ) AS pending,
					SUM( status = %s AND type = %s ) AS threats,
					SUM( quarantine_path <> '' ) AS quarantined,
					MAX( CASE WHEN status = %s AND type IN (%s, %s, %s, %s, %s) THEN id ELSE 0 END ) AS newest
				FROM %i WHERE status IN (%s, %s)",
				self::STATUS_PENDING,
				self::TYPE_UPLOAD,
				self::TYPE_INSTALL,
				self::TYPE_FILE,
				self::TYPE_USER,
				self::STATUS_PENDING,
				self::TYPE_THREAT,
				self::STATUS_PENDING,
				self::TYPE_UPLOAD,
				self::TYPE_INSTALL,
				self::TYPE_FILE,
				self::TYPE_USER,
				self::TYPE_THREAT,
				$table,
				self::STATUS_PENDING,
				self::STATUS_QUARANTINED
			),
			ARRAY_A
		);
		$counts = array(
			'pending'     => is_array( $row ) ? (int) $row['pending'] : 0,
			'threats'     => is_array( $row ) ? (int) $row['threats'] : 0,
			'quarantined' => is_array( $row ) ? (int) $row['quarantined'] : 0,
			'newest'      => is_array( $row ) ? (int) $row['newest'] : 0,
		);
		self::$counts_cache = $counts;
		if ( is_array( $row ) && ! ( function_exists( 'wp_installing' ) && wp_installing() ) ) {
			Network::update_option( self::COUNTS_OPTION, array_merge( $counts, array( 'v' => self::COUNTS_FORMAT, 'at' => time() ) ) );
		}
		return $counts;
	}

	/**
	 * Finds an open (pending) item for the same thing, to avoid duplicates.
	 *
	 * @param string $type   Item type.
	 * @param string $path   Path (relative path, file name or install key).
	 * @param string $sha256 Optional hash; when given it must match too.
	 * @return array|null
	 */
	public function item_find_open( $type, $path, $sha256 = '' ) {
		global $wpdb;
		$table = self::table( 'items' );
		$path  = self::db_text( $path ); // Same form item_insert() stored.
		if ( $sha256 ) {
			$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE type = %s AND status = %s AND path = %s AND sha256 = %s ORDER BY id DESC LIMIT 1', $table, $type, self::STATUS_PENDING, $path, $sha256 ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		} else {
			$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE type = %s AND status = %s AND path = %s ORDER BY id DESC LIMIT 1', $table, $type, self::STATUS_PENDING, $path ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		}
		return $row ? self::decode_item( $row ) : null;
	}

	/**
	 * Closes open file/threat items for a path that no longer need a decision
	 * (the file is now verified original or approved elsewhere, or it is gone).
	 * Items with a held quarantine copy are left alone: their original being
	 * gone is expected.
	 *
	 * @param string $rel    Relative path.
	 * @param string $reason now_trusted | file_gone.
	 * @return int Items closed.
	 */
	public function items_resolve_open( $rel, $reason ) {
		global $wpdb;
		$table = self::table( 'items' );
		$ids   = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM %i WHERE type IN (%s, %s) AND status = %s AND path = %s AND quarantine_path = '' AND source <> %s", $table, self::TYPE_FILE, self::TYPE_THREAT, self::STATUS_PENDING, self::db_text( $rel ), self::SOURCE_DATABASE ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		foreach ( (array) $ids as $id ) {
			$this->item_update(
				(int) $id,
				array(
					'status'     => self::STATUS_RESOLVED,
					'decided_at' => self::now(),
					'details'    => array( 'resolution' => $reason ),
				)
			);
		}
		if ( $ids ) {
			$message = 'file_gone' === $reason
				/* translators: %s: file path */
				? sprintf( __( 'Closed the report for %s: the file no longer exists.', 'qartvelo-guard' ), $rel )
				/* translators: %s: file path */
				: sprintf( __( 'Closed the report for %s: the file now matches its official checksum or an approved fingerprint.', 'qartvelo-guard' ), $rel );
			$this->log_insert( 'item_auto_resolved', $message, array( 'ids' => array_map( 'intval', $ids ) ) );
		}
		return count( (array) $ids );
	}

	/**
	 * @param int[] $ids Ids.
	 * @return int Rows deleted.
	 */
	public function items_delete( array $ids ) {
		global $wpdb;
		$ids = array_values( array_filter( array_map( 'intval', $ids ) ) );
		if ( ! $ids ) {
			return 0;
		}
		$deleted = (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE id IN (' . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ')', array_merge( array( self::table( 'items' ) ), $ids ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		if ( $deleted ) {
			self::flush_counts();
		}
		return $deleted;
	}

	/**
	 * The filters of items_query() as values for the one fixed WHERE clause of
	 * the items statements:
	 *
	 *   ( %d = 0 OR type IN (...) ) AND ( %d = 0 OR status IN (...) )
	 *   AND ( %d = 0 OR quarantine_path <> '' ) AND ( %d = 0 OR severity >= %d )
	 *   AND ( %d = 0 OR path LIKE %s OR sha256 LIKE %s )
	 *
	 * A filter that is not set gets the switch 0 in front, which makes its
	 * condition true for every row (the database removes such a constant
	 * condition before it reads the table), so the statements never change
	 * shape and hold no variable part besides placeholders.
	 *
	 * @param array $args Filters.
	 * @return array { types: string[], statuses: string[] (one empty string when the filter is off, so
	 *               the IN list is never empty), params: values in statement order, the table name first }
	 */
	private function items_filter( array $args ) {
		global $wpdb;
		$types    = array_values( array_filter( (array) $args['type'], 'strlen' ) );
		$statuses = array_values( array_filter( (array) $args['status'], 'strlen' ) );
		$by_type  = $types ? 1 : 0;
		$by_state = $statuses ? 1 : 0;
		$types    = $types ? $types : array( '' );
		$statuses = $statuses ? $statuses : array( '' );
		$search   = '' !== (string) $args['search'];
		$like     = $search ? '%' . $wpdb->esc_like( $args['search'] ) . '%' : '';
		$severity = ! empty( $args['min_severity'] ) ? (int) $args['min_severity'] : 0;
		return array(
			'types'    => $types,
			'statuses' => $statuses,
			'params'   => array_merge(
				array( self::table( 'items' ), $by_type ),
				$types,
				array( $by_state ),
				$statuses,
				array(
					! empty( $args['held'] ) ? 1 : 0,
					! empty( $args['min_severity'] ) ? 1 : 0,
					$severity,
					$search ? 1 : 0,
					$like,
					$like,
				)
			),
		);
	}

	/**
	 * @param array $row Raw row.
	 * @return array
	 */
	public static function decode_item( $row ) {
		$details        = json_decode( (string) $row['details'], true );
		$row['details'] = is_array( $details ) ? $details : array();
		foreach ( array( 'id', 'severity', 'size', 'user_id', 'decided_by' ) as $int ) {
			$row[ $int ] = (int) $row[ $int ];
		}
		return $row;
	}

	/* ------------------------------------------------------------------ */
	/* Manifest                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string[] $path_hashes Paths::hash() values.
	 * @return array path_hash => row
	 */
	public function manifest_get_many( array $path_hashes ) {
		global $wpdb;
		$path_hashes = array_values( array_unique( array_filter( $path_hashes ) ) );
		$out         = array();
		foreach ( array_chunk( $path_hashes, 500 ) as $chunk ) {
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE path_hash IN (' . implode( ',', array_fill( 0, count( $chunk ), '%s' ) ) . ')', array_merge( array( self::table( 'manifest' ) ), $chunk ) ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
			foreach ( (array) $rows as $row ) {
				$out[ $row['path_hash'] ] = $row;
			}
		}
		return $out;
	}

	/**
	 * @param string $rel Relative path.
	 * @return array|null
	 */
	public function manifest_get( $rel ) {
		$rows = $this->manifest_get_many( array( Paths::hash( $rel ) ) );
		return $rows ? reset( $rows ) : null;
	}

	/**
	 * Inserts or replaces manifest rows.
	 *
	 * path_hash is computed from the exact path bytes (that is how rows are
	 * looked up); the path column gets a UTF-8 safe copy for display and
	 * prefix queries. When a batch statement fails, the rows are written one by
	 * one so a single bad row can never drop the others.
	 *
	 * @param array $rows Each: path (relative), sha256, size, mtime, state, run_id. path_hash is computed.
	 */
	public function manifest_upsert_many( array $rows ) {
		$now = self::now();
		foreach ( array_chunk( $rows, 200 ) as $chunk ) {
			if ( false === $this->manifest_upsert_chunk( $chunk, $now ) && count( $chunk ) > 1 ) {
				foreach ( $chunk as $row ) {
					$this->manifest_upsert_chunk( array( $row ), $now );
				}
			}
		}
	}

	/**
	 * One INSERT ... ON DUPLICATE KEY UPDATE statement.
	 *
	 * @param array  $chunk Rows (at most 200).
	 * @param string $now   Datetime.
	 * @return int|false Rows affected, false on a database error.
	 */
	private function manifest_upsert_chunk( array $chunk, $now ) {
		global $wpdb;
		if ( ! $chunk ) {
			return 0;
		}
		$params = array( self::table( 'manifest' ) );
		foreach ( $chunk as $row ) {
			array_push(
				$params,
				Paths::hash( $row['path'] ),
				self::db_text( $row['path'] ),
				isset( $row['sha256'] ) ? (string) $row['sha256'] : '',
				isset( $row['size'] ) ? (int) $row['size'] : 0,
				isset( $row['mtime'] ) ? (int) $row['mtime'] : 0,
				isset( $row['state'] ) ? (string) $row['state'] : self::STATE_TRUSTED,
				isset( $row['run_id'] ) ? (string) $row['run_id'] : '',
				$now
			);
		}
		// One group of eight placeholders per row. ReplacementsWrongNumber: the sniff cannot count placeholders that come in groups; $params holds the table name and eight values per row.
		return $wpdb->query( $wpdb->prepare( 'INSERT INTO %i (path_hash, path, sha256, size, mtime, state, run_id, updated_at) VALUES ' . implode( ',', array_fill( 0, count( $chunk ), '(%s,%s,%s,%d,%d,%s,%s,%s)' ) ) . ' ON DUPLICATE KEY UPDATE path = VALUES(path), sha256 = VALUES(sha256), size = VALUES(size), mtime = VALUES(mtime), state = VALUES(state), run_id = VALUES(run_id), updated_at = VALUES(updated_at)', $params ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * Marks rows as seen by a scan run.
	 *
	 * @param string[] $path_hashes Hashes.
	 * @param string   $run_id      Run id.
	 */
	public function manifest_touch( array $path_hashes, $run_id ) {
		global $wpdb;
		foreach ( array_chunk( array_values( array_unique( $path_hashes ) ), 500 ) as $chunk ) {
			$wpdb->query( $wpdb->prepare( 'UPDATE %i SET run_id = %s WHERE path_hash IN (' . implode( ',', array_fill( 0, count( $chunk ), '%s' ) ) . ')', array_merge( array( self::table( 'manifest' ), $run_id ), $chunk ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		}
	}

	/**
	 * Rows not seen by a run (deleted files), optionally under a path prefix.
	 *
	 * Rows written after the run started (by trust_file(), a rebaseline after an
	 * update, an approved upload...) are never returned when $before is given:
	 * they describe files that exist even though this run did not list them.
	 *
	 * @param string $run_id Run id.
	 * @param int    $limit  Max rows.
	 * @param string $prefix Relative path prefix ("" for all).
	 * @param string $before Only rows last written before this UTC datetime ("Y-m-d H:i:s"; "" for no limit).
	 * @return array[]
	 */
	public function manifest_unseen( $run_id, $limit = 500, $prefix = '', $before = '' ) {
		global $wpdb;
		// A filter that is not asked for gets the switch 0, which makes its condition true for every row.
		$by_prefix = '' !== (string) $prefix ? 1 : 0;
		$by_before = '' !== (string) $before ? 1 : 0;
		$like      = $by_prefix ? $wpdb->esc_like( self::db_text( $prefix ) ) . '%' : '';
		return (array) $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE run_id <> %s AND ( %d = 0 OR path LIKE %s ) AND ( %d = 0 OR updated_at < %s ) LIMIT %d', self::table( 'manifest' ), (string) $run_id, $by_prefix, $like, $by_before, (string) $before, (int) $limit ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * @param string[] $path_hashes Hashes.
	 */
	public function manifest_delete( array $path_hashes ) {
		global $wpdb;
		foreach ( array_chunk( array_values( array_unique( array_filter( $path_hashes ) ) ), 500 ) as $chunk ) {
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE path_hash IN (' . implode( ',', array_fill( 0, count( $chunk ), '%s' ) ) . ')', array_merge( array( self::table( 'manifest' ) ), $chunk ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		}
	}

	/**
	 * @param string $prefix Relative path prefix.
	 */
	public function manifest_delete_prefix( $prefix ) {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE path LIKE %s', self::table( 'manifest' ), $wpdb->esc_like( self::db_text( $prefix ) ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * @param string $state Optional state filter.
	 * @return int
	 */
	public function manifest_count( $state = '' ) {
		global $wpdb;
		$table = self::table( 'manifest' );
		if ( $state ) {
			return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE state = %s', $table, $state ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		}
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * @param string $rel   Relative path.
	 * @param string $state New state.
	 */
	public function manifest_set_state( $rel, $state ) {
		global $wpdb;
		$wpdb->update( self::table( 'manifest' ), array( 'state' => $state, 'updated_at' => self::now() ), array( 'path_hash' => Paths::hash( $rel ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * Empties the manifest (before a full re-baseline).
	 */
	public function manifest_truncate() {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'TRUNCATE TABLE %i', self::table( 'manifest' ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * Every trusted row, in pages (for exports such as the fapolicyd trust file).
	 *
	 * @param int $limit  Rows.
	 * @param int $offset Offset.
	 * @return array[]
	 */
	public function manifest_page( $limit, $offset ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( 'SELECT path, sha256, size FROM %i WHERE state = %s ORDER BY path LIMIT %d OFFSET %d', self::table( 'manifest' ), self::STATE_TRUSTED, $limit, $offset ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/* ------------------------------------------------------------------ */
	/* Log                                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $event   Machine name, e.g. upload_held.
	 * @param string $message Human message.
	 * @param array  $context Extra data.
	 * @return int
	 */
	public function log_insert( $event, $message, array $context = array() ) {
		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- plugin's own table; no WordPress API covers it.
			self::table( 'log' ),
			array(
				'event'      => substr( (string) $event, 0, 50 ),
				'message'    => self::db_text( $message ), // Messages often quote file names.
				'context'    => wp_json_encode( $context ),
				'user_id'    => get_current_user_id(),
				'ip'         => self::client_ip(),
				'created_at' => self::now(),
			)
		);
		return (int) $wpdb->insert_id;
	}

	/**
	 * @param array $args { event, search, per_page (50), page (1) }.
	 * @return array { rows, total }
	 */
	public function log_query( array $args = array() ) {
		global $wpdb;
		$args   = array_merge( array( 'event' => '', 'search' => '', 'per_page' => 50, 'page' => 1 ), $args );
		$table = self::table( 'log' );
		// A filter that is not asked for gets the switch 0, which makes its condition true for every row.
		$by_event  = $args['event'] ? 1 : 0;
		$by_search = $args['search'] ? 1 : 0;
		$event     = $by_event ? (string) $args['event'] : '';
		$like      = $by_search ? '%' . $wpdb->esc_like( $args['search'] ) . '%' : '';
		$per_page  = max( 1, (int) $args['per_page'] );
		$offset    = max( 0, ( (int) $args['page'] - 1 ) * $per_page );
		$total     = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE ( %d = 0 OR event = %s ) AND ( %d = 0 OR message LIKE %s )', $table, $by_event, $event, $by_search, $like ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		$rows      = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE ( %d = 0 OR event = %s ) AND ( %d = 0 OR message LIKE %s ) ORDER BY id DESC LIMIT %d OFFSET %d', $table, $by_event, $event, $by_search, $like, $per_page, $offset ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		foreach ( $rows as &$row ) {
			$context        = json_decode( (string) $row['context'], true );
			$row['context'] = is_array( $context ) ? $context : array();
		}
		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}

	/**
	 * Distinct event names (for the Activity filter).
	 *
	 * @return string[]
	 */
	public function log_events() {
		global $wpdb;
		return (array) $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT event FROM %i ORDER BY event LIMIT 200', self::table( 'log' ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * @param int $days Keep this many days.
	 */
	public function log_prune( $days ) {
		global $wpdb;
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS * (int) $days );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE created_at < %s', self::table( 'log' ), $cutoff ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Best-effort client IP (REMOTE_ADDR only; proxies headers are spoofable).
	 *
	 * @return string
	 */
	public static function client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}
}
