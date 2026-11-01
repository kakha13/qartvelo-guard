<?php
/**
 * Database scan: code injected into options and posts.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Looks for the database side of a compromise: payloads stored in options
 * (run later by a small backdoor elsewhere) and scripts or hidden iframes
 * injected into posts and widgets.
 *
 * Work is done in chunks by primary key range (OPTIONS_RANGE / POSTS_RANGE
 * ids per query, at most ROWS_LIMIT matching rows, values cut at MAX_VALUE
 * bytes), so Scan_Job can spread it over several ticks: begin() returns a
 * cursor, step() advances it until a deadline, finish() closes the run.
 * run() does all of it at once (WP-CLI, tests).
 *
 * Multisite: one run covers every site of the network, one site after the
 * other (cursor "blog", resumable like the chunks). Findings on a site other
 * than the main one carry it in their place: "db:site:<blog id>:option:<name>",
 * and every finding records details.blog_id.
 *
 * Every finding is a threat item with source "database" (Store::SOURCE_DATABASE):
 *   path     "db:option:<name>" or "db:post:<ID>"
 *   sha256   fingerprint of the value at that place (see fingerprint())
 *   details  table, key, label, hits (redacted snippets), seen_run,
 *            post_type / post_title / post_status for posts
 * Deduplicated by path + fingerprint. "Mark safe" stores the fingerprint in
 * the allowlist (kind db), so the same value at the same place is never
 * reported again; any change to it is checked again. Open findings that a
 * complete run no longer sees (the value was cleaned or removed) are
 * resolved. Nothing here touches files.
 */
class Db_Scanner {

	/** Option with the summary of the last complete run. */
	const LAST_OPTION = 'wpcybersec_db_scan';

	/** option_id / post ID span read per query. */
	const OPTIONS_RANGE = 2000;
	const POSTS_RANGE   = 1000;

	/** Matching rows fetched per query (the rest of the range follows in the next query). */
	const ROWS_LIMIT = 50;

	/** Bytes of a value that are inspected. */
	const MAX_VALUE = 1048576;

	/** Hits kept per finding. */
	const MAX_HITS = 10;

	/** Tags of one kind looked at per value. */
	const MAX_TAGS = 200;

	/** Post types never scanned: revisions, caches of third party embeds, Customizer drafts. */
	const SKIP_POST_TYPES = array( 'revision', 'oembed_cache', 'customize_changeset', 'user_request' );

	/** Post statuses scanned. */
	const POST_STATUSES = array( 'publish', 'draft', 'private', 'pending', 'future' );

	/**
	 * Hosts whose scripts are fixed embed code of a large provider (an attacker
	 * cannot publish code there), so an embed in a post or widget is not
	 * reported. Filter: wpcybersec_db_trusted_script_hosts.
	 */
	const TRUSTED_SCRIPT_HOSTS = array(
		'platform.twitter.com',
		'www.instagram.com',
		'instagram.com',
		'www.tiktok.com',
		'connect.facebook.net',
		'assets.pinterest.com',
		'embed.reddit.com',
		'embed.redditmedia.com',
		's.imgur.com', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- a host name in an allowlist; nothing is loaded from it.
		'embedr.flickr.com',
		'player.vimeo.com',
		'www.youtube.com',
		'www.google.com',
		'www.gstatic.com', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- a host name in an allowlist; nothing is loaded from it.
		'apis.google.com',
		'js.stripe.com',
		'www.paypal.com',
	);

	/**
	 * Options of header / footer code plugins (option name => plugin). Code
	 * there is printed on every page, so attackers with admin access add their
	 * scripts there; anything script like is reported for review.
	 */
	const CODE_OPTIONS = array(
		'ihaf_insert_header' => 'WPCode (Insert Headers and Footers)',
		'ihaf_insert_body'   => 'WPCode (Insert Headers and Footers)',
		'ihaf_insert_footer' => 'WPCode (Insert Headers and Footers)',
		'hefo'               => 'Head, Footer and Post Injections',
	);

	/** Post types of code snippet plugins (post type => plugin). */
	const CODE_POST_TYPES = array(
		'wpcode' => 'WPCode',
	);

	/**
	 * Tables of code snippet plugins, scanned when they exist:
	 * stage => { table (without prefix), id, code and name columns, plugin,
	 * base (the table carries the network's base prefix and exists once per
	 * network, so it is visited with the main site only) }.
	 */
	const CODE_TABLES = array(
		'hfcm'     => array(
			'table'  => 'hfcm_scripts',
			'id'     => 'script_id',
			'code'   => 'snippet',
			'name'   => 'name',
			'plugin' => 'Header Footer Code Manager',
		),
		'snippets' => array(
			'table'  => 'snippets',
			'id'     => 'id',
			'code'   => 'code',
			'name'   => 'name',
			'plugin' => 'Code Snippets',
		),
		'ms_snippets' => array(
			'table'  => 'ms_snippets',
			'id'     => 'id',
			'code'   => 'code',
			'name'   => 'name',
			'plugin' => 'Code Snippets (network)',
			'base'   => true,
		),
	);

	/** @var string[]|null Hosts of this site (lowercase, without "www."). */
	private $own_hosts = null;

	/** @var string[]|null Trusted script hosts after the filter. */
	private $trusted_hosts = null;

	/** @var int|null Rows per query for this request (see rows_limit()). */
	private $rows_limit = null;

	/**
	 * Nothing to hook: Scan_Job drives the scan.
	 */
	public function register() {}

	/**
	 * Matching rows fetched per query: ROWS_LIMIT, lowered when PHP has little
	 * memory left, because every row can carry MAX_VALUE bytes and inspecting
	 * it makes a few more copies (50 rows of 1 MB do not fit a 64 MB limit).
	 *
	 * @return int Between 2 and ROWS_LIMIT.
	 */
	private function rows_limit() {
		if ( null !== $this->rows_limit ) {
			return $this->rows_limit;
		}
		$limit = function_exists( 'wp_convert_hr_to_bytes' ) ? wp_convert_hr_to_bytes( (string) ini_get( 'memory_limit' ) ) : -1;
		if ( $limit <= 0 ) {
			$this->rows_limit = self::ROWS_LIMIT; // No limit.
			return $this->rows_limit;
		}
		$free = $limit - memory_get_usage( true );
		// Half the free memory for the result set, about 4 copies of each value while inspecting it.
		$rows             = (int) floor( max( 0, $free ) / 2 / ( 4 * self::MAX_VALUE ) );
		$this->rows_limit = max( 2, min( self::ROWS_LIMIT, $rows ) );
		return $this->rows_limit;
	}

	/* ------------------------------------------------------------------ */
	/* Run lifecycle                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Cursor for a new run.
	 *
	 * @param string $run_id Id that marks findings seen by this run.
	 * @return array
	 */
	public function begin( $run_id = '' ) {
		$run_id = '' !== (string) $run_id ? (string) $run_id : gmdate( 'YmdHis' ) . substr( md5( uniqid( 'wpcsdb', true ) ), 0, 8 );
		$cursor = array(
			'run'           => substr( preg_replace( '/[^A-Za-z0-9_-]/', '', $run_id ), 0, 40 ),
			'stage'         => 'options',
			'last'          => 0,
			'max'           => 0,
			'options_total' => 0,
			'posts_total'   => 0,
			'options'       => 0,
			'posts'         => 0,
			'findings'      => 0,
			'new'           => 0,
			'started'       => time(),
			'blog'          => 0,
			'sites'         => 0,
		);
		if ( Network::active() ) {
			$first = Network::site_ids_after( 0, 1 );
			$this->with_blog(
				$first ? $first[0] : (int) get_current_blog_id(),
				function () use ( &$cursor, $first ) {
					$this->enter_blog( $cursor, $first ? $first[0] : (int) get_current_blog_id() );
				}
			);
		} else {
			$this->enter_blog( $cursor, 0 );
		}
		return $cursor;
	}

	/**
	 * Points the cursor at the options of a site (the current one, already
	 * switched to on multisite).
	 *
	 * @param array $cursor  Cursor.
	 * @param int   $blog_id Site id (0 on a single site).
	 */
	private function enter_blog( array &$cursor, $blog_id ) {
		global $wpdb;
		$cursor['blog']           = (int) $blog_id;
		$cursor['stage']          = 'options';
		$cursor['last']           = 0;
		$cursor['max']            = (int) $wpdb->get_var( "SELECT MAX(option_id) FROM {$wpdb->options}" ); // phpcs:ignore WordPress.DB
		$cursor['options_total'] += (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options}" ); // phpcs:ignore WordPress.DB
		++$cursor['sites'];
	}

	/**
	 * Runs $fn on site $blog_id (multisite) and returns its result.
	 *
	 * @param int      $blog_id Site id.
	 * @param callable $fn      Callback.
	 * @return mixed
	 */
	private function with_blog( $blog_id, callable $fn ) {
		$blog_id  = (int) $blog_id;
		$switched = Network::active() && $blog_id > 0 && $blog_id !== (int) get_current_blog_id();
		if ( $switched ) {
			switch_to_blog( $blog_id );
		}
		try {
			return call_user_func( $fn );
		} finally {
			if ( $switched ) {
				restore_current_blog();
			}
		}
	}

	/**
	 * Advances a run until $deadline (always at least one query).
	 *
	 * @param array         $cursor   Cursor from begin() (updated).
	 * @param float         $deadline Microtime.
	 * @param callable|null $stop     Returns true to stop early (cancel requested).
	 * @return bool True when the run is complete.
	 */
	public function step( array &$cursor, $deadline, $stop = null ) {
		if ( ! Network::active() || empty( $cursor['blog'] ) ) {
			return $this->step_site( $cursor, $deadline, $stop );
		}
		// Multisite: the sites one after the other, each in its own context.
		while ( true ) {
			$blog = (int) $cursor['blog'];
			$done = get_site( $blog )
				? $this->with_blog(
					$blog,
					function () use ( &$cursor, $deadline, $stop ) {
						return $this->step_site( $cursor, $deadline, $stop );
					}
				)
				: true; // Deleted while the run was going on.
			if ( ! $done ) {
				return false;
			}
			$next = Network::site_ids_after( $blog, 1 );
			if ( ! $next ) {
				$cursor['stage'] = 'done';
				return true;
			}
			$this->own_hosts = null;
			$this->with_blog(
				$next[0],
				function () use ( &$cursor, $next ) {
					$this->enter_blog( $cursor, $next[0] );
				}
			);
			if ( microtime( true ) >= (float) $deadline || ( is_callable( $stop ) && call_user_func( $stop ) ) ) {
				return false;
			}
		}
	}

	/**
	 * Advances the run on the current site until $deadline.
	 *
	 * @param array         $cursor   Cursor (updated).
	 * @param float         $deadline Microtime.
	 * @param callable|null $stop     Cancel check.
	 * @return bool True when this site is complete.
	 */
	private function step_site( array &$cursor, $deadline, $stop = null ) {
		$first = true;
		while ( 'done' !== $cursor['stage'] ) {
			if ( ! $first && ( microtime( true ) >= (float) $deadline || ( is_callable( $stop ) && call_user_func( $stop ) ) ) ) {
				return false;
			}
			$first = false;
			if ( 'options' === $cursor['stage'] ) {
				$this->options_chunk( $cursor );
			} elseif ( 'posts' === $cursor['stage'] ) {
				$this->posts_chunk( $cursor );
			} elseif ( array_key_exists( (string) $cursor['stage'], self::CODE_TABLES ) ) {
				$this->table_chunk( $cursor );
			} else {
				$cursor['stage'] = 'done';
			}
		}
		return true;
	}

	/**
	 * Closes a complete run: resolves open findings it did not see again,
	 * saves the summary and logs it.
	 *
	 * @param array $cursor Completed cursor.
	 * @return array Summary (also stored in LAST_OPTION).
	 */
	public function finish( array $cursor ) {
		$resolved = $this->resolve_unseen( (string) $cursor['run'] );
		$summary  = array(
			'run'           => (string) $cursor['run'],
			'started_at'    => (int) $cursor['started'],
			'finished_at'   => time(),
			'options_total' => (int) $cursor['options_total'],
			'posts_total'   => (int) $cursor['posts_total'],
			'sites'         => isset( $cursor['sites'] ) ? (int) $cursor['sites'] : 1,
			'options'       => (int) $cursor['options'],
			'posts'         => (int) $cursor['posts'],
			'findings'      => (int) $cursor['findings'],
			'new'           => (int) $cursor['new'],
			'resolved'      => $resolved,
		);
		Network::update_option( self::LAST_OPTION, $summary, false );
		wpcybersec()->logger->log(
			'db_scan_finished',
			sprintf(
				/* translators: 1: number of options, 2: number of posts, 3: findings, 4: new reports */
				__( 'Database scan finished: %1$s options and %2$s posts checked, %3$s suspicious values (%4$s new).', 'qartvelo-guard' ),
				number_format_i18n( $summary['options_total'] ),
				number_format_i18n( $summary['posts_total'] ),
				number_format_i18n( $summary['findings'] ),
				number_format_i18n( $summary['new'] )
			),
			$summary
		);
		return $summary;
	}

	/**
	 * Complete scan in one call.
	 *
	 * @param string $run_id Optional run id.
	 * @return array finish() summary.
	 */
	public function run( $run_id = '' ) {
		$cursor = $this->begin( $run_id );
		$this->step( $cursor, PHP_INT_MAX );
		return $this->finish( $cursor );
	}

	/**
	 * Summary of the last complete run.
	 *
	 * @return array Empty when the database was never scanned.
	 */
	public function last_run() {
		$last = Network::get_option( self::LAST_OPTION, array() );
		return is_array( $last ) ? $last : array();
	}

	/* ------------------------------------------------------------------ */
	/* Chunks                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * One query over a range of option ids.
	 *
	 * @param array $cursor Cursor.
	 */
	private function options_chunk( array &$cursor ) {
		global $wpdb;
		$from = (int) $cursor['last'];
		$to   = $from + self::OPTIONS_RANGE;

		$params = array(
			self::MAX_VALUE,
			$from,
			$to,
			$wpdb->esc_like( '_transient_' ) . '%',
			$wpdb->esc_like( '_site_transient_' ) . '%',
			$wpdb->esc_like( 'wpcybersec_' ) . '%',
			'%eval%',
			'%assert%',
			'%document.write%',
			'ihaf_insert_header',
			'ihaf_insert_body',
			'ihaf_insert_footer',
			'hefo',
			$wpdb->esc_like( 'widget_' ) . '%',
			$wpdb->esc_like( 'theme_mods_' ) . '%',
			'%' . $wpdb->esc_like( 'custom_html' ) . '%',
			'%<script%',
			'%u003cscript%',
			'%<iframe%',
			'%u003ciframe%',
			$this->rows_limit(),
		);
		// phpcs:disable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- core table from $wpdb, every value is a placeholder.
		$sql  = "SELECT option_id, option_name, LENGTH(option_value) AS len, SUBSTRING(option_value, 1, %d) AS val FROM {$wpdb->options}"
			. ' WHERE option_id > %d AND option_id <= %d AND option_name NOT LIKE %s AND option_name NOT LIKE %s AND option_name NOT LIKE %s'
			. ' AND ( LOWER(option_value) LIKE %s OR LOWER(option_value) LIKE %s OR LOWER(option_value) LIKE %s'
			. ' OR option_name IN (%s, %s, %s, %s)'
			. ' OR ( ( option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s )'
			. ' AND ( LOWER(option_value) LIKE %s OR LOWER(option_value) LIKE %s OR LOWER(option_value) LIKE %s OR LOWER(option_value) LIKE %s ) ) )'
			. ' ORDER BY option_id LIMIT %d';
		$rows = (array) $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );
		// phpcs:enable

		foreach ( $rows as $row ) {
			++$cursor['options'];
			$name    = (string) $row['option_name'];
			$context = self::option_context( $name );
			$hits    = $this->inspect( (string) $row['val'], $context, array_key_exists( $name, self::CODE_OPTIONS ) ? self::CODE_OPTIONS[ $name ] : '' );
			if ( $hits ) {
				$this->report(
					$this->loc( $cursor, 'option:' . $name ),
					array(
						'table' => 'options',
						'key'   => $name,
						/* translators: %s: option name */
						'label' => sprintf( __( 'Option %s', 'qartvelo-guard' ), $name ),
					),
					$hits,
					self::fingerprint( $this->loc( $cursor, 'option:' . $name ), (string) $row['val'], (int) $row['len'] ),
					(int) $row['len'],
					$cursor
				);
			}
		}

		if ( count( $rows ) >= $this->rows_limit() ) {
			$last           = end( $rows );
			$cursor['last'] = (int) $last['option_id']; // The rest of this range comes next.
			return;
		}
		$cursor['last'] = $to;
		if ( $to >= (int) $cursor['max'] ) {
			$cursor['stage']       = 'posts';
			$cursor['last']        = 0;
			$cursor['max']         = (int) $wpdb->get_var( "SELECT MAX(ID) FROM {$wpdb->posts}" ); // phpcs:ignore WordPress.DB
			$cursor['posts_total'] += $this->count_posts();
		}
	}

	/**
	 * One query over a range of post ids.
	 *
	 * @param array $cursor Cursor.
	 */
	private function posts_chunk( array &$cursor ) {
		global $wpdb;
		$from = (int) $cursor['last'];
		$to   = $from + self::POSTS_RANGE;

		$types    = self::SKIP_POST_TYPES;
		$statuses = self::POST_STATUSES;
		$params   = array_merge(
			array( self::MAX_VALUE, $from, $to ),
			$types,
			$statuses,
			array_keys( self::CODE_POST_TYPES ),
			array( '%<script%', '%<iframe%', '%eval%', '%document.write%', $this->rows_limit() )
		);
		// phpcs:disable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- core table from $wpdb; the IN lists are placeholders from array_fill().
		$sql  = "SELECT ID, post_type, post_status, post_title, LENGTH(post_content) AS len, SUBSTRING(post_content, 1, %d) AS val FROM {$wpdb->posts}"
			. ' WHERE ID > %d AND ID <= %d'
			. ' AND post_type NOT IN (' . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ')'
			. ' AND post_status IN (' . implode( ',', array_fill( 0, count( $statuses ), '%s' ) ) . ')'
			. ' AND ( post_type IN (' . implode( ',', array_fill( 0, count( self::CODE_POST_TYPES ), '%s' ) ) . ') OR LOWER(post_content) LIKE %s OR LOWER(post_content) LIKE %s OR LOWER(post_content) LIKE %s OR LOWER(post_content) LIKE %s )'
			. ' ORDER BY ID LIMIT %d';
		$rows = (array) $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );
		// phpcs:enable

		foreach ( $rows as $row ) {
			++$cursor['posts'];
			$id     = (int) $row['ID'];
			$plugin = array_key_exists( (string) $row['post_type'], self::CODE_POST_TYPES ) ? self::CODE_POST_TYPES[ (string) $row['post_type'] ] : '';
			$hits   = $this->inspect( (string) $row['val'], '' !== $plugin ? 'code' : 'post', $plugin );
			if ( $hits ) {
				$title = Store::db_text( (string) $row['post_title'] );
				$title = function_exists( 'mb_substr' ) ? mb_substr( $title, 0, 120 ) : substr( $title, 0, 120 );
				$this->report(
					$this->loc( $cursor, 'post:' . $id ),
					array(
						'table'       => 'posts',
						'key'         => $id,
						'post_type'   => (string) $row['post_type'],
						'post_status' => (string) $row['post_status'],
						'post_title'  => $title,
						'label'       => '' !== trim( $title )
							/* translators: 1: post id, 2: post title */
							? sprintf( __( 'Post #%1$d (%2$s)', 'qartvelo-guard' ), $id, $title )
							/* translators: %d: post id */
							: sprintf( __( 'Post #%d', 'qartvelo-guard' ), $id ),
					),
					$hits,
					self::fingerprint( $this->loc( $cursor, 'post:' . $id ), (string) $row['val'], (int) $row['len'] ),
					(int) $row['len'],
					$cursor
				);
			}
		}

		if ( count( $rows ) >= $this->rows_limit() ) {
			$last           = end( $rows );
			$cursor['last'] = (int) $last['ID'];
			return;
		}
		$cursor['last'] = $to;
		if ( $to >= (int) $cursor['max'] ) {
			$this->next_table( $cursor, 'posts' );
		}
	}

	/**
	 * Moves the cursor to the next code plugin table that exists (or done).
	 *
	 * @param array  $cursor Cursor.
	 * @param string $after  Stage just finished.
	 */
	private function next_table( array &$cursor, $after ) {
		global $wpdb;
		$stages = array_keys( self::CODE_TABLES );
		$start  = 'posts' === $after ? 0 : (int) array_search( $after, $stages, true ) + 1;
		$blog   = ! empty( $cursor['blog'] ) ? (int) $cursor['blog'] : get_current_blog_id();
		for ( $i = $start; $i < count( $stages ); $i++ ) {
			$def = self::CODE_TABLES[ $stages[ $i ] ];
			if ( ! empty( $def['base'] ) && Network::active() && $blog !== Network::main_site_id() ) {
				continue; // One table for the whole network: visited with the main site.
			}
			$table = self::table_name( $def );
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ); // phpcs:ignore WordPress.DB
			if ( $found === $table ) {
				$cursor['stage'] = $stages[ $i ];
				$cursor['last']  = 0;
				$cursor['max']   = (int) $wpdb->get_var( 'SELECT MAX(`' . $def['id'] . "`) FROM `{$table}`" ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table and column names come from the CODE_TABLES constant.
				return;
			}
		}
		$cursor['stage'] = 'done';
	}

	/**
	 * Full name of a code plugin table: the site's prefix, or the network's
	 * base prefix for a table that exists once per network.
	 *
	 * @param array $def CODE_TABLES entry.
	 * @return string
	 */
	private static function table_name( array $def ) {
		global $wpdb;
		return ( empty( $def['base'] ) ? $wpdb->prefix : $wpdb->base_prefix ) . $def['table'];
	}

	/**
	 * One query over a code plugin table (Header Footer Code Manager, Code Snippets).
	 *
	 * @param array $cursor Cursor.
	 */
	private function table_chunk( array &$cursor ) {
		global $wpdb;
		$stage = (string) $cursor['stage'];
		$def   = self::CODE_TABLES[ $stage ];
		$table = self::table_name( $def );
		$from  = (int) $cursor['last'];
		$to    = $from + self::POSTS_RANGE;
		// phpcs:disable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table and column names come from the CODE_TABLES constant.
		$sql  = "SELECT `{$def['id']}` AS id, `{$def['name']}` AS name, LENGTH(`{$def['code']}`) AS len, SUBSTRING(`{$def['code']}`, 1, %d) AS val FROM `{$table}`"
			. " WHERE `{$def['id']}` > %d AND `{$def['id']}` <= %d ORDER BY `{$def['id']}` LIMIT %d";
		$rows = (array) $wpdb->get_results( $wpdb->prepare( $sql, self::MAX_VALUE, $from, $to, $this->rows_limit() ), ARRAY_A );
		// phpcs:enable
		foreach ( $rows as $row ) {
			if ( ! isset( $cursor['code_rows'] ) ) {
				$cursor['code_rows'] = 0;
			}
			++$cursor['code_rows'];
			$id   = (int) $row['id'];
			$hits = $this->inspect( (string) $row['val'], 'code', $def['plugin'] );
			if ( ! $hits ) {
				continue;
			}
			$name = Store::db_text( (string) $row['name'] );
			$name = function_exists( 'mb_substr' ) ? mb_substr( $name, 0, 100 ) : substr( $name, 0, 100 );
			$this->report(
				$this->loc( $cursor, $stage . ':' . $id ),
				array(
					'table'  => $def['table'],
					'key'    => $id,
					'plugin' => $def['plugin'],
					'label'  => '' !== trim( $name )
						/* translators: 1: plugin name, 2: snippet id, 3: snippet name */
						? sprintf( __( '%1$s snippet #%2$d (%3$s)', 'qartvelo-guard' ), $def['plugin'], $id, $name )
						/* translators: 1: plugin name, 2: snippet id */
						: sprintf( __( '%1$s snippet #%2$d', 'qartvelo-guard' ), $def['plugin'], $id ),
				),
				$hits,
				self::fingerprint( $this->loc( $cursor, $stage . ':' . $id ), (string) $row['val'], (int) $row['len'] ),
				(int) $row['len'],
				$cursor
			);
		}
		if ( count( $rows ) >= $this->rows_limit() ) {
			$last           = end( $rows );
			$cursor['last'] = (int) $last['id'];
			return;
		}
		$cursor['last'] = $to;
		if ( $to >= (int) $cursor['max'] ) {
			$this->next_table( $cursor, $stage );
		}
	}

	/**
	 * Posts the scan covers.
	 *
	 * @return int
	 */
	private function count_posts() {
		global $wpdb;
		$types    = self::SKIP_POST_TYPES;
		$statuses = self::POST_STATUSES;
		$sql      = "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type NOT IN (" . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ') AND post_status IN (' . implode( ',', array_fill( 0, count( $statuses ), '%s' ) ) . ')';
		return (int) $wpdb->get_var( $wpdb->prepare( $sql, array_merge( $types, $statuses ) ) ); // phpcs:ignore WordPress.DB
	}

	/* ------------------------------------------------------------------ */
	/* Findings                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Place of a finding: "option:<name>", or on a site of a network other
	 * than the main one "site:<blog id>:option:<name>" (so the same option of
	 * two sites are two places, with their own fingerprints).
	 *
	 * @param array  $cursor   Cursor.
	 * @param string $location Place on the site.
	 * @return string
	 */
	private function loc( array $cursor, $location ) {
		$blog = isset( $cursor['blog'] ) ? (int) $cursor['blog'] : 0;
		if ( $blog > 0 && Network::active() && $blog !== Network::main_site_id() ) {
			return 'site:' . $blog . ':' . $location;
		}
		return $location;
	}

	/**
	 * Creates (or refreshes) the threat item for one finding.
	 *
	 * @param string $location    "option:<name>" | "post:<id>".
	 * @param array  $info        table, key, label and post fields.
	 * @param array  $hits        Hits.
	 * @param string $fingerprint fingerprint().
	 * @param int    $size        Full length of the value.
	 * @param array  $cursor      Cursor (counters).
	 */
	private function report( $location, array $info, array $hits, $fingerprint, $size, array &$cursor ) {
		$plugin = wpcybersec();
		if ( $plugin->allowlist && $plugin->allowlist->is_allowed_db( $fingerprint ) ) {
			return; // Marked safe before; this exact value at this place is trusted.
		}
		++$cursor['findings'];

		$store = $plugin->store;
		$path  = 'db:' . $location;
		$open  = $store->item_find_open( Store::TYPE_THREAT, $path, $fingerprint );
		if ( $open ) {
			$store->item_update( (int) $open['id'], array( 'details' => array( 'seen_run' => (string) $cursor['run'] ) ) );
			return;
		}

		$severity = Signatures::max_severity( $hits );
		$details  = array_merge(
			$info,
			array(
				'hits'        => array_values( $hits ),
				'fingerprint' => $fingerprint,
				'seen_run'    => (string) $cursor['run'],
			)
		);
		if ( ! empty( $cursor['blog'] ) ) {
			$details['blog_id'] = (int) $cursor['blog'];
		}
		$id = $store->item_insert(
			array(
				'type'     => Store::TYPE_THREAT,
				'status'   => Store::STATUS_PENDING,
				'severity' => $severity,
				'path'     => $path,
				'sha256'   => $fingerprint,
				'size'     => max( 0, (int) $size ),
				'source'   => Store::SOURCE_DATABASE,
				'details'  => $details,
			)
		);
		if ( ! $id ) {
			return;
		}
		++$cursor['new'];
		$plugin->logger->log(
			'db_threat_found',
			sprintf(
				/* translators: 1: severity label, 2: where in the database (for example "Option widget_text") */
				__( '%1$s finding in the database: %2$s', 'qartvelo-guard' ),
				Store::severity_label( $severity ),
				$info['label']
			),
			array(
				'item_id'  => $id,
				'path'     => $path,
				'severity' => $severity,
			)
		);
		if ( $plugin->notifier && method_exists( $plugin->notifier, 'item_created' ) ) {
			$plugin->notifier->item_created( $id );
		}
	}

	/**
	 * Resolves open findings a complete run did not see again.
	 *
	 * @param string $run Run id.
	 * @return int Items resolved.
	 */
	private function resolve_unseen( $run ) {
		global $wpdb;
		$table = Store::table( 'items' );
		$rows  = (array) $wpdb->get_results( $wpdb->prepare( "SELECT id, path, details FROM {$table} WHERE type = %s AND status = %s AND source = %s ORDER BY id LIMIT 5000", Store::TYPE_THREAT, Store::STATUS_PENDING, Store::SOURCE_DATABASE ), ARRAY_A ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is Store::table(): $wpdb->prefix plus a fixed name.
		$done  = 0;
		foreach ( $rows as $row ) {
			$details = json_decode( (string) $row['details'], true );
			$seen    = is_array( $details ) && isset( $details['seen_run'] ) ? (string) $details['seen_run'] : '';
			if ( $seen === $run ) {
				continue;
			}
			wpcybersec()->store->item_update(
				(int) $row['id'],
				array(
					'status'     => Store::STATUS_RESOLVED,
					'decided_at' => Store::now(),
					'details'    => array( 'resolution' => 'db_clean' ),
				)
			);
			++$done;
		}
		if ( $done ) {
			wpcybersec()->logger->log(
				'item_auto_resolved',
				sprintf(
					/* translators: %s: number of reports */
					_n( 'Closed %s database report: the value is clean now or no longer exists.', 'Closed %s database reports: the values are clean now or no longer exist.', $done, 'qartvelo-guard' ),
					number_format_i18n( $done )
				)
			);
		}
		return $done;
	}

	/**
	 * Fingerprint of a value at a place. Bound to the place, so "Mark safe" for
	 * a widget never approves the same text somewhere else, and namespaced, so
	 * it can never equal the hash of a file.
	 *
	 * @param string $location "option:<name>" | "post:<id>".
	 * @param string $value    Value (as read, up to MAX_VALUE bytes).
	 * @param int    $length   Full length of the value.
	 * @return string 64 hex chars.
	 */
	public static function fingerprint( $location, $value, $length ) {
		return hash( 'sha256', "wpcybersec-db\n" . (string) $location . "\n" . (int) $length . "\n" . (string) $value );
	}

	/**
	 * How an option is checked: "option_html" for widgets, theme mods and
	 * custom HTML (where scripts and iframes are shown to visitors as they are),
	 * "option" for everything else (plugin settings often hold tracking code
	 * legitimately, so only code payloads count there).
	 *
	 * @param string $name Option name.
	 * @return string
	 */
	public static function option_context( $name ) {
		if ( array_key_exists( (string) $name, self::CODE_OPTIONS ) ) {
			return 'code';
		}
		$name = strtolower( (string) $name );
		if ( 0 === strpos( $name, 'widget_' ) || 0 === strpos( $name, 'theme_mods_' ) || false !== strpos( $name, 'custom_html' ) ) {
			return 'option_html';
		}
		return 'option';
	}

	/* ------------------------------------------------------------------ */
	/* Detection                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Hits for one value.
	 *
	 * Every context: eval/assert of decoded data (eval(base64_decode(,
	 * eval(atob(, eval(String.fromCharCode(...) and document.write(unescape(.
	 * Options also: eval/assert together with a PHP decoder anywhere in the
	 * value, and eval together with String.fromCharCode. Posts and widget like
	 * options also: eval inside a script or an event handler, scripts loaded
	 * from another site, hidden iframes.
	 *
	 * Only linear patterns and plain string searches are used: a value is
	 * attacker controlled and can be up to MAX_VALUE bytes.
	 *
	 * Code plugin storage ("code": header / footer code plugins, Code
	 * Snippets, WPCode): scripts from another site, eval, base64 decoding and
	 * unescape are reported as medium "review" findings, so the administrator
	 * confirms the code is theirs (Mark safe remembers it).
	 *
	 * @param string $value   Value.
	 * @param string $context option | option_html | post | code.
	 * @param string $plugin  Plugin that stores the value (code context).
	 * @return array[] Hits { sig, title, severity, line, snippet }.
	 */
	public function inspect( $value, $context, $plugin = '' ) {
		$value = (string) $value;
		if ( '' === $value ) {
			return array();
		}
		// Serialized and JSON values escape slashes, quotes and angle brackets.
		$text  = str_replace( array( '\\/', '\\"', "\\'", '\\u003c', '\\u003C', '\\u003e', '\\u003E' ), array( '/', '"', "'", '<', '<', '>', '>' ), $value );
		$lower = strtolower( $text );
		$hits  = array();

		$has_eval = false !== strpos( $lower, 'eval' ) || false !== strpos( $lower, 'assert' );
		if ( $has_eval && preg_match( '~(?<![\w$.])(?<!->)(?<!::)(?:eval|assert)\s{0,20}+\(\s{0,20}+(?:@\s{0,5}+)?(?:\x5c?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uudecode)|(?:window\.)?(?:atob|unescape|decodeURIComponent)|String\.fromCharCode)\s{0,20}+\(~i', $text, $m, PREG_OFFSET_CAPTURE ) ) {
			$hits[] = $this->hit( 'db_eval_decoded', __( 'Runs hidden code: eval of decoded data stored in the database', 'qartvelo-guard' ), Store::SEV_HIGH, $text, $m[0][1], strlen( $m[0][0] ) );
		}
		if ( false !== strpos( $lower, 'document.write' ) && preg_match( '~document\.write(?:ln)?\s{0,20}+\(\s{0,20}+(?:window\.)?unescape\s{0,20}+\(~i', $text, $m, PREG_OFFSET_CAPTURE ) ) {
			$hits[] = $this->hit( 'db_docwrite_unescape', __( 'Writes a hidden, escaped script into the page (document.write of unescape)', 'qartvelo-guard' ), Store::SEV_HIGH, $text, $m[0][1], strlen( $m[0][0] ) );
		}

		if ( in_array( $context, array( 'option', 'option_html' ), true ) && $has_eval && ! $this->has_sig( $hits, 'db_eval_decoded' ) ) {
			$eval = preg_match( '~(?<![\w$.])(?<!->)(?<!::)(?:eval|assert)\s{0,20}+\(~i', $text, $e, PREG_OFFSET_CAPTURE ) ? $e[0] : null;
			if ( $eval ) {
				if ( preg_match( '~\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s{0,20}+\(~i', $text ) ) {
					$hits[] = $this->hit( 'db_php_payload', __( 'Code payload stored in an option: eval together with a decoder', 'qartvelo-guard' ), Store::SEV_HIGH, $text, $eval[1], strlen( $eval[0] ) );
				} elseif ( preg_match( '~String\s{0,5}+\.\s{0,5}+fromCharCode\s{0,20}+\(~i', $text ) ) {
					$hits[] = $this->hit( 'db_js_charcode_eval', __( 'Script stored in an option runs code built from character codes', 'qartvelo-guard' ), Store::SEV_HIGH, $text, $eval[1], strlen( $eval[0] ) );
				}
			}
		}

		if ( 'code' === $context ) {
			$hits = array_merge( $hits, $this->code_hits( $text, $lower, $hits, '' !== $plugin ? $plugin : __( 'a code plugin', 'qartvelo-guard' ) ) );
		} elseif ( 'option' !== $context ) {
			$hits = array_merge( $hits, $this->html_hits( $text, $lower, $hits ) );
		}

		return Signatures::unique( $hits, self::MAX_HITS );
	}

	/**
	 * Script and iframe checks for HTML that visitors see (posts, widgets).
	 *
	 * @param string $text  Value (unescaped).
	 * @param string $lower Lowercase copy.
	 * @param array  $found Hits so far.
	 * @return array[]
	 */
	private function html_hits( $text, $lower, array $found ) {
		$hits = array();

		foreach ( self::tags( $text, $lower, 'script' ) as $tag ) {
			list( $offset, $open, $body ) = $tag;
			if ( preg_match( '~\bsrc\s{0,10}+=\s{0,10}+(["\x27]?)([^"\x27\s>]{1,500}+)~i', $open, $src ) ) {
				$host = $this->external_host( $src[2] );
				if ( '' !== $host && ! $this->is_trusted_host( $host ) ) {
					$hits[] = $this->hit(
						'db_external_script',
						/* translators: %s: host name */
						sprintf( __( 'Loads a script from another site (%s)', 'qartvelo-guard' ), $host ),
						Store::SEV_MEDIUM,
						$text,
						$offset,
						strlen( $open )
					);
				}
			}
			if ( '' !== $body && ! $this->has_sig( $found, 'db_eval_decoded' ) && preg_match( '~(?<![\w$.])eval\s{0,20}+\(~i', $body, $m, PREG_OFFSET_CAPTURE ) ) {
				$hits[] = $this->hit( 'db_script_eval', __( 'Inline script runs code with eval', 'qartvelo-guard' ), Store::SEV_HIGH, $text, $offset + strlen( $open ) + $m[0][1], strlen( $m[0][0] ) );
			}
		}

		// eval in an event handler attribute (onload="eval(...)"). The value is
		// captured possessively and searched with strpos: linear.
		if ( false !== strpos( $lower, 'eval' ) && preg_match_all( '~\bon[a-z]{3,20}+\s{0,10}+=\s{0,10}+["\x27]([^"\x27]{0,2000}+)~i', $text, $attrs, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
			foreach ( array_slice( $attrs, 0, self::MAX_TAGS ) as $attr ) {
				if ( preg_match( '~(?<![\w$.])eval\s{0,20}+\(~i', $attr[1][0] ) ) {
					$hits[] = $this->hit( 'db_script_eval', __( 'Event handler runs code with eval', 'qartvelo-guard' ), Store::SEV_HIGH, $text, $attr[0][1], strlen( $attr[0][0] ) );
					break;
				}
			}
		}

		foreach ( self::tags( $text, $lower, 'iframe' ) as $tag ) {
			list( $offset, $open ) = $tag;
			if ( ! self::is_hidden_iframe( $open ) ) {
				continue;
			}
			if ( preg_match( '~\bsrc\s{0,10}+=\s{0,10}+(["\x27]?)([^"\x27\s>]{1,500}+)~i', $open, $src ) && $this->is_tag_manager_frame( $src[2] ) ) {
				continue; // Google Tag Manager's noscript frame is hidden on purpose.
			}
			if ( $this->is_benign_hidden_frame( $open ) ) {
				continue;
			}
			$hits[] = $this->hit( 'db_hidden_iframe', __( 'Hidden iframe (invisible frame loading another page)', 'qartvelo-guard' ), Store::SEV_MEDIUM, $text, $offset, strlen( $open ) );
		}
		return $hits;
	}

	/**
	 * Review findings for code stored by a header / footer or snippet plugin.
	 *
	 * @param string $text   Value (unescaped).
	 * @param string $lower  Lowercase copy.
	 * @param array  $found  Hits so far.
	 * @param string $plugin Plugin name.
	 * @return array[]
	 */
	private function code_hits( $text, $lower, array $found, $plugin ) {
		$hits = array();
		foreach ( self::tags( $text, $lower, 'script' ) as $tag ) {
			list( $offset, $open ) = $tag;
			if ( preg_match( '~\bsrc\s{0,10}+=\s{0,10}+(["\x27]?)([^"\x27\s>]{1,500}+)~i', $open, $src ) ) {
				$host = $this->external_host( $src[2] );
				if ( '' !== $host ) {
					$hits[] = $this->hit(
						'db_code_external_script',
						/* translators: 1: host name, 2: plugin name */
						sprintf( __( 'Review: script from another site (%1$s) injected through %2$s', 'qartvelo-guard' ), $host, $plugin ),
						Store::SEV_MEDIUM,
						$text,
						$offset,
						strlen( $open )
					);
				}
			}
		}
		$checks = array(
			/* translators: %s: plugin name */
			'db_code_eval'     => array( '~(?<![\w$.])(?<!->)(?<!::)eval\s{0,20}+\(~i', 'eval', 'db_eval_decoded', __( 'Review: eval() in code injected through %s', 'qartvelo-guard' ) ),
			/* translators: %s: plugin name */
			'db_code_base64'   => array( '~\b(?:base64_decode|atob)\s{0,20}+\(~i', 'base64_decode', 'db_eval_decoded', __( 'Review: base64 decoding in code injected through %s', 'qartvelo-guard' ) ),
			/* translators: %s: plugin name */
			'db_code_unescape' => array( '~\bunescape\s{0,20}+\(~i', 'unescape', 'db_docwrite_unescape', __( 'Review: unescape() in code injected through %s', 'qartvelo-guard' ) ),
		);
		foreach ( $checks as $sig => $check ) {
			$needle = 'base64_decode' === $check[1] ? ( false !== strpos( $lower, 'base64_decode' ) || false !== strpos( $lower, 'atob' ) ) : false !== strpos( $lower, $check[1] );
			if ( ! $needle || $this->has_sig( $found, $check[2] ) ) {
				continue;
			}
			if ( preg_match( $check[0], $text, $m, PREG_OFFSET_CAPTURE ) ) {
				$hits[] = $this->hit( $sig, sprintf( $check[3], $plugin ), Store::SEV_MEDIUM, $text, $m[0][1], strlen( $m[0][0] ) );
			}
		}
		foreach ( self::tags( $text, $lower, 'iframe' ) as $tag ) {
			list( $offset, $open ) = $tag;
			if ( self::is_hidden_iframe( $open ) && ! $this->is_benign_hidden_frame( $open ) && ! ( preg_match( '~\bsrc\s{0,10}+=\s{0,10}+(["\x27]?)([^"\x27\s>]{1,500}+)~i', $open, $src ) && $this->is_tag_manager_frame( $src[2] ) ) ) {
				$hits[] = $this->hit( 'db_hidden_iframe', __( 'Hidden iframe (invisible frame loading another page)', 'qartvelo-guard' ), Store::SEV_MEDIUM, $text, $offset, strlen( $open ) );
			}
		}
		return $hits;
	}

	/**
	 * Opening tags of one kind with their offset (and the body for scripts).
	 * Plain string search: linear in the length of the value.
	 *
	 * @param string $text  Value.
	 * @param string $lower Lowercase copy.
	 * @param string $name  script | iframe.
	 * @return array[] [ offset, opening tag, body ]
	 */
	private static function tags( $text, $lower, $name ) {
		$out    = array();
		$needle = '<' . $name;
		$len    = strlen( $lower );
		$pos    = 0;
		while ( count( $out ) < self::MAX_TAGS && false !== ( $start = strpos( $lower, $needle, $pos ) ) ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition
			$after = $start + strlen( $needle );
			if ( $after < $len && ( preg_match( '/[a-z0-9]/', $lower[ $after ] ) || '-' === $lower[ $after ] ) ) {
				$pos = $after; // <scripts>, <iframe-x>: another tag.
				continue;
			}
			$end = strpos( $lower, '>', $after );
			if ( false === $end ) {
				break;
			}
			if ( $end - $start > 4000 ) {
				$pos = $after;
				continue;
			}
			$open = substr( $text, $start, $end - $start + 1 );
			$body = '';
			$pos  = $end + 1;
			if ( 'script' === $name ) {
				$close = strpos( $lower, '</script', $pos );
				$stop  = false === $close ? $len : $close;
				$body  = substr( $text, $pos, min( $stop - $pos, 262144 ) );
				$pos   = $stop;
			}
			$out[] = array( $start, $open, $body );
		}
		return $out;
	}

	/**
	 * Whether an iframe opening tag hides the frame.
	 *
	 * @param string $open Opening tag.
	 * @return bool
	 */
	private static function is_hidden_iframe( $open ) {
		$open = (string) $open;
		if ( preg_match( '~display\s{0,10}+:\s{0,10}+none|visibility\s{0,10}+:\s{0,10}+hidden~i', $open ) ) {
			return true;
		}
		// width="0", height=1, width:0px ...
		return 1 === preg_match( '~\b(?:width|height)\s{0,10}+(?:=\s{0,10}+["\x27]?|:)\s{0,10}+(?:0*+1|0++)(?:\.0++)?+(?:px)?+(?![\d.%a-z])~i', $open );
	}

	/**
	 * Host of an absolute or protocol relative URL when it is not this site.
	 *
	 * @param string $url URL from a src attribute.
	 * @return string Lowercase host, '' for this site or a relative URL.
	 */
	private function external_host( $url ) {
		$url = trim( html_entity_decode( (string) $url, ENT_QUOTES ) );
		if ( 0 === strpos( $url, '//' ) ) {
			$url = 'https:' . $url;
		}
		if ( ! preg_match( '~^https?://~i', $url ) ) {
			return '';
		}
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		if ( '' === $host ) {
			return '';
		}
		$bare = 0 === strpos( $host, 'www.' ) ? substr( $host, 4 ) : $host;
		foreach ( $this->own_hosts() as $own ) {
			if ( $bare === $own || ( strlen( $bare ) > strlen( $own ) && '.' . $own === substr( $bare, -1 - strlen( $own ) ) ) ) {
				return '';
			}
		}
		return $host;
	}

	/**
	 * @return string[] This site's hosts without "www.".
	 */
	private function own_hosts() {
		if ( null === $this->own_hosts ) {
			$hosts = array();
			foreach ( array( home_url( '/' ), site_url( '/' ) ) as $url ) {
				$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
				if ( '' !== $host ) {
					$hosts[] = 0 === strpos( $host, 'www.' ) ? substr( $host, 4 ) : $host;
				}
			}
			$this->own_hosts = array_values( array_unique( $hosts ) );
		}
		return $this->own_hosts;
	}

	/**
	 * Hidden iframes WordPress itself produces: post embeds
	 * (class "wp-embedded-content", hidden until the embed has loaded) and
	 * frames that load a page of this same site.
	 *
	 * @param string $open Opening iframe tag.
	 * @return bool
	 */
	private function is_benign_hidden_frame( $open ) {
		if ( preg_match( '~\bclass\s{0,10}+=\s{0,10}+["\x27][^"\x27]{0,200}?\bwp-embedded-content\b~i', $open ) ) {
			return true;
		}
		if ( preg_match( '~\bsrc\s{0,10}+=\s{0,10}+(["\x27]?)([^"\x27\s>]{1,500}+)~i', $open, $src ) ) {
			$host = strtolower( (string) wp_parse_url( html_entity_decode( $src[2] ), PHP_URL_HOST ) );
			$host = 0 === strpos( $host, 'www.' ) ? substr( $host, 4 ) : $host;
			if ( '' === $host || in_array( $host, $this->own_hosts(), true ) ) {
				return true; // Relative or same-site page.
			}
		}
		return false;
	}

	/**
	 * @param string $host Lowercase host.
	 * @return bool
	 */
	private function is_trusted_host( $host ) {
		if ( null === $this->trusted_hosts ) {
			/**
			 * Hosts whose scripts in posts and widgets are not reported.
			 *
			 * @param string[] $hosts Lowercase host names.
			 */
			$this->trusted_hosts = array_map( 'strtolower', (array) apply_filters( 'wpcybersec_db_trusted_script_hosts', self::TRUSTED_SCRIPT_HOSTS ) );
		}
		return in_array( $host, $this->trusted_hosts, true );
	}

	/**
	 * @param string $url iframe src.
	 * @return bool
	 */
	private function is_tag_manager_frame( $url ) {
		$url = (string) $url;
		if ( 0 === strpos( $url, '//' ) ) {
			$url = 'https:' . $url;
		}
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		return 'www.googletagmanager.com' === $host && '/ns.html' === $path;
	}

	/**
	 * @param string $sig      Id.
	 * @param string $title    Title.
	 * @param int    $severity Severity.
	 * @param string $text     Value.
	 * @param int    $offset   Match offset.
	 * @param int    $length   Match length.
	 * @return array Hit with a redacted snippet.
	 */
	private function hit( $sig, $title, $severity, $text, $offset, $length ) {
		$snippet = Signatures::snippet( $text, (int) $offset, (int) $length );
		if ( class_exists( __NAMESPACE__ . '\Diff' ) ) {
			$snippet = Diff::redact_snippet( $snippet, 'database-value.html' );
		}
		return array(
			'sig'      => $sig,
			'title'    => $title,
			'severity' => (int) $severity,
			'line'     => 0,
			'snippet'  => $snippet,
		);
	}

	/**
	 * @param array  $hits Hits.
	 * @param string $sig  Id.
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

	/* ------------------------------------------------------------------ */
	/* Display helpers                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Whether an item is a database finding.
	 *
	 * @param array $item Item.
	 * @return bool
	 */
	public static function is_db_item( array $item ) {
		return isset( $item['source'] ) && Store::SOURCE_DATABASE === (string) $item['source'];
	}

	/**
	 * Readable place of a database finding ("Option widget_text", "Post #12 (About)").
	 *
	 * @param array $item Item.
	 * @return string Plain text.
	 */
	public static function location_label( array $item ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		if ( ! empty( $details['label'] ) ) {
			return (string) $details['label'];
		}
		$path = self::site_path( (string) $item['path'] );
		if ( 0 === strpos( $path, 'db:option:' ) ) {
			/* translators: %s: option name */
			return sprintf( __( 'Option %s', 'qartvelo-guard' ), substr( $path, 10 ) );
		}
		if ( 0 === strpos( $path, 'db:post:' ) ) {
			/* translators: %d: post id */
			return sprintf( __( 'Post #%d', 'qartvelo-guard' ), (int) substr( $path, 8 ) );
		}
		return $path;
	}

	/**
	 * Post id of a finding in a post (0 for options).
	 *
	 * @param array $item Item.
	 * @return int
	 */
	public static function post_id( array $item ) {
		$path = self::site_path( (string) $item['path'] );
		return 0 === strpos( $path, 'db:post:' ) ? (int) substr( $path, 8 ) : 0;
	}

	/**
	 * Site of a finding (multisite): details.blog_id, else the site in the
	 * path, else the main site.
	 *
	 * @param array $item Item.
	 * @return int 0 on a single site.
	 */
	public static function blog_id( array $item ) {
		if ( ! Network::active() ) {
			return 0;
		}
		if ( ! empty( $item['details']['blog_id'] ) ) {
			return (int) $item['details']['blog_id'];
		}
		if ( preg_match( '/^db:site:(\d+):/', (string) $item['path'], $m ) ) {
			return (int) $m[1];
		}
		return Network::main_site_id();
	}

	/**
	 * "db:site:<id>:option:x" without the site part ("db:option:x").
	 *
	 * @param string $path Item path.
	 * @return string
	 */
	private static function site_path( $path ) {
		return (string) preg_replace( '/^db:site:\d+:/', 'db:', $path );
	}
}
