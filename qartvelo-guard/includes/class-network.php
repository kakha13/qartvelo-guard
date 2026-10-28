<?php
/**
 * Multisite network mode: shared options, main-site cron and migration.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Every site of a multisite network shares one file system, so the plugin
 * keeps ONE state for the whole network:
 *
 *   - tables use $wpdb->base_prefix (Store::table()), never a site's prefix;
 *   - every plugin option is a network option (get_site_option()), read and
 *     written through get_option() / update_option() / add_option() /
 *     delete_option() here; on a single site these are the normal options;
 *   - cron events live on the main site only (schedule_event() and friends
 *     switch to it), so scans run once for the whole network;
 *   - plugin screens live in Network Admin (Admin\Admin), held uploads
 *     remember the site they came from (details.blog_id).
 *
 * Static and free of services, so Installer and uninstall-time code may use it
 * before the plugin is booted. On a single site every method behaves exactly
 * like the WordPress function it wraps.
 */
class Network {

	/** Network option: sites already migrated from per-site tables and options ("done" when finished). */
	const MIGRATION_OPTION = 'wpcybersec_ms_migration';

	/** Sites handled per migration or cleanup pass (the rest continues on the next request). */
	const BATCH = 50;

	/** Seconds one migration pass may take. */
	const BUDGET = 10.0;

	/** Table suffixes the plugin owns. */
	const TABLES = array( 'items', 'manifest', 'allowlist', 'log' );

	/**
	 * Small state options read on most admin requests. On a single site they
	 * are always autoloaded (update_option() / add_option() here force it, and
	 * Installer::autoload_state_options() fixes rows written by older
	 * versions), and the ones that do not exist are marked missing in the
	 * request cache from the autoloaded set (prime()), so neither a value nor
	 * a missing option costs a query. On multisite they are read from the
	 * network options table in one query (prime()). Write them only through
	 * this class.
	 */
	const STATE_OPTIONS = array(
		'wpcybersec_guard_installed',
		'wpcybersec_guard_chain',
		'wpcybersec_front_root',
		'wpcybersec_data_dir',
		'wpcybersec_data_fallback',
		'wpcybersec_data_move',
		'wpcybersec_storage_status',
		'wpcybersec_legacy_move',
		'wpcybersec_data_token',
		'wpcybersec_activation_redirect',
		'wpcybersec_counts',
	);

	/** Single sites: autoloaded once the state options were made autoloaded (Installer). */
	const AUTOLOAD_FLAG = 'wpcybersec_autoload_v';

	/** Network options read on most admin requests besides STATE_OPTIONS (multisite priming only). */
	const NETWORK_PRIME = array(
		'wpcybersec_settings',
		'wpcybersec_db_version',
		'wpcybersec_autoload_v',
		self::MIGRATION_OPTION,
	);

	/** @var bool Whether prime() ran in this request. */
	private static $primed = false;

	/** @var string[]|null Per-request cache of home_paths(). */
	private static $home_paths = null;

	/**
	 * @return bool True on a multisite install.
	 */
	public static function active() {
		return function_exists( 'is_multisite' ) && is_multisite();
	}

	/* ------------------------------------------------------------------ */
	/* Options                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Plugin option (network option on multisite).
	 *
	 * @param string $name    Option name.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public static function get_option( $name, $default = false ) {
		if ( ! self::$primed ) {
			self::prime();
		}
		return self::active() ? get_site_option( $name, $default ) : get_option( $name, $default );
	}

	/**
	 * Loads the state options into the request cache once, so reading them
	 * costs no query on a single site and one query on multisite.
	 *
	 * Single site: every row of STATE_OPTIONS is autoloaded (once AUTOLOAD_FLAG
	 * says the rows of older versions were fixed), so a name missing from the
	 * autoloaded set does not exist; it goes into core's "notoptions" cache like
	 * after a failed lookup. Skipped with a persistent object cache, which
	 * already remembers missing options between requests (and could be changed
	 * by another request meanwhile).
	 *
	 * Multisite: one query for STATE_OPTIONS and NETWORK_PRIME
	 * (wp_prime_network_option_caches() on WordPress 6.6+, the same query here
	 * on older versions).
	 */
	public static function prime() {
		if ( self::$primed ) {
			return;
		}
		self::$primed = true;
		if ( ! function_exists( 'wp_cache_get' ) || ( function_exists( 'wp_installing' ) && wp_installing() ) ) {
			return;
		}
		if ( self::active() ) {
			self::prime_network( array_merge( self::STATE_OPTIONS, self::NETWORK_PRIME ) );
			return;
		}
		if ( wp_using_ext_object_cache() || ! function_exists( 'wp_load_alloptions' ) ) {
			return;
		}
		$all = wp_load_alloptions();
		if ( ! is_array( $all ) || ! isset( $all[ self::AUTOLOAD_FLAG ] ) ) {
			return; // Rows of an older version may still be stored without autoload.
		}
		$notoptions = wp_cache_get( 'notoptions', 'options' );
		$notoptions = is_array( $notoptions ) ? $notoptions : array();
		$changed    = false;
		foreach ( self::STATE_OPTIONS as $name ) {
			if ( ! isset( $all[ $name ] ) && ! isset( $notoptions[ $name ] ) && false === wp_cache_get( $name, 'options' ) ) {
				$notoptions[ $name ] = true;
				$changed             = true;
			}
		}
		if ( $changed ) {
			wp_cache_set( 'notoptions', $notoptions, 'options' );
		}
	}

	/**
	 * Multisite: reads network options into the request cache in one query.
	 *
	 * @param string[] $names Option names.
	 */
	private static function prime_network( array $names ) {
		$network = function_exists( 'get_current_network_id' ) ? (int) get_current_network_id() : 1;
		if ( function_exists( 'wp_prime_network_option_caches' ) ) {
			wp_prime_network_option_caches( $network, $names );
			return;
		}
		if ( wp_using_ext_object_cache() ) {
			return; // The persistent cache keeps values and misses between requests.
		}
		global $wpdb;
		$keys = array();
		foreach ( $names as $name ) {
			if ( false === wp_cache_get( $network . ':' . $name, 'site-options' ) ) {
				$keys[] = $name;
			}
		}
		$notoptions = wp_cache_get( $network . ':notoptions', 'site-options' );
		$notoptions = is_array( $notoptions ) ? $notoptions : array();
		$keys       = array_values( array_diff( $keys, array_keys( $notoptions ) ) );
		if ( ! $keys || empty( $wpdb->sitemeta ) ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- core sitemeta table, one placeholder per name; WordPress 6.0-6.5 have no wp_prime_network_option_caches().
		$rows  = (array) $wpdb->get_results( $wpdb->prepare( "SELECT meta_key, meta_value FROM {$wpdb->sitemeta} WHERE site_id = %d AND meta_key IN (" . implode( ',', array_fill( 0, count( $keys ), '%s' ) ) . ')', array_merge( array( $network ), $keys ) ) );
		$found = array();
		foreach ( $rows as $row ) {
			$found[ (string) $row->meta_key ] = true;
			wp_cache_set( $network . ':' . $row->meta_key, maybe_unserialize( $row->meta_value ), 'site-options' );
		}
		foreach ( $keys as $key ) {
			if ( ! isset( $found[ $key ] ) ) {
				$notoptions[ $key ] = true;
			}
		}
		wp_cache_set( $network . ':notoptions', $notoptions, 'site-options' );
	}

	/**
	 * @param string    $name     Option name.
	 * @param mixed     $value    Value.
	 * @param bool|null $autoload Autoload on a single site (network options have no autoload flag).
	 *                            Always on for STATE_OPTIONS.
	 * @return bool
	 */
	public static function update_option( $name, $value, $autoload = null ) {
		if ( self::active() ) {
			return update_site_option( $name, $value );
		}
		if ( in_array( $name, self::STATE_OPTIONS, true ) ) {
			$autoload = true;
		}
		return null === $autoload ? update_option( $name, $value ) : update_option( $name, $value, $autoload );
	}

	/**
	 * Adds an option only when it does not exist yet.
	 *
	 * Same arguments as add_option().
	 *
	 * @param string      $name       Option name.
	 * @param mixed       $value      Value.
	 * @param string      $deprecated Unused.
	 * @param bool|string $autoload   Autoload on a single site.
	 * @return bool False when it already existed.
	 */
	public static function add_option( $name, $value, $deprecated = '', $autoload = true ) {
		unset( $deprecated ); // Kept for the add_option() signature; core ignores it since 2.3.
		if ( self::active() ) {
			return add_site_option( $name, $value );
		}
		if ( in_array( $name, self::STATE_OPTIONS, true ) ) {
			$autoload = true;
		}
		return add_option( $name, $value, '', $autoload );
	}

	/**
	 * @param string $name Option name.
	 * @return bool
	 */
	public static function delete_option( $name ) {
		if ( self::active() ) {
			return delete_site_option( $name );
		}
		$deleted = delete_option( $name );
		if ( $deleted && in_array( $name, self::STATE_OPTIONS, true ) && ! wp_using_ext_object_cache() ) {
			// Core does not remember the deletion: the next read in this request would query.
			$notoptions          = wp_cache_get( 'notoptions', 'options' );
			$notoptions          = is_array( $notoptions ) ? $notoptions : array();
			$notoptions[ $name ] = true;
			wp_cache_set( 'notoptions', $notoptions, 'options' );
		}
		return $deleted;
	}

	/**
	 * Transient of the plugin's shared data: a site transient on multisite
	 * (every site sees the same scan data), a normal transient on a single site.
	 *
	 * @param string $name Transient name.
	 * @return mixed
	 */
	public static function get_transient( $name ) {
		return self::active() ? get_site_transient( $name ) : get_transient( $name );
	}

	/**
	 * @param string $name  Transient name.
	 * @param mixed  $value Value.
	 * @param int    $ttl   Seconds.
	 * @return bool
	 */
	public static function set_transient( $name, $value, $ttl = 0 ) {
		return self::active() ? set_site_transient( $name, $value, $ttl ) : set_transient( $name, $value, $ttl );
	}

	/**
	 * @param string $name Transient name.
	 * @return bool
	 */
	public static function delete_transient( $name ) {
		return self::active() ? delete_site_transient( $name ) : delete_transient( $name );
	}

	/**
	 * Drops an option from this request's object cache, so the next read
	 * goes to the database (another process may have changed it).
	 *
	 * @param string $name Option name.
	 */
	public static function flush_option_cache( $name ) {
		if ( self::active() ) {
			$network = function_exists( 'get_current_network_id' ) ? (int) get_current_network_id() : 1;
			wp_cache_delete( $network . ':' . $name, 'site-options' );
			$key        = $network . ':notoptions';
			$notoptions = wp_cache_get( $key, 'site-options' );
			if ( is_array( $notoptions ) && isset( $notoptions[ $name ] ) ) {
				unset( $notoptions[ $name ] );
				wp_cache_set( $key, $notoptions, 'site-options' );
			}
			return;
		}
		wp_cache_delete( $name, 'options' );
		$notoptions = wp_cache_get( 'notoptions', 'options' );
		if ( is_array( $notoptions ) && isset( $notoptions[ $name ] ) ) {
			unset( $notoptions[ $name ] );
			wp_cache_set( 'notoptions', $notoptions, 'options' );
		}
	}

	/**
	 * Options table that holds the raw lock rows (scan job lock and cancel
	 * request): the main site's table, so every site and the CLI share them.
	 *
	 * @return string
	 */
	public static function lock_table() {
		global $wpdb;
		if ( ! self::active() ) {
			return $wpdb->options;
		}
		return $wpdb->get_blog_prefix( self::main_site_id() ) . 'options';
	}

	/* ------------------------------------------------------------------ */
	/* Sites                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * @return int Main site id (1 on a single site).
	 */
	public static function main_site_id() {
		if ( self::active() && function_exists( 'get_main_site_id' ) ) {
			$id = (int) get_main_site_id();
			return $id > 0 ? $id : 1;
		}
		return function_exists( 'get_current_blog_id' ) ? (int) get_current_blog_id() : 1;
	}

	/**
	 * @return bool Whether this request runs on the main site (always on a single site).
	 */
	public static function is_main() {
		return ! self::active() || (int) get_current_blog_id() === self::main_site_id();
	}

	/**
	 * Runs $fn on the main site and returns its result.
	 *
	 * @param callable $fn Callback.
	 * @return mixed
	 */
	public static function on_main( callable $fn ) {
		if ( self::is_main() ) {
			return call_user_func( $fn );
		}
		switch_to_blog( self::main_site_id() );
		try {
			return call_user_func( $fn );
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Runs $fn on site $blog_id when it exists (on the current site when 0
	 * or on a single site).
	 *
	 * @param int      $blog_id Site id.
	 * @param callable $fn      Callback.
	 * @return mixed
	 */
	public static function on_site( $blog_id, callable $fn ) {
		$blog_id = (int) $blog_id;
		if ( ! self::active() || $blog_id <= 0 || $blog_id === (int) get_current_blog_id() || ! get_site( $blog_id ) ) {
			return call_user_func( $fn );
		}
		switch_to_blog( $blog_id );
		try {
			return call_user_func( $fn );
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Site ids of this network after $after, in id order.
	 *
	 * @param int $after Last id already handled.
	 * @param int $limit Most ids returned.
	 * @return int[]
	 */
	public static function site_ids_after( $after, $limit = self::BATCH ) {
		if ( ! self::active() ) {
			return (int) $after < 1 ? array( 1 ) : array();
		}
		global $wpdb;
		$network = function_exists( 'get_current_network_id' ) ? (int) get_current_network_id() : 1;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT blog_id FROM {$wpdb->blogs} WHERE site_id = %d AND blog_id > %d ORDER BY blog_id ASC LIMIT %d", $network, (int) $after, max( 1, (int) $limit ) ) );
		return array_map( 'intval', (array) $ids );
	}

	/**
	 * "Site name (example.com/blog/)" for reports and emails.
	 *
	 * @param int $blog_id Site id.
	 * @return string '' on a single site or for an unknown site.
	 */
	public static function site_label( $blog_id ) {
		$blog_id = (int) $blog_id;
		if ( ! self::active() || $blog_id <= 0 ) {
			return '';
		}
		$site = get_site( $blog_id );
		if ( ! $site ) {
			/* translators: %d: site id */
			return sprintf( __( 'Site #%d (deleted)', 'qartvelo-guard' ), $blog_id );
		}
		$name = wp_specialchars_decode( (string) get_blog_option( $blog_id, 'blogname', '' ), ENT_QUOTES );
		$addr = untrailingslashit( (string) $site->domain . (string) $site->path ) . '/';
		return '' !== trim( $name ) ? $name . ' (' . $addr . ')' : $addr;
	}

	/**
	 * URL paths of every site of the network (no trailing slash, '' for a
	 * site at the root), for the early guard's REST exemptions. The main
	 * site's path comes first.
	 *
	 * @return string[]
	 */
	public static function home_paths() {
		if ( null !== self::$home_paths ) {
			return self::$home_paths;
		}
		$main  = untrailingslashit( (string) wp_parse_url( self::on_main( 'home_url' ), PHP_URL_PATH ) );
		$paths = array( $main );
		if ( self::active() && function_exists( 'get_sites' ) ) {
			$sites = get_sites(
				array(
					'number'                 => 5000,
					'fields'                 => '',
					'network_id'             => function_exists( 'get_current_network_id' ) ? get_current_network_id() : null,
					'update_site_meta_cache' => false,
				)
			);
			foreach ( (array) $sites as $site ) {
				if ( is_object( $site ) && isset( $site->path ) ) {
					$paths[] = untrailingslashit( '/' . trim( (string) $site->path, '/' ) );
				}
			}
		}
		$paths = array_map(
			static function ( $path ) {
				return '/' === $path ? '' : $path;
			},
			$paths
		);
		self::$home_paths = array_values( array_unique( $paths ) );
		return self::$home_paths;
	}

	/**
	 * Forgets cached site data (after a site was added or removed).
	 */
	public static function reset() {
		self::$home_paths = null;
	}

	/* ------------------------------------------------------------------ */
	/* Identity and links                                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * Admin URL of the plugin's screens: Network Admin on multisite.
	 *
	 * @param string $path Path relative to the admin.
	 * @return string
	 */
	public static function admin_url( $path = '' ) {
		return self::active() ? network_admin_url( $path ) : admin_url( $path );
	}

	/**
	 * @param string $path Path.
	 * @return string Home URL of the site, or of the network's main site.
	 */
	public static function home_url( $path = '/' ) {
		return self::active() ? network_home_url( $path ) : home_url( $path );
	}

	/**
	 * @return string Site name, or the network name on multisite.
	 */
	public static function name() {
		$name = '';
		if ( self::active() && function_exists( 'get_network' ) ) {
			$network = get_network();
			$name    = $network && isset( $network->site_name ) ? (string) $network->site_name : '';
		}
		if ( '' === trim( $name ) ) {
			$name = (string) get_bloginfo( 'name' );
		}
		$name = wp_specialchars_decode( $name, ENT_QUOTES );
		return '' !== trim( $name ) ? $name : (string) wp_parse_url( self::home_url(), PHP_URL_HOST );
	}

	/**
	 * Who gets alerts when no address is configured: the site admin email,
	 * on multisite the network admin email and every super admin (they are
	 * the only ones who can approve).
	 *
	 * @return string[]
	 */
	public static function default_recipients() {
		if ( ! self::active() ) {
			$email = (string) get_option( 'admin_email' );
			return '' !== $email ? array( $email ) : array();
		}
		$emails = array( (string) get_site_option( 'admin_email', '' ) );
		foreach ( array_slice( (array) get_super_admins(), 0, 20 ) as $login ) {
			$user = get_user_by( 'login', (string) $login );
			if ( $user && is_email( $user->user_email ) ) {
				$emails[] = (string) $user->user_email;
			}
		}
		return array_values( array_unique( array_filter( $emails, 'is_email' ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* Cron (main site only)                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * @param int    $timestamp  First run.
	 * @param string $recurrence Schedule name.
	 * @param string $hook       Hook.
	 * @return mixed
	 */
	public static function schedule_event( $timestamp, $recurrence, $hook ) {
		return self::on_main(
			static function () use ( $timestamp, $recurrence, $hook ) {
				return wp_schedule_event( $timestamp, $recurrence, $hook );
			}
		);
	}

	/**
	 * @param int    $timestamp Run time.
	 * @param string $hook      Hook.
	 * @return mixed
	 */
	public static function schedule_single( $timestamp, $hook ) {
		return self::on_main(
			static function () use ( $timestamp, $hook ) {
				return wp_schedule_single_event( $timestamp, $hook );
			}
		);
	}

	/**
	 * @param string $hook Hook.
	 * @return int|false
	 */
	public static function next_scheduled( $hook ) {
		return self::on_main(
			static function () use ( $hook ) {
				return wp_next_scheduled( $hook );
			}
		);
	}

	/**
	 * @param string $hook Hook.
	 * @return string|false Schedule name.
	 */
	public static function get_schedule( $hook ) {
		return self::on_main(
			static function () use ( $hook ) {
				return wp_get_schedule( $hook );
			}
		);
	}

	/**
	 * @param int    $timestamp Run time of the event.
	 * @param string $hook      Hook.
	 * @return mixed
	 */
	public static function unschedule_event( $timestamp, $hook ) {
		return self::on_main(
			static function () use ( $timestamp, $hook ) {
				return wp_unschedule_event( $timestamp, $hook );
			}
		);
	}

	/**
	 * @param string $hook Hook.
	 */
	public static function clear_hook( $hook ) {
		self::on_main(
			static function () use ( $hook ) {
				wp_clear_scheduled_hook( $hook );
			}
		);
	}

	/**
	 * A site other than the main one never keeps plugin cron events (older
	 * versions scheduled a whole-network scan on every site).
	 */
	public static function clear_site_cron() {
		if ( self::is_main() ) {
			return;
		}
		foreach ( Installer::CRON_HOOKS as $hook ) {
			if ( wp_next_scheduled( $hook ) ) {
				wp_clear_scheduled_hook( $hook );
			}
		}
	}

	/**
	 * Clears the plugin's cron events on every site (network deactivation).
	 * Stops after a time budget on very large networks; leftover events on
	 * other sites find no handler while the plugin is inactive, and the next
	 * activation clears them (clear_site_cron()).
	 */
	public static function clear_cron_everywhere() {
		foreach ( Installer::CRON_HOOKS as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
		if ( ! self::active() ) {
			return;
		}
		$start = microtime( true );
		$after = 0;
		do {
			$ids = self::site_ids_after( $after, 200 );
			foreach ( $ids as $id ) {
				$after = $id;
				switch_to_blog( $id );
				foreach ( Installer::CRON_HOOKS as $hook ) {
					if ( wp_next_scheduled( $hook ) ) {
						wp_clear_scheduled_hook( $hook );
					}
				}
				restore_current_blog();
				if ( microtime( true ) - $start > 20.0 ) {
					return;
				}
			}
		} while ( $ids );
	}

	/* ------------------------------------------------------------------ */
	/* Migration from per-site tables and options                          */
	/* ------------------------------------------------------------------ */

	/**
	 * Moves the main site's plugin options into network options (those that
	 * do not exist there yet). Runs before Installer seeds defaults. The
	 * trusted administrators of every site are merged later, per site.
	 */
	public static function migrate_main_options() {
		if ( ! self::active() || 'done' === get_site_option( self::MIGRATION_OPTION, '' ) ) {
			return;
		}
		global $wpdb;
		$table = esc_sql( $wpdb->get_blog_prefix( self::main_site_id() ) . 'options' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- core options table of the main site.
		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT option_name, option_value FROM {$table} WHERE option_name LIKE %s", $wpdb->esc_like( 'wpcybersec_' ) . '%' ), ARRAY_A );
		foreach ( $rows as $row ) {
			$name = (string) $row['option_name'];
			if ( in_array( $name, array( 'wpcybersec_job_lock', 'wpcybersec_job_cancel' ), true ) ) {
				continue; // Raw lock rows stay in the main site's table (lock_table()).
			}
			if ( false === get_site_option( $name, false ) ) {
				add_site_option( $name, maybe_unserialize( $row['option_value'] ) );
			}
			if ( self::main_site_id() === (int) get_current_blog_id() ) {
				delete_option( $name );
			} else {
				delete_blog_option( self::main_site_id(), $name );
			}
		}
		if ( '' === (string) get_site_option( self::MIGRATION_OPTION, '' ) ) {
			update_site_option( self::MIGRATION_OPTION, '0' );
		}
	}

	/**
	 * Whether sites still wait for the migration.
	 *
	 * @return bool
	 */
	public static function migration_pending() {
		return self::active() && 'done' !== self::get_option( self::MIGRATION_OPTION, '' );
	}

	/**
	 * One bounded pass of the per-site migration: for each site (in id order,
	 * resuming after the last one done) its plugin tables are merged into
	 * the network tables and dropped, its plugin options deleted (trusted
	 * administrators merged first), its cron events cleared and its old
	 * snapshot folder removed. Holds a MySQL named lock, so two requests never
	 * merge the same site twice.
	 *
	 * @return bool True when every site is done.
	 */
	public static function migrate_sites() {
		if ( ! self::migration_pending() ) {
			return true;
		}
		global $wpdb;
		$lock = 'wpcybersec_ms_migrate_' . substr( md5( $wpdb->base_prefix . DB_NAME ), 0, 8 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		if ( '1' !== (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 0)', $lock ) ) ) {
			return false;
		}
		try {
			$start = microtime( true );
			$after = (int) get_site_option( self::MIGRATION_OPTION, '0' );
			while ( microtime( true ) - $start < self::BUDGET ) {
				$ids = self::site_ids_after( $after, self::BATCH );
				if ( ! $ids ) {
					update_site_option( self::MIGRATION_OPTION, 'done' );
					self::log( 'network_migrated', __( 'Multisite network mode: all sites now share one set of scan data, approvals and settings.', 'qartvelo-guard' ) );
					return true;
				}
				foreach ( $ids as $id ) {
					self::migrate_site( $id );
					$after = $id;
					update_site_option( self::MIGRATION_OPTION, (string) $after );
					if ( microtime( true ) - $start >= self::BUDGET ) {
						break;
					}
				}
			}
			return false;
		} finally {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->query( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) );
		}
	}

	/**
	 * Migrates one site (see migrate_sites()).
	 *
	 * @param int $blog_id Site id.
	 */
	private static function migrate_site( $blog_id ) {
		global $wpdb;
		$blog_id = (int) $blog_id;
		$prefix  = $wpdb->get_blog_prefix( $blog_id );
		$main    = self::main_site_id() === $blog_id;

		// Tables: only a site whose prefix differs from the base prefix has its own copies.
		if ( $prefix !== $wpdb->base_prefix ) {
			$moved = self::merge_tables( $prefix, $blog_id, $main );
			if ( $moved ) {
				self::log(
					'network_site_merged',
					/* translators: 1: site id, 2: number of items, 3: number of allowlist entries */
					sprintf( __( 'Site #%1$d: moved %2$d items and %3$d approvals into the network tables and removed the site\'s own copies.', 'qartvelo-guard' ), $blog_id, $moved['items'], $moved['allowlist'] ),
					$moved
				);
			}
		}

		// Options: trusted administrators are merged, everything else is the main site's (already migrated).
		$table = esc_sql( $prefix . 'options' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- core options table of a site of this network.
		$trusted = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$table} WHERE option_name = %s", User_Watch::TRUSTED_OPTION ) );
		if ( null !== $trusted ) {
			$ids    = maybe_unserialize( $trusted );
			$merged = get_site_option( User_Watch::TRUSTED_OPTION, array() );
			$merged = array_values( array_unique( array_filter( array_map( 'intval', array_merge( is_array( $merged ) ? $merged : array(), is_array( $ids ) ? $ids : array() ) ) ) ) );
			update_site_option( User_Watch::TRUSTED_OPTION, $merged );
		}
		if ( ! $main ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$names = (array) $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$table} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( 'wpcybersec_' ) . '%', $wpdb->esc_like( '_transient_wpcybersec_' ) . '%', $wpdb->esc_like( '_transient_timeout_wpcybersec_' ) . '%' ) );
			switch_to_blog( $blog_id );
			foreach ( $names as $name ) {
				delete_option( (string) $name );
			}
			foreach ( Installer::CRON_HOOKS as $hook ) {
				wp_clear_scheduled_hook( $hook );
			}
			restore_current_blog();
		}

		// Copies a site other than the main one kept in its own snapshot folder.
		if ( ! $main && class_exists( __NAMESPACE__ . '\\Storage' ) ) {
			$storage = new Storage();
			$dir     = $storage->path( 'snapshots/site-' . $blog_id );
			if ( @is_dir( $dir ) && Storage::is_within( $dir, $storage->data_dir() ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				self::delete_tree( $dir );
			}
		}
	}

	/**
	 * Merges a site's own plugin tables into the network tables and drops
	 * them. The manifest of a site other than the main one is a duplicate of
	 * the network's (older versions built one per site) and is not copied;
	 * the main site's is copied when the network manifest is empty. Items
	 * get details.blog_id; an item the network tables already hold (same
	 * type, path, hash and status) is not copied twice.
	 *
	 * @param string $prefix  Site table prefix.
	 * @param int    $blog_id Site id.
	 * @param bool   $main    Whether it is the main site.
	 * @return array|null { items, allowlist, log } or null when the site had no tables.
	 */
	private static function merge_tables( $prefix, $blog_id, $main ) {
		global $wpdb;
		$old = array();
		foreach ( self::TABLES as $name ) {
			$table = $prefix . 'wpcybersec_' . $name;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table ) {
				$old[ $name ] = esc_sql( $table );
			}
		}
		if ( ! $old ) {
			return null;
		}
		$counts = array(
			'items'     => 0,
			'allowlist' => 0,
			'log'       => 0,
		);

		// Table names cannot be placeholders before WordPress 6.2 (%i); these are the plugin's
		// fixed names with a prefix from $wpdb, confirmed by SHOW TABLES above and escaped.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- see above.
		if ( isset( $old['allowlist'] ) ) {
			$counts['allowlist'] = (int) $wpdb->query( 'INSERT IGNORE INTO ' . Store::table( 'allowlist' ) . ' (kind, value, label, note, created_by, created_at) SELECT kind, value, label, note, created_by, created_at FROM ' . $old['allowlist'] . ' ORDER BY id' );
		}
		if ( isset( $old['manifest'] ) && $main && 0 === (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . Store::table( 'manifest' ) ) ) {
			$wpdb->query( 'INSERT IGNORE INTO ' . Store::table( 'manifest' ) . ' SELECT * FROM ' . $old['manifest'] );
		}
		if ( isset( $old['log'] ) ) {
			$counts['log'] = (int) $wpdb->query( 'INSERT INTO ' . Store::table( 'log' ) . ' (event, message, context, user_id, ip, created_at) SELECT event, message, context, user_id, ip, created_at FROM ' . $old['log'] . ' ORDER BY id' );
		}
		if ( isset( $old['items'] ) ) {
			$items = Store::table( 'items' );
			$last  = 0;
			do {
				$rows = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM ' . $old['items'] . ' WHERE id > %d ORDER BY id LIMIT 500', $last ), ARRAY_A );
				foreach ( $rows as $row ) {
					$last = (int) $row['id'];
					$details = json_decode( (string) $row['details'], true );
					$details = is_array( $details ) ? $details : array();
					if ( ! isset( $details['blog_id'] ) ) {
						$details['blog_id'] = $blog_id;
					}
					$details['migrated_from'] = $blog_id;
					// Database findings of a site other than the main one carry the site in their place.
					if ( ! $main && Store::SOURCE_DATABASE === (string) $row['source'] && 0 === strpos( (string) $row['path'], 'db:' ) && 0 !== strpos( (string) $row['path'], 'db:site:' ) ) {
						$row['path'] = 'db:site:' . $blog_id . ':' . substr( (string) $row['path'], 3 );
					}
					$dupe = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$items} WHERE type = %s AND status = %s AND sha256 = %s AND path = %s LIMIT 1", $row['type'], $row['status'], $row['sha256'], $row['path'] ) );
					if ( $dupe ) {
						continue;
					}
					unset( $row['id'] );
					$row['details'] = wp_json_encode( $details );
					if ( $wpdb->insert( $items, $row ) ) {
						++$counts['items'];
					}
				}
			} while ( count( $rows ) >= 500 );
			if ( $counts['items'] ) {
				Store::flush_counts();
			}
		}
		foreach ( $old as $table ) {
			$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		}
		// phpcs:enable
		return $counts;
	}

	/**
	 * Deletes a folder with everything in it (symlinks are removed, never followed).
	 *
	 * @param string $dir Folder.
	 */
	private static function delete_tree( $dir ) {
		$items = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $items as $item ) {
			$path = $item->getPathname();
			if ( $item->isDir() && ! $item->isLink() ) {
				Fs::rmdir( $path );
			} else {
				Fs::delete( $path );
			}
		}
		Fs::rmdir( $dir );
	}

	/**
	 * Activity log entry without the booted services.
	 *
	 * @param string $event   Event.
	 * @param string $message Message.
	 * @param array  $context Context.
	 */
	private static function log( $event, $message, array $context = array() ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->insert(
			Store::table( 'log' ),
			array(
				'event'      => $event,
				'message'    => $message,
				'context'    => wp_json_encode( $context ),
				'user_id'    => function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0,
				'ip'         => '',
				'created_at' => Store::now(),
			)
		);
	}
}
