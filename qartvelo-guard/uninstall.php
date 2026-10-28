<?php
/**
 * Uninstall: removes data only when "Delete all data on uninstall" is on.
 * Backups of wp-config.php are always removed.
 *
 * @package WPCyberSecurity
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

/**
 * A plugin option: on multisite a network option (older versions kept them
 * per site, so the main site's copy is the fallback).
 *
 * @param string $name    Option name.
 * @param mixed  $default Fallback.
 * @return mixed
 */
function wpcybersec_uninstall_option( $name, $default = '' ) {
	if ( ! is_multisite() ) {
		return get_option( $name, $default );
	}
	$value = get_site_option( $name, null );
	if ( null === $value ) {
		$value = get_blog_option( get_main_site_id(), $name, $default );
	}
	return $value;
}

/*
 * The data folder, resolved like Storage::data_dir(): WPCYBERSEC_DATA_DIR, else
 * the folder chosen by the one-click move (single sites only), else the
 * pre-1.1.0 wp-content/wpcybersec while it exists, else
 * the random folder inside uploads/qartvelo-guard. Read before the options are deleted.
 */
// Before 1.1.0 the default folder was wp-content/wpcybersec; it is now a
// random folder inside uploads/qartvelo-guard of the main site (Storage::default_dir()).
$wpcybersec_legacy = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) . '/wpcybersec';
if ( is_multisite() && ! is_main_site() ) {
	switch_to_blog( get_main_site_id() );
	$wpcybersec_uploads = wp_upload_dir( null, false );
	restore_current_blog();
} else {
	$wpcybersec_uploads = wp_upload_dir( null, false );
}
$wpcybersec_root    = is_array( $wpcybersec_uploads ) && empty( $wpcybersec_uploads['error'] ) && ! empty( $wpcybersec_uploads['basedir'] )
	? untrailingslashit( wp_normalize_path( (string) $wpcybersec_uploads['basedir'] ) ) . '/qartvelo-guard'
	: '';
$wpcybersec_token   = wpcybersec_uninstall_option( 'wpcybersec_data_token', '' );
if ( '' !== $wpcybersec_root && ( is_dir( $wpcybersec_root . '/quarantine' ) || is_dir( $wpcybersec_root . '/jobs' ) ) ) {
	$wpcybersec_default = $wpcybersec_root; // Version 1.1.0 kept the data in the folder itself.
} elseif ( '' !== $wpcybersec_root && is_string( $wpcybersec_token ) && preg_match( '/^[a-z0-9]{32}$/', $wpcybersec_token ) ) {
	$wpcybersec_default = $wpcybersec_root . '/' . $wpcybersec_token;
} else {
	$wpcybersec_default = '';
}
$wpcybersec_moved   = is_multisite() ? '' : get_option( 'wpcybersec_data_dir', '' );
$wpcybersec_moved   = is_string( $wpcybersec_moved ) && '' !== $wpcybersec_moved ? untrailingslashit( wp_normalize_path( $wpcybersec_moved ) ) : '';
if ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) {
	$wpcybersec_data = untrailingslashit( wp_normalize_path( WPCYBERSEC_DATA_DIR ) );
} elseif ( '' !== $wpcybersec_moved && is_dir( $wpcybersec_moved ) ) {
	$wpcybersec_data = $wpcybersec_moved;
} elseif ( is_dir( $wpcybersec_legacy ) && ( '' === $wpcybersec_default || ! is_dir( $wpcybersec_default ) ) ) {
	$wpcybersec_data = $wpcybersec_legacy;
} else {
	$wpcybersec_data = $wpcybersec_default;
}

/*
 * Fallback folder inside uploads, used while no configured folder was
 * writable (Storage::FALLBACK_OPTION, a site option on multisite).
 */
$wpcybersec_fallback = wpcybersec_uninstall_option( 'wpcybersec_data_fallback', '' );
$wpcybersec_fallback = is_string( $wpcybersec_fallback ) && '' !== $wpcybersec_fallback ? untrailingslashit( wp_normalize_path( $wpcybersec_fallback ) ) : '';

// Front controller folder (WordPress in a sub folder, Bedrock), where the guard may be wired in too.
$wpcybersec_front = wpcybersec_uninstall_option( 'wpcybersec_front_root', '' );
$wpcybersec_front = is_string( $wpcybersec_front ) && '' !== $wpcybersec_front ? trailingslashit( wp_normalize_path( $wpcybersec_front ) ) : '';

$wpcybersec_settings = wpcybersec_uninstall_option( 'wpcybersec_settings', array() );
$wpcybersec_delete   = is_array( $wpcybersec_settings ) && ! empty( $wpcybersec_settings['delete_data_on_uninstall'] );

/*
 * Opt-in statistics only (setting "share_stats", off by default): one last
 * "uninstall" message to the developer, sent before the options that hold the
 * install id are deleted, without waiting for the reply.
 */
if ( is_array( $wpcybersec_settings ) && ! empty( $wpcybersec_settings['share_stats'] ) && ! ( defined( 'WPCYBERSEC_DISABLE_STATS' ) && WPCYBERSEC_DISABLE_STATS ) ) {
	require_once __DIR__ . '/qartvelo-guard.php';
	if ( class_exists( '\WPCyberSecurity\Stats' ) ) {
		try {
			\WPCyberSecurity\Stats::on_uninstall();
		} catch ( \Throwable $wpcybersec_e ) {
			unset( $wpcybersec_e ); // Never break the uninstall over a statistics message.
		}
	}
}

/*
 * "Delete all data": first undo what the plugin wrote into the site's own
 * files, while its classes can still be loaded (wp-config.php edits keep a
 * backup in the data folder, which is removed below).
 */
if ( $wpcybersec_delete ) {
	require_once __DIR__ . '/qartvelo-guard.php';

	// Only the define lines the plugin marked ("// Added by Qartvelo Guard on <date>."),
	// and only when wp-config.php parses before and after. A DISABLE_WP_CRON the plugin
	// added goes too: without the plugin's cron setup WP-Cron must run on visits again.
	if ( class_exists( '\WPCyberSecurity\Config_Editor' ) ) {
		foreach ( array( 'WPCYBERSEC_HMAC_KEY', 'DISABLE_WP_CRON' ) as $wpcybersec_const ) {
			try {
				\WPCyberSecurity\Config_Editor::remove_marked_constant( $wpcybersec_const );
			} catch ( \Throwable $wpcybersec_e ) {
				unset( $wpcybersec_e ); // Never break the uninstall over a config edit.
			}
		}
	}

	// Backups of a replaced WordPress core (Core_Repair) that live next to the WordPress
	// folder instead of in the data folder: only folders that carry their own marker.
	$wpcybersec_core_backups = wpcybersec_uninstall_option( 'wpcybersec_core_backups', array() );
	if ( is_array( $wpcybersec_core_backups ) && class_exists( '\WPCyberSecurity\Fs' ) ) {
		foreach ( $wpcybersec_core_backups as $wpcybersec_entry ) {
			$wpcybersec_dir = is_array( $wpcybersec_entry ) && isset( $wpcybersec_entry['dir'], $wpcybersec_entry['id'] ) ? (string) $wpcybersec_entry['dir'] : '';
			$wpcybersec_mk  = '' !== $wpcybersec_dir ? json_decode( (string) @file_get_contents( $wpcybersec_dir . '/.wpcybersec-core-backup' ), true ) : null; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- direct file call: uninstall cannot ask for FTP credentials.
			if ( is_array( $wpcybersec_mk ) && isset( $wpcybersec_mk['id'] ) && (string) $wpcybersec_mk['id'] === (string) $wpcybersec_entry['id'] ) {
				\WPCyberSecurity\Fs::delete_tree( $wpcybersec_dir );
			}
		}
	}

	// The guard lines in .user.ini and .htaccess of the WordPress folder (and the
	// front controller folder), and the PHP block in the uploads .htaccess.
	$wpcybersec_ini_name = (string) ini_get( 'user_ini.filename' );
	$wpcybersec_ini_name = '' === $wpcybersec_ini_name ? '.user.ini' : $wpcybersec_ini_name;
	$wpcybersec_wiring   = array_unique( array_filter( array( trailingslashit( wp_normalize_path( ABSPATH ) ), $wpcybersec_front ) ) );
	foreach ( $wpcybersec_wiring as $wpcybersec_dir ) {
		foreach ( array_unique( array( $wpcybersec_ini_name, '.user.ini' ) ) as $wpcybersec_name ) {
			$wpcybersec_file = $wpcybersec_dir . $wpcybersec_name;
			if ( ! is_file( $wpcybersec_file ) || is_link( $wpcybersec_file ) || ! is_writable( $wpcybersec_file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
				continue;
			}
			$wpcybersec_old  = (string) @file_get_contents( $wpcybersec_file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- direct file call: uninstall cannot ask for FTP credentials.
			$wpcybersec_kept = array();
			foreach ( preg_split( '/\r\n|\n|\r/', $wpcybersec_old ) as $wpcybersec_line ) {
				$wpcybersec_trim = trim( $wpcybersec_line );
				if ( in_array( $wpcybersec_trim, array( '; BEGIN Qartvelo Guard early guard', '; END Qartvelo Guard early guard', '; BEGIN CyberGate Security Guard', '; END CyberGate Security Guard' ), true ) ) {
					continue;
				}
				if ( preg_match( '/^\s*auto_prepend_file\s*=/i', $wpcybersec_line ) && false !== strpos( $wpcybersec_line, 'wpcybersec-guard.php' ) ) {
					continue;
				}
				$wpcybersec_kept[] = $wpcybersec_line;
			}
			$wpcybersec_new = rtrim( implode( "\n", $wpcybersec_kept ) );
			$wpcybersec_new = '' === trim( $wpcybersec_new ) ? '' : $wpcybersec_new . "\n";
			if ( $wpcybersec_new !== $wpcybersec_old ) {
				if ( '' === $wpcybersec_new ) {
					@unlink( $wpcybersec_file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- held nothing but the guard lines (and blank lines); direct file call: uninstall cannot ask for FTP credentials.
				} else {
					@file_put_contents( $wpcybersec_file, $wpcybersec_new, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- direct file call: uninstall cannot ask for FTP credentials.
				}
			}
		}
	}
	$wpcybersec_up      = wp_upload_dir( null, false );
	if ( is_multisite() && ! is_main_site() ) {
		switch_to_blog( get_main_site_id() );
		$wpcybersec_up = wp_upload_dir( null, false );
		restore_current_blog();
	}
	$wpcybersec_htaccess_files = array();
	foreach ( $wpcybersec_wiring as $wpcybersec_dir ) {
		$wpcybersec_htaccess_files[] = array( $wpcybersec_dir . '.htaccess', 'Qartvelo Guard early guard' );
		$wpcybersec_htaccess_files[] = array( $wpcybersec_dir . '.htaccess', 'CyberGate Security Guard' ); // Before 1.1.0.
	}
	if ( ! empty( $wpcybersec_up['basedir'] ) ) {
		$wpcybersec_htaccess_files[] = array( untrailingslashit( wp_normalize_path( $wpcybersec_up['basedir'] ) ) . '/.htaccess', 'Qartvelo Guard' );
		$wpcybersec_htaccess_files[] = array( untrailingslashit( wp_normalize_path( $wpcybersec_up['basedir'] ) ) . '/.htaccess', 'CyberGate Security' ); // Before 1.1.0.
	}
	foreach ( $wpcybersec_htaccess_files as $wpcybersec_pair ) {
		list( $wpcybersec_file, $wpcybersec_marker ) = $wpcybersec_pair;
		if ( ! is_file( $wpcybersec_file ) || is_link( $wpcybersec_file ) || ! is_writable( $wpcybersec_file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
			continue;
		}
		$wpcybersec_old = (string) @file_get_contents( $wpcybersec_file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- direct file call: uninstall cannot ask for FTP credentials.
		// Exactly the marked block ("# BEGIN <marker>" ... "# END <marker>"), every copy of it.
		$wpcybersec_new = preg_replace( '/^[ \t]*# BEGIN ' . preg_quote( $wpcybersec_marker, '/' ) . '[ \t]*\R.*?^[ \t]*# END ' . preg_quote( $wpcybersec_marker, '/' ) . '[ \t]*(\R|\z)/ms', '', $wpcybersec_old );
		if ( is_string( $wpcybersec_new ) && $wpcybersec_new !== $wpcybersec_old ) {
			$wpcybersec_new = rtrim( $wpcybersec_new );
			$wpcybersec_new = '' === trim( $wpcybersec_new ) ? '' : $wpcybersec_new . "\n";
			if ( '' === $wpcybersec_new ) {
				@unlink( $wpcybersec_file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- the file held nothing but our block (and blank lines); direct file call: uninstall cannot ask for FTP credentials.
			} else {
				@file_put_contents( $wpcybersec_file, $wpcybersec_new, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- direct file call: uninstall cannot ask for FTP credentials.
			}
		}
	}
}

/*
 * Backups of wp-config.php hold the database password and the salts: remove
 * them even when the rest of the data is kept. Only the plugin's own backup
 * files and deny files are deleted, so a folder set by hand stays intact.
 */
foreach ( array_unique( array_filter( array( $wpcybersec_data, $wpcybersec_default, $wpcybersec_legacy, $wpcybersec_fallback ) ) ) as $wpcybersec_base ) {
	$wpcybersec_backups = $wpcybersec_base . '/backups';
	if ( ! is_dir( $wpcybersec_backups ) || is_link( $wpcybersec_backups ) ) {
		continue;
	}
	foreach ( (array) scandir( $wpcybersec_backups ) as $wpcybersec_name ) {
		$wpcybersec_file = $wpcybersec_backups . '/' . $wpcybersec_name;
		if ( ( is_file( $wpcybersec_file ) || is_link( $wpcybersec_file ) ) && ( preg_match( '/^wp-config-[0-9-]+(-[a-z0-9]+)?(\.php)?\.bak$/', $wpcybersec_name ) || in_array( $wpcybersec_name, array( '.htaccess', 'index.php', 'web.config' ), true ) ) ) {
			@unlink( $wpcybersec_file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- direct file call: uninstall cannot ask for FTP credentials.
		}
	}
	@rmdir( $wpcybersec_backups ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- direct file call: uninstall cannot ask for FTP credentials.
}

if ( ! $wpcybersec_delete ) {
	return;
}

$wpcybersec_hooks  = array( 'wpcybersec_scheduled_scan', 'wpcybersec_scan_tick', 'wpcybersec_digest', 'wpcybersec_maintenance', 'wpcybersec_guard_import', 'wpcybersec_notify_flush', 'wpcybersec_stats_heartbeat' );
$wpcybersec_tables = array( 'items', 'manifest', 'allowlist', 'log' );

/**
 * Removes the plugin's tables (with this prefix), options, transients and
 * site transients (single sites keep those in the options table) and cron
 * events of the current site.
 *
 * @param string   $prefix Table prefix of the site.
 * @param string[] $tables Table suffixes.
 * @param string[] $hooks  Cron hooks.
 */
function wpcybersec_uninstall_site( $prefix, array $tables, array $hooks ) {
	global $wpdb;
	foreach ( $tables as $table ) {
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $prefix . 'wpcybersec_' . $table ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table names come from the fixed list above.
	}
	$options = $prefix . 'options';
	$wpdb->query( "DELETE FROM {$options} WHERE option_name LIKE 'wpcybersec\\_%' OR option_name LIKE '\\_transient\\_wpcybersec\\_%' OR option_name LIKE '\\_transient\\_timeout\\_wpcybersec\\_%' OR option_name LIKE '\\_site\\_transient\\_wpcybersec\\_%' OR option_name LIKE '\\_site\\_transient\\_timeout\\_wpcybersec\\_%'" ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- core options table of the site.
	wp_cache_delete( 'alloptions', 'options' );
	foreach ( $hooks as $hook ) {
		wp_clear_scheduled_hook( $hook );
	}
}

if ( is_multisite() ) {
	// Every site of every network on this database: older versions kept tables,
	// options and cron events per site.
	$wpcybersec_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( (array) $wpcybersec_site_ids as $wpcybersec_site_id ) {
		switch_to_blog( (int) $wpcybersec_site_id );
		wpcybersec_uninstall_site( $wpdb->get_blog_prefix( (int) $wpcybersec_site_id ), $wpcybersec_tables, $wpcybersec_hooks );
		restore_current_blog();
	}
	wpcybersec_uninstall_site( $wpdb->base_prefix, $wpcybersec_tables, array() );
	$wpdb->query( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE 'wpcybersec\\_%' OR meta_key LIKE '\\_site\\_transient\\_wpcybersec\\_%' OR meta_key LIKE '\\_site\\_transient\\_timeout\\_wpcybersec\\_%'" ); // phpcs:ignore WordPress.DB
	wp_cache_flush();
} else {
	wpcybersec_uninstall_site( $wpdb->prefix, $wpcybersec_tables, $wpcybersec_hooks );
}

delete_metadata( 'user', 0, 'wpcybersec_dismiss_setup', '', true );
delete_metadata( 'user', 0, 'wpcybersec_dismiss_pending', '', true );
delete_metadata( 'user', 0, 'wpcybersec_dismiss_storage', '', true );
delete_metadata( 'user', 0, 'wpcybersec_diff_layout', '', true );
delete_metadata( 'user', 0, 'wpcybersec_storage_move', '', true );

/*
 * Remove the data folder: the default one inside uploads (and the pre-1.1.0
 * one inside wp-content), and the one the
 * plugin moved itself, but only when that folder carries this site's marker
 * file (another install on the same server may use a folder with a similar
 * name). A WPCYBERSEC_DATA_DIR set by hand in wp-config.php is left for the
 * system administrator.
 */
$wpcybersec_marker_ok = static function ( $dir ) use ( $wpdb ) {
	$file = $dir . '/.wpcybersec-site';
	if ( ! is_file( $file ) || is_link( $file ) ) {
		return false;
	}
	$text = (string) @file_get_contents( $file, false, null, 0, 1024 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- direct file call: uninstall cannot ask for FTP credentials.
	// Same id as WPCyberSecurity\Storage::site_id().
	$id = substr( md5( ABSPATH . $wpdb->base_prefix ), 0, 8 );
	return (bool) preg_match( '/^site:\s*' . $id . '\s*$/m', $text );
};
$wpcybersec_dirs = array();
$wpcybersec_own_name = static function ( $dir ) {
	return 0 === strpos( basename( $dir ), 'wpcybersec-' ) || 0 === strpos( basename( $dir ), 'qartvelo-guard' );
};
if ( ! defined( 'WPCYBERSEC_DATA_DIR' ) ) {
	$wpcybersec_dirs[] = $wpcybersec_legacy;
	if ( '' !== $wpcybersec_default && is_dir( $wpcybersec_default ) && ! is_link( $wpcybersec_default ) && $wpcybersec_marker_ok( $wpcybersec_default ) ) {
		$wpcybersec_dirs[] = $wpcybersec_default;
	}
	if ( '' !== $wpcybersec_moved && $wpcybersec_moved !== $wpcybersec_default && $wpcybersec_own_name( $wpcybersec_moved ) && is_dir( $wpcybersec_moved ) && ! is_link( $wpcybersec_moved ) && $wpcybersec_marker_ok( $wpcybersec_moved ) ) {
		$wpcybersec_dirs[] = $wpcybersec_moved;
	}
}
if ( '' !== $wpcybersec_fallback && $wpcybersec_own_name( $wpcybersec_fallback ) && is_dir( $wpcybersec_fallback ) && ! is_link( $wpcybersec_fallback ) && $wpcybersec_marker_ok( $wpcybersec_fallback ) ) {
	$wpcybersec_dirs[] = $wpcybersec_fallback;
}
foreach ( $wpcybersec_dirs as $wpcybersec_dir ) {
	if ( ! is_dir( $wpcybersec_dir ) || is_link( $wpcybersec_dir ) ) {
		continue;
	}
	$wpcybersec_it = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $wpcybersec_dir, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ( $wpcybersec_it as $wpcybersec_file ) {
		if ( $wpcybersec_file->isLink() || $wpcybersec_file->isFile() ) {
			@unlink( $wpcybersec_file->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- direct file call: uninstall cannot ask for FTP credentials.
		} else {
			@rmdir( $wpcybersec_file->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- direct file call: uninstall cannot ask for FTP credentials.
		}
	}
	@rmdir( $wpcybersec_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- direct file call: uninstall cannot ask for FTP credentials.
}

// The uploads/qartvelo-guard folder around the random data folder: only its deny files, then the folder when empty.
if ( '' !== $wpcybersec_root && $wpcybersec_root !== $wpcybersec_default && is_dir( $wpcybersec_root ) && ! is_link( $wpcybersec_root ) ) {
	foreach ( array( '.htaccess', 'index.php', 'web.config' ) as $wpcybersec_name ) {
		if ( is_file( $wpcybersec_root . '/' . $wpcybersec_name ) ) {
			@unlink( $wpcybersec_root . '/' . $wpcybersec_name ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- direct file call: uninstall cannot ask for FTP credentials.
		}
	}
	@rmdir( $wpcybersec_root ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- only when empty; direct file call: uninstall cannot ask for FTP credentials.
}

/*
 * The guard bootstrap (ABSPATH/wpcybersec-guard.php) is removed only when it is
 * certain that nothing points auto_prepend_file at it. Deleting it while PHP
 * still prepends it makes every request on the site fail with a fatal error.
 * Left in place it does nothing: it only loads the guard when the plugin's
 * guard file and config still exist, and both are gone after uninstall.
 *
 * It is always kept when uninstalling from WP-CLI: the command line PHP does
 * not see the web server's settings (mod_php .htaccess values, PHP-FPM pool,
 * nginx fastcgi_param, the web php.ini), so ini_get() proves nothing there.
 */
$wpcybersec_bootstrap = ABSPATH . 'wpcybersec-guard.php';
if ( is_file( $wpcybersec_bootstrap ) && ! is_link( $wpcybersec_bootstrap ) && 'cli' !== PHP_SAPI && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
	$wpcybersec_referenced = false !== strpos( (string) ini_get( 'auto_prepend_file' ), 'wpcybersec-guard.php' );

	// Also check the files the guard setup tells administrators to edit, in
	// case PHP has not picked up a change yet (.user.ini is cached for minutes).
	$wpcybersec_ini_name = (string) ini_get( 'user_ini.filename' );
	$wpcybersec_ini_name = '' === $wpcybersec_ini_name ? '.user.ini' : $wpcybersec_ini_name;
	$wpcybersec_configs  = array_unique(
		array(
			ABSPATH . '.htaccess',
			ABSPATH . $wpcybersec_ini_name,
			ABSPATH . '.user.ini',
			dirname( ABSPATH ) . '/.htaccess',
			dirname( ABSPATH ) . '/' . $wpcybersec_ini_name,
			dirname( ABSPATH ) . '/.user.ini',
		)
	);
	if ( '' !== $wpcybersec_front ) {
		$wpcybersec_configs[] = $wpcybersec_front . '.htaccess';
		$wpcybersec_configs[] = $wpcybersec_front . $wpcybersec_ini_name;
		$wpcybersec_configs[] = $wpcybersec_front . '.user.ini';
	}
	foreach ( $wpcybersec_configs as $wpcybersec_config ) {
		if ( $wpcybersec_referenced ) {
			break;
		}
		if ( ! @is_readable( $wpcybersec_config ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			continue;
		}
		foreach ( preg_split( '/\r\n|\n|\r/', (string) @file_get_contents( $wpcybersec_config ) ) as $wpcybersec_line ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- direct file call: uninstall cannot ask for FTP credentials.
			$wpcybersec_line = ltrim( $wpcybersec_line );
			if ( '' === $wpcybersec_line || ';' === $wpcybersec_line[0] || '#' === $wpcybersec_line[0] ) {
				continue;
			}
			if ( false !== stripos( $wpcybersec_line, 'auto_prepend_file' ) && false !== strpos( $wpcybersec_line, 'wpcybersec-guard.php' ) ) {
				$wpcybersec_referenced = true;
				break;
			}
		}
	}

	// Only delete the file this plugin generated.
	$wpcybersec_head = (string) @file_get_contents( $wpcybersec_bootstrap, false, null, 0, 4096 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- direct file call: uninstall cannot ask for FTP credentials.
	if ( ! $wpcybersec_referenced && false !== strpos( $wpcybersec_head, 'WPCYBERSEC_GUARD_BOOTSTRAPPED' ) ) {
		@unlink( $wpcybersec_bootstrap ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- direct file call: uninstall cannot ask for FTP credentials.
	}
}
