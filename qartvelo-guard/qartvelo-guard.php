<?php
/**
 * Plugin Name:       Qartvelo Guard
 * Description:       Scans the whole site for malware and backdoors, holds every new upload, plugin or theme install and unknown file until an administrator approves it, and remembers each approval permanently.
 * Version:           1.1.2
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Kakha Giorgashvili
 * Author URI:        https://qartvelo.com
 * Plugin URI:        https://qartvelo.com/qartvelo-guard
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       qartvelo-guard
 * Domain Path:       /languages
 * Network:           true
 *
 * @package WPCyberSecurity
 */

defined( 'ABSPATH' ) || exit;

define( 'WPCYBERSEC_VERSION', '1.1.2' );
define( 'WPCYBERSEC_DB_VERSION', '6' ); // 4: manifest mtime index (Reports > Recent changes). 5: multisite network mode (Network). 6: php2/php6 executable extensions.
define( 'WPCYBERSEC_FILE', __FILE__ );
define( 'WPCYBERSEC_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPCYBERSEC_URL', plugin_dir_url( __FILE__ ) );
define( 'WPCYBERSEC_BASENAME', plugin_basename( __FILE__ ) );

if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
	add_action(
		'admin_notices',
		static function () {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Qartvelo Guard needs PHP 7.4 or newer.', 'qartvelo-guard' ) . '</p></div>';
		}
	);
	return;
}

/*
 * Autoloader: WPCyberSecurity\Scan_Job -> includes/class-scan-job.php,
 * WPCyberSecurity\Admin\Reports_Page -> includes/admin/class-reports-page.php.
 */
spl_autoload_register(
	static function ( $class ) {
		$prefix = 'WPCyberSecurity\\';
		if ( 0 !== strpos( $class, $prefix ) ) {
			return;
		}
		$parts = explode( '\\', substr( $class, strlen( $prefix ) ) );
		$name  = array_pop( $parts );
		$dir   = WPCYBERSEC_DIR . 'includes/' . ( $parts ? strtolower( implode( '/', $parts ) ) . '/' : '' );
		$file  = $dir . 'class-' . strtolower( str_replace( '_', '-', $name ) ) . '.php';
		if ( is_readable( $file ) ) {
			require_once $file;
		}
	}
);

/**
 * Service container accessor.
 *
 * @return \WPCyberSecurity\Plugin
 */
function wpcybersec() {
	return \WPCyberSecurity\Plugin::instance();
}

register_activation_hook( __FILE__, array( '\WPCyberSecurity\Installer', 'activate' ) );
register_deactivation_hook( __FILE__, array( '\WPCyberSecurity\Installer', 'deactivate' ) );

add_action(
	'plugins_loaded',
	static function () {
		wpcybersec()->boot();
	},
	5
);
