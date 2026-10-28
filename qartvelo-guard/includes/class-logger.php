<?php
/**
 * Activity log.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Thin wrapper so modules log with one call.
 */
class Logger {

	/**
	 * @param string $event   Machine name, e.g. upload_held, install_held, file_quarantined, scan_finished.
	 * @param string $message Human readable message.
	 * @param array  $context Extra data (item_id, path, sha256, ...).
	 * @return int Log id.
	 */
	public function log( $event, $message, array $context = array() ) {
		if ( defined( 'WP_CLI' ) && WP_CLI && ! isset( $context['actor'] ) ) {
			$context['actor'] = 'wp-cli'; // No WordPress user: the Activity tab says who it was.
		}
		return wpcybersec()->store->log_insert( $event, $message, $context );
	}
}
