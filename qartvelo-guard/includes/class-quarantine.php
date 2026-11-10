<?php
/**
 * Quarantine storage for held and suspicious files.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Held files are stored as <data>/quarantine/YYYY/MM/<random>.bin with mode 0600.
 * The random name and .bin extension mean nothing in quarantine can be executed
 * even if the folder is reachable from the web.
 */
class Quarantine {

	/**
	 * Copies or moves a file into quarantine.
	 *
	 * @param string $src  Absolute source path.
	 * @param bool   $move True to move (the source disappears), false to copy.
	 * @return array|\WP_Error { quarantine_path, sha256, size }
	 */
	public function hold( $src, $move = true ) {
		if ( ! is_file( $src ) || ! is_readable( $src ) ) {
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_q_missing', sprintf( __( 'File not found: %s', 'qartvelo-guard' ), $src ) );
		}
		$storage = wpcybersec()->storage;
		$ensured = $storage->ensure();
		if ( is_wp_error( $ensured ) ) {
			return $ensured;
		}

		$dir = $storage->quarantine_dir() . '/' . gmdate( 'Y/m' );
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'wpcybersec_q_dir', __( 'Could not create the quarantine folder.', 'qartvelo-guard' ) );
		}

		$sha256 = (string) hash_file( 'sha256', $src );
		$size   = (int) filesize( $src );
		$dest   = $dir . '/' . strtolower( wp_generate_password( 24, false ) ) . '.bin';

		if ( $move ) {
			// Rename, or copy and delete across disks; fails when the original cannot be removed.
			$ok = Fs::move( $src, $dest );
		} else {
			$ok = @copy( $src, $dest ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		if ( ! $ok ) {
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_q_write', sprintf( __( 'Could not move %s into quarantine. Check file permissions.', 'qartvelo-guard' ), $src ) );
		}
		Fs::chmod( $dest, 0600 );

		return array(
			'quarantine_path' => wp_normalize_path( $dest ),
			'sha256'          => $sha256,
			'size'            => $size,
		);
	}

	/**
	 * Moves an item's quarantined copy back to its original path.
	 *
	 * @param array $item Item row (needs quarantine_path and original_path).
	 * @return true|\WP_Error
	 */
	public function restore( array $item ) {
		$src = $this->safe_path( $item );
		if ( is_wp_error( $src ) ) {
			return $src;
		}
		$dest = wp_normalize_path( (string) $item['original_path'] );
		if ( '' === $dest ) {
			return new \WP_Error( 'wpcybersec_q_target', __( 'This item has no original location to restore to.', 'qartvelo-guard' ) );
		}
		// Same rule as Decisions::live_path(): only inside the scanned folders,
		// never inside the data folder (the row is data, not a trusted path).
		$scope = file_exists( $dest ) ? $dest : dirname( $dest );
		if ( ! Paths::in_scope( $scope ) || Storage::is_within( $dest, wpcybersec()->storage->data_dir() ) ) {
			return new \WP_Error( 'wpcybersec_q_target', __( 'Refusing to restore a file outside the scanned folders.', 'qartvelo-guard' ) );
		}
		// Nothing is written into wp-admin, wp-includes or the plugin's own
		// folder: an official file comes back with a reinstall (of WordPress
		// core, or of this plugin), any other file is put back by hand.
		// When the same file is already there again, nothing is written: the
		// held copy is removed below and the restore counts as done.
		if ( Paths::in_core_dir( $dest ) && ! file_exists( $dest ) ) {
			return self::core_refusal();
		}
		if ( file_exists( $dest ) ) {
			if ( $item['sha256'] && hash_file( 'sha256', $dest ) === $item['sha256'] ) {
				$this->purge( $item );
				return true;
			}
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_q_exists', sprintf( __( 'A different file already exists at %s. Move it away first.', 'qartvelo-guard' ), $dest ) );
		}
		if ( ! is_dir( dirname( $dest ) ) && ! wp_mkdir_p( dirname( $dest ) ) ) {
			return new \WP_Error( 'wpcybersec_q_dir', __( 'Could not recreate the original folder.', 'qartvelo-guard' ) );
		}
		// Rename, or copy and delete across disks. A quarantine copy that cannot be
		// deleted stays behind, but the file is back where it belongs.
		$ok = @Fs::direct()->move( $src, $dest, false ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $ok ) {
			return new \WP_Error( 'wpcybersec_q_restore', __( 'Could not restore the file. Check file permissions.', 'qartvelo-guard' ) );
		}
		Fs::chmod( $dest, 0644 );
		return true;
	}

	/**
	 * Why a held file is not put back into wp-admin, wp-includes or the plugin's own folder, and what to
	 * do instead. One sentence for restore() and for Decisions::apply(), which
	 * refuses approve, mark safe and restore for such an item before it gets here.
	 *
	 * @return \WP_Error Code wpcybersec_q_core.
	 */
	public static function core_refusal() {
		return new \WP_Error( 'wpcybersec_q_core', __( 'This file was in wp-admin, wp-includes or the Qartvelo Guard folder, and Qartvelo Guard does not write into those folders. A WordPress file comes back when you reinstall WordPress core, a file of this plugin when you install the plugin again. Any other file: download it from quarantine and put it back yourself.', 'qartvelo-guard' ) );
	}

	/**
	 * Copies the quarantined file to a temp file (for importing approved uploads).
	 *
	 * @param array $item Item row.
	 * @return string|\WP_Error Temp file path. Caller deletes it.
	 */
	public function to_temp( array $item ) {
		$src = $this->safe_path( $item );
		if ( is_wp_error( $src ) ) {
			return $src;
		}
		if ( ! function_exists( 'wp_tempnam' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$tmp = wp_tempnam( basename( (string) $item['path'] ) );
		if ( ! $tmp || ! @copy( $src, $tmp ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new \WP_Error( 'wpcybersec_q_temp', __( 'Could not copy the held file to a temporary location.', 'qartvelo-guard' ) );
		}
		return $tmp;
	}

	/**
	 * Reads the quarantined copy (for the changes view). Unlike to_temp() no
	 * copy is written anywhere, so held configuration files never land in the
	 * system temp folder.
	 *
	 * @param array $item      Item row.
	 * @param int   $max_bytes Larger copies are refused.
	 * @return string|\WP_Error Content.
	 */
	public function read( array $item, $max_bytes ) {
		$src = $this->safe_path( $item );
		if ( is_wp_error( $src ) ) {
			return $src;
		}
		$size = @filesize( $src ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > (int) $max_bytes ) {
			return new \WP_Error( 'wpcybersec_q_large', __( 'The held copy is too large to show here.', 'qartvelo-guard' ) );
		}
		$content = @file_get_contents( $src ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		if ( ! is_string( $content ) ) {
			return new \WP_Error( 'wpcybersec_q_read', __( 'The held copy could not be read. Check file permissions.', 'qartvelo-guard' ) );
		}
		return $content;
	}

	/**
	 * Deletes an item's quarantined copy.
	 *
	 * @param array $item Item row.
	 * @return bool
	 */
	public function purge( array $item ) {
		$src = $this->safe_path( $item );
		if ( is_wp_error( $src ) ) {
			return false;
		}
		return Fs::delete( $src );
	}

	/**
	 * @param array $item Item row.
	 * @return bool
	 */
	public function exists( array $item ) {
		return ! is_wp_error( $this->safe_path( $item ) );
	}

	/**
	 * Sends the quarantined file as a download and exits.
	 *
	 * @param array $item Item row.
	 */
	public function stream( array $item ) {
		$src = $this->safe_path( $item );
		if ( is_wp_error( $src ) ) {
			wp_die( esc_html( $src->get_error_message() ) );
		}
		$name = sanitize_file_name( basename( (string) $item['path'] ) ) . '.quarantined';
		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . $name . '"' );
		header( 'Content-Length: ' . filesize( $src ) );
		header( 'X-Content-Type-Options: nosniff' );
		readfile( $src ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- streams the raw bytes of the held file as an application/octet-stream attachment (nosniff); a binary download, never rendered as HTML.
		exit;
	}

	/**
	 * Validates that the stored quarantine path really is inside the quarantine folder.
	 *
	 * @param array $item Item row.
	 * @return string|\WP_Error
	 */
	private function safe_path( array $item ) {
		$path = isset( $item['quarantine_path'] ) ? (string) $item['quarantine_path'] : '';
		if ( '' === $path || ! is_file( $path ) ) {
			return new \WP_Error( 'wpcybersec_q_none', __( 'The quarantined copy no longer exists.', 'qartvelo-guard' ) );
		}
		if ( ! Storage::is_within( $path, wpcybersec()->storage->quarantine_dir() ) ) {
			return new \WP_Error( 'wpcybersec_q_path', __( 'Refusing to touch a file outside the quarantine folder.', 'qartvelo-guard' ) );
		}
		return $path;
	}
}
