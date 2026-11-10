<?php
/**
 * Permanent allowlist of approved file hashes and installs.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Three kinds of entries:
 *   hash      value = sha256 of file content approved under a NON-executable
 *             name (image, PDF, ZIP...). "Allowed once, allowed always": the same
 *             bytes are never held again under a non-executable name.
 *   hash_exec value = sha256 approved under an executable name (.php, .htaccess...).
 *             Only this kind lets the same bytes through as an executable file, so
 *             an approved image can never come back as an approved PHP file.
 *   install   value = "plugin:<folder>" or "theme:<folder>".
 *   db        value = Db_Scanner fingerprint of a database value marked safe
 *             (bound to where it is stored). Never a file hash: it can not let
 *             any file through, and it is not exported to the early guard.
 *
 * Every change re-exports <data>/guard/allow.php for the early guard and
 * refreshes the tamper checksum (see verify_integrity()).
 */
class Allowlist {

	const KIND_HASH      = 'hash';
	const KIND_HASH_EXEC = 'hash_exec';
	const KIND_INSTALL   = 'install';
	const KIND_DB        = 'db';

	const CHECKSUM_OPTION = 'wpcybersec_allowlist_checksum';

	/** @var array|null sha256 => 1 (non-executable approval) or 2 (executable approval), loaded lazily. */
	private $hash_cache = null;

	/**
	 * @param string $sha256     Hash.
	 * @param bool   $executable True when the bytes arrive under an executable name
	 *                           (see Paths::is_executable()). Executable names need an
	 *                           executable approval; other names accept either kind.
	 * @return bool
	 */
	public function is_allowed_hash( $sha256, $executable = false ) {
		$sha256 = strtolower( (string) $sha256 );
		if ( 64 !== strlen( $sha256 ) ) {
			return false;
		}
		$map = $this->hash_map();
		if ( ! isset( $map[ $sha256 ] ) ) {
			return false;
		}
		return $executable ? 2 === $map[ $sha256 ] : true;
	}

	/**
	 * Every approved hash with its level.
	 *
	 * @return array sha256 => 1 (non-executable names only) | 2 (any name)
	 */
	public function hash_map() {
		if ( null === $this->hash_cache ) {
			global $wpdb;
			$this->hash_cache = array();
			$rows             = $wpdb->get_results( $wpdb->prepare( 'SELECT kind, value FROM %i WHERE kind IN (%s, %s)', Store::table( 'allowlist' ), self::KIND_HASH, self::KIND_HASH_EXEC ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
			foreach ( (array) $rows as $row ) {
				$level = self::KIND_HASH_EXEC === $row['kind'] ? 2 : 1;
				if ( ! isset( $this->hash_cache[ $row['value'] ] ) || $level > $this->hash_cache[ $row['value'] ] ) {
					$this->hash_cache[ $row['value'] ] = $level;
				}
			}
		}
		return $this->hash_cache;
	}

	/**
	 * @param string $sha256     Hash.
	 * @param string $label      Human label (usually the file name).
	 * @param string $note       Why it was allowed.
	 * @param bool   $executable True when the approved file has an executable name.
	 * @return int Entry id (existing id if already allowed).
	 */
	public function allow_hash( $sha256, $label = '', $note = '', $executable = false ) {
		$sha256 = strtolower( (string) $sha256 );
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $sha256 ) ) {
			return 0;
		}
		$this->hash_cache = null;
		return $this->insert( $executable ? self::KIND_HASH_EXEC : self::KIND_HASH, $sha256, $label, $note );
	}

	/**
	 * Whether a database value (Db_Scanner fingerprint) was marked safe.
	 *
	 * @param string $fingerprint 64 hex chars.
	 * @return bool
	 */
	public function is_allowed_db( $fingerprint ) {
		global $wpdb;
		$fingerprint = strtolower( (string) $fingerprint );
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $fingerprint ) ) {
			return false;
		}
		return (bool) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM %i WHERE kind = %s AND value = %s', Store::table( 'allowlist' ), self::KIND_DB, $fingerprint ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * Marks a database value safe.
	 *
	 * @param string $fingerprint Db_Scanner fingerprint.
	 * @param string $label       Where it is stored (for example "Option widget_text").
	 * @param string $note        Why it was allowed.
	 * @return int Entry id.
	 */
	public function allow_db( $fingerprint, $label = '', $note = '' ) {
		$fingerprint = strtolower( (string) $fingerprint );
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $fingerprint ) ) {
			return 0;
		}
		return $this->insert( self::KIND_DB, $fingerprint, $label, $note );
	}

	/**
	 * @param string $type plugin | theme.
	 * @param string $slug Folder name.
	 * @return bool
	 */
	public function is_allowed_install( $type, $slug ) {
		global $wpdb;
		$value = self::install_key( $type, $slug );
		return (bool) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM %i WHERE kind = %s AND value = %s', Store::table( 'allowlist' ), self::KIND_INSTALL, $value ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * @param string $type  plugin | theme.
	 * @param string $slug  Folder name.
	 * @param string $label Human label.
	 * @param string $note  Note.
	 * @return int
	 */
	public function allow_install( $type, $slug, $label = '', $note = '' ) {
		return $this->insert( self::KIND_INSTALL, self::install_key( $type, $slug ), $label, $note );
	}

	/**
	 * @param string $type plugin | theme.
	 * @param string $slug Folder.
	 * @return string
	 */
	public static function install_key( $type, $slug ) {
		// The value column is varchar(150); real folder names are far shorter.
		return substr( ( 'theme' === $type ? 'theme' : 'plugin' ) . ':' . sanitize_key( $slug ), 0, 150 );
	}

	/**
	 * @param int $id Entry id.
	 * @return bool
	 */
	public function remove( $id ) {
		global $wpdb;
		$row = $this->get( $id );
		if ( ! $row ) {
			return false;
		}
		$wpdb->delete( Store::table( 'allowlist' ), array( 'id' => (int) $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		$this->hash_cache = null;
		$this->after_change();
		wpcybersec()->logger->log( 'allowlist_removed', sprintf( /* translators: %s: label */ __( 'Removed from allowlist: %s', 'qartvelo-guard' ), $row['label'] ? $row['label'] : $row['value'] ), array( 'entry' => $row ) );
		return true;
	}

	/**
	 * @param int $id Entry id.
	 * @return array|null
	 */
	public function get( $id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE id = %d', Store::table( 'allowlist' ), $id ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		return $row ? $row : null;
	}

	/**
	 * @param array $args { kind, search, per_page (50), page (1) }.
	 * @return array { rows, total }
	 */
	public function query( array $args = array() ) {
		global $wpdb;
		$args   = array_merge( array( 'kind' => '', 'search' => '', 'per_page' => 50, 'page' => 1 ), $args );
		$table = Store::table( 'allowlist' );
		// A filter that is not asked for gets the switch 0, which makes its condition true for every row.
		$by_kind = $args['kind'] ? 1 : 0;
		$kind_a  = $by_kind ? (string) $args['kind'] : '';
		// "File fingerprints": approvals under executable names are fingerprints too.
		$kind_b    = self::KIND_HASH === $args['kind'] ? self::KIND_HASH_EXEC : $kind_a;
		$by_search = $args['search'] ? 1 : 0;
		$like      = $by_search ? '%' . $wpdb->esc_like( $args['search'] ) . '%' : '';
		$per_page  = max( 1, (int) $args['per_page'] );
		$offset    = max( 0, ( (int) $args['page'] - 1 ) * $per_page );
		$total     = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE ( %d = 0 OR kind IN (%s, %s) ) AND ( %d = 0 OR value LIKE %s OR label LIKE %s )', $table, $by_kind, $kind_a, $kind_b, $by_search, $like, $like ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		$rows      = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE ( %d = 0 OR kind IN (%s, %s) ) AND ( %d = 0 OR value LIKE %s OR label LIKE %s ) ORDER BY id DESC LIMIT %d OFFSET %d', $table, $by_kind, $kind_a, $kind_b, $by_search, $like, $like, $per_page, $offset ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		return array(
			'rows'  => (array) $rows,
			'total' => $total,
		);
	}

	/**
	 * @return int
	 */
	public function count() {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', Store::table( 'allowlist' ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
	}

	/**
	 * All approved hashes (either kind).
	 *
	 * @return string[]
	 */
	public function hashes() {
		$hashes = array_keys( $this->hash_map() );
		sort( $hashes );
		return $hashes;
	}

	/**
	 * Writes <data>/guard/allow.php: return array( sha256 => 1|2, ... ).
	 * 1 = approved for non-executable names only, 2 = approved for any name.
	 *
	 * @return bool
	 */
	public function export_guard_file() {
		$this->hash_cache = null;
		$map              = $this->hash_map();
		ksort( $map );
		( new Storage() )->ensure();
		$code = "<?php\n// Generated by Qartvelo Guard: approved upload hashes for the early guard.\n// 1 = allowed under non-executable names only, 2 = allowed under any name.\nreturn " . var_export( $map, true ) . ";\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		return Guard_Config::atomic_write( Guard_Config::allow_file(), $code );
	}

	/**
	 * Tamper check. Needs define( 'WPCYBERSEC_HMAC_KEY', '<random>' ) in wp-config.php.
	 * Code running as the web user can still read that key, so this raises the bar
	 * for blind database edits; it is not a guarantee.
	 *
	 * @return bool|null True when intact, false when changed outside the plugin, null without a key.
	 */
	public function verify_integrity() {
		$key = self::hmac_key();
		if ( ! $key ) {
			return null;
		}
		$stored = Network::get_option( self::CHECKSUM_OPTION, '' );
		if ( '' === $stored ) {
			Network::update_option( self::CHECKSUM_OPTION, $this->checksum( $key ), false );
			return true;
		}
		return hash_equals( $stored, $this->checksum( $key ) );
	}

	/**
	 * @return string
	 */
	private static function hmac_key() {
		return defined( 'WPCYBERSEC_HMAC_KEY' ) ? (string) WPCYBERSEC_HMAC_KEY : '';
	}

	/**
	 * @param string $key HMAC key.
	 * @return string
	 */
	private function checksum( $key ) {
		global $wpdb;
		$rows = $wpdb->get_col( $wpdb->prepare( 'SELECT CONCAT(kind, ":", value) FROM %i ORDER BY kind, value', Store::table( 'allowlist' ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		return hash_hmac( 'sha256', implode( "\n", (array) $rows ), $key );
	}

	/**
	 * @param string $kind  Kind.
	 * @param string $value Value.
	 * @param string $label Label.
	 * @param string $note  Note.
	 * @return int
	 */
	private function insert( $kind, $value, $label, $note ) {
		global $wpdb;
		$table    = Store::table( 'allowlist' );
		$existing = $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM %i WHERE kind = %s AND value = %s', $table, $kind, $value ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin's own table; no WordPress API covers it.
		if ( $existing ) {
			return (int) $existing;
		}
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- plugin's own table; no WordPress API covers it.
			$table,
			array(
				'kind'       => $kind,
				'value'      => $value,
				'label'      => function_exists( 'mb_strcut' ) ? mb_strcut( sanitize_text_field( $label ), 0, 255, 'UTF-8' ) : substr( wp_check_invalid_utf8( sanitize_text_field( $label ), true ), 0, 255 ),
				'note'       => sanitize_textarea_field( $note ),
				'created_by' => get_current_user_id(),
				'created_at' => Store::now(),
			)
		);
		$id = (int) $wpdb->insert_id;
		$this->after_change();
		return $id;
	}

	/**
	 * Keeps the guard file and the tamper checksum in sync.
	 */
	private function after_change() {
		$this->export_guard_file();
		$key = self::hmac_key();
		if ( $key ) {
			Network::update_option( self::CHECKSUM_OPTION, $this->checksum( $key ), false );
		}
		do_action( 'wpcybersec_allowlist_changed' );
	}
}
