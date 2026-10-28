<?php
/**
 * Plugin settings: defaults, presets and sanitizing.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * All settings live in one option array. Read with get(), write with update().
 */
class Settings {

	const OPTION = 'wpcybersec_settings';

	/** @var array|null */
	private $cache = null;

	/**
	 * Every setting with its default value.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			// Setup state.
			'wizard_completed'         => false,
			'protection_level'         => 'balanced', // strict | balanced | relaxed | custom.

			// Uploads.
			'upload_mode'              => 'hold_all', // hold_all | hold_risky | scan_only | off.
			'upload_bypass_roles'      => array(),    // Roles whose CLEAN uploads pass without approval.
			'gate_sideloads'           => true,       // Also hold files WordPress downloads (importers, media_sideload_image).

			// Plugin and theme installs.
			'install_mode'             => 'hold',     // hold | off.
			'hold_updates'             => false,      // Also hold updates of already installed plugins/themes.
			'freeze_mods'              => false,      // Disallow all file modifications unless temporarily unlocked.
			'disable_file_editor'      => false,      // Defines DISALLOW_FILE_EDIT (built-in theme/plugin code editor off).
			'unlock_minutes'           => 15,

			// File monitor (new and modified files found by scans).
			'file_mode'                => 'report',   // quarantine_exec | report | off  (what to do with NEW unknown files).
			'modified_action'          => 'report',   // report | quarantine  (what to do with MODIFIED executable files).
			'auto_quarantine'          => false,      // Move files with critical malware hits to quarantine automatically.

			// Scanning.
			'scan_schedule'            => 'twicedaily', // hourly | twicedaily | daily | weekly | off.
			'scan_malware'             => true,         // Run malware signatures during scheduled scans.
			'min_severity'             => 1,            // 1 medium, 2 high, 3 critical. Hits below are ignored.
			'use_checksums'            => true,         // Verify core and wordpress.org plugin files against official checksums.
			'snapshots'                => true,         // Keep compressed copies of PHP and config files to show what changed.
			'snapshot_max_kb'          => 256,          // Largest file copied (16 - 4096 KB).
			'snapshot_max_files'       => 20000,        // Most stored copies (1000 - 1000000); the oldest go first (inode quotas).
			'snapshot_max_mb'          => 200,          // Most disk space for stored copies (10 - 10240 MB).

			// Notifications.
			'notify_mode'              => 'instant',    // instant | digest | off.
			'notify_emails'            => array(),      // Empty means the site admin email (multisite: network admin email and super admins).
			'webhook_url'              => '',           // Slack/Discord/Teams compatible incoming webhook.

			// Advanced: scan scope and performance.
			'scan_root'                => 'abspath',    // abspath | parent | custom.
			'scan_root_custom'         => '',
			'exclusions'               => array(
				'.git/',
				'node_modules/',
				'wp-content/upgrade/',
				'wp-content/upgrade-temp-backup/',
				'wp-content/wflogs/',
				'*.log',
				'error_log',
			),
			'max_file_mb'              => 10,
			'exec_extensions'          => array( 'php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps', 'inc', 'shtml', 'cgi', 'pl', 'py', 'sh', 'asp', 'aspx', 'jsp' ),
			'exec_filenames'           => array( '.htaccess', '.user.ini', 'php.ini', 'web.config' ),
			'tick_seconds'             => 15,

			// Advanced: early upload guard (auto_prepend_file).
			'guard_action'             => 'block',      // block | strip.
			'guard_exempt'             => array(
				'/wp-admin/async-upload.php',
				'/wp-admin/media-new.php',
				'/wp-admin/update.php',
				'/wp-json/wp/v2/media',
				'rest_route=/wp/v2/media',
			),

			// Advanced: external engines.
			'clamav_enabled'           => false,
			'clamav_binary'            => '',

			// Advanced: hosting panel the instructions follow ('' detects it, see Hosting).
			'hosting_panel'            => '',

			// Housekeeping.
			'log_retention_days'       => 90,
			'delete_data_on_uninstall' => false,

			// Opt-in install statistics for the developer (Stats). Off until an administrator turns it on.
			'share_stats'              => false,
		);
	}

	/**
	 * Allowed values for enum settings.
	 *
	 * @return array
	 */
	public static function enums() {
		return array(
			'protection_level' => array( 'strict', 'balanced', 'relaxed', 'custom' ),
			'upload_mode'      => array( 'hold_all', 'hold_risky', 'scan_only', 'off' ),
			'install_mode'     => array( 'hold', 'off' ),
			'file_mode'        => array( 'quarantine_exec', 'report', 'off' ),
			'modified_action'  => array( 'report', 'quarantine' ),
			'scan_schedule'    => array( 'hourly', 'twicedaily', 'daily', 'weekly', 'off' ),
			'notify_mode'      => array( 'instant', 'digest', 'off' ),
			'scan_root'        => array( 'abspath', 'parent', 'custom' ),
			'guard_action'     => array( 'block', 'strip' ),
			'hosting_panel'    => array_merge( array( '' ), Hosting::ids() ),
		);
	}

	/**
	 * Protection level presets used by the wizard and the settings page.
	 *
	 * @return array level => settings
	 */
	public static function presets() {
		return array(
			'strict'   => array(
				'upload_mode'         => 'hold_all',
				'upload_bypass_roles' => array(),
				'gate_sideloads'      => true,
				'install_mode'        => 'hold',
				'hold_updates'        => false,
				'file_mode'           => 'quarantine_exec',
				'modified_action'     => 'report',
				'auto_quarantine'     => true,
				'scan_schedule'       => 'hourly',
				'scan_malware'        => true,
				'notify_mode'         => 'instant',
			),
			'balanced' => array(
				'upload_mode'         => 'hold_all',
				'upload_bypass_roles' => array(),
				'gate_sideloads'      => true,
				'install_mode'        => 'hold',
				'hold_updates'        => false,
				'file_mode'           => 'report',
				'modified_action'     => 'report',
				'auto_quarantine'     => false,
				'scan_schedule'       => 'twicedaily',
				'scan_malware'        => true,
				'notify_mode'         => 'instant',
			),
			'relaxed'  => array(
				'upload_mode'         => 'hold_risky',
				'upload_bypass_roles' => array( 'administrator' ),
				'gate_sideloads'      => false,
				'install_mode'        => 'off',
				'hold_updates'        => false,
				'file_mode'           => 'report',
				'modified_action'     => 'report',
				'auto_quarantine'     => false,
				'scan_schedule'       => 'daily',
				'scan_malware'        => true,
				'notify_mode'         => 'digest',
			),
		);
	}

	/**
	 * @return array All settings merged over defaults.
	 */
	public function all() {
		if ( null === $this->cache ) {
			$saved       = Network::get_option( self::OPTION, array() );
			$this->cache = array_merge( self::defaults(), is_array( $saved ) ? $saved : array() );
		}
		return $this->cache;
	}

	/**
	 * @param string $key     Setting name.
	 * @param mixed  $default Fallback when the key is unknown.
	 * @return mixed
	 */
	public function get( $key, $default = null ) {
		$all = $this->all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : $default;
	}

	/**
	 * Merges, sanitizes and saves values. Unknown keys are dropped.
	 *
	 * @param array $values Partial settings.
	 * @return array The saved settings.
	 */
	public function update( array $values ) {
		$old         = $this->all();
		$new         = $this->sanitize( array_merge( $old, $values ) );
		$this->cache = $new;
		Network::update_option( self::OPTION, $new, true );

		/**
		 * Fires after settings are saved.
		 *
		 * @param array $new New settings.
		 * @param array $old Previous settings.
		 */
		do_action( 'wpcybersec_settings_updated', $new, $old );
		return $new;
	}

	/**
	 * Applies a protection level preset.
	 *
	 * @param string $level strict | balanced | relaxed.
	 * @return array Saved settings.
	 */
	public function apply_level( $level ) {
		$presets = self::presets();
		if ( ! isset( $presets[ $level ] ) ) {
			return $this->all();
		}
		return $this->update( array_merge( $presets[ $level ], array( 'protection_level' => $level ) ) );
	}

	/**
	 * Drops the in-memory cache (after another process changed the option).
	 */
	public function flush() {
		$this->cache = null;
	}

	/**
	 * Coerces every value to the type of its default.
	 *
	 * @param array $values Raw values.
	 * @return array
	 */
	public function sanitize( array $values ) {
		$defaults = self::defaults();
		$enums    = self::enums();
		$clean    = array();

		foreach ( $defaults as $key => $default ) {
			$value = array_key_exists( $key, $values ) ? $values[ $key ] : $default;

			if ( isset( $enums[ $key ] ) ) {
				$value = in_array( $value, $enums[ $key ], true ) ? $value : $default;
			} elseif ( is_bool( $default ) ) {
				$value = (bool) filter_var( $value, FILTER_VALIDATE_BOOLEAN );
			} elseif ( is_int( $default ) ) {
				$value = (int) $value;
			} elseif ( is_array( $default ) ) {
				if ( is_string( $value ) ) {
					$value = preg_split( '/[\r\n,]+/', $value );
				}
				$value = array_values( array_unique( array_filter( array_map( 'trim', array_map( 'strval', (array) $value ) ), 'strlen' ) ) );
			} else {
				$value = trim( (string) $value );
			}
			$clean[ $key ] = $value;
		}

		// Range limits.
		$clean['min_severity']       = max( 1, min( 3, $clean['min_severity'] ) );
		$clean['max_file_mb']        = max( 1, min( 512, $clean['max_file_mb'] ) );
		$clean['tick_seconds']       = max( 3, min( 25, $clean['tick_seconds'] ) );
		$clean['unlock_minutes']     = max( 1, min( 240, $clean['unlock_minutes'] ) );
		$clean['log_retention_days'] = max( 0, min( 3650, $clean['log_retention_days'] ) );
		$clean['snapshot_max_kb']    = max( 16, min( 4096, $clean['snapshot_max_kb'] ) );
		$clean['snapshot_max_files'] = max( 1000, min( 1000000, $clean['snapshot_max_files'] ) );
		$clean['snapshot_max_mb']    = max( 10, min( 10240, $clean['snapshot_max_mb'] ) );

		// Specific formats.
		$clean['notify_emails']       = array_values( array_filter( array_map( 'sanitize_email', $clean['notify_emails'] ), 'is_email' ) );
		$clean['webhook_url']         = $clean['webhook_url'] ? esc_url_raw( $clean['webhook_url'], array( 'https' ) ) : '';
		$clean['exec_extensions']     = array_values( array_unique( array_map( static function ( $ext ) {
			return strtolower( ltrim( $ext, '.' ) );
		}, $clean['exec_extensions'] ) ) );
		$clean['upload_bypass_roles'] = array_values( array_map( 'sanitize_key', $clean['upload_bypass_roles'] ) );
		$clean['scan_root_custom']    = $clean['scan_root_custom'] ? wp_normalize_path( $clean['scan_root_custom'] ) : '';
		$clean['clamav_binary']       = $clean['clamav_binary'] ? wp_normalize_path( $clean['clamav_binary'] ) : '';

		return $clean;
	}

	/**
	 * Notification recipients, falling back to the site admin email (on
	 * multisite the network admin email and the super admins, the only ones
	 * who can approve).
	 *
	 * @return string[]
	 */
	public function recipients() {
		$emails = $this->get( 'notify_emails', array() );
		return $emails ? $emails : Network::default_recipients();
	}
}
