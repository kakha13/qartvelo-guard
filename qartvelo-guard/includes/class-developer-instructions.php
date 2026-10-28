<?php
/**
 * Developer instructions: every open step that needs someone with server
 * access (SSH, SFTP or the hosting panel), with this server's real paths.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * The plugin first tries every file change from the admin panel (one-click
 * fixes, uploads/.htaccess, the guard's .user.ini or .htaccess line,
 * wp-config.php edits, the data folder move). When the server does not allow
 * it, the step lands here, together with what can never be done from PHP:
 * a real cron job, installing ClamAV or Linux Malware Detect, and fixes this
 * server has no automatic way for.
 *
 * Failed attempts are remembered in a small option (id => { at, message })
 * so a click that failed shows up here with the server's error, and are
 * forgotten as soon as the same fix succeeds or the problem is gone.
 *
 * Entries never contain secrets: no keys, passwords or database details.
 */
class Developer_Instructions {

	/** Option with the last failed attempts (not autoloaded). */
	const FAILURES_OPTION = 'wpcybersec_fix_failures';

	/** Transient with the number of open entries (Dashboard and wizard links). */
	const COUNT_TRANSIENT = 'wpcybersec_dev_count';

	/** Failed attempts kept at most. */
	const MAX_FAILURES = 20;

	/**
	 * Fix ids that one entry stands for (several actions fix the same thing).
	 */
	const ALIASES = array(
		'quarantine_web'       => 'data_dir',
		'uploads_htaccess'     => 'uploads_php',
		'write_htaccess'       => 'uploads_php',
		'guard_install'        => 'guard',
		'guard_write_user_ini' => 'guard',
		'guard_htaccess'       => 'guard',
	);

	public function register() {
		add_action( 'admin_post_wpcybersec_dev_instructions', array( $this, 'handle_download' ) );
		add_action( 'wpcybersec_settings_updated', array( __CLASS__, 'flush' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Failed attempts                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $id Fix id.
	 * @return string The id the entry is listed under.
	 */
	public static function canonical( $id ) {
		$id = sanitize_key( (string) $id );
		return isset( self::ALIASES[ $id ] ) ? self::ALIASES[ $id ] : $id;
	}

	/**
	 * Remembers that a change from the admin panel failed.
	 *
	 * @param string $id      Fix id.
	 * @param string $message The server's error, as shown to the administrator.
	 */
	public static function record_failure( $id, $message ) {
		$id = self::canonical( $id );
		if ( '' === $id ) {
			return;
		}
		$all        = self::failures();
		$all[ $id ] = array(
			'at'      => time(),
			'message' => wp_strip_all_tags( (string) $message ),
		);
		uasort(
			$all,
			static function ( $a, $b ) {
				return (int) $b['at'] - (int) $a['at'];
			}
		);
		Network::update_option( self::FAILURES_OPTION, array_slice( $all, 0, self::MAX_FAILURES, true ), false );
		self::flush();
	}

	/**
	 * Forgets a failed attempt (the same fix worked, or the problem is gone).
	 *
	 * @param string $id Fix id.
	 */
	public static function clear_failure( $id ) {
		$id  = self::canonical( $id );
		$all = self::failures();
		if ( isset( $all[ $id ] ) ) {
			unset( $all[ $id ] );
			Network::update_option( self::FAILURES_OPTION, $all, false );
		}
		self::flush();
	}

	/**
	 * @return array id => { at, message }
	 */
	public static function failures() {
		$all = Network::get_option( self::FAILURES_OPTION, array() );
		$out = array();
		foreach ( is_array( $all ) ? $all : array() as $id => $row ) {
			if ( is_array( $row ) && isset( $row['at'], $row['message'] ) ) {
				$out[ self::canonical( (string) $id ) ] = array(
					'at'      => (int) $row['at'],
					'message' => (string) $row['message'],
				);
			}
		}
		return $out;
	}

	/**
	 * Drops the cached count, so the Dashboard shows the new number.
	 */
	public static function flush() {
		Network::delete_transient( self::COUNT_TRANSIENT );
	}

	/* ------------------------------------------------------------------ */
	/* Entries                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Every open entry.
	 *
	 * @param array[]|null $checks Environment checks already computed (Sysadmin_Tools::diagnostics()), or null.
	 * @return array[] Each { id, title, why, steps: [ { text, code } ], error, at, optional }.
	 */
	public function items( $checks = null ) {
		$tools  = wpcybersec()->sysadmin;
		$checks = is_array( $checks ) ? $checks : ( $tools ? $tools->diagnostics( false, false ) : array() ); // Cached probes only: this also runs for the dashboard count.
		$by_id  = array();
		foreach ( $checks as $check ) {
			if ( ! empty( $check['id'] ) ) {
				$by_id[ (string) $check['id'] ] = $check;
			}
		}

		$items    = array();
		$failures = self::failures();

		// 1. Fixes that failed from the admin panel, while the problem is still there.
		foreach ( $failures as $id => $failure ) {
			if ( $this->is_resolved( $id, $by_id ) ) {
				self::clear_failure( $id );
				continue;
			}
			$entry = $this->entry_for( $id, $by_id );
			if ( $entry ) {
				$entry['error'] = $failure['message'];
				$entry['at']    = $failure['at'];
				$items[ $id ]   = $entry;
			}
		}

		// 2. Open checks this server has no automatic fix for.
		foreach ( $checks as $check ) {
			$id = self::canonical( isset( $check['id'] ) ? (string) $check['id'] : '' );
			// A data folder PHP cannot write to is never fixed by the move button: it needs server access.
			$has_fix = ! empty( $check['auto_fix'] ) && ! ( 'data_dir' === $id && 'fail' === $check['status'] );
			if ( '' === $id || isset( $items[ $id ] ) || ! in_array( $check['status'], array( 'warn', 'fail' ), true ) || $has_fix ) {
				continue;
			}
			$entry = $this->entry_for( $id, $by_id );
			if ( $entry ) {
				$items[ $id ] = $entry;
			}
		}

		// 3. Things PHP can never do: cron, the early guard's server line, antivirus engines.
		foreach ( array( 'wp_cron', 'guard', 'clamav', 'clamav_exec', 'maldet_inotify', 'maldet', 'maldet_watch', 'maldet_monitor', 'maldet_link' ) as $id ) {
			if ( isset( $items[ $id ] ) || ! $this->is_needed( $id ) ) {
				continue;
			}
			$entry = $this->entry_for( $id, $by_id );
			if ( $entry ) {
				$items[ $id ] = $entry;
			}
		}

		// 4. A damaged WordPress core (Core_Repair): the reinstall by hand, with the panel's file manager.
		$repair = Sysadmin_Tools::service( 'core_repair' );
		if ( $repair instanceof Core_Repair ) {
			try {
				$damage = $repair->damage();
				if ( $damage['show'] ) {
					$items['core_reinstall'] = array(
						'id'       => 'core_reinstall',
						/* translators: %s: WordPress version */
						'title'    => sprintf( __( 'Reinstall a clean WordPress %s core', 'qartvelo-guard' ), $damage['version'] ),
						'why'      => sprintf(
							/* translators: 1: number of files, 2: changed, 3: threats, 4: extra files, 5: missing */
							__( '%1$s core files are affected (%2$s changed, %3$s threats, %4$s extra files in wp-admin or wp-includes, %5$s missing). Replacing core is faster and safer than reviewing them one by one; the one-click reinstall on the Dashboard does it when the server allows it.', 'qartvelo-guard' ),
							number_format_i18n( $damage['total'] ),
							number_format_i18n( $damage['modified'] ),
							number_format_i18n( $damage['threats'] ),
							number_format_i18n( $damage['unknown'] ),
							number_format_i18n( $damage['missing'] )
						),
						'steps'    => $repair->manual_steps(),
						'error'    => '',
						'at'       => 0,
						'optional' => false,
					);
				}
			} catch ( \Throwable $e ) {
				unset( $items['core_reinstall'] );
			}
		}

		$items = array_values( $items );
		usort(
			$items,
			static function ( $a, $b ) {
				return (int) $a['optional'] - (int) $b['optional'];
			}
		);
		Network::set_transient( self::COUNT_TRANSIENT, count( $items ), 15 * MINUTE_IN_SECONDS );
		return $items;
	}

	/**
	 * Number of open entries, cached for the Dashboard and the wizard.
	 *
	 * @return int
	 */
	public function count() {
		$cached = Network::get_transient( self::COUNT_TRANSIENT );
		if ( false !== $cached ) {
			return (int) $cached;
		}
		try {
			return count( $this->items() );
		} catch ( \Throwable $e ) {
			return 0;
		}
	}

	/**
	 * Whether a remembered failure no longer matters.
	 *
	 * @param string  $id    Entry id.
	 * @param array[] $by_id Checks by id.
	 * @return bool
	 */
	private function is_resolved( $id, array $by_id ) {
		switch ( $id ) {
			case 'guard':
				$status = Sysadmin_Tools::call( 'guard_manager', 'status', array(), array() );
				return ! empty( $status['active'] ) || ! empty( $status['confirmed'] );
			case 'hmac_key':
				return defined( 'WPCYBERSEC_HMAC_KEY' );
			case 'disable_wp_cron':
				return defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
			case 'file_edit':
				return defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		}
		if ( isset( $by_id[ $id ] ) ) {
			return ! in_array( $by_id[ $id ]['status'], array( 'warn', 'fail' ), true );
		}
		if ( 'data_dir' === $id && isset( $by_id['quarantine_web'] ) ) {
			return ! in_array( $by_id['quarantine_web']['status'], array( 'warn', 'fail' ), true );
		}
		return false;
	}

	/**
	 * Whether one of the "never from PHP" entries applies to this server now.
	 *
	 * @param string $id Entry id.
	 * @return bool
	 */
	private function is_needed( $id ) {
		$av = Sysadmin_Tools::call( 'sysadmin', 'antivirus_status', array(), array() );
		switch ( $id ) {
			case 'maldet_watch':
			case 'maldet_monitor':
				// The "On the server now" rows: this site not in monitor_paths, or the monitor state unknown.
				$row = $this->live_row( $id );
				return $row && ( 'maldet_watch' === $id ? 'bad' === $row['state'] : 'unknown' === $row['state'] ) && '' !== $row['code'];
			case 'wp_cron':
				// bin/cron.php and the WP-CLI cron lines record every run; none in the last two hours means no real cron job.
				return (int) Network::get_option( 'wpcybersec_cli_cron_at', 0 ) < time() - 2 * HOUR_IN_SECONDS;
			case 'guard':
				$status = Sysadmin_Tools::call( 'guard_manager', 'status', array(), array() );
				$hard   = Sysadmin_Tools::service( 'hardening' );
				return ! empty( $status['installed'] ) && empty( $status['active'] ) && empty( $status['confirmed'] ) && empty( $status['conflict'] )
					&& $hard && method_exists( $hard, 'guard_method' ) && '' === $hard->guard_method();
			case 'clamav':
				return isset( $av['clamav']['state'] ) && 'missing' === $av['clamav']['state'];
			case 'clamav_exec':
				return isset( $av['clamav']['state'] ) && 'blocked' === $av['clamav']['state'];
			case 'maldet':
				return ! empty( $av['maldet']['supported'] ) && '' === (string) $av['maldet']['binary'];
			case 'maldet_inotify':
				return ! empty( $av['maldet']['binary'] ) && false === $av['maldet']['monitor'];
			case 'maldet_link':
				return ! empty( $av['maldet']['binary'] ) && false === $av['maldet']['linked'] && isset( $av['clamav']['state'] ) && 'missing' !== $av['clamav']['state'];
		}
		return false;
	}

	/**
	 * One row of Sysadmin_Tools::antivirus_live() by id.
	 *
	 * @param string $id Row id.
	 * @return array|null
	 */
	private function live_row( $id ) {
		$tools = Sysadmin_Tools::service( 'sysadmin' );
		if ( ! $tools instanceof Sysadmin_Tools ) {
			return null;
		}
		try {
			foreach ( $tools->antivirus_live() as $row ) {
				if ( isset( $row['id'] ) && $row['id'] === $id ) {
					return $row;
				}
			}
		} catch ( \Throwable $e ) {
			return null;
		}
		return null;
	}

	/**
	 * Title, reason and steps of one entry.
	 *
	 * @param string  $id    Entry id.
	 * @param array[] $by_id Checks by id.
	 * @return array|null
	 */
	private function entry_for( $id, array $by_id ) {
		$hard  = Sysadmin_Tools::service( 'hardening' );
		$tools = Sysadmin_Tools::service( 'sysadmin' );
		$tools = $tools instanceof Sysadmin_Tools ? $tools : null;
		$steps = ( $hard && method_exists( $hard, 'manual_steps' ) ) ? $hard->manual_steps( $id ) : array();
		$check = isset( $by_id[ $id ] ) ? $by_id[ $id ] : ( 'data_dir' === $id && isset( $by_id['quarantine_web'] ) ? $by_id['quarantine_web'] : null );
		$user  = self::web_user();
		$entry = array(
			'id'       => $id,
			'title'    => $check ? (string) $check['label'] : $id,
			'why'      => $check ? (string) $check['detail'] : '',
			'steps'    => $steps,
			'error'    => '',
			'at'       => 0,
			'optional' => false,
		);

		switch ( $id ) {
			case 'data_dir':
				$storage = Sysadmin_Tools::service( 'storage' );
				$dir     = $storage ? $storage->data_dir() : '';
				if ( $check && 'fail' === $check['status'] && '' !== $dir ) {
					$entry['title'] = __( 'Make the data folder writable', 'qartvelo-guard' );
					$entry['steps'] = array(
						array(
							/* translators: %s: web server user name */
							'text' => sprintf( __( 'Held files cannot be stored until PHP can write there. As root, give the folder to the web server user (%s here):', 'qartvelo-guard' ), $user ),
							'code' => 'mkdir -p ' . Sysadmin_Tools::shell_arg( $dir ) . "\nchown -R " . $user . ': ' . Sysadmin_Tools::shell_arg( $dir ) . "\nchmod 750 " . Sysadmin_Tools::shell_arg( $dir ),
						),
					);
				} else {
					$entry['title'] = __( 'Move the data folder outside the web root', 'qartvelo-guard' );
					$entry['why']   = __( 'Held files live inside the public website folder. The automatic move is not possible on this server.', 'qartvelo-guard' );
				}
				break;

			case 'wp_config_perms':
				$entry['title'] = __( 'Restrict wp-config.php', 'qartvelo-guard' );
				$config         = Config_Editor::path();
				if ( '' !== $config ) {
					$entry['steps'] = array(
						array(
							'text' => __( 'As the owner of the file (or root), run:', 'qartvelo-guard' ),
							'code' => 'chmod 640 ' . Sysadmin_Tools::shell_arg( $config ),
						),
						array( 'text' => __( 'Use 600 instead when PHP runs as the owner of the file.', 'qartvelo-guard' ) ),
					);
				}
				break;

			case 'world_writable':
				$entry['title'] = __( 'Remove write access for other users from the code folders', 'qartvelo-guard' );
				break;

			case 'file_edit':
				$entry['title'] = __( 'Turn off the theme and plugin file editor', 'qartvelo-guard' );
				$entry['why']   = __( 'Anyone with a stolen administrator login can plant code through the built-in editor. wp-config.php could not be changed from the admin panel.', 'qartvelo-guard' );
				$entry['steps'] = self::config_steps( "define( 'DISALLOW_FILE_EDIT', true );", __( 'If it already contains define( \'DISALLOW_FILE_EDIT\', false ); change false to true instead.', 'qartvelo-guard' ) );
				break;

			case 'disable_wp_cron':
				$entry['title'] = __( 'Switch off visitor-triggered cron', 'qartvelo-guard' );
				$entry['why']   = __( 'A real cron job runs WordPress cron, so page visits do not need to. wp-config.php could not be changed from the admin panel.', 'qartvelo-guard' );
				$entry['steps'] = self::config_steps( "define( 'DISABLE_WP_CRON', true );" );
				break;

			case 'hmac_key':
				// Never put a real key in instructions that are copied or downloaded.
				$entry['title'] = __( 'Add the allowlist tamper key', 'qartvelo-guard' );
				$entry['why']   = __( 'A secret key in wp-config.php lets the plugin notice allowlist entries added directly in the database. wp-config.php could not be changed from the admin panel.', 'qartvelo-guard' );
				$entry['steps'] = array_merge(
					array(
						array(
							'text' => __( 'Create a random key on the server:', 'qartvelo-guard' ),
							'code' => 'openssl rand -hex 32',
						),
					),
					self::config_steps( "define( 'WPCYBERSEC_HMAC_KEY', 'PASTE-THE-KEY-HERE' );", __( 'Put the printed key in place of PASTE-THE-KEY-HERE. Keep it only in wp-config.php.', 'qartvelo-guard' ) )
				);
				break;

			case 'uploads_php':
				$entry['title'] = __( 'Block PHP in the uploads folder', 'qartvelo-guard' );
				if ( '' === $entry['why'] ) {
					$entry['why'] = __( 'A PHP file dropped into uploads by a vulnerable plugin could run. The rule could not be written from the admin panel.', 'qartvelo-guard' );
				}
				if ( $tools && 'nginx' !== Sysadmin_Tools::server_type() ) {
					$uploads        = wp_upload_dir( null, false );
					$file           = ! empty( $uploads['basedir'] ) ? trailingslashit( wp_normalize_path( $uploads['basedir'] ) ) . '.htaccess' : 'wp-content/uploads/.htaccess';
					$entry['steps'] = array(
						array(
							/* translators: %s: file path */
							'text' => sprintf( __( 'Add these lines to %s (create the file if it does not exist; keep anything already in it):', 'qartvelo-guard' ), $file ),
							'code' => $tools->apache_uploads_rules(),
						),
						array(
							/* translators: %s: web server user name */
							'text' => sprintf( __( 'Or make the file writable for the web server user (%s here) and press the button in Settings > Advanced > Web server again:', 'qartvelo-guard' ), $user ),
							'code' => 'touch ' . Sysadmin_Tools::shell_arg( $file ) . "\nchown " . $user . ' ' . Sysadmin_Tools::shell_arg( $file ),
						),
					);
					$entry['steps'] = self::panel( 'web_rules', $entry['steps'] );
				}
				break;

			case 'guard':
				$entry['title'] = __( 'Load the early upload guard (auto_prepend_file)', 'qartvelo-guard' );
				$entry['why']   = __( 'The guard is installed, but PHP does not load it yet and the plugin cannot write the setting on this server.', 'qartvelo-guard' );
				// The way that fits this PHP SAPI; the hosting panel's own way goes first through panel().
				$snippet = null;
				$sapi_id = (string) Sysadmin_Tools::call( 'guard_manager', 'recommended_snippet', array(), '' );
				foreach ( (array) Sysadmin_Tools::call( 'guard_manager', 'snippets', array(), array() ) as $candidate ) {
					if ( is_array( $candidate ) && isset( $candidate['id'] ) && $candidate['id'] === $sapi_id ) {
						$snippet = $candidate;
						break;
					}
				}
				if ( is_array( $snippet ) && ! empty( $snippet['code'] ) ) {
					$where          = ! empty( $snippet['file'] ) ? (string) $snippet['file'] : (string) ( isset( $snippet['label'] ) ? $snippet['label'] : '' );
					$entry['steps'] = array(
						array(
							/* translators: %s: configuration file */
							'text' => sprintf( __( 'Add this to %s:', 'qartvelo-guard' ), $where ),
							'code' => (string) $snippet['code'],
						),
						array( 'text' => __( 'Restart PHP (or the web server), then open Settings > Advanced > Early guard: it shows "Active in this request: Yes" once it works.', 'qartvelo-guard' ) ),
					);
					$entry['steps'] = self::panel( 'prepend', $entry['steps'] );
				} elseif ( $steps ) {
					$entry['steps'] = array_slice( $steps, 1 ); // The first step installs the guard files, which is done.
				}
				break;

			case 'wp_cron':
				$snippets       = $tools ? $tools->cron_snippets() : array();
				$entry['title'] = __( 'Set up a real cron job', 'qartvelo-guard' );
				$entry['why']   = __( 'WordPress runs scheduled scans only when someone visits the site. A cron job on the server makes them run on time, and no real cron run was seen in the last two hours.', 'qartvelo-guard' );
				if ( $snippets ) {
					$entry['steps'] = array(
						array(
							/* translators: %s: web server user name */
							'text' => sprintf( __( 'Open the crontab of the user that owns the site files (%s here) with "crontab -e" and add these lines:', 'qartvelo-guard' ), $user ),
							'code' => $snippets[0]['code'],
						),
						Sysadmin_Tools::cron_disable_step(),
					);
				}
				$entry['steps'] = self::panel( 'cron', $entry['steps'] );
				break;

			case 'clamav':
				$entry['title']    = __( 'Install ClamAV (optional)', 'qartvelo-guard' );
				$entry['why']      = __( 'ClamAV knows millions of existing infections and gives every upload a second opinion. It finds more, but it does not block attacks. It is installed once per server and shared by every site on it; when another site of this server already has it, nothing needs to be installed here.', 'qartvelo-guard' );
				$entry['steps']    = self::panel( 'clamav', Admin\Clamav_Guide::install_steps() );
				$entry['optional'] = true;
				break;

			case 'clamav_exec':
				$entry['title'] = __( 'Let PHP run ClamAV', 'qartvelo-guard' );
				$entry['why']   = __( 'ClamAV is installed, but PHP is not allowed to run programs (exec and proc_open are disabled), so uploads cannot be scanned with it.', 'qartvelo-guard' );
				$entry['steps'] = array(
					array(
						'text' => __( 'Remove proc_open (or exec) from disable_functions in the PHP configuration of this site, then restart PHP. This shows where it is set:', 'qartvelo-guard' ),
						'code' => 'php -i | grep -E "^(Loaded Configuration File|disable_functions)"',
					),
				);
				break;

			case 'maldet':
				$entry['title']    = __( 'Install Linux Malware Detect (optional)', 'qartvelo-guard' );
				$entry['why']      = __( 'maldet adds signatures made for website malware such as PHP web shells. With ClamAV installed, its signatures are used by ClamAV too. It is installed once per server and shared by every site on it; each site only needs its folder added to the monitor.', 'qartvelo-guard' );
				$entry['steps']    = self::panel( 'maldet', array_merge( Admin\Clamav_Guide::maldet_install_steps(), $tools ? array_slice( $tools->maldet_steps(), 0, 5 ) : array() ) );
				$entry['optional'] = true;
				break;

			case 'maldet_inotify':
				$entry['title'] = __( 'Install inotify-tools for the maldet real-time monitor', 'qartvelo-guard' );
				$entry['why']   = __( 'maldet is installed, but its real-time monitor is unavailable: maldet --monitor stops with "could not find inotifywait command" until inotify-tools is installed.', 'qartvelo-guard' );
				$entry['steps'] = $tools ? array_slice( $tools->maldet_steps(), 0, 5 ) : array();
				break;

			case 'maldet_watch':
				$row               = $this->live_row( $id );
				$entry['title']    = __( 'Add this site to the maldet real-time monitor', 'qartvelo-guard' );
				$entry['why']      = __( 'maldet is installed on this server, but its monitor does not watch this site\'s folder. ClamAV and maldet are installed once per server and shared by every site on it: this site needs no install of its own, only its folder in the monitor.', 'qartvelo-guard' );
				$entry['steps']    = $row ? array( array_filter( array( 'text' => $row['hint'], 'code' => $row['code'] ) ) ) : array();
				$entry['optional'] = true;
				break;

			case 'maldet_monitor':
				$row               = $this->live_row( $id );
				$entry['title']    = __( 'Check that the maldet real-time monitor runs', 'qartvelo-guard' );
				$entry['why']      = __( 'PHP cannot tell whether the monitor runs on this server, so the Antivirus card shows it as unknown.', 'qartvelo-guard' );
				$entry['steps']    = $row ? array( array_filter( array( 'text' => $row['hint'], 'code' => $row['code'] ) ) ) : array();
				$entry['optional'] = true;
				break;

			case 'maldet_link':
				$entry['title']    = __( 'Link the maldet signatures into ClamAV', 'qartvelo-guard' );
				$entry['why']      = __( 'maldet is installed, but its signatures are not in ClamAV\'s database folder, so clamdscan and this plugin do not use them.', 'qartvelo-guard' );
				$entry['steps']    = array(
					array(
						'text' => __( 'As root, turn on the ClamAV integration and update maldet; the update copies the signatures and reloads clamd:', 'qartvelo-guard' ),
						'code' => "sed -i 's/^scan_clamscan=.*/scan_clamscan=\"1\"/' /usr/local/maldetect/conf.maldet\nmaldet -u",
					),
				);
				$entry['optional'] = true;
				break;

			default:
				if ( ! $check ) {
					return null;
				}
				if ( ! $steps ) {
					if ( '' === trim( (string) $check['fix'] ) && '' === trim( (string) $check['code'] ) ) {
						return null;
					}
					$entry['steps'] = array(
						array_filter(
							array(
								'text' => (string) $check['fix'],
								'code' => (string) $check['code'],
							)
						),
					);
				}
		}
		return $entry['steps'] ? $entry : null;
	}

	/**
	 * The hosting panel's steps first, these under "Other ways" (Hosting::merge()).
	 *
	 * @param string  $task    Hosting task.
	 * @param array[] $generic Generic steps.
	 * @return array[]
	 */
	private static function panel( $task, array $generic ) {
		$hosting = wpcybersec()->hosting;
		if ( ! is_object( $hosting ) || ! method_exists( $hosting, 'merge' ) ) {
			return $generic;
		}
		try {
			return $hosting->merge( $task, $generic );
		} catch ( \Throwable $e ) {
			return $generic;
		}
	}

	/**
	 * "Hosting: CyberPanel (OpenLiteSpeed, lsphp)" for the instructions header, '' when unavailable.
	 *
	 * @return string
	 */
	public static function hosting_line() {
		$hosting = wpcybersec()->hosting;
		if ( ! is_object( $hosting ) || ! method_exists( $hosting, 'label' ) ) {
			return '';
		}
		try {
			$info = $hosting->current();
		} catch ( \Throwable $e ) {
			return '';
		}
		$note = ! empty( $info['overridden'] ) ? __( 'chosen in Settings > Advanced', 'qartvelo-guard' ) : ( 'high' === $info['confidence'] ? '' : ( 'likely' === $info['confidence'] ? __( 'likely', 'qartvelo-guard' ) : __( 'not detected, generic steps', 'qartvelo-guard' ) ) );
		/* translators: %s: hosting panel with web server and PHP handler */
		return sprintf( __( 'Hosting: %s', 'qartvelo-guard' ), $hosting->label( $info ) ) . ( '' !== $note ? ' [' . $note . ']' : '' );
	}

	/**
	 * Steps for adding one line to wp-config.php.
	 *
	 * @param string $line The define() line.
	 * @param string $note Optional extra sentence.
	 * @return array[]
	 */
	private static function config_steps( $line, $note = '' ) {
		$config = Config_Editor::path();
		$steps  = array(
			array(
				/* translators: %s: file path */
				'text' => sprintf( __( 'Open %s and add this line just above "That\'s all, stop editing!":', 'qartvelo-guard' ), '' !== $config ? $config : 'wp-config.php' ),
				'code' => $line,
			),
		);
		if ( '' !== $note ) {
			$steps[] = array( 'text' => $note );
		}
		return $steps;
	}

	/**
	 * Name of the user PHP runs as (for chown commands), or a placeholder.
	 *
	 * @return string
	 */
	public static function web_user() {
		if ( function_exists( 'posix_geteuid' ) && function_exists( 'posix_getpwuid' ) ) {
			$info = @posix_getpwuid( posix_geteuid() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( is_array( $info ) && ! empty( $info['name'] ) && preg_match( '/^[A-Za-z0-9._-]{1,32}$/', $info['name'] ) ) {
				return $info['name'];
			}
		}
		return 'www-data';
	}

	/* ------------------------------------------------------------------ */
	/* Plain text and download                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Plain text for "Copy all" and the .txt download.
	 *
	 * @param array[] $items items().
	 * @return string
	 */
	public static function as_text( array $items ) {
		$host  = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$lines = array(
			/* translators: %s: site domain */
			sprintf( __( 'Qartvelo Guard - developer instructions for %s', 'qartvelo-guard' ), $host ),
			/* translators: %s: date and time */
			sprintf( __( 'Generated %s UTC. Each item needs someone with access to the server (SSH, SFTP or the hosting panel).', 'qartvelo-guard' ), gmdate( 'Y-m-d H:i' ) ),
			/* translators: %s: WordPress folder */
			sprintf( __( 'WordPress folder: %s', 'qartvelo-guard' ), untrailingslashit( wp_normalize_path( ABSPATH ) ) ),
		);
		$hosting = self::hosting_line();
		if ( '' !== $hosting ) {
			$lines[] = $hosting;
		}
		$lines[] = '';
		if ( ! $items ) {
			$lines[] = __( 'Nothing needs server access right now.', 'qartvelo-guard' );
		}
		foreach ( array_values( $items ) as $i => $item ) {
			$lines[] = ( $i + 1 ) . '. ' . $item['title'] . ( $item['optional'] ? ' [' . __( 'optional', 'qartvelo-guard' ) . ']' : '' );
			if ( '' !== $item['why'] ) {
				$lines[] = '   ' . $item['why'];
			}
			if ( '' !== $item['error'] ) {
				/* translators: 1: date and time, 2: error message */
				$lines[] = '   ' . sprintf( __( 'Tried from the admin panel on %1$s: %2$s', 'qartvelo-guard' ), gmdate( 'Y-m-d H:i', (int) $item['at'] ) . ' UTC', $item['error'] );
			}
			foreach ( $item['steps'] as $step ) {
				if ( ! empty( $step['other'] ) ) {
					$lines[] = '   ' . ( ! empty( $step['text'] ) ? $step['text'] : __( 'Other ways', 'qartvelo-guard' ) ) . ':';
					continue;
				}
				if ( ! empty( $step['text'] ) ) {
					$lines[] = '   - ' . $step['text'];
				}
				if ( ! empty( $step['code'] ) ) {
					foreach ( preg_split( '/\r\n|\r|\n/', (string) $step['code'] ) as $code ) {
						$lines[] = '       ' . $code;
					}
				}
			}
			$lines[] = '';
		}
		// The antivirus server script, ready to paste.
		$block = Sysadmin_Tools::cgav_install_block();
		if ( '' !== $block ) {
			$lines[] = __( 'Antivirus server script (cgav): installs and checks ClamAV and Linux Malware Detect for this site.', 'qartvelo-guard' );
			$lines[] = __( 'Paste the whole block into an SSH session as root. Each section prints the status before and after. ClamAV and maldet are installed once per server and shared by every site on it; another site of the server only needs "cgav add-site" with its folder.', 'qartvelo-guard' );
			$lines[] = '';
			$lines[] = $block;
			$lines[] = '';
			foreach ( Sysadmin_Tools::cgav_commands() as $command => $what ) {
				$lines[] = '   ' . $command . ' - ' . $what;
			}
			$lines[] = '';
		}
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * admin-post: downloads the instructions as <host>-qartvelo-guard-developer-instructions.txt.
	 */
	public function handle_download() {
		if ( ! Sysadmin_Tools::user_can_manage() ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'qartvelo-guard' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'wpcybersec_dev_instructions' );
		$host = sanitize_title( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$host = $host ? $host : 'site';
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $host . '-qartvelo-guard-developer-instructions.txt"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo self::as_text( $this->items() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain text download.
		exit;
	}

	/**
	 * Address of the download.
	 *
	 * @return string Unescaped URL.
	 */
	public static function download_url() {
		return wp_nonce_url( add_query_arg( 'action', 'wpcybersec_dev_instructions', admin_url( 'admin-post.php' ) ), 'wpcybersec_dev_instructions' );
	}
}
