<?php
/**
 * One-click fixes for the environment checks, plus plain instructions when a
 * fix cannot run on this server.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Each environment check (Sysadmin_Tools::diagnostics()) that is not passing
 * gets two extra keys through the wpcybersec_diagnostics filter:
 *
 *   auto_fix     { id, label, description, link (optional) } or null
 *                One button for the signed-in administrator. "link" fixes open
 *                another admin screen instead of running here.
 *   manual_steps [ { text, code (optional) }, ... ]
 *                Numbered steps for doing it by hand (hosting panel or SSH),
 *                shown when the button is not available or fails.
 *
 * AJAX: wpcybersec_fix ( fix=<id> ) and wpcybersec_fix_all ( fixes[]=<id> ),
 * nonce Ajax::NONCE, administrators only.
 */
class Hardening {

	/**
	 * Fix ids that "Fix all" may run, in the order they run (links are never
	 * part of it). The data folder moves first, so a wp-config.php backup made
	 * by a later fix lands outside the web root. The guard and the cron switch
	 * are left out on purpose: they change how every request starts, so they
	 * need their own click.
	 */
	const AUTO = array( 'data_dir', 'wp_config_perms', 'world_writable', 'file_edit', 'uploads_php', 'hmac_key' );

	public function register() {
		add_filter( 'wpcybersec_diagnostics', array( $this, 'enrich' ), 20 );
		add_action( 'wp_ajax_wpcybersec_fix', array( $this, 'ajax_fix' ) );
		add_action( 'wp_ajax_wpcybersec_fix_all', array( $this, 'ajax_fix_all' ) );
		// Loopback check used right after installing the early guard.
		add_action( 'wp_ajax_wpcybersec_guard_ping', array( $this, 'ajax_guard_ping' ) );
		add_action( 'wp_ajax_nopriv_wpcybersec_guard_ping', array( $this, 'ajax_guard_ping' ) );
		// The same check through the front controller (only hooked for that request).
		if ( isset( $_GET['wpcybersec_guard_ping'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only decides whether to hook; the token is checked in front_guard_ping().
			add_action( 'init', array( $this, 'front_guard_ping' ), 0 );
		}
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ), 20 );
		add_action( 'admin_init', array( $this, 'admin_upkeep' ) );
	}

	/**
	 * On the plugin's own admin pages: finishes an interrupted data folder move
	 * and renames wp-config.php backups that still have guessable names.
	 */
	public function admin_upkeep() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only decides whether to look.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( 0 !== strpos( $page, 'wpcybersec' ) || wp_doing_ajax() || ! self::can() ) {
			return;
		}
		$storage = wpcybersec()->storage;
		if ( is_object( $storage ) && method_exists( $storage, 'resume_move' ) && Network::get_option( Storage::MOVE_OPTION ) ) {
			$storage->resume_move();
		}
		$this->move_legacy_data_dir();
		Config_Editor::secure_backups();
	}

	/**
	 * Before 1.1.0 the data folder defaulted to wp-content/wpcybersec. Moves it
	 * once to the current default inside uploads (tried at most once a day, on
	 * the plugin's own admin pages). Multisite networks and folders set with
	 * WPCYBERSEC_DATA_DIR are left alone.
	 */
	private function move_legacy_data_dir() {
		$storage = wpcybersec()->storage;
		if ( is_multisite() || ! is_object( $storage ) || ! method_exists( $storage, 'legacy_in_use' ) || ! $storage->legacy_in_use() ) {
			return;
		}
		if ( $storage->data_dir() !== $storage->legacy_dir() || Network::get_option( Storage::MOVE_OPTION ) ) {
			return;
		}
		$tried = (int) Network::get_option( Storage::LEGACY_MOVE_OPTION, 0 );
		if ( $tried > time() - DAY_IN_SECONDS ) {
			return;
		}
		if ( '' === $storage->default_dir() ) {
			return; // WordPress reports no uploads folder.
		}
		Network::update_option( Storage::LEGACY_MOVE_OPTION, time(), true );
		$moved = $this->move_data_dir( $storage->default_dir() );
		if ( is_wp_error( $moved ) && wpcybersec()->logger ) {
			// Tried again tomorrow; the activity log says why it did not happen today.
			wpcybersec()->logger->log(
				'data_dir_move',
				/* translators: 1: old folder, 2: error message */
				sprintf( __( 'The old data folder %1$s could not be moved yet: %2$s', 'qartvelo-guard' ), $storage->legacy_dir(), $moved->get_error_message() ),
				array( 'from' => $storage->legacy_dir(), 'to' => $storage->default_dir() )
			);
		}
	}

	/**
	 * Administrators only (network administrators on multisite).
	 *
	 * @return bool
	 */
	public static function can() {
		return is_multisite() ? current_user_can( 'manage_network_options' ) : current_user_can( 'manage_options' );
	}

	/**
	 * @param string $hook Admin page hook suffix.
	 */
	public function enqueue( $hook ) {
		if ( false === strpos( (string) $hook, 'wpcybersec' ) ) {
			return;
		}
		if ( ! wp_script_is( 'wpcybersec-core', 'registered' ) ) {
			Admin\Assets::register();
		}
		wp_enqueue_script( 'wpcybersec-fixes', WPCYBERSEC_URL . 'assets/js/fixes.js', array( 'wpcybersec-core' ), \WPCyberSecurity\Admin\Assets::ver( 'assets/js/fixes.js' ), true );
		wp_localize_script(
			'wpcybersec-fixes',
			'wpcybersecFixes',
			array(
				'working'  => __( 'Fixing...', 'qartvelo-guard' ),
				'fixed'    => __( 'Fixed', 'qartvelo-guard' ),
				'failed'   => __( 'Could not fix this automatically. The steps to do it by hand are shown below it.', 'qartvelo-guard' ),
				'allDone'  => __( 'All fixes applied. Refreshing the checks...', 'qartvelo-guard' ),
				'partDone' => __( 'The fixes that can run together were applied. Refreshing the checks...', 'qartvelo-guard' ),
				'nothing'  => __( 'Nothing here can be fixed together. Use the buttons of the single items.', 'qartvelo-guard' ),
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/* Diagnostics enrichment                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Adds auto_fix and manual_steps to failing checks.
	 *
	 * @param array[] $checks Checks.
	 * @return array[]
	 */
	public function enrich( $checks ) {
		foreach ( (array) $checks as $i => $check ) {
			$id                         = isset( $check['id'] ) ? (string) $check['id'] : '';
			$open                       = isset( $check['status'] ) && in_array( $check['status'], array( 'warn', 'fail' ), true );
			$checks[ $i ]['auto_fix']     = $open ? $this->descriptor( $id ) : null;
			$checks[ $i ]['manual_steps'] = $open ? $this->manual_steps( $id ) : array();
		}
		return $checks;
	}

	/**
	 * The button for a check, or null when this server cannot fix it in place.
	 *
	 * @param string $id Check id.
	 * @return array|null
	 */
	public function descriptor( $id ) {
		switch ( $id ) {
			case 'wp_version':
				return array(
					'id'          => 'wp_version',
					'label'       => __( 'Open WordPress updates', 'qartvelo-guard' ),
					'description' => __( 'Opens Dashboard > Updates where WordPress updates itself with one click.', 'qartvelo-guard' ),
					'link'        => Network::admin_url( 'update-core.php' ),
				);

			case 'wp_config_perms':
				$path = Config_Editor::path();
				if ( ! $path || '\\' === DIRECTORY_SEPARATOR || ! $this->owns( $path ) ) {
					return null;
				}
				return array(
					'id'          => 'wp_config_perms',
					'label'       => __( 'Fix permissions', 'qartvelo-guard' ),
					'description' => __( 'Makes wp-config.php readable only by its owner and group (640). The site keeps working; the change is undone automatically if WordPress could no longer read the file.', 'qartvelo-guard' ),
				);

			case 'world_writable':
				$own = count( $this->world_writable_owned() );
				if ( ! $own ) {
					return null; // Windows, no posix functions, or every path belongs to another user.
				}
				return array(
					'id'          => 'world_writable',
					'label'       => __( 'Remove write access for other users', 'qartvelo-guard' ),
					'description' => sprintf(
						/* translators: %s: number of folders and files */
						_n(
							'Removes only the write permission for other users (chmod o-w) from the %s folder or file PHP owns. The owner and the web server keep their access, symlinks are never followed, and the folders are checked again afterwards.',
							'Removes only the write permission for other users (chmod o-w) from the %s folders and files PHP owns. The owner and the web server keep their access, symlinks are never followed, and the folders are checked again afterwards.',
							$own,
							'qartvelo-guard'
						),
						number_format_i18n( $own )
					),
				);

			case 'file_edit':
				if ( defined( 'DISALLOW_FILE_EDIT' ) && ! DISALLOW_FILE_EDIT && ! Config_Editor::can_edit() ) {
					return null; // Explicitly enabled in a read-only wp-config.php.
				}
				return array(
					'id'          => 'file_edit',
					'label'       => __( 'Turn off the code editor', 'qartvelo-guard' ),
					'description' => __( 'Removes Appearance > Theme File Editor and Plugins > Plugin File Editor. You can switch it back on under Settings > Advanced > Freeze lock > Code editor.', 'qartvelo-guard' ),
				);

			case 'data_dir':
			case 'quarantine_web':
				// On multisite the folder is shared by every site of the network: by hand only.
				if ( ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) || is_multisite() ) {
					return null;
				}
				$storage = wpcybersec()->storage;
				$target  = $storage->suggested_outside_dir();
				$parent  = dirname( $target );
				if ( ! Storage::path_allowed( $target ) || ! Storage::path_allowed( $parent ) ) {
					return null; // open_basedir hides it: see the manual steps.
				}
				if ( ! ( is_dir( $target ) ? Fs::is_writable( $target ) : Fs::is_writable( $parent ) ) || $storage->is_in_webroot( $target ) || Storage::looks_served( $parent ) || ! $storage->dir_usable( $target ) ) {
					return null;
				}
				return array(
					'id'          => 'data_dir',
					'label'       => __( 'Move it outside the web root', 'qartvelo-guard' ),
					/* translators: %s: folder path */
					'description' => sprintf( __( 'Moves held files and scan data to %s, outside every website folder. Held items keep working.', 'qartvelo-guard' ), $target ),
				);

			case 'hmac_key':
				if ( defined( 'WPCYBERSEC_HMAC_KEY' ) || ! Config_Editor::can_edit() ) {
					return null;
				}
				return array(
					'id'          => 'hmac_key',
					'label'       => __( 'Add the key for me', 'qartvelo-guard' ),
					'description' => __( 'Writes a new random key into wp-config.php. The file is checked for errors first; a backup is kept in the plugin\'s data folder when that folder cannot be downloaded from the web.', 'qartvelo-guard' ),
				);

			case 'guard':
				$method = $this->guard_method();
				$gm     = wpcybersec()->guard_manager;
				if ( '' === $method || ! is_object( $gm ) || ! method_exists( $gm, 'install' ) ) {
					return null;
				}
				return array(
					'id'          => 'guard',
					'label'       => __( 'Install and switch on the early guard', 'qartvelo-guard' ),
					'description' => ( 'htaccess' === $method
						? __( 'Installs the guard files, adds the guard to the .htaccess file in the WordPress folder (PHP runs as an Apache or LiteSpeed module here), then makes a live test request. Everything is undone automatically if the site stops answering.', 'qartvelo-guard' )
						: __( 'Installs the guard files, adds the guard to a .user.ini file in the WordPress folder (this server runs PHP through PHP-FPM, CGI or OpenLiteSpeed), then makes a live test request. Everything is undone automatically if the site stops answering.', 'qartvelo-guard' ) )
						. ( method_exists( $gm, 'front_root' ) && '' !== $gm->front_root() ? ' ' . __( 'The site\'s front controller (index.php) is in another folder, so that folder gets the same line.', 'qartvelo-guard' ) : '' ),
				);

			case 'guard_files':
				$gm = wpcybersec()->guard_manager;
				if ( ! is_object( $gm ) || ! method_exists( $gm, 'install' ) || $gm->is_installed() ) {
					return null;
				}
				return array(
					'id'          => 'guard_files',
					'label'       => __( 'Install the guard files', 'qartvelo-guard' ),
					'description' => __( 'Writes the guard bootstrap next to wp-config.php and its configuration into the data folder. It does nothing until PHP loads it through auto_prepend_file (the steps below).', 'qartvelo-guard' ),
				);

			case 'disable_wp_cron':
				$last = (int) Network::get_option( 'wpcybersec_cli_cron_at', 0 );
				if ( ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) || $last < time() - 2 * HOUR_IN_SECONDS || ! Config_Editor::can_edit() ) {
					return null;
				}
				return array(
					'id'          => 'disable_wp_cron',
					'label'       => __( 'Switch off visitor-triggered cron', 'qartvelo-guard' ),
					/* translators: %s: time ago */
					'description' => sprintf( __( 'Your real cron job last ran %s ago, so page visits no longer need to trigger background work. Adds DISABLE_WP_CRON to wp-config.php.', 'qartvelo-guard' ), human_time_diff( $last ) ),
				);

			case 'uploads_php':
				if ( in_array( $this->server_type(), array( 'nginx', 'iis' ), true ) ) {
					return null; // Neither reads .htaccess: the by-hand steps apply.
				}
				return array(
					'id'          => 'uploads_php',
					'label'       => __( 'Block PHP in uploads', 'qartvelo-guard' ),
					'description' => __( 'Adds a rule to wp-content/uploads/.htaccess so a PHP file placed in uploads can never run. It is tested right away and removed again if the server rejects it.', 'qartvelo-guard' ),
				);
		}
		return null;
	}

	/**
	 * Plain numbered steps for doing a fix by hand.
	 *
	 * @param string $id Check id.
	 * @return array[] { text, code }
	 */
	public function manual_steps( $id ) {
		$config = Config_Editor::path();
		$above  = __( 'Paste it on a new line just above the line that says "That\'s all, stop editing!" and save.', 'qartvelo-guard' );
		$panel  = __( 'In your hosting control panel open File Manager (or connect with SFTP) and go to the WordPress folder.', 'qartvelo-guard' );

		switch ( $id ) {
			case 'wp_version':
				return array(
					array( 'text' => __( 'Go to Dashboard > Updates.', 'qartvelo-guard' ) ),
					array( 'text' => __( 'Click "Update to version ..." and wait until WordPress says it is done.', 'qartvelo-guard' ) ),
				);

			case 'wp_config_perms':
				return array(
					array( 'text' => $panel ),
					array( 'text' => __( 'Right-click wp-config.php and choose "Permissions" (or "Change permissions").', 'qartvelo-guard' ) ),
					array( 'text' => __( 'Enter 640 (or 600 if your host recommends it) and save. Then reload this page.', 'qartvelo-guard' ) ),
					array(
						'text' => __( 'With SSH instead, run:', 'qartvelo-guard' ),
						'code' => 'chmod 640 ' . Sysadmin_Tools::shell_arg( $config ? $config : 'wp-config.php' ),
					),
				);

			case 'world_writable':
				$scan = Sysadmin_Tools::world_writable_scan();
				if ( ! $scan || ! $scan['roots'] ) {
					return array();
				}
				$owned  = $this->world_writable_owned( $scan );
				$others = array_values( array_diff( $scan['paths'], $owned ) );
				$steps  = array();
				if ( $others ) {
					$steps[] = array(
						'text' => sprintf(
							/* translators: %s: paths */
							__( 'PHP does not own these, so it may not change them: %s. Someone with SSH access (the owner of the files, or root) has to.', 'qartvelo-guard' ),
							implode( ', ', array_map( array( '\WPCyberSecurity\Sysadmin_Tools', 'display_path' ), array_slice( $others, 0, 10 ) ) ) . ( count( $others ) > 10 ? ', ...' : '' )
						),
					);
				}
				$steps[] = array(
					'text' => __( 'With SSH, as the owner of the files or as root, run this. It removes only the write permission for other users, below each folder too, and skips symlinks:', 'qartvelo-guard' ),
					'code' => Sysadmin_Tools::world_writable_command( $scan['roots'] ),
				);
				$steps[] = array( 'text' => __( 'If PHP runs as a user that neither owns these files nor is in their group, it writes through exactly this permission: give the files to that user first (chown), or plugin updates and uploads stop working. Then reload this page.', 'qartvelo-guard' ) );
				return $this->for_panel( 'permissions', $steps );

			case 'file_edit':
				return array(
					array( 'text' => $panel ),
					array( 'text' => __( 'Open wp-config.php in the editor.', 'qartvelo-guard' ) ),
					array(
						'text' => __( 'If it contains define( \'DISALLOW_FILE_EDIT\', false ); change false to true. Otherwise add this line:', 'qartvelo-guard' ),
						'code' => "define( 'DISALLOW_FILE_EDIT', true );",
					),
					array( 'text' => $above ),
				);

			case 'data_dir':
			case 'quarantine_web':
				return $this->for_panel( 'data_dir', $this->data_dir_steps( $above ) );

			case 'uploads_php':
				if ( 'iis' === $this->server_type() ) {
					return $this->for_panel(
						'web_rules',
						array(
							array( 'text' => __( 'IIS ignores .htaccess files. Save this as web.config inside wp-content/uploads (or merge the rules into the one that is there), then run the live test again:', 'qartvelo-guard' ), 'code' => Sysadmin_Tools::iis_uploads_rule() ),
						)
					);
				}
				if ( 'nginx' === $this->server_type() ) {
					return $this->for_panel(
						'web_rules',
						array(
							array( 'text' => __( 'nginx ignores .htaccess files, so ask your host (or your system administrator) to add this rule to the site\'s server block and reload nginx:', 'qartvelo-guard' ), 'code' => Sysadmin_Tools::nginx_uploads_rule() ),
						)
					);
				}
				return $this->for_panel(
					'web_rules',
					array(
						array( 'text' => $panel ),
						array( 'text' => __( 'Open the folder wp-content/uploads and create (or edit) a file named .htaccess. Turn on "Show hidden files" if you do not see it.', 'qartvelo-guard' ) ),
						array( 'text' => __( 'Add these lines and save:', 'qartvelo-guard' ), 'code' => ( new Sysadmin_Tools() )->apache_uploads_rules() ),
					)
				);

			case 'hmac_key':
				return array(
					array( 'text' => $panel ),
					array( 'text' => __( 'Open wp-config.php and add this line (the key below was generated for you just now):', 'qartvelo-guard' ), 'code' => "define( 'WPCYBERSEC_HMAC_KEY', '" . wp_generate_password( 64, false, false ) . "' );" ),
					array( 'text' => $above ),
				);

			case 'guard':
				$boot  = wp_normalize_path( ABSPATH . 'wpcybersec-guard.php' );
				$gm    = wpcybersec()->guard_manager;
				$front = is_object( $gm ) && method_exists( $gm, 'front_root' ) ? $gm->front_root() : '';
				$extra = array();
				if ( '' !== $front ) {
					/* translators: %s: folder path */
					$extra[] = array( 'text' => sprintf( __( 'The site\'s front controller (index.php) is in %s, not in the WordPress folder. Put the same .user.ini or .htaccess line in that folder too, or pages and REST requests run without the guard.', 'qartvelo-guard' ), $front ) );
				}
				if ( 'litespeed' === PHP_SAPI || 'openlitespeed' === Guard_Manager::litespeed_edition() ) {
					$extra[] = array(
						'text' => __( 'On OpenLiteSpeed (CyberPanel) .htaccess php_value lines are ignored. In WebAdmin open Virtual Hosts > this site > General > php.ini Override, add this line, then restart OpenLiteSpeed (and run killall lsphp when PHP runs in detached mode):', 'qartvelo-guard' ),
						'code' => 'php_value auto_prepend_file ' . $boot,
					);
				}
				$first = array();
				if ( ! is_object( $gm ) || ! method_exists( $gm, 'is_installed' ) || ! $gm->is_installed() ) {
					$first[] = array( 'text' => __( 'Install the guard files first (the "Install the guard files" button, also in Settings > Advanced > Early guard).', 'qartvelo-guard' ) );
				}
				return array_merge(
					$first,
					$this->for_panel(
						'prepend',
						array_merge(
							array(
								array( 'text' => __( 'If PHP runs through PHP-FPM or CGI, create a file named .user.ini in the WordPress folder with:', 'qartvelo-guard' ), 'code' => "auto_prepend_file = '" . $boot . "'" ),
								array( 'text' => __( 'If PHP runs as an Apache module, add to the .htaccess file in the WordPress folder:', 'qartvelo-guard' ), 'code' => "<IfModule php_module>\n    php_value auto_prepend_file \"" . $boot . "\"\n</IfModule>" ),
								array( 'text' => __( 'On nginx with PHP-FPM, ask your host to add this to the PHP location block and reload nginx:', 'qartvelo-guard' ), 'code' => 'fastcgi_param PHP_VALUE "auto_prepend_file=' . $boot . '";' ),
							),
							$extra
						)
					)
				);

			case 'disable_wp_cron':
				$off = Sysadmin_Tools::cron_disable_step();
				return array(
					array( 'text' => __( 'Only do this after the real cron jobs run WordPress cron (see "Real cron job").', 'qartvelo-guard' ) ),
					array( 'text' => __( 'Open wp-config.php and add this line:', 'qartvelo-guard' ), 'code' => $off['code'] ),
					array( 'text' => $above ),
				);

			case 'wp_cron':
				// The same three jobs as the crontab block (Sysadmin_Tools::cron_jobs()), one panel entry each.
				$steps = array(
					array( 'text' => __( 'In your hosting control panel open "Cron Jobs" (cPanel, Plesk "Scheduled Tasks", or your host\'s equivalent) and add these three jobs.', 'qartvelo-guard' ) ),
				);
				foreach ( Sysadmin_Tools::cron_jobs() as $job ) {
					$steps[] = array(
						/* translators: 1: what the job does and when, 2: cron schedule */
						'text' => sprintf( __( '%1$s. Schedule: %2$s. Command:', 'qartvelo-guard' ), $job['when'], $job['schedule'] ),
						'code' => $job['command'],
					);
				}
				$steps[] = Sysadmin_Tools::cron_disable_step();
				return $this->for_panel( 'cron', $steps );
		}
		return array();
	}

	/**
	 * The hosting panel's own steps first, these folded under "Other ways"
	 * (Hosting::merge()); just these when the panel has none.
	 *
	 * @param string  $task    Hosting task.
	 * @param array[] $generic Generic steps.
	 * @return array[]
	 */
	private function for_panel( $task, array $generic ) {
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
	 * By-hand steps for moving the data folder.
	 *
	 * @param string $above Where to paste a wp-config.php line.
	 * @return array[]
	 */
	private function data_dir_steps( $above ) {
		$storage = wpcybersec()->storage;
		$current = $storage->data_dir();
		$target  = $storage->suggested_outside_dir();
		$steps   = array();
		if ( is_multisite() ) {
			$steps[] = array( 'text' => __( 'All sites of this multisite network share one data folder, so it is moved for the whole network with one line in wp-config.php. The one-click move is not available on a network; the review below is done once, in Network Admin.', 'qartvelo-guard' ) );
		} elseif ( $this->descriptor( 'data_dir' ) ) {
			$steps[] = array( 'text' => __( 'Easiest: use the button above. It copies everything, checks the copy, keeps the items held so far working and only then removes the old folder.', 'qartvelo-guard' ) );
		}
		/* translators: %s: folder path */
		$steps[] = array( 'text' => sprintf( __( 'By hand, first open the Reports page and approve or delete everything that is held. The copies of items still held when you switch stay in the old folder (%s), and those items can then no longer be approved or restored.', 'qartvelo-guard' ), $current ) );
		/* translators: %s: folder path */
		$steps[] = array( 'text' => sprintf( __( 'Create a folder outside the public website folder, for example %s, and make it writable for the web server (permissions 750 or 770).', 'qartvelo-guard' ), $target ) );
		if ( ! Storage::path_allowed( $target ) ) {
			$steps[] = array(
				/* translators: 1: folder path, 2: open_basedir value */
				'text' => sprintf( __( 'PHP on this site is limited to these folders (open_basedir): %2$s. Add %1$s to open_basedir in the PHP settings of the site (hosting panel or PHP-FPM pool), or create the folder inside one of the allowed folders that the web server does not serve.', 'qartvelo-guard' ), $target, (string) ini_get( 'open_basedir' ) ),
			);
		}
		$steps[] = array(
			'text' => __( 'Open wp-config.php and add this line:', 'qartvelo-guard' ),
			'code' => "define( 'WPCYBERSEC_DATA_DIR', '" . addcslashes( $target, "\\'" ) . "' );",
		);
		$steps[] = array( 'text' => $above );
		/* translators: %s: folder path */
		$steps[] = array( 'text' => sprintf( __( 'Reload this page. The plugin creates its folders in the new place, and an installed early guard switches over on the next admin page load. Then delete the old folder %s; it also holds backups of wp-config.php.', 'qartvelo-guard' ), $current ) );
		return $steps;
	}

	/* ------------------------------------------------------------------ */
	/* Running fixes                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Runs one fix.
	 *
	 * @param string $id Fix id.
	 * @return true|\WP_Error
	 */
	public function run( $id ) {
		switch ( $id ) {
			case 'wp_config_perms':
				$result = $this->fix_wp_config_perms();
				break;
			case 'world_writable':
				$result = $this->fix_world_writable();
				break;
			case 'file_edit':
				$result = $this->fix_file_edit();
				break;
			case 'data_dir':
			case 'quarantine_web':
				$result = $this->fix_data_dir();
				break;
			case 'uploads_php':
				$result = $this->fix_uploads_php();
				break;
			case 'hmac_key':
				$result = $this->fix_hmac_key();
				break;
			case 'guard':
				$result = $this->fix_guard();
				break;
			case 'guard_files':
				$gm     = wpcybersec()->guard_manager;
				$result = is_object( $gm ) && method_exists( $gm, 'install' )
					? $gm->install()
					: new \WP_Error( 'wpcybersec_fix', __( 'The early guard module is not available in this installation.', 'qartvelo-guard' ) );
				if ( true === $result ) {
					$result = __( 'The guard files are installed. Now point auto_prepend_file at the bootstrap with one of the steps below.', 'qartvelo-guard' );
				}
				break;
			case 'disable_wp_cron':
				$result = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ? true : Config_Editor::set_constant( 'DISABLE_WP_CRON', true );
				break;
			default:
				return new \WP_Error( 'wpcybersec_fix', __( 'There is no automatic fix for this item.', 'qartvelo-guard' ) );
		}
		if ( is_wp_error( $result ) ) {
			// Remembered for Settings > Advanced > Developer instructions.
			Developer_Instructions::record_failure( $id, $result->get_error_message() );
		} else {
			Developer_Instructions::clear_failure( $id );
			if ( ! in_array( $id, array( 'guard', 'guard_files' ), true ) ) {
				// The guard logs its own entry (one per install).
				/* translators: %s: fix id */
				wpcybersec()->logger->log( 'hardening_fixed', sprintf( __( 'Applied the one-click fix "%s".', 'qartvelo-guard' ), $id ), array( 'fix' => $id ) );
			}
			Network::delete_transient( Sysadmin_Tools::PROBE_TRANSIENT );
		}
		return $result;
	}

	/**
	 * @return true|\WP_Error
	 */
	private function fix_wp_config_perms() {
		$path = Config_Editor::path();
		if ( ! $path ) {
			return new \WP_Error( 'wpcybersec_fix', __( 'wp-config.php was not found.', 'qartvelo-guard' ) );
		}
		clearstatcache( true, $path );
		$before = fileperms( $path ) & 0777;
		if ( 0 === ( $before & 0007 ) ) {
			return true;
		}
		if ( ! Fs::chmod( $path, 0640 ) ) {
			return new \WP_Error( 'wpcybersec_fix', __( 'The server did not allow the change: WordPress does not own wp-config.php.', 'qartvelo-guard' ) );
		}
		clearstatcache( true, $path );
		if ( ! is_readable( $path ) ) {
			Fs::chmod( $path, $before );
			return new \WP_Error( 'wpcybersec_fix', __( 'WordPress could not read wp-config.php after the change, so it was undone.', 'qartvelo-guard' ) );
		}
		return true;
	}

	/**
	 * The paths of world_writable_scan() that PHP owns (only the owner may chmod).
	 * Strict: without the posix functions nothing counts as owned.
	 *
	 * @param array|null $scan Sysadmin_Tools::world_writable_scan() (run when null).
	 * @return string[]
	 */
	private function world_writable_owned( $scan = null ) {
		if ( ! function_exists( 'posix_geteuid' ) ) {
			return array();
		}
		$scan = is_array( $scan ) ? $scan : Sysadmin_Tools::world_writable_scan();
		if ( ! $scan ) {
			return array();
		}
		$uid = posix_geteuid();
		$out = array();
		foreach ( $scan['paths'] as $path ) {
			$stat = @lstat( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( is_array( $stat ) && 0120000 !== ( $stat['mode'] & 0170000 ) && (int) $stat['uid'] === $uid ) {
				$out[] = $path;
			}
		}
		return $out;
	}

	/**
	 * Removes the write bit for other users (o-w) from the code folders and
	 * files of the world-writable check that PHP owns. Nothing else of the mode
	 * changes, symlinks are never touched, then the check runs again.
	 *
	 * @return string|\WP_Error String = done, with what changed.
	 */
	private function fix_world_writable() {
		$scan = Sysadmin_Tools::world_writable_scan();
		if ( null === $scan ) {
			return new \WP_Error( 'wpcybersec_fix', __( 'File permissions cannot be changed on Windows servers.', 'qartvelo-guard' ) );
		}
		$fixed  = 0;
		$failed = array();
		foreach ( $this->world_writable_owned( $scan ) as $path ) {
			clearstatcache( true, $path );
			$stat = @lstat( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! is_array( $stat ) || 0120000 === ( $stat['mode'] & 0170000 ) ) {
				continue; // Became a symlink meanwhile: never followed.
			}
			$mode = (int) $stat['mode'] & 07777;
			$new  = $mode & ~0002;
			if ( $new === $mode ) {
				continue;
			}
			if ( $new > 0 && Fs::chmod( $path, $new ) ) {
				++$fixed;
			} else {
				$failed[] = $path;
			}
		}
		clearstatcache();
		$after = Sysadmin_Tools::world_writable_scan();
		$left  = $after ? count( $after['paths'] ) : 0;
		if ( $left > 0 && 0 === $fixed ) {
			return new \WP_Error(
				'wpcybersec_fix',
				/* translators: %s: number of folders and files */
				sprintf( __( 'Nothing was changed: PHP does not own the %s folders and files that other users can write, so it may not change them. The steps below do it with SSH or the hosting panel.', 'qartvelo-guard' ), number_format_i18n( $left ) )
			);
		}
		if ( $left > 0 ) {
			return new \WP_Error(
				'wpcybersec_fix',
				sprintf(
					/* translators: 1: number of folders and files fixed, 2: number left */
					_n(
						'Removed write access for other users from %1$s folders and files. %2$s folder or file still has it: PHP does not own it, so it may not change it. The steps below do it with SSH or the hosting panel.',
						'Removed write access for other users from %1$s folders and files. %2$s folders and files still have it: PHP does not own them, so it may not change them. The steps below do it with SSH or the hosting panel.',
						$left,
						'qartvelo-guard'
					),
					number_format_i18n( $fixed ),
					number_format_i18n( $left )
				)
			);
		}
		return sprintf(
			/* translators: %s: number of folders and files */
			_n( 'Removed write access for other users from %s folder or file. Checked again: no code folder is writable by every user now.', 'Removed write access for other users from %s folders and files. Checked again: no code folder is writable by every user now.', max( 1, $fixed ), 'qartvelo-guard' ),
			number_format_i18n( $fixed )
		);
	}

	/**
	 * @return true|\WP_Error
	 */
	private function fix_file_edit() {
		if ( defined( 'DISALLOW_FILE_EDIT' ) ) {
			if ( DISALLOW_FILE_EDIT ) {
				return true;
			}
			// Explicitly set to false in wp-config.php: flip that line.
			return Config_Editor::set_constant( 'DISALLOW_FILE_EDIT', true );
		}
		wpcybersec()->settings->update( array( 'disable_file_editor' => true ) );
		return true;
	}

	/**
	 * Moves the data folder outside the web root (Storage::relocate()), with the
	 * guard following it to the new folder.
	 *
	 * @return string|\WP_Error String = success with a note for the admin.
	 */
	private function fix_data_dir() {
		return $this->move_data_dir( wpcybersec()->storage->suggested_outside_dir(), true );
	}

	/**
	 * Moves the data folder to $target (Storage::relocate()), with the guard
	 * following it. Also used to bring the data back from the fallback folder
	 * inside uploads once the configured folder is writable again.
	 *
	 * @param string $target       Absolute folder.
	 * @param bool   $outside_only Refuse a folder the web server serves.
	 * @return string|\WP_Error String = success with a note for the admin.
	 */
	public function move_data_dir( $target, $outside_only = false ) {
		$plugin  = wpcybersec();
		$storage = $plugin->storage;
		$target  = untrailingslashit( wp_normalize_path( (string) $target ) );
		if ( is_multisite() ) {
			return new \WP_Error( 'wpcybersec_fix', __( 'On a multisite network the data folder is shared by all sites. Follow the steps below to move it for the whole network.', 'qartvelo-guard' ) );
		}
		$job = is_object( $plugin->scan_job ) && method_exists( $plugin->scan_job, 'status' ) ? $plugin->scan_job->status() : array();
		if ( isset( $job['state'] ) && in_array( $job['state'], array( 'enumerating', 'processing', 'finishing' ), true ) ) {
			return new \WP_Error( 'wpcybersec_fix', __( 'A scan is running. Try again when it has finished.', 'qartvelo-guard' ) );
		}
		if ( ! Storage::path_allowed( $target ) ) {
			return new \WP_Error(
				'wpcybersec_fix',
				/* translators: 1: folder path, 2: open_basedir value */
				sprintf( __( 'PHP may not use %1$s on this server (open_basedir allows only %2$s), so nothing was moved. Add the folder to open_basedir in the PHP settings of this site, or choose a folder inside the allowed ones that the web server does not serve.', 'qartvelo-guard' ), $target, (string) ini_get( 'open_basedir' ) )
			);
		}
		if ( $outside_only && $storage->is_in_webroot( $target ) ) {
			return new \WP_Error( 'wpcybersec_fix', __( 'The folder next to WordPress is still served by the web server here, so the move would not help.', 'qartvelo-guard' ) );
		}
		if ( ! $storage->dir_usable( $target ) ) {
			/* translators: %s: folder path */
			return new \WP_Error( 'wpcybersec_fix', sprintf( __( '%s already exists and holds files that do not belong to this site, so nothing was moved.', 'qartvelo-guard' ), $target ) );
		}

		// The guard bootstrap has the config path built in: it must be rewritable,
		// or the guard would lose its config when the old folder is removed.
		$gm       = $plugin->guard_manager;
		$guard_on = is_object( $gm ) && method_exists( $gm, 'is_installed' ) && $gm->is_installed();
		if ( $guard_on ) {
			$bootstrap = $gm->bootstrap_path();
			if ( ! Fs::is_writable( dirname( $bootstrap ) ) ) {
				return new \WP_Error(
					'wpcybersec_fix',
					/* translators: %s: file path */
					sprintf( __( 'The early guard file %s has the data folder path written into it, and WordPress cannot rewrite it because the WordPress folder is read-only. Nothing was moved. Make the folder writable for a moment, or switch the guard off first, then try again.', 'qartvelo-guard' ), $bootstrap )
				);
			}
			// Import what the guard already holds, so little is left to carry over.
			Storage::keep_running();
			$gm->import_spool();
		}

		$after = static function ( $source, $new_dir ) use ( $plugin, $gm, $guard_on ) {
			// The allowlist mirror and the guard config live in the data folder: rewrite them there.
			if ( is_object( $plugin->allowlist ) ) {
				$plugin->allowlist->export_guard_file();
			}
			if ( $guard_on ) {
				$installed = $gm->install();
				if ( is_wp_error( $installed ) ) {
					return new \WP_Error(
						'wpcybersec_fix',
						sprintf(
							/* translators: 1: folder path, 2: error message, 3: folder path */
							__( 'The data folder was moved to %1$s, but the early guard could not be switched to it: %2$s The old folder %3$s is kept so the guard keeps working; it is removed once the guard file is updated (Settings > Advanced > Early guard shows its content).', 'qartvelo-guard' ),
							$new_dir,
							$installed->get_error_message(),
							$source
						)
					);
				}
			} elseif ( is_object( $gm ) && method_exists( $gm, 'sync_config' ) && is_file( Guard_Config::file() ) ) {
				$gm->sync_config(); // Switched off, but keep its paths current.
			}
			return true;
		};

		$moved = $storage->relocate( $target, $after );
		if ( is_wp_error( $moved ) ) {
			if ( $storage->data_dir() === $target ) {
				Network::delete_transient( Sysadmin_Tools::PROBE_TRANSIENT ); // Switched over despite the error.
			}
			return $moved;
		}
		if ( $storage->move_pending() ) {
			/* translators: %s: folder path */
			return sprintf( __( 'Moved to %s. A few files that arrived during the move are still in the old folder; they are moved over the next time you open the plugin.', 'qartvelo-guard' ), $target );
		}
		/* translators: %s: folder path */
		return sprintf( __( 'Moved to %s. Held items keep working.', 'qartvelo-guard' ), $target );
	}

	/**
	 * @return true|\WP_Error
	 */
	private function fix_hmac_key() {
		if ( defined( 'WPCYBERSEC_HMAC_KEY' ) ) {
			return true;
		}
		$result = Config_Editor::set_constant( 'WPCYBERSEC_HMAC_KEY', wp_generate_password( 64, false, false ) );
		if ( true === $result ) {
			// The next request seeds the checksum with the new key.
			Network::delete_option( Allowlist::CHECKSUM_OPTION );
		}
		return $result;
	}

	/**
	 * How the guard can be wired in on this server: htaccess (mod_php,
	 * LiteSpeed Enterprise), user_ini (PHP-FPM / CGI, OpenLiteSpeed) or ''
	 * (needs the server config).
	 *
	 * @return string
	 */
	public function guard_method() {
		$methods = $this->guard_methods();
		return $methods ? $methods[0] : '';
	}

	/**
	 * Every way to wire the guard in that fits this server, in the order the
	 * one-click install tries them. LiteSpeed of unknown edition gets both:
	 * Enterprise reads php_value in .htaccess, OpenLiteSpeed does not (it
	 * reads .user.ini when lsphp is set up for it).
	 *
	 * @return string[]
	 */
	public function guard_methods() {
		$sapi    = PHP_SAPI;
		$ini_on  = '' !== (string) ini_get( 'user_ini.filename' );
		$methods = array();
		if ( 'apache2handler' === $sapi ) {
			$methods[] = 'htaccess';
		} elseif ( 'litespeed' === $sapi ) {
			$edition = Guard_Manager::litespeed_edition();
			if ( 'openlitespeed' !== $edition ) {
				$methods[] = 'htaccess';
			}
			if ( 'enterprise' !== $edition && $ini_on ) {
				$methods[] = 'user_ini';
			}
		} elseif ( in_array( $sapi, array( 'fpm-fcgi', 'cgi-fcgi', 'cgi' ), true ) && $ini_on ) {
			$methods[] = 'user_ini';
		}
		return array_values( array_filter( $methods, array( $this, 'can_wire' ) ) );
	}

	/**
	 * Whether the file of a method can be written in every folder that needs it
	 * (the WordPress folder and the front controller folder).
	 *
	 * @param string $method htaccess | user_ini.
	 * @return bool
	 */
	private function can_wire( $method ) {
		$gm = wpcybersec()->guard_manager;
		if ( ! is_object( $gm ) ) {
			return false;
		}
		$name = 'htaccess' === $method ? '.htaccess' : (string) ini_get( 'user_ini.filename' );
		$dirs = method_exists( $gm, 'wiring_dirs' ) ? $gm->wiring_dirs() : array( ABSPATH );
		foreach ( $dirs as $dir ) {
			if ( ! Fs::is_writable( $dir ) && ! Fs::is_writable( $dir . $name ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Installs the early guard end to end, then makes real requests to the site
	 * (wp-admin and the front controller) to confirm it still answers. Any
	 * failure undoes every step. On LiteSpeed of unknown edition a .htaccess
	 * line PHP ignores is replaced by .user.ini.
	 *
	 * @return true|string|\WP_Error String = success with a note for the admin.
	 */
	private function fix_guard() {
		$gm      = wpcybersec()->guard_manager;
		$methods = $this->guard_methods();
		if ( ! $methods || ! is_object( $gm ) ) {
			return new \WP_Error( 'wpcybersec_fix', __( 'This server needs the PHP setting changed in its own configuration. Follow the steps below.', 'qartvelo-guard' ) );
		}
		// One activity log entry for the whole install instead of one per file.
		$gm->set_quiet( true );
		try {
			$result = $this->wire_guard( $gm, $methods );
		} finally {
			$gm->set_quiet( false );
		}
		$how = $this->wired_with;
		if ( is_wp_error( $result ) ) {
			wpcybersec()->logger->log(
				'guard_enable_failed',
				/* translators: %s: error message */
				sprintf( __( 'Could not switch on the early upload guard: %s', 'qartvelo-guard' ), $result->get_error_message() )
			);
		} else {
			$files = array();
			foreach ( $gm->wiring_dirs() as $dir ) {
				$files[] = wp_normalize_path( $dir . ( 'htaccess' === $how ? '.htaccess' : (string) ini_get( 'user_ini.filename' ) ) );
			}
			$check = $this->last_check;
			if ( 'active' === $check ) {
				$shown = __( 'A live test confirmed that PHP loads it.', 'qartvelo-guard' );
			} elseif ( 'user_ini' === $how && 'inactive' === $check && Guard_Manager::ols_activation_step() ) {
				$shown = __( 'Not loaded yet: OpenLiteSpeed reads .user.ini only after lsphp restarts.', 'qartvelo-guard' );
			} elseif ( 'user_ini' === $how && 'inactive' === $check ) {
				$shown = __( 'PHP reads .user.ini again within a few minutes; the Dashboard shows when the guard runs.', 'qartvelo-guard' );
			} else {
				$shown = __( 'The live test got no answer, so it is not confirmed yet.', 'qartvelo-guard' );
			}
			wpcybersec()->logger->log(
				'guard_installed',
				sprintf(
					/* translators: 1: file list, 2: what the live test showed */
					__( 'Early upload guard installed and switched on in %1$s. %2$s', 'qartvelo-guard' ),
					implode( ', ', $files ),
					$shown
				)
			);
		}
		return $result;
	}

	/** @var string Method fix_guard() wired the guard in with (htaccess | user_ini). */
	private $wired_with = '';

	/** @var string Last live test result of wire_guard(). */
	private $last_check = '';

	/**
	 * Writes the guard files and the auto_prepend_file line, tests, rolls back.
	 *
	 * @param Guard_Manager $gm      Guard manager.
	 * @param string[]      $methods guard_methods().
	 * @return true|string|\WP_Error
	 */
	private function wire_guard( $gm, array $methods ) {
		$installed = $gm->install();
		if ( is_wp_error( $installed ) ) {
			return $installed;
		}
		$minutes = max( 1, (int) ceil( max( 0, (int) ini_get( 'user_ini.cache_ttl' ) ) / 60 ) );
		// OpenLiteSpeed: .user.ini needs an lsphp restart, so say exactly what to run instead of "within N minutes".
		$ols_step = Guard_Manager::ols_activation_step();
		$ols      = $ols_step ? ' ' . $ols_step['inline'] : '';
		$count   = count( $methods );
		foreach ( $methods as $i => $method ) {
			$more             = $i < $count - 1;
			$this->wired_with = $method;
			$wired            = 'htaccess' === $method ? $gm->write_htaccess() : $gm->write_user_ini();
			if ( is_wp_error( $wired ) ) {
				if ( $more ) {
					continue;
				}
				$gm->uninstall();
				return $wired;
			}

			$check = $this->ping_guard();
			$ttl   = (int) ini_get( 'user_ini.cache_ttl' );
			if ( 'inactive' === $check && 'user_ini' === $method && $ttl > 0 && $ttl <= 15 ) {
				// PHP rereads .user.ini within seconds here: test once more after that.
				sleep( $ttl + 1 );
				$check = $this->ping_guard();
			}
			$this->last_check = $check;
			if ( 'down' === $check ) {
				$this->roll_back_guard( $gm, $method );
				return new \WP_Error( 'wpcybersec_fix', __( 'The site stopped answering after the change, so it was undone. Follow the steps below or ask your host.', 'qartvelo-guard' ) );
			}
			if ( 'active' === $check ) {
				return __( 'The early guard is installed and active.', 'qartvelo-guard' );
			}
			if ( 'unknown' === $check ) {
				// A timeout, a blocked loopback, an HTTP password or a firewall page: nothing is known about the change, so keep it.
				$parts = array( __( 'Installed, but it could not be verified from here because the site did not answer its own test request (a firewall, an HTTP password or a slow server can cause this).', 'qartvelo-guard' ) );
				if ( 'user_ini' === $method && $ols_step ) {
					$parts[] = $ols_step['inline'];
				} elseif ( 'user_ini' === $method ) {
					/* translators: %d: minutes */
					$parts[] = sprintf( __( 'PHP reads .user.ini every %d minutes, so the guard becomes active within that time.', 'qartvelo-guard' ), $minutes );
				}
				$parts[] = __( 'The Dashboard shows when the guard is active.', 'qartvelo-guard' );
				return implode( ' ', $parts );
			}
			if ( 'user_ini' === $method && $ols_step ) {
				return __( 'Installed, but PHP has not loaded it yet.', 'qartvelo-guard' ) . $ols;
			}
			if ( 'user_ini' === $method ) {
				/* translators: %d: minutes */
				return sprintf( __( 'Installed. PHP reads .user.ini every %d minutes, so the guard becomes active within that time. The Dashboard shows when it is.', 'qartvelo-guard' ), $minutes );
			}
			if ( $more ) {
				// The server ignored php_value (OpenLiteSpeed does): try the next way.
				$gm->remove_htaccess();
				continue;
			}
			// WordPress answered that the guard did not run although the server accepted the line: undo rather than leave a half setup.
			$this->roll_back_guard( $gm, $method );
			return new \WP_Error( 'wpcybersec_fix', __( 'The server accepted the setting but PHP did not load the guard, so the change was undone. Follow the steps below.', 'qartvelo-guard' ) );
		}
		$gm->uninstall( true );
		return new \WP_Error( 'wpcybersec_fix', __( 'The guard could not be wired in on this server. Follow the steps below.', 'qartvelo-guard' ) );
	}

	/**
	 * Undoes the guard installation after a failed check. The bootstrap file
	 * stays: PHP workers can keep prepending it from a cached .user.ini (up to
	 * user_ini.cache_ttl) after the line is gone, and deleting it then would
	 * break every request. Without its config it does nothing.
	 *
	 * @param Guard_Manager $gm     Guard manager.
	 * @param string        $method htaccess | user_ini.
	 */
	private function roll_back_guard( $gm, $method ) {
		if ( 'htaccess' === $method ) {
			$gm->remove_htaccess();
		} else {
			$gm->remove_user_ini();
		}
		$gm->uninstall( true );
	}

	/**
	 * Requests the site twice, through wp-admin (admin-ajax.php) and through
	 * the front controller (the home URL, where pages and /wp-json/ run, which
	 * is another folder when WordPress lives in a sub folder or on Bedrock),
	 * and asks whether the guard ran in those requests.
	 *
	 * @return string active | inactive | down | unknown
	 */
	private function ping_guard( $timeout = 20 ) {
		$this->ping_timeout = max( 2, (int) $timeout );
		$token = wp_generate_password( 24, false );
		set_transient( 'wpcybersec_guard_ping', $token, 5 * MINUTE_IN_SECONDS );
		$admin = $this->ping_url(
			add_query_arg(
				array(
					'action' => 'wpcybersec_guard_ping',
					'token'  => $token,
				),
				admin_url( 'admin-ajax.php' )
			)
		);
		$front = 'down' === $admin ? 'unknown' : $this->ping_url( add_query_arg( 'wpcybersec_guard_ping', $token, home_url( '/' ) ) );
		delete_transient( 'wpcybersec_guard_ping' );
		$result = self::combine_pings( $admin, $front );
		$gm     = wpcybersec()->guard_manager;
		if ( is_object( $gm ) && method_exists( $gm, 'record_ping' ) ) {
			// Kept for WP-CLI, cron and development servers, which cannot tell themselves.
			$gm->record_ping( $result );
		}
		return $result;
	}

	/** @var int Seconds per test request of ping_guard(). */
	private $ping_timeout = 20;

	/**
	 * Repeats the live test of an installed guard (Guard_Manager::maybe_reping(),
	 * "Test again" in Settings > Advanced > Early guard).
	 *
	 * @param int $timeout Seconds per test request.
	 * @return string active | inactive | down | unknown
	 */
	public function reping( $timeout = 10 ) {
		return $this->ping_guard( $timeout );
	}

	/**
	 * One answer out of the two pings: a broken request wins, then a request
	 * that ran without the guard; "unknown" only when nothing was learned.
	 *
	 * @param string $admin Result through wp-admin.
	 * @param string $front Result through the front controller.
	 * @return string active | inactive | down | unknown
	 */
	public static function combine_pings( $admin, $front ) {
		$both = array( $admin, $front );
		foreach ( array( 'down', 'inactive', 'active' ) as $state ) {
			if ( in_array( $state, $both, true ) ) {
				return $state;
			}
		}
		return 'unknown';
	}

	/**
	 * @param string $url Ping URL.
	 * @return string active | inactive | down | unknown
	 */
	private function ping_url( $url ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => $this->ping_timeout,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core filter, same as wp-cron uses for loopback requests.
				'headers'   => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return 'unknown'; // Timeout or blocked loopback: that says nothing about the change.
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code >= 500 ) {
			return 'down';
		}
		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( 200 !== $code || ! is_array( $body ) || ! array_key_exists( 'active', $body ) ) {
			return 'unknown'; // A login page, an HTTP password prompt, a cached page or a firewall answered instead of WordPress.
		}
		return ! empty( $body['active'] ) ? 'active' : 'inactive';
	}

	/**
	 * Answers the loopback check (only with the one-time token).
	 */
	public function ajax_guard_ping() {
		$given = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		self::answer_ping( $given );
	}

	/**
	 * Answers the loopback check sent to the front controller (init, early).
	 */
	public function front_guard_ping() {
		$given = isset( $_GET['wpcybersec_guard_ping'] ) ? sanitize_text_field( wp_unslash( $_GET['wpcybersec_guard_ping'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- one-time token, checked below.
		$token = (string) get_transient( 'wpcybersec_guard_ping' );
		if ( '' === $token || ! hash_equals( $token, $given ) ) {
			return; // Not our test request: the page loads as usual.
		}
		self::answer_ping( $given );
	}

	/**
	 * @param string $given Token from the request.
	 */
	private static function answer_ping( $given ) {
		$token  = (string) get_transient( 'wpcybersec_guard_ping' );
		$active = '' !== $token && hash_equals( $token, (string) $given ) && defined( 'WPCYBERSEC_GUARD_ACTIVE' );
		nocache_headers();
		wp_send_json( array( 'active' => $active ) );
	}

	/**
	 * @return string|\WP_Error String = applied, with what the live test showed.
	 */
	private function fix_uploads_php() {
		$sysadmin = wpcybersec()->sysadmin;
		if ( ! is_object( $sysadmin ) || ! method_exists( $sysadmin, 'write_uploads_htaccess' ) ) {
			return new \WP_Error( 'wpcybersec_fix', __( 'This fix is not available.', 'qartvelo-guard' ) );
		}
		$result = $sysadmin->write_uploads_htaccess();
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		if ( 'unverified' === $result ) {
			// Not "Fixed": nothing proved that PHP stopped running there.
			return __( 'The rules are in uploads/.htaccess, but the site could not test itself, so it is not confirmed that PHP no longer runs in uploads. Run the live test under Settings > Advanced > Web server later.', 'qartvelo-guard' );
		}
		return __( 'PHP no longer runs in the uploads folder (checked with a live test).', 'qartvelo-guard' );
	}

	/* ------------------------------------------------------------------ */
	/* AJAX                                                                */
	/* ------------------------------------------------------------------ */

	public function ajax_fix() {
		$this->ajax_guard();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in ajax_guard().
		$id     = isset( $_POST['fix'] ) ? sanitize_key( wp_unslash( $_POST['fix'] ) ) : '';
		$result = $this->run( $id );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'message' => $result->get_error_message(),
					'steps'   => $this->manual_steps( $id ),
				)
			);
		}
		wp_send_json_success( array( 'message' => is_string( $result ) ? $result : __( 'Fixed.', 'qartvelo-guard' ) ) );
	}

	public function ajax_fix_all() {
		$this->ajax_guard();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in ajax_guard().
		$ids     = isset( $_POST['fixes'] ) ? array_values( array_unique( array_map( 'sanitize_key', (array) wp_unslash( $_POST['fixes'] ) ) ) ) : array();
		$results = array();
		$skipped = array();
		foreach ( array_diff( $ids, self::AUTO ) as $id ) {
			$reason = $this->skip_reason( $id );
			if ( '' !== $reason ) {
				$skipped[ $id ] = $reason;
			}
		}
		Storage::keep_running();
		foreach ( array_intersect( self::AUTO, $ids ) as $id ) {
			$result         = $this->run( $id );
			$results[ $id ] = is_wp_error( $result )
				? array(
					'ok'      => false,
					'message' => $result->get_error_message(),
				)
				: array(
					'ok'      => true,
					'message' => is_string( $result ) ? $result : __( 'Fixed.', 'qartvelo-guard' ),
					'note'    => is_string( $result ),
				);
		}
		wp_send_json_success(
			array(
				'results' => $results,
				'skipped' => $skipped,
			)
		);
	}

	/**
	 * Why "Fix all" leaves a fix to its own button ('' for ids that are no fix).
	 *
	 * @param string $id Fix id.
	 * @return string
	 */
	private function skip_reason( $id ) {
		switch ( $id ) {
			case 'guard':
				return __( 'The early guard was not installed: it changes how PHP starts every request, so use its own "Install and switch on the early guard" button.', 'qartvelo-guard' );
			case 'disable_wp_cron':
				return __( 'Visitor-triggered cron was not switched off: use its own button once you are sure the real cron job keeps running.', 'qartvelo-guard' );
			case 'wp_version':
				return __( 'WordPress itself is updated from Dashboard > Updates.', 'qartvelo-guard' );
		}
		return '';
	}

	private function ajax_guard() {
		if ( ! check_ajax_referer( Ajax::NONCE, '_ajax_nonce', false ) || ! self::can() ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'qartvelo-guard' ) ), 403 );
		}
	}

	/**
	 * Prints a fix button (with by-hand steps folded under it), or the steps
	 * alone when this server cannot do it automatically.
	 *
	 * @param string $id Fix id.
	 */
	public function render_fix( $id ) {
		$auto  = $this->descriptor( $id );
		$steps = $this->manual_steps( $id );
		// By hand, the early guard still needs its files: offer them as their own button.
		$files = 'guard' === $id ? $this->descriptor( 'guard_files' ) : null;
		$extra = '';
		if ( $files ) {
			$extra = '<p class="wpcs-autofix wpcs-autofix--inline"><button type="button" class="button" data-wpcs-fix="guard_files"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html( $files['label'] ) . '</button>'
				. '<span class="wpcs-sub">' . esc_html( $files['description'] ) . '</span></p>';
		}
		if ( $auto ) {
			echo '<div class="wpcs-autofix">';
			if ( ! empty( $auto['link'] ) ) {
				echo '<a class="button button-primary" href="' . esc_url( $auto['link'] ) . '">' . esc_html( $auto['label'] ) . '</a>';
			} else {
				echo '<button type="button" class="button button-primary" data-wpcs-fix="' . esc_attr( $auto['id'] ) . '"><span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>' . esc_html( $auto['label'] ) . '</button>';
			}
			if ( ! empty( $auto['description'] ) ) {
				echo '<span class="wpcs-sub">' . esc_html( $auto['description'] ) . '</span>';
			}
			echo '</div>';
			if ( $steps ) {
				echo '<details class="wpcs-manual" data-wpcs-manual="' . esc_attr( $auto['id'] ) . '"><summary>' . esc_html( 'guard' === $id ? __( 'Do it by hand', 'qartvelo-guard' ) : __( 'Do it by hand instead', 'qartvelo-guard' ) ) . '</summary>';
				echo $extra; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
				Admin\Settings_Page::render_steps( $steps );
				echo '</details>';
			}
		} elseif ( $steps ) {
			echo '<div class="wpcs-manual wpcs-manual--open" data-wpcs-manual="' . esc_attr( $id ) . '">';
			echo '<span class="wpcs-sub wpcs-check__fix">' . esc_html__( 'How to set it up:', 'qartvelo-guard' ) . '</span>';
			echo $extra; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
			Admin\Settings_Page::render_steps( $steps );
			echo '</div>';
		}
	}

	/* ------------------------------------------------------------------ */

	/**
	 * Whether PHP runs as the owner of $path (only the owner may chmod).
	 *
	 * @param string $path File.
	 * @return bool
	 */
	private function owns( $path ) {
		if ( ! function_exists( 'posix_geteuid' ) ) {
			return Fs::is_writable( $path );
		}
		return @fileowner( $path ) === posix_geteuid(); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * @return string apache | litespeed | nginx | iis | unknown
	 */
	private function server_type() {
		$soft = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		foreach ( array( 'litespeed', 'nginx', 'apache', 'iis' ) as $type ) {
			if ( false !== strpos( $soft, $type ) ) {
				return $type;
			}
		}
		return 'unknown';
	}
}
