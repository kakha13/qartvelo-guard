<?php
/**
 * Install gate: holds new plugin and theme installs until approved, and keeps
 * the file manifest current after updates.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * - upgrader_source_selection: new plugin/theme installs (and, with hold_updates,
 *   updates) that are not in the allowlist are stopped with a WP_Error, which
 *   WordPress shows as "Installation failed: <message>". A pending item of type
 *   install is created. Approving it allowlists "plugin:<folder>" or
 *   "theme:<folder>" so the next attempt goes through.
 * - upgrader_process_complete: re-trusts only the folders an update or install
 *   touched (File_Monitor::rebaseline_paths), so updates do not show up as
 *   hundreds of modified files.
 * - file_mod_allowed: with freeze_mods on, every file modification through
 *   WordPress (installs, updates, editors) is refused unless temporarily unlocked.
 */
class Install_Gate {

	const UNLOCK_OPTION = 'wpcybersec_unlock_until';

	/** Budget for the malware check of a held package. */
	const SCAN_SECONDS = 8;
	const SCAN_FILES   = 3000;

	/** @var string[] Folders to re-trust at shutdown. */
	private $rebaseline_dirs = array();

	/** @var string[] Single files to re-trust at shutdown. */
	private $rebaseline_files = array();

	/** @var string[] "type:slug" held during this request (skip their rebaseline). */
	private $held_now = array();

	/** @var bool */
	private $shutdown_hooked = false;

	/**
	 * Nothing heavy here; see register().
	 */
	public function __construct() {}

	/**
	 * Hooks.
	 */
	public function register() {
		// Priority 20: WordPress validates the package itself at 10 (check_package).
		add_filter( 'upgrader_source_selection', array( $this, 'source_selection' ), 20, 4 );
		add_action( 'upgrader_process_complete', array( $this, 'process_complete' ), 20, 2 );
		add_filter( 'file_mod_allowed', array( $this, 'file_mod_allowed' ), 20, 2 );
	}

	/* ------------------------------------------------------------------ */
	/* Holding installs                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * upgrader_source_selection callback.
	 *
	 * @param string|\WP_Error $source        Unpacked package folder.
	 * @param string           $remote_source Working folder.
	 * @param object|null      $upgrader      WP_Upgrader instance.
	 * @param array            $hook_extra    Extra arguments.
	 * @return string|\WP_Error
	 */
	public function source_selection( $source, $remote_source = '', $upgrader = null, $hook_extra = array() ) {
		if ( is_wp_error( $source ) || ! is_string( $source ) || '' === $source ) {
			return $source;
		}
		$hook_extra = is_array( $hook_extra ) ? $hook_extra : array();
		$type       = $this->upgrader_type( $upgrader, $hook_extra );
		if ( '' === $type ) {
			return $source; // Core, translations and anything else are not gated here.
		}

		try {
			return $this->check_package( $source, (string) $remote_source, $type, $hook_extra );
		} catch ( \Throwable $e ) {
			$this->log(
				'install_gate_error',
				/* translators: %s: error message */
				sprintf( __( 'The install gate could not check a package: %s', 'qartvelo-guard' ), $e->getMessage() )
			);
			return new \WP_Error( 'wpcybersec_install_error', __( 'This package could not be checked right now (Qartvelo Guard). Please try again in a moment.', 'qartvelo-guard' ) );
		}
	}

	/**
	 * Decision for one unpacked package.
	 *
	 * @param string $source        Package folder.
	 * @param string $remote_source Working folder.
	 * @param string $type          plugin | theme.
	 * @param array  $hook_extra    Extra arguments.
	 * @return string|\WP_Error
	 */
	private function check_package( $source, $remote_source, $type, array $hook_extra ) {
		$plugin = wpcybersec();
		if ( ! $plugin->is_booted() || ! $plugin->settings ) {
			return $source;
		}
		$settings  = $plugin->settings;
		$is_update = $this->is_update( $hook_extra );

		$slug = basename( untrailingslashit( wp_normalize_path( $source ) ) );
		if ( '' === sanitize_key( $slug ) ) {
			return $source;
		}
		// A ZIP of a plugin or theme that is already installed ("Replace current
		// with uploaded", wp plugin install --force, a new version of this
		// plugin itself) arrives as an install: it replaces code that already
		// runs here, so it is an update and "hold updates" decides.
		if ( ! $is_update && '' !== self::installed_dir( $type, $slug ) ) {
			$is_update = true;
		}

		if ( $is_update ) {
			if ( ! $settings->get( 'hold_updates', false ) ) {
				return $source;
			}
		} elseif ( 'hold' !== $settings->get( 'install_mode', 'hold' ) ) {
			return $source;
		}

		if ( $this->is_unlocked() ) {
			$this->log(
				'install_unlocked',
				/* translators: 1: plugin or theme, 2: folder */
				sprintf( __( 'Allowed %1$s %2$s without approval because file changes are unlocked.', 'qartvelo-guard' ), $type, $slug ),
				array( 'slug' => $slug )
			);
			return $source;
		}

		$info       = $this->package_info( $source, $type );
		$version    = '' !== $info['version'] ? $info['version'] : 'unknown';
		$allow_slug = $is_update ? self::update_slug( $slug, $version ) : $slug;
		if ( $plugin->allowlist->is_allowed_install( $type, $allow_slug ) ) {
			return $source;
		}

		list( $hits, $partial, $verified, $unchanged ) = $this->scan_package( self::local_path( $source ), $type, $slug, $info['version'] );
		$info['checksum_verified']                     = $verified;
		$info['unchanged_files']                       = $unchanged;
		$info['self_package']                          = 'plugin' === $type && $slug === self::own_slug();
		$severity = $this->max_severity( $hits );
		$display                = self::display_name( '' !== $info['name'] ? $info['name'] : $slug );

		$this->hold_item( $type, $slug, $version, $is_update, $info, $hits, $partial, $severity );
		$this->held_now[] = $type . ':' . $slug;
		$this->discard_working_dir( $remote_source );

		return new \WP_Error( 'wpcybersec_install_held', $this->hold_message( $display, $is_update, $severity ) );
	}

	/**
	 * Creates (or refreshes) the pending install item.
	 *
	 * @param string $type      plugin | theme.
	 * @param string $slug      Folder.
	 * @param string $version   Version.
	 * @param bool   $is_update Update or new install.
	 * @param array  $info      Header data.
	 * @param array  $hits      Malware hits.
	 * @param bool   $partial   Whether the check stopped early.
	 * @param int    $severity  Max severity.
	 * @return int Item id.
	 */
	private function hold_item( $type, $slug, $version, $is_update, array $info, array $hits, $partial, $severity ) {
		$plugin = wpcybersec();
		$path   = Allowlist::install_key( $type, $slug ) . ( $is_update ? '@' . $version : '' );

		$existing = $plugin->store->item_find_open( Store::TYPE_INSTALL, $path );
		if ( $existing ) {
			$plugin->store->item_update(
				$existing['id'],
				array(
					'severity' => max( (int) $existing['severity'], (int) $severity ),
					'details'  => array(
						'repeat_count' => ( isset( $existing['details']['repeat_count'] ) ? (int) $existing['details']['repeat_count'] : 0 ) + 1,
						'last_attempt' => Store::now(),
					),
				)
			);
			return (int) $existing['id'];
		}

		$id = $plugin->store->item_insert(
			array(
				'type'     => Store::TYPE_INSTALL,
				'status'   => Store::STATUS_PENDING,
				'severity' => (int) $severity,
				'path'     => $path,
				'source'   => 'install',
				'details'  => array(
					'install_type'   => $type,
					'slug'           => $slug,
					'name'           => $info['name'],
					'version'        => $is_update ? $version : $info['version'],
					'author'         => $info['author'],
					'uri'            => $info['uri'],
					'install_source' => $this->install_source(),
					'update'         => (bool) $is_update,
					'hits'           => array_slice( $hits, 0, 50 ),
					'scan_partial'   => (bool) $partial,
					'request_uri'    => self::request_uri(),
				) + ( ! empty( $info['checksum_verified'] ) ? array( 'checksum_verified' => (int) $info['checksum_verified'] ) : array() )
					+ ( ! empty( $info['unchanged_files'] ) ? array( 'unchanged_files' => (int) $info['unchanged_files'] ) : array() )
					+ ( ! empty( $info['self_package'] ) ? array( 'self_package' => true ) : array() ),
			)
		);
		if ( ! $id ) {
			return 0;
		}

		$label = '' !== $info['name'] ? $info['name'] : $slug;
		$this->log(
			'install_held',
			$is_update
				/* translators: 1: plugin or theme, 2: name, 3: version */
				? sprintf( __( 'Held the %1$s update %2$s %3$s for administrator approval.', 'qartvelo-guard' ), $type, $label, $version )
				/* translators: 1: plugin or theme, 2: name */
				: sprintf( __( 'Held the %1$s install %2$s for administrator approval.', 'qartvelo-guard' ), $type, $label ),
			array(
				'item_id'  => $id,
				'slug'     => $slug,
				'severity' => (int) $severity,
			)
		);

		if ( $plugin->notifier && method_exists( $plugin->notifier, 'item_created' ) ) {
			try {
				$plugin->notifier->item_created( $id );
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}
		return $id;
	}

	/**
	 * Called by Decisions when an install item is approved.
	 *
	 * @param array $item Item row.
	 * @return true|\WP_Error
	 */
	public function on_approve( array $item ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$path    = (string) $item['path'];
		$type    = isset( $details['install_type'] ) && 'theme' === $details['install_type'] ? 'theme' : ( 0 === strpos( $path, 'theme:' ) ? 'theme' : 'plugin' );
		$slug    = isset( $details['slug'] ) ? (string) $details['slug'] : '';
		if ( '' === $slug && false !== strpos( $path, ':' ) ) {
			$slug = substr( $path, strpos( $path, ':' ) + 1 );
			if ( false !== strpos( $slug, '@' ) ) {
				$slug = substr( $slug, 0, strpos( $slug, '@' ) );
			}
		}
		if ( '' === sanitize_key( $slug ) ) {
			return new \WP_Error( 'wpcybersec_install_slug', __( 'This install item has no folder name, so it cannot be approved. Deny it and install again.', 'qartvelo-guard' ) );
		}

		$name    = ! empty( $details['name'] ) ? (string) $details['name'] : $slug;
		$version = ! empty( $details['version'] ) ? (string) $details['version'] : 'unknown';
		$note    = sprintf( 'install item #%d', (int) $item['id'] );
		$plugin  = wpcybersec();

		if ( ! empty( $details['update'] ) ) {
			/* translators: 1: name, 2: version */
			$label = Upload_Gate::cut( sprintf( __( '%1$s %2$s (update)', 'qartvelo-guard' ), $name, $version ), 255 );
			$plugin->allowlist->allow_install( $type, self::update_slug( $slug, $version ), $label, $note );
			/* translators: %s: name */
			$next = sprintf( __( 'Run the update of %s again; it will go through now.', 'qartvelo-guard' ), $name );
		} else {
			$plugin->allowlist->allow_install( $type, $slug, Upload_Gate::cut( $name, 255 ), $note );
			/* translators: %s: name */
			$next = sprintf( __( 'Install %s again; it will go through now and will not be held again.', 'qartvelo-guard' ), $name );
		}
		if ( ! empty( $item['sha256'] ) ) {
			$plugin->allowlist->allow_hash( (string) $item['sha256'], Upload_Gate::cut( $name, 255 ), $note );
		}

		$plugin->store->item_update( (int) $item['id'], array( 'details' => array( 'approval_note' => $next ) ) );
		return true;
	}

	/**
	 * Called by Decisions when an install item is denied.
	 *
	 * @param array $item Item row.
	 */
	public function on_deny( array $item ) {
		/**
		 * Fires when a held install is denied.
		 *
		 * @param array $item Item row.
		 */
		do_action( 'wpcybersec_install_denied', $item );
	}

	/* ------------------------------------------------------------------ */
	/* Rebaseline after updates                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * upgrader_process_complete callback: queues the touched folders.
	 *
	 * @param object $upgrader   Upgrader.
	 * @param array  $hook_extra Extra data.
	 */
	public function process_complete( $upgrader, $hook_extra = array() ) {
		if ( ! is_array( $hook_extra ) ) {
			return;
		}
		$dirs_before  = count( $this->rebaseline_dirs );
		$files_before = count( $this->rebaseline_files );
		try {
			$this->collect_rebaseline_targets( $upgrader, $hook_extra );
			// Remembered for Reports > Recent changes ("<Plugin> update" explains these files).
			$touched = array_merge( array_slice( $this->rebaseline_dirs, $dirs_before ), array_slice( $this->rebaseline_files, $files_before ) );
			if ( $touched ) {
				Recent_Changes::remember_update( $touched, isset( $hook_extra['action'] ) && 'install' === $hook_extra['action'] ? 'install' : 'update' );
			}
		} catch ( \Throwable $e ) {
			$this->log(
				'rebaseline_error',
				/* translators: %s: error message */
				sprintf( __( 'Could not work out which files an update changed: %s', 'qartvelo-guard' ), $e->getMessage() )
			);
			return;
		}
		if ( ( $this->rebaseline_dirs || $this->rebaseline_files ) && ! $this->shutdown_hooked ) {
			$this->shutdown_hooked = true;
			// Once per request, after a bulk update finished, and immune to timeouts.
			add_action( 'shutdown', array( $this, 'run_rebaseline' ), 5 );
		}
	}

	/**
	 * @param object $upgrader   Upgrader.
	 * @param array  $hook_extra Extra data.
	 */
	private function collect_rebaseline_targets( $upgrader, array $hook_extra ) {
		$type   = isset( $hook_extra['type'] ) ? (string) $hook_extra['type'] : '';
		$action = isset( $hook_extra['action'] ) ? (string) $hook_extra['action'] : '';

		if ( 'plugin' === $type ) {
			$plugin_dir = wp_normalize_path( WP_PLUGIN_DIR );
			$plugins    = array();
			if ( ! empty( $hook_extra['plugins'] ) && is_array( $hook_extra['plugins'] ) ) {
				$plugins = $hook_extra['plugins'];
			}
			if ( ! empty( $hook_extra['plugin'] ) && is_string( $hook_extra['plugin'] ) ) {
				$plugins[] = $hook_extra['plugin'];
			}
			foreach ( $plugins as $plugin_file ) {
				$plugin_file = wp_normalize_path( (string) $plugin_file );
				if ( '' === $plugin_file || false !== strpos( $plugin_file, '..' ) ) {
					continue;
				}
				$folder = dirname( $plugin_file );
				if ( in_array( 'plugin:' . $folder, $this->held_now, true ) ) {
					continue;
				}
				if ( '.' === $folder || '' === $folder ) {
					$this->add_file( $plugin_dir . '/' . basename( $plugin_file ), $plugin_dir );
				} else {
					$this->add_dir( $plugin_dir . '/' . $folder, $plugin_dir );
				}
			}
			if ( 'install' === $action ) {
				$dest = $this->result_destination( $upgrader );
				if ( $dest ) {
					$this->add_dir( $dest, $plugin_dir );
				}
			}
			return;
		}

		if ( 'theme' === $type ) {
			$themes = array();
			if ( ! empty( $hook_extra['themes'] ) && is_array( $hook_extra['themes'] ) ) {
				$themes = $hook_extra['themes'];
			}
			if ( ! empty( $hook_extra['theme'] ) && is_string( $hook_extra['theme'] ) ) {
				$themes[] = $hook_extra['theme'];
			}
			foreach ( $themes as $stylesheet ) {
				$stylesheet = sanitize_file_name( (string) $stylesheet );
				if ( '' === $stylesheet || in_array( 'theme:' . $stylesheet, $this->held_now, true ) ) {
					continue;
				}
				$root = wp_normalize_path( get_theme_root( $stylesheet ) );
				$this->add_dir( $root . '/' . $stylesheet, $root );
			}
			if ( 'install' === $action ) {
				$dest = $this->result_destination( $upgrader );
				if ( $dest ) {
					$this->add_dir( $dest, wp_normalize_path( WP_CONTENT_DIR ) );
				}
			}
			return;
		}

		if ( 'core' === $type ) {
			$abspath = untrailingslashit( wp_normalize_path( ABSPATH ) );
			$this->add_dir( $abspath . '/wp-admin', $abspath );
			$this->add_dir( $abspath . '/' . WPINC, $abspath );
			$root_files = (array) glob( $abspath . '/wp-*.php' );
			$root_files[] = $abspath . '/index.php';
			$root_files[] = $abspath . '/xmlrpc.php';
			foreach ( $root_files as $file ) {
				$file = wp_normalize_path( (string) $file );
				if ( '' !== $file && 'wp-config.php' !== basename( $file ) ) {
					$this->add_file( $file, $abspath );
				}
			}
			return;
		}

		if ( 'translation' === $type && defined( 'WP_LANG_DIR' ) ) {
			$lang = untrailingslashit( wp_normalize_path( WP_LANG_DIR ) );
			$this->add_dir( $lang, dirname( $lang ) );
		}
	}

	/**
	 * Shutdown callback: re-trusts the queued folders and files once.
	 */
	public function run_rebaseline() {
		$dirs  = array_values( array_unique( $this->rebaseline_dirs ) );
		$files = array_values( array_unique( $this->rebaseline_files ) );
		$this->rebaseline_dirs  = array();
		$this->rebaseline_files = array();
		if ( ! $dirs && ! $files ) {
			return;
		}

		$plugin  = wpcybersec();
		$monitor = $plugin->file_monitor;
		if ( ! $monitor ) {
			return;
		}
		ignore_user_abort( true );
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 300 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- hashing and copying a whole plugin or theme package into quarantine can take minutes.
		}

		$done = array();
		try {
			if ( $dirs && method_exists( $monitor, 'rebaseline_paths' ) ) {
				$monitor->rebaseline_paths( $dirs );
				$done = $dirs;
			}
			$trusted = $files ? $this->rebaseline_files( $files ) : 0;
		} catch ( \Throwable $e ) {
			$this->log(
				'rebaseline_error',
				/* translators: %s: error message */
				sprintf( __( 'Could not re-check updated files: %s', 'qartvelo-guard' ), $e->getMessage() )
			);
			return;
		}

		$labels = array();
		foreach ( $done as $dir ) {
			$labels[] = Paths::rel( $dir );
		}
		if ( $trusted ) {
			/* translators: %d: number of files */
			$labels[] = sprintf( _n( '%d root file', '%d root files', $trusted, 'qartvelo-guard' ), $trusted );
		}
		if ( $labels ) {
			$this->log(
				'rebaselined',
				/* translators: %s: comma separated folders */
				sprintf( __( 'Updated files were re-checked and trusted: %s', 'qartvelo-guard' ), implode( ', ', $labels ) ),
				array(
					'dirs'  => $done,
					'files' => $files,
				)
			);
		}
	}

	/**
	 * Re-trusts single files (core root files, single-file plugins) after checking them.
	 * A file with a checksum mismatch or malware hits >= 2 is left alone; the next
	 * scan reports it.
	 *
	 * @param string[] $files Absolute paths.
	 * @return int Files trusted.
	 */
	private function rebaseline_files( array $files ) {
		$plugin  = wpcybersec();
		$monitor = $plugin->file_monitor;
		$scanner = $plugin->scanner;
		if ( ! $monitor || ! method_exists( $monitor, 'trust_file' ) ) {
			return 0;
		}
		$trusted = 0;
		foreach ( $files as $abs ) {
			if ( ! is_file( $abs ) || ! is_readable( $abs ) ) {
				continue;
			}
			$sha256  = (string) hash_file( 'sha256', $abs );
			$rel     = Paths::rel( $abs );
			$verdict = 'unknown';
			if ( $scanner && method_exists( $scanner, 'verify' ) ) {
				$verdict = (string) $scanner->verify( $rel, $sha256, (string) md5_file( $abs ) );
			}
			if ( 'mismatch' === $verdict ) {
				continue;
			}
			if ( 'match' !== $verdict && $scanner && method_exists( $scanner, 'scan_file' ) ) {
				$hits = (array) $scanner->scan_file( $abs, $rel );
				if ( $this->max_severity( $hits ) >= Store::SEV_HIGH ) {
					continue;
				}
			}
			$monitor->trust_file( $abs, $sha256 );
			++$trusted;
		}
		return $trusted;
	}

	/**
	 * @param string $dir    Folder.
	 * @param string $parent Folder it must be inside.
	 */
	private function add_dir( $dir, $parent ) {
		$dir = untrailingslashit( wp_normalize_path( (string) $dir ) );
		if ( '' !== $dir && is_dir( $dir ) && Storage::is_within( $dir, $parent ) ) {
			$this->rebaseline_dirs[] = $dir;
		}
	}

	/**
	 * @param string $file   File.
	 * @param string $parent Folder it must be inside.
	 */
	private function add_file( $file, $parent ) {
		$file = wp_normalize_path( (string) $file );
		if ( '' !== $file && is_file( $file ) && Storage::is_within( $file, $parent ) ) {
			$this->rebaseline_files[] = $file;
		}
	}

	/**
	 * @param object $upgrader Upgrader.
	 * @return string Destination folder of a finished install, '' when unknown.
	 */
	private function result_destination( $upgrader ) {
		if ( ! is_object( $upgrader ) || empty( $upgrader->result ) || ! is_array( $upgrader->result ) || empty( $upgrader->result['destination'] ) ) {
			return '';
		}
		$local = self::local_path( (string) $upgrader->result['destination'] );
		return '' !== $local ? untrailingslashit( $local ) : '';
	}

	/* ------------------------------------------------------------------ */
	/* Freeze lock                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * file_mod_allowed callback.
	 *
	 * @param bool   $allowed Current value.
	 * @param string $context Context.
	 * @return bool
	 */
	public function file_mod_allowed( $allowed, $context = '' ) {
		if ( ! $allowed ) {
			return $allowed;
		}
		$plugin = wpcybersec();
		if ( ! $plugin->is_booted() || ! $plugin->settings ) {
			return $allowed;
		}
		if ( $plugin->settings->get( 'freeze_mods', false ) && ! $this->is_unlocked() ) {
			return false;
		}
		return $allowed;
	}

	/**
	 * Temporarily allows file changes (and installs without approval).
	 *
	 * @param int $minutes Minutes (1 to 240).
	 * @return int Unix time when the unlock ends (0 when DISALLOW_FILE_MODS leaves nothing to unlock).
	 */
	public function unlock( $minutes ) {
		if ( self::mods_disallowed() ) {
			return 0; // wp-config.php disables installs and updates: nothing to unlock.
		}
		$minutes = max( 1, min( 240, (int) $minutes ) );
		$until   = time() + $minutes * MINUTE_IN_SECONDS;
		Network::update_option( self::UNLOCK_OPTION, $until, false );
		$this->log(
			'unlocked',
			/* translators: %d: minutes */
			sprintf( _n( 'File changes unlocked for %d minute.', 'File changes unlocked for %d minutes.', $minutes, 'qartvelo-guard' ), $minutes ),
			array( 'until' => $until )
		);
		return $until;
	}

	/**
	 * Ends an unlock window immediately.
	 */
	public function lock() {
		$was = $this->unlocked_until();
		Network::delete_option( self::UNLOCK_OPTION );
		if ( $was ) {
			$this->log( 'locked', __( 'File changes locked again.', 'qartvelo-guard' ) );
		}
	}

	/**
	 * @return bool
	 */
	public function is_unlocked() {
		return $this->unlocked_until() > 0;
	}

	/**
	 * @return int Unix time when the unlock ends, 0 when locked.
	 */
	public function unlocked_until() {
		$until = (int) Network::get_option( self::UNLOCK_OPTION, 0 );
		return $until > time() ? $until : 0;
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * plugin | theme | '' for upgraders this gate does not handle.
	 *
	 * @param object|null $upgrader   Upgrader.
	 * @param array       $hook_extra Extra data.
	 * @return string
	 */
	private function upgrader_type( $upgrader, array $hook_extra ) {
		if ( $upgrader instanceof \Plugin_Upgrader ) {
			return 'plugin';
		}
		if ( $upgrader instanceof \Theme_Upgrader ) {
			return 'theme';
		}
		if ( is_object( $upgrader ) && ( $upgrader instanceof \Language_Pack_Upgrader || $upgrader instanceof \Core_Upgrader ) ) {
			return '';
		}
		if ( isset( $hook_extra['type'] ) && in_array( $hook_extra['type'], array( 'plugin', 'theme' ), true ) ) {
			return $hook_extra['type'];
		}
		if ( isset( $hook_extra['plugin'] ) ) {
			return 'plugin';
		}
		if ( isset( $hook_extra['theme'] ) ) {
			return 'theme';
		}
		return '';
	}

	/**
	 * @param array $hook_extra Extra data.
	 * @return bool True for updates of installed plugins/themes.
	 */
	private function is_update( array $hook_extra ) {
		if ( isset( $hook_extra['action'] ) ) {
			return 'update' === $hook_extra['action'];
		}
		// Bulk updates pass only the plugin/theme key.
		return isset( $hook_extra['plugin'] ) || isset( $hook_extra['theme'] );
	}

	/**
	 * Where a plugin or theme with this folder name is installed, '' when it is not.
	 *
	 * @param string $type plugin | theme.
	 * @param string $slug Folder name.
	 * @return string
	 */
	public static function installed_dir( $type, $slug ) {
		$slug = (string) $slug;
		if ( '' === $slug || '' === sanitize_key( $slug ) || '.' === $slug || '..' === $slug ) {
			return '';
		}
		$dir = ( 'theme' === $type ? get_theme_root() : WP_PLUGIN_DIR ) . '/' . $slug;
		return @is_dir( $dir ) ? untrailingslashit( wp_normalize_path( $dir ) ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * This plugin's own folder name.
	 *
	 * @return string
	 */
	public static function own_slug() {
		return basename( untrailingslashit( wp_normalize_path( WPCYBERSEC_DIR ) ) );
	}

	/**
	 * Allowlist slug for an approved update of one version.
	 *
	 * @param string $slug    Folder.
	 * @param string $version Version.
	 * @return string
	 */
	public static function update_slug( $slug, $version ) {
		$version = preg_replace( '/[^A-Za-z0-9]+/', '-', (string) $version );
		return $slug . '--update-' . trim( (string) $version, '-' );
	}

	/**
	 * Name, version, author and URI from the unpacked package headers.
	 *
	 * @param string $source Package folder.
	 * @param string $type   plugin | theme.
	 * @return array
	 */
	private function package_info( $source, $type ) {
		$info  = array(
			'name'      => '',
			'version'   => '',
			'author'    => '',
			'uri'       => '',
			'main_file' => '',
		);
		$local = self::local_path( $source );
		if ( '' === $local ) {
			// FTP or SSH filesystem whose paths are not local paths: read through it.
			return $this->package_info_remote( $source, $type, $info );
		}
		$source = trailingslashit( wp_normalize_path( $local ) );

		if ( 'theme' === $type ) {
			$candidates = array( $source . 'style.css' );
			$headers    = array(
				'name'    => 'Theme Name',
				'version' => 'Version',
				'author'  => 'Author',
				'uri'     => 'Theme URI',
			);
		} else {
			$candidates = glob( $source . '*.php' );
			$candidates = is_array( $candidates ) ? array_slice( $candidates, 0, 50 ) : array();
			$headers    = array(
				'name'    => 'Plugin Name',
				'version' => 'Version',
				'author'  => 'Author',
				'uri'     => 'Plugin URI',
			);
		}

		foreach ( $candidates as $file ) {
			if ( ! is_file( $file ) || ! is_readable( $file ) ) {
				continue;
			}
			$data = get_file_data( $file, $headers );
			if ( empty( $data['name'] ) ) {
				continue;
			}
			foreach ( array( 'name', 'version', 'author', 'uri' ) as $key ) {
				// Cut on a character boundary: a broken UTF-8 character makes the database refuse the item.
				$info[ $key ] = Upload_Gate::cut( sanitize_text_field( wp_strip_all_tags( (string) $data[ $key ] ) ), 200 );
			}
			$info['uri']       = esc_url_raw( $info['uri'] );
			$info['main_file'] = basename( $file );
			break;
		}
		return $info;
	}

	/**
	 * package_info() through $wp_filesystem, for FTP / SSH filesystems
	 * (FS_METHOD ftpext, ftpsockets, ssh2) whose paths are not local.
	 *
	 * @param string $source Package folder (filesystem path).
	 * @param string $type   plugin | theme.
	 * @param array  $info   Empty info.
	 * @return array
	 */
	private function package_info_remote( $source, $type, array $info ) {
		global $wp_filesystem;
		if ( ! is_object( $wp_filesystem ) || ! method_exists( $wp_filesystem, 'get_contents' ) ) {
			return $info;
		}
		$source = trailingslashit( wp_normalize_path( $source ) );
		if ( 'theme' === $type ) {
			$candidates = array( $source . 'style.css' );
			$headers    = array(
				'name'    => 'Theme Name',
				'version' => 'Version',
				'author'  => 'Author',
				'uri'     => 'Theme URI',
			);
		} else {
			$candidates = array();
			$list       = method_exists( $wp_filesystem, 'dirlist' ) ? $wp_filesystem->dirlist( $source, false, false ) : false;
			foreach ( is_array( $list ) ? $list : array() as $name => $entry ) {
				if ( isset( $entry['type'] ) && 'f' === $entry['type'] && '.php' === strtolower( substr( (string) $name, -4 ) ) ) {
					$candidates[] = $source . $name;
				}
				if ( count( $candidates ) >= 50 ) {
					break;
				}
			}
			$headers = array(
				'name'    => 'Plugin Name',
				'version' => 'Version',
				'author'  => 'Author',
				'uri'     => 'Plugin URI',
			);
		}
		foreach ( $candidates as $file ) {
			$data = $wp_filesystem->get_contents( $file );
			if ( ! is_string( $data ) || '' === $data ) {
				continue;
			}
			// Same header parsing as get_file_data(): the first 8 KB.
			$data = str_replace( "\r", "\n", substr( $data, 0, 8192 ) );
			$found = array();
			foreach ( $headers as $key => $label ) {
				$found[ $key ] = preg_match( '/^(?:[ \t]*<\?php)?[ \t\/*#@]*' . preg_quote( $label, '/' ) . ':(.*)$/mi', $data, $m ) && $m[1] ? self::header_value( $m[1] ) : '';
			}
			if ( '' === $found['name'] ) {
				continue;
			}
			foreach ( array( 'name', 'version', 'author', 'uri' ) as $key ) {
				$info[ $key ] = Upload_Gate::cut( sanitize_text_field( wp_strip_all_tags( (string) $found[ $key ] ) ), 200 );
			}
			$info['uri']       = esc_url_raw( $info['uri'] );
			$info['main_file'] = basename( $file );
			break;
		}
		return $info;
	}

	/**
	 * A header value without a trailing comment close or PHP close tag (what
	 * get_file_data() does for local files).
	 *
	 * @param string $value Raw value after "Label:".
	 * @return string
	 */
	private static function header_value( $value ) {
		return trim( (string) preg_replace( '/\s*(?:\*\/|\?>).*/', '', (string) $value ) );
	}

	/**
	 * Local path of a path WordPress's filesystem API handed over. With FTP
	 * or SSH (FS_METHOD ftpext, ftpsockets, ssh2) the upgrader works with the
	 * server's FTP paths ("/public_html/wp-content/upgrade/x/"), which PHP
	 * cannot open; they map back through the folders both sides know.
	 *
	 * @param string $path Path from the upgrader.
	 * @return string Local path, or '' when it cannot be mapped.
	 */
	public static function local_path( $path ) {
		$path = wp_normalize_path( (string) $path );
		if ( '' === $path ) {
			return '';
		}
		if ( Storage::path_allowed( $path ) && @file_exists( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $path;
		}
		global $wp_filesystem;
		if ( ! is_object( $wp_filesystem ) ) {
			return '';
		}
		$pairs = array();
		if ( method_exists( $wp_filesystem, 'wp_content_dir' ) ) {
			$pairs[] = array( (string) $wp_filesystem->wp_content_dir(), WP_CONTENT_DIR );
		}
		if ( method_exists( $wp_filesystem, 'wp_plugins_dir' ) ) {
			$pairs[] = array( (string) $wp_filesystem->wp_plugins_dir(), WP_PLUGIN_DIR );
		}
		if ( method_exists( $wp_filesystem, 'abspath' ) ) {
			$pairs[] = array( (string) $wp_filesystem->abspath(), ABSPATH );
		}
		foreach ( $pairs as $pair ) {
			$remote = trailingslashit( wp_normalize_path( $pair[0] ) );
			if ( '/' === $remote || 0 !== strpos( trailingslashit( $path ), $remote ) ) {
				continue;
			}
			$local = trailingslashit( wp_normalize_path( $pair[1] ) ) . ltrim( substr( $path, strlen( $remote ) ), '/' );
			$local = rtrim( $local, '/' ) . ( '/' === substr( $path, -1 ) ? '/' : '' );
			if ( Storage::path_allowed( $local ) && @file_exists( $local ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return $local;
			}
		}
		return '';
	}

	/**
	 * Whether wp-config.php switches off every install and update
	 * (DISALLOW_FILE_MODS): the freeze lock then has nothing to unlock.
	 *
	 * @return bool
	 */
	public static function mods_disallowed() {
		return defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS;
	}

	/**
	 * Bounded malware check of an unpacked package, so the reviewer sees hits.
	 *
	 * Hits in a plugin file that is byte for byte the wordpress.org file of
	 * that slug and version (the plugin checksums the scanner uses after the
	 * install) are dropped: they are the official code, typically test
	 * fixtures in vendor/ that quote malware patterns. A file that differs
	 * from the official one, or is not listed there, keeps its hits.
	 *
	 * @param string $dir     Package folder.
	 * @param string $type    plugin | theme.
	 * @param string $slug    Package folder name.
	 * @param string $version Version from the package header.
	 * @return array [ hits, partial, verified (files whose hits the official checksums cleared), unchanged (files identical to the installed copy) ]
	 */
	private function scan_package( $dir, $type = '', $slug = '', $version = '' ) {
		$scanner = wpcybersec()->scanner;
		if ( '' === (string) $dir ) {
			return array( array(), true, 0, 0 ); // Not reachable as a local folder: not checked, shown as partial.
		}
		if ( ! $scanner || ! method_exists( $scanner, 'scan_file' ) || ! is_dir( $dir ) ) {
			return array( array(), false, 0, 0 );
		}
		$base     = trailingslashit( wp_normalize_path( $dir ) );
		$deadline = microtime( true ) + self::SCAN_SECONDS;
		$checked  = 0;
		$hits     = array();
		$partial  = false;
		$verified = 0;
		// A file identical to the one already installed under the same name is
		// code that runs here today, so its matches are not news (this plugin's
		// own signature file, for example, matches the patterns it looks for).
		$installed = self::installed_dir( $type, $slug );
		$unchanged = 0;
		$checks   = wpcybersec()->settings ? wpcybersec()->settings->get( 'use_checksums', true ) : true;
		$map      = ( $checks && 'plugin' === $type && '' !== (string) $slug && '' !== (string) $version && method_exists( $scanner, 'checksum_map' ) ) ? null : false;
		$scan_ext = array( 'js', 'html', 'htm', 'svg', 'htaccess' );

		try {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS )
			);
			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() || $file->isLink() ) {
					continue;
				}
				$name = $file->getFilename();
				if ( ! Paths::is_executable( $name ) && ! in_array( Paths::ext( $name ), $scan_ext, true ) ) {
					continue;
				}
				if ( ++$checked > self::SCAN_FILES || microtime( true ) > $deadline ) {
					$partial = true;
					break;
				}
				$abs       = wp_normalize_path( $file->getPathname() );
				$rel       = 0 === strpos( $abs, $base ) ? substr( $abs, strlen( $base ) ) : $name;
				$file_hits = (array) $scanner->scan_file( $abs, $rel );
				if ( $file_hits && false !== $map ) {
					if ( null === $map ) {
						$map = $scanner->checksum_map( $slug, $version ); // Fetched once, only when something was found.
						$map = is_array( $map ) && $map ? $map : false;
					}
					if ( false !== $map && $scanner->matches_map( $map, $rel, $abs ) ) {
						++$verified;
						continue;
					}
				}
				if ( $file_hits && '' !== $installed && self::same_file( $abs, $installed . '/' . $rel ) ) {
					++$unchanged;
					continue;
				}
				foreach ( $file_hits as $hit ) {
					if ( ! is_array( $hit ) ) {
						continue;
					}
					$hit['file'] = $rel;
					$hits[]      = $hit;
					if ( count( $hits ) >= 50 ) {
						$partial = true;
						break 2;
					}
				}
			}
		} catch ( \Throwable $e ) {
			$partial = true;
		}
		return array( $hits, $partial, $verified, $unchanged );
	}

	/**
	 * Whether two files have the same content.
	 *
	 * @param string $a File.
	 * @param string $b File.
	 * @return bool
	 */
	private static function same_file( $a, $b ) {
		if ( ! @is_file( $b ) || @is_link( $b ) || @filesize( $a ) !== @filesize( $b ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$ha = @hash_file( 'sha256', $a ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$hb = @hash_file( 'sha256', $b ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return is_string( $ha ) && '' !== $ha && $ha === $hb;
	}

	/**
	 * @param array $hits Hits.
	 * @return int
	 */
	private function max_severity( array $hits ) {
		$scanner = wpcybersec()->scanner;
		if ( $scanner && method_exists( $scanner, 'max_severity' ) ) {
			return (int) $scanner->max_severity( $hits );
		}
		$max = 0;
		foreach ( $hits as $hit ) {
			$max = max( $max, is_array( $hit ) && isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 );
		}
		return $max;
	}

	/**
	 * Deletes the unpacked working folder of a held package, so its code is not
	 * left in wp-content/upgrade where it could be reached from the web.
	 *
	 * @param string $remote_source Working folder.
	 */
	private function discard_working_dir( $remote_source ) {
		$fs_path     = untrailingslashit( wp_normalize_path( (string) $remote_source ) );
		$local       = untrailingslashit( self::local_path( $fs_path ) );
		$upgrade_dir = wp_normalize_path( WP_CONTENT_DIR . '/upgrade' );
		if ( '' === $fs_path || '' === $local || ! is_dir( $local ) || ! is_dir( $upgrade_dir ) ) {
			return;
		}
		$real_source  = realpath( $local );
		$real_upgrade = realpath( $upgrade_dir );
		if ( ! $real_source || ! $real_upgrade || wp_normalize_path( $real_source ) === wp_normalize_path( $real_upgrade ) || ! Storage::is_within( $local, $upgrade_dir ) ) {
			return;
		}
		// Deleted through the filesystem API with the path it knows (FTP paths on FTP filesystems).
		global $wp_filesystem;
		if ( is_object( $wp_filesystem ) && method_exists( $wp_filesystem, 'delete' ) ) {
			$wp_filesystem->delete( $fs_path, true );
		}
	}

	/**
	 * Where the install was started from.
	 *
	 * @return string wporg | upload | url | cli
	 */
	private function install_source() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'cli';
		}
		// phpcs:disable WordPress.Security.NonceVerification -- read-only, WordPress verifies the install request.
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		if ( ! empty( $_FILES ) || in_array( $action, array( 'upload-plugin', 'upload-theme' ), true ) || isset( $_REQUEST['package'] ) ) {
			return 'upload';
		}
		if ( isset( $_REQUEST['slug'] ) || in_array( $action, array( 'install-plugin', 'install-theme', 'update-plugin', 'update-theme', 'update-selected', 'update-selected-themes', 'do-plugin-upgrade', 'do-theme-upgrade' ), true ) ) {
			return 'wporg';
		}
		// phpcs:enable
		return 'url';
	}

	/**
	 * Message WordPress shows after "Installation failed:".
	 *
	 * @param string $display   Safe display name.
	 * @param bool   $is_update Update or install.
	 * @param int    $severity  Max severity.
	 * @return string
	 */
	private function hold_message( $display, $is_update, $severity ) {
		if ( $severity >= Store::SEV_HIGH ) {
			/* translators: %s: plugin or theme name */
			$message = sprintf( __( '"%s" was held because it contains code that looks unsafe (Qartvelo Guard). An administrator needs to review it.', 'qartvelo-guard' ), $display );
		} elseif ( $is_update ) {
			/* translators: %s: plugin or theme name */
			$message = sprintf( __( 'The update of "%s" is waiting for administrator approval (Qartvelo Guard). After approval, run the update again and it will go through.', 'qartvelo-guard' ), $display );
		} else {
			/* translators: %s: plugin or theme name */
			$message = sprintf( __( '"%s" is waiting for administrator approval (Qartvelo Guard). After approval, install it again and it will go through.', 'qartvelo-guard' ), $display );
		}
		if ( Admin\Admin::can() ) {
			$message .= ' ' . ( is_multisite()
				? __( 'Review it under Network Admin > Qartvelo Guard > Reports.', 'qartvelo-guard' )
				: __( 'Review it under Qartvelo Guard > Reports.', 'qartvelo-guard' ) );
		}
		return $message;
	}

	/**
	 * Package names come from untrusted headers and WordPress prints install
	 * errors without escaping, so only plain characters are kept.
	 *
	 * @param string $name Name.
	 * @return string
	 */
	private static function display_name( $name ) {
		$name = wp_strip_all_tags( (string) $name );
		$name = preg_replace( '/[<>"\'&`\\\\]/', '', $name );
		$name = trim( preg_replace( '/\s+/', ' ', (string) $name ) );
		return '' !== $name ? Upload_Gate::cut( $name, 120 ) : __( 'This package', 'qartvelo-guard' );
	}

	/**
	 * @return string
	 */
	private static function request_uri() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		return Upload_Gate::cut( $uri, 1000 );
	}

	/**
	 * @param string $event   Event.
	 * @param string $message Message.
	 * @param array  $context Context.
	 */
	private function log( $event, $message, array $context = array() ) {
		$logger = wpcybersec()->logger;
		if ( $logger ) {
			$logger->log( $event, $message, $context );
		}
	}
}
