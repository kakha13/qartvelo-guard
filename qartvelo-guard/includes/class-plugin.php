<?php
/**
 * Plugin bootstrap and service container.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Holds one instance of every service. Modules reach each other through
 * wpcybersec()->service_name, so constructors stay cheap and side-effect free.
 */
final class Plugin {

	/** @var Plugin|null */
	private static $instance = null;

	/** @var bool */
	private $booted = false;

	/** @var Settings */
	public $settings;
	/** @var Storage */
	public $storage;
	/** @var Store */
	public $store;
	/** @var Logger */
	public $logger;
	/** @var Allowlist */
	public $allowlist;
	/** @var Quarantine */
	public $quarantine;
	/** @var Decisions */
	public $decisions;
	/** @var Snapshots */
	public $snapshots;
	/** @var Scanner */
	public $scanner;
	/** @var File_Monitor */
	public $file_monitor;
	/** @var Scan_Job */
	public $scan_job;
	/** @var Db_Scanner */
	public $db_scanner;
	/** @var User_Watch */
	public $user_watch;
	/** @var Notifier */
	public $notifier;
	/** @var Upload_Gate */
	public $upload_gate;
	/** @var Install_Gate */
	public $install_gate;
	/** @var Guard_Manager */
	public $guard_manager;
	/** @var Sysadmin_Tools */
	public $sysadmin;
	/** @var Hardening */
	public $hardening;
	/** @var Developer_Instructions */
	public $developer;
	/** @var Hosting */
	public $hosting;
	/** @var Core_Repair */
	public $core_repair;
	/** @var Stats */
	public $stats;
	/** @var Ajax */
	public $ajax;
	/** @var Admin\Admin|null */
	public $admin;

	/**
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Builds services and registers hooks. Runs on plugins_loaded.
	 */
	public function boot() {
		if ( $this->booted ) {
			return;
		}
		$this->booted = true;

		// Core services (no hooks).
		$this->settings   = new Settings();
		$this->storage    = new Storage();
		$this->store      = new Store();
		$this->logger     = new Logger();
		$this->allowlist  = new Allowlist();
		$this->quarantine = new Quarantine();
		$this->decisions  = new Decisions();
		$this->snapshots  = new Snapshots();

		Installer::maybe_upgrade();

		// One-click "turn off the code editor": same effect as the wp-config.php line.
		if ( $this->settings->get( 'disable_file_editor', false ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- WordPress core constant.
		}

		// Feature modules.
		$this->scanner       = new Scanner();
		$this->file_monitor  = new File_Monitor();
		$this->scan_job      = new Scan_Job();
		$this->db_scanner    = new Db_Scanner();
		$this->user_watch    = new User_Watch();
		$this->notifier      = new Notifier();
		$this->upload_gate   = new Upload_Gate();
		$this->install_gate  = new Install_Gate();
		$this->guard_manager = new Guard_Manager();
		$this->sysadmin      = new Sysadmin_Tools();
		$this->hardening     = new Hardening();
		$this->developer     = new Developer_Instructions();
		$this->hosting       = new Hosting();
		$this->core_repair   = new Core_Repair();
		$this->stats         = new Stats();
		$this->ajax          = new Ajax();

		$modules = array(
			$this->snapshots,
			$this->scanner,
			$this->file_monitor,
			$this->scan_job,
			$this->db_scanner,
			$this->user_watch,
			$this->notifier,
			$this->upload_gate,
			$this->install_gate,
			$this->guard_manager,
			$this->sysadmin,
			$this->hardening,
			$this->developer,
			$this->core_repair,
			$this->stats,
			$this->ajax,
		);
		foreach ( $modules as $module ) {
			if ( method_exists( $module, 'register' ) ) {
				$module->register();
			}
		}

		add_action( 'wpcybersec_maintenance', array( $this, 'maintenance' ) );
		if ( Network::is_main() ) {
			if ( ! wp_next_scheduled( 'wpcybersec_maintenance' ) ) {
				wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'wpcybersec_maintenance' );
			}
		} elseif ( is_admin() || wp_doing_cron() ) {
			// Multisite: cron events of the plugin live on the main site only.
			add_action( 'init', array( __NAMESPACE__ . '\\Network', 'clear_site_cron' ), 1 );
		}
		if ( Network::migration_pending() && ( is_admin() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) ) {
			add_action( 'init', array( __NAMESPACE__ . '\\Network', 'migrate_sites' ), 2 );
		}

		if ( is_admin() ) {
			$this->admin = new Admin\Admin();
			$this->admin->register();
		} else {
			add_action(
				'init',
				static function () {
					if ( is_user_logged_in() && Admin\Admin::can() && is_admin_bar_showing() ) {
						( new Admin\Admin() )->register_admin_bar();
					}
				}
			);
		}

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\WP_CLI' ) ) {
			Cli::register();
		} elseif ( wp_doing_cron() ) {
			// wp-cron.php requested by a cron job on the server: proof that real cron runs.
			Sysadmin_Tools::record_wp_cron_request();
		}

		/**
		 * Fires after every service is ready.
		 *
		 * @param Plugin $plugin The container.
		 */
		do_action( 'wpcybersec_booted', $this );
	}

	/**
	 * @return bool
	 */
	public function is_booted() {
		return $this->booted;
	}

	/**
	 * Daily housekeeping: prune the activity log and the stored file copies
	 * nothing refers to any more.
	 */
	public function maintenance() {
		$days = (int) $this->settings->get( 'log_retention_days', 90 );
		if ( $days > 0 ) {
			$this->store->log_prune( $days );
		}
		try {
			$this->snapshots->prune();
		} catch ( \Throwable $e ) {
			$this->logger->log( 'snapshots_prune_failed', $e->getMessage() );
		}
	}
}
