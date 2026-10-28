<?php
/**
 * Hosting control panel detection and panel-specific instructions.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Finds out which hosting control panel, managed host or local development
 * tool runs this site, so every instruction the plugin cannot carry out itself
 * (cron, auto_prepend_file, web server rules, antivirus, the data folder) names
 * the menus of that panel first.
 *
 * Detection only looks at folders, files, constants and environment variables
 * (never runs a program). Every look at the file system goes through the probe,
 * which by default checks Storage::path_allowed() (open_basedir) before an
 * @is_dir() / @is_file(). Tests pass their own probe to fake all of it.
 *
 * Confidence: "high" only when a marker that belongs to that panel matched
 * (its install folder, a constant of the host); site paths alone such as
 * /www/wwwroot/<site> or /home/<user>/web/<domain>/public_html give "likely".
 *
 * The result is cached in the non-autoloaded option CACHE_OPTION and read only
 * on pages that show instructions. The administrator's choice (setting
 * hosting_panel) always wins over detection.
 */
class Hosting {

	/** Non-autoloaded option with the last detection { v, at, result }. */
	const CACHE_OPTION = 'wpcybersec_hosting';

	/** Seconds a detection is reused (12 hours). */
	const CACHE_TTL = 43200;

	/** Version of the detection rules; a change invalidates the cache. */
	const RULES_VERSION = 1;

	/** Setting value for "not listed". */
	const OTHER = 'other';

	/** @var callable|null */
	private $probe;

	/** @var array|null Current result (override applied) for this request. */
	private $current = null;

	/** @var array Probe answers of the last detect(). */
	private $memo = array();

	/** @var bool Whether this request already detected afresh. */
	private $fresh_done = false;

	/**
	 * @param callable|null $probe Optional probe: function ( string $what, string $arg ) returning
	 *                             bool for dir|file|func, a value or null for const|env|server|value.
	 *                             Default: self::default_probe().
	 */
	public function __construct( $probe = null ) {
		$this->probe = is_callable( $probe ) ? $probe : null;
	}

	/* ------------------------------------------------------------------ */
	/* Known panels                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Every known hosting environment: id => { name, kind }. Kind is panel
	 * (a control panel or server manager), managed (managed WordPress host:
	 * server changes go through its own tools or support), local (development
	 * machine) or unknown.
	 *
	 * @return array
	 */
	public static function panels() {
		return array(
			'cpanel'      => array( 'name' => 'cPanel', 'kind' => 'panel' ),
			'plesk'       => array( 'name' => 'Plesk', 'kind' => 'panel' ),
			'directadmin' => array( 'name' => 'DirectAdmin', 'kind' => 'panel' ),
			'cyberpanel'  => array( 'name' => 'CyberPanel', 'kind' => 'panel' ),
			'aapanel'     => array( 'name' => 'aaPanel / BT Panel', 'kind' => 'panel' ),
			'hestia'      => array( 'name' => 'HestiaCP', 'kind' => 'panel' ),
			'vesta'       => array( 'name' => 'VestaCP', 'kind' => 'panel' ),
			'cloudpanel'  => array( 'name' => 'CloudPanel', 'kind' => 'panel' ),
			'cwp'         => array( 'name' => 'CWP (Control Web Panel)', 'kind' => 'panel' ),
			'ispconfig'   => array( 'name' => 'ISPConfig', 'kind' => 'panel' ),
			'virtualmin'  => array( 'name' => 'Virtualmin', 'kind' => 'panel' ),
			'webmin'      => array( 'name' => 'Webmin', 'kind' => 'panel' ),
			'fastpanel'   => array( 'name' => 'FASTPANEL', 'kind' => 'panel' ),
			'ispmanager'  => array( 'name' => 'ISPmanager', 'kind' => 'panel' ),
			'runcloud'    => array( 'name' => 'RunCloud', 'kind' => 'panel' ),
			'gridpane'    => array( 'name' => 'GridPane', 'kind' => 'panel' ),
			'spinupwp'    => array( 'name' => 'SpinupWP', 'kind' => 'panel' ),
			'ploi'        => array( 'name' => 'Ploi', 'kind' => 'panel' ),
			'forge'       => array( 'name' => 'Laravel Forge', 'kind' => 'panel' ),
			'cloudways'   => array( 'name' => 'Cloudways', 'kind' => 'panel' ),
			'hostinger'   => array( 'name' => 'Hostinger (hPanel)', 'kind' => 'panel' ),
			'wpengine'    => array( 'name' => 'WP Engine', 'kind' => 'managed' ),
			'kinsta'      => array( 'name' => 'Kinsta', 'kind' => 'managed' ),
			'siteground'  => array( 'name' => 'SiteGround', 'kind' => 'managed' ),
			'pantheon'    => array( 'name' => 'Pantheon', 'kind' => 'managed' ),
			'pressable'   => array( 'name' => 'Pressable', 'kind' => 'managed' ),
			'flywheel'    => array( 'name' => 'Flywheel', 'kind' => 'managed' ),
			'godaddy'     => array( 'name' => 'GoDaddy Managed WordPress', 'kind' => 'managed' ),
			'wpcom'       => array( 'name' => 'WordPress.com', 'kind' => 'managed' ),
			'localwp'     => array( 'name' => 'Local', 'kind' => 'local' ),
			'ddev'        => array( 'name' => 'DDEV', 'kind' => 'local' ),
			'lando'       => array( 'name' => 'Lando', 'kind' => 'local' ),
			'mamp'        => array( 'name' => 'MAMP', 'kind' => 'local' ),
			'xampp'       => array( 'name' => 'XAMPP', 'kind' => 'local' ),
			'homebrew'    => array( 'name' => 'Homebrew (macOS)', 'kind' => 'local' ),
			'docker'      => array( 'name' => 'Docker', 'kind' => 'local' ),
		);
	}

	/**
	 * Ids the hosting_panel setting accepts besides '' (detect).
	 *
	 * @return string[]
	 */
	public static function ids() {
		return array_merge( array_keys( self::panels() ), array( self::OTHER ) );
	}

	/**
	 * Display name of an id.
	 *
	 * @param string $id Panel id.
	 * @return string
	 */
	public static function name( $id ) {
		$panels = self::panels();
		if ( isset( $panels[ $id ] ) ) {
			return $panels[ $id ]['name'];
		}
		return self::OTHER === $id ? __( 'Other / not listed', 'qartvelo-guard' ) : __( 'Unknown', 'qartvelo-guard' );
	}

	/**
	 * Choices for the select on Settings > Advanced: '' (detected) first.
	 *
	 * @param string $detected Name of the detected panel, for the first option.
	 * @return array value => label
	 */
	public static function choices( $detected = '' ) {
		$groups = array(
			'panel'   => array(),
			'managed' => array(),
			'local'   => array(),
		);
		foreach ( self::panels() as $id => $panel ) {
			$groups[ $panel['kind'] ][ $id ] = $panel['name'];
		}
		$out = array(
			/* translators: %s: detected hosting panel */
			'' => '' !== $detected ? sprintf( __( 'Detect automatically (now: %s)', 'qartvelo-guard' ), $detected ) : __( 'Detect automatically', 'qartvelo-guard' ),
		);
		foreach ( $groups as $group ) {
			asort( $group, SORT_FLAG_CASE | SORT_STRING );
			$out += $group;
		}
		$out[ self::OTHER ] = self::name( self::OTHER );
		return $out;
	}

	/* ------------------------------------------------------------------ */
	/* Probe                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * Asks the probe (memoized per request).
	 *
	 * @param string $what dir | file | func | const | env | server | value.
	 * @param string $arg  Path, name or value key.
	 * @return mixed
	 */
	private function ask( $what, $arg = '' ) {
		$key = $what . "\0" . $arg;
		if ( ! array_key_exists( $key, $this->memo ) ) {
			try {
				$this->memo[ $key ] = call_user_func( $this->probe ? $this->probe : array( __CLASS__, 'default_probe' ), $what, $arg );
			} catch ( \Throwable $e ) {
				$this->memo[ $key ] = null;
			}
		}
		return $this->memo[ $key ];
	}

	/**
	 * The real probe: open_basedir-aware file checks, constants, environment.
	 * Never runs a program.
	 *
	 * @param string $what dir | file | func | const | env | server | value.
	 * @param string $arg  Path, name or value key.
	 * @return mixed
	 */
	public static function default_probe( $what, $arg = '' ) {
		$arg = (string) $arg;
		switch ( $what ) {
			case 'dir':
				return '' !== $arg && Storage::path_allowed( $arg ) && @is_dir( $arg ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- open_basedir checked, may still be unreadable.
			case 'file':
				return '' !== $arg && Storage::path_allowed( $arg ) && @is_file( $arg ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- open_basedir checked, may still be unreadable.
			case 'func':
				return function_exists( $arg );
			case 'const':
				return defined( $arg ) ? constant( $arg ) : null;
			case 'env':
				$value = getenv( $arg );
				if ( false !== $value ) {
					return (string) $value;
				}
				if ( isset( $_SERVER[ $arg ] ) && is_scalar( $_SERVER[ $arg ] ) ) {
					return sanitize_text_field( wp_unslash( (string) $_SERVER[ $arg ] ) );
				}
				if ( isset( $_ENV[ $arg ] ) && is_scalar( $_ENV[ $arg ] ) ) {
					return sanitize_text_field( (string) $_ENV[ $arg ] );
				}
				return null;
			case 'server':
				return isset( $_SERVER[ $arg ] ) && is_scalar( $_SERVER[ $arg ] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER[ $arg ] ) ) : null;
			case 'value':
				return self::default_value( $arg );
		}
		return null;
	}

	/**
	 * Values of the real environment for default_probe().
	 *
	 * @param string $key Value name.
	 * @return mixed
	 */
	private static function default_value( $key ) {
		switch ( $key ) {
			case 'abspath':
				return ABSPATH;
			case 'document_root':
				return isset( $_SERVER['DOCUMENT_ROOT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['DOCUMENT_ROOT'] ) ) : '';
			case 'php_binary':
				return defined( 'PHP_BINARY' ) ? (string) PHP_BINARY : '';
			case 'php_ini':
				$ini     = php_ini_loaded_file();
				$scanned = php_ini_scanned_files();
				$first   = is_string( $scanned ) && '' !== $scanned ? trim( strtok( $scanned, ",\n" ) ) : '';
				return trim( ( is_string( $ini ) ? $ini : '' ) . "\n" . $first );
			case 'sapi':
				return PHP_SAPI;
			case 'os':
				return PHP_OS_FAMILY;
			case 'home':
				if ( function_exists( 'posix_geteuid' ) && function_exists( 'posix_getpwuid' ) ) {
					$info = @posix_getpwuid( posix_geteuid() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
					if ( is_array( $info ) && ! empty( $info['dir'] ) ) {
						return (string) $info['dir'];
					}
				}
				$home = getenv( 'HOME' );
				return is_string( $home ) ? $home : '';
			case 'user':
				return class_exists( __NAMESPACE__ . '\\Developer_Instructions' ) ? Developer_Instructions::web_user() : '';
			case 'web_server':
				return Sysadmin_Tools::server_type();
			case 'litespeed':
				return Guard_Manager::litespeed_edition();
			case 'server_software':
				return isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['SERVER_SOFTWARE'] ) ) : '';
			case 'mu_dir':
				return defined( 'WPMU_PLUGIN_DIR' ) ? (string) WPMU_PLUGIN_DIR : '';
		}
		return '';
	}

	/**
	 * @param mixed $path Path.
	 * @return string Forward slashes, no trailing slash (except "/").
	 */
	private static function norm( $path ) {
		$path = str_replace( '\\', '/', (string) $path );
		$path = preg_replace( '#/+#', '/', $path );
		return '/' === $path ? $path : rtrim( (string) $path, '/' );
	}

	/* ------------------------------------------------------------------ */
	/* Detection                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Runs the detection now (no cache, no override).
	 *
	 * @return array { id, name, kind, confidence high|likely|'', signals[], web_server, web_server_name, php_handler, php_handler_name, all: { id: { high[], likely[] } } }
	 */
	public function detect() {
		$this->memo = array();
		$hits       = array();
		$add        = static function ( $id, $strength, $label ) use ( &$hits ) {
			if ( ! isset( $hits[ $id ] ) ) {
				$hits[ $id ] = array(
					'high'   => array(),
					'likely' => array(),
					'weak'   => array(),
				);
			}
			if ( ! in_array( $label, $hits[ $id ][ $strength ], true ) ) {
				$hits[ $id ][ $strength ][] = $label;
			}
		};

		$abspath = self::norm( $this->ask( 'value', 'abspath' ) );
		$docroot = self::norm( $this->ask( 'value', 'document_root' ) );
		$roots   = array_values( array_unique( array_filter( array( $abspath, $docroot ) ) ) );
		$bins    = array();
		foreach ( array( $this->ask( 'value', 'php_binary' ), $this->ask( 'value', 'php_ini' ) ) as $value ) {
			foreach ( preg_split( '/[\r\n]+/', (string) $value ) as $line ) {
				if ( '' !== trim( $line ) ) {
					$bins[] = self::norm( trim( $line ) );
				}
			}
		}
		$os       = (string) $this->ask( 'value', 'os' );
		$web      = (string) $this->ask( 'value', 'web_server' );
		$edition  = (string) $this->ask( 'value', 'litespeed' );
		$homes    = array();
		$home_raw = self::norm( $this->ask( 'value', 'home' ) );
		if ( '' !== $home_raw && '/' !== $home_raw ) {
			$homes[] = $home_raw;
		}
		foreach ( $roots as $root ) {
			if ( preg_match( '#^(/home\d*/[^/]+)/#', $root . '/', $m ) ) {
				$homes[] = $m[1];
			}
		}
		$homes = array_values( array_unique( $homes ) );

		$in_roots = function ( $pattern ) use ( $roots ) {
			foreach ( $roots as $root ) {
				if ( preg_match( $pattern, $root . '/' ) ) {
					return true;
				}
			}
			return false;
		};
		$in_bins = function ( $pattern ) use ( $bins ) {
			foreach ( $bins as $bin ) {
				if ( preg_match( $pattern, $bin ) ) {
					return true;
				}
			}
			return false;
		};
		$const = function ( $name ) {
			$value = $this->ask( 'const', $name );
			return null !== $value && false !== $value && '' !== $value;
		};
		$env = function ( $name ) {
			$value = $this->ask( 'env', $name );
			return null !== $value && '' !== (string) $value;
		};
		$dir  = function ( $path ) {
			return (bool) $this->ask( 'dir', $path );
		};
		$file = function ( $path ) {
			return (bool) $this->ask( 'file', $path );
		};
		$mu = self::norm( $this->ask( 'value', 'mu_dir' ) );

		// Managed WordPress hosts: their own constants and environment. Files of
		// their mu-plugins alone are only "likely": they travel with site copies.
		$wpe_env = $this->ask( 'env', 'IS_WPE' );
		if ( null !== $wpe_env && '' !== (string) $wpe_env && '0' !== (string) $wpe_env ) {
			$add( 'wpengine', 'high', 'environment variable IS_WPE' );
		}
		if ( $const( 'WPE_APIKEY' ) ) {
			$add( 'wpengine', 'high', 'constant WPE_APIKEY' );
		}
		if ( $this->ask( 'func', 'is_wpe' ) ) {
			$add( 'wpengine', 'likely', 'function is_wpe()' );
		}
		if ( '' !== $mu && $dir( $mu . '/wpengine-common' ) ) {
			$add( 'wpengine', 'likely', 'mu-plugin wpengine-common' );
		}
		if ( $env( 'KINSTA_CACHE_ZONE' ) ) {
			$add( 'kinsta', 'high', 'server variable KINSTA_CACHE_ZONE' );
		}
		if ( $const( 'KINSTAMU_VERSION' ) || $const( 'Kinsta\\KMP\\VERSION' ) ) {
			$add( 'kinsta', 'high', 'Kinsta mu-plugin version constant' );
		}
		if ( '' !== $mu && $dir( $mu . '/kinsta-mu-plugins' ) ) {
			$add( 'kinsta', 'likely', 'mu-plugin kinsta-mu-plugins' );
		}
		// The check SiteGround's own plugins use.
		if ( $dir( '/Z' ) && $file( '/etc/yum.repos.d/baseos.repo' ) ) {
			$add( 'siteground', 'high', '/Z and /etc/yum.repos.d/baseos.repo (SiteGround servers)' );
		}
		$pantheon = $this->ask( 'env', 'PANTHEON_ENVIRONMENT' );
		if ( null !== $pantheon && '' !== (string) $pantheon && 'lando' !== strtolower( (string) $pantheon ) ) {
			$add( 'pantheon', 'high', 'environment variable PANTHEON_ENVIRONMENT' );
		}
		if ( $const( 'IS_PRESSABLE' ) ) {
			$add( 'pressable', 'high', 'constant IS_PRESSABLE' );
		}
		if ( $const( 'FLYWHEEL_CONFIG_DIR' ) ) {
			$add( 'flywheel', 'high', 'constant FLYWHEEL_CONFIG_DIR' );
		}
		foreach ( array( 'WPAAS_SITE_ID', 'WPAAS_V2_SITE_ID' ) as $name ) {
			if ( $env( $name ) ) {
				$add( 'godaddy', 'high', 'environment variable ' . $name );
			}
		}
		if ( $const( 'GD_SYSTEM_PLUGIN_DIR' ) ) {
			$add( 'godaddy', 'high', 'constant GD_SYSTEM_PLUGIN_DIR' );
		}
		if ( '' !== $mu && $file( $mu . '/gd-system-plugin.php' ) ) {
			$add( 'godaddy', 'likely', 'mu-plugin gd-system-plugin.php' );
		}
		$atomic_client = $this->ask( 'const', 'ATOMIC_CLIENT_ID' );
		if ( $const( 'ATOMIC_SITE_ID' ) && null !== $atomic_client ) {
			// Client 2 is WordPress.com; other clients run on the same WP Cloud platform (Pressable is checked first).
			$add( 'wpcom', 2 === (int) $atomic_client ? 'high' : 'likely', 'constants ATOMIC_SITE_ID and ATOMIC_CLIENT_ID' );
		}
		if ( $const( 'WPCOMSH_VERSION' ) ) {
			$add( 'wpcom', 'high', 'constant WPCOMSH_VERSION (wpcomsh mu-plugin)' );
		}

		// Control panels: their install folders (high), site layouts (likely).
		foreach ( array( '/usr/local/cpanel', '/var/cpanel' ) as $path ) {
			if ( $dir( $path ) ) {
				$add( 'cpanel', 'high', $path );
			}
		}
		foreach ( $homes as $home ) {
			if ( $dir( $home . '/.cpanel' ) ) {
				$add( 'cpanel', 'high', $home . '/.cpanel' );
			}
		}
		if ( $in_bins( '#^/opt/cpanel/ea-php\d+/#' ) ) {
			$add( 'cpanel', 'high', 'EasyApache PHP (/opt/cpanel/ea-php)' );
		}
		// CloudLinux runs under cPanel, DirectAdmin and Plesk alike: it only decides when nothing else does.
		if ( $in_bins( '#^/opt/alt/php\d+/#' ) ) {
			$add( 'cpanel', 'weak', 'CloudLinux alt-php (/opt/alt/php)' );
		}
		if ( $file( '/usr/sbin/cagefsctl' ) || $dir( '/etc/cl.selector' ) ) {
			$add( 'cpanel', 'weak', 'CloudLinux (CageFS or PHP Selector)' );
		}

		if ( $dir( '/usr/local/psa' ) ) {
			$add( 'plesk', 'high', '/usr/local/psa' );
		}
		if ( $dir( '/opt/psa' ) ) {
			$add( 'plesk', 'high', '/opt/psa' );
		}
		if ( $in_bins( '#^/opt/plesk/php/#' ) ) {
			$add( 'plesk', 'high', 'Plesk PHP (/opt/plesk/php)' );
		}
		if ( $in_roots( '#^/var/www/vhosts/[^/]+/#' ) ) {
			$add( 'plesk', 'likely', 'site under /var/www/vhosts/<domain>/' );
		}

		if ( $dir( '/usr/local/directadmin' ) ) {
			$add( 'directadmin', 'high', '/usr/local/directadmin' );
		}
		if ( $in_bins( '#^/usr/local/php\d+/lib/php\.ini$#' ) ) {
			$add( 'directadmin', 'likely', 'CustomBuild PHP (/usr/local/phpXX/lib/php.ini)' );
		}
		$hostinger_path = $in_roots( '#^/home/u\d+/domains/[^/]+/public_html/#' );
		if ( ! $hostinger_path && $in_roots( '#^/home/[^/]+/domains/[^/]+/public_html/#' ) ) {
			$add( 'directadmin', 'likely', 'site under /home/<user>/domains/<domain>/public_html' );
		}
		if ( $hostinger_path ) {
			$add( 'hostinger', 'likely', 'site under /home/u<number>/domains/<domain>/public_html' );
		}

		if ( $dir( '/usr/local/CyberCP' ) ) {
			$add( 'cyberpanel', 'high', '/usr/local/CyberCP' );
		}
		$ols = 'openlitespeed' === $edition || $dir( '/usr/local/lsws/bin/openlitespeed' );
		if ( $in_roots( '#^/home/[^/]+\.[^/]+/public_html/#' ) && ( $ols || $in_bins( '#^/usr/local/lsws/lsphp\d+/#' ) ) ) {
			$add( 'cyberpanel', 'likely', 'site under /home/<domain>/public_html on OpenLiteSpeed' );
		}

		if ( $dir( '/www/server/panel' ) ) {
			$add( 'aapanel', 'high', '/www/server/panel' );
		}
		if ( $in_bins( '#^/www/server/php/\d+/#' ) ) {
			$add( 'aapanel', 'high', 'aaPanel PHP (/www/server/php)' );
		}
		if ( $in_roots( '#^/www/wwwroot/[^/]+/#' ) ) {
			$add( 'aapanel', 'likely', 'site under /www/wwwroot/' );
		}

		if ( $dir( '/usr/local/hestia' ) ) {
			$add( 'hestia', 'high', '/usr/local/hestia' );
		}
		if ( $dir( '/usr/local/vesta' ) ) {
			$add( 'vesta', 'high', '/usr/local/vesta' );
		}
		if ( $in_roots( '#^/home/[^/]+/web/[^/]+/public_html/#' ) ) {
			$add( 'hestia', 'likely', 'site under /home/<user>/web/<domain>/public_html' );
		}

		if ( $dir( '/home/clp' ) ) {
			$add( 'cloudpanel', 'high', '/home/clp' );
		}
		if ( $file( '/usr/bin/clpctl' ) || $file( '/usr/local/bin/clpctl' ) ) {
			$add( 'cloudpanel', 'high', 'clpctl (CloudPanel command line)' );
		}
		if ( $in_roots( '#^/home/[^/]+/htdocs/[^/]+/#' ) ) {
			$add( 'cloudpanel', 'likely', 'site under /home/<user>/htdocs/<domain>' );
		}

		if ( $dir( '/usr/local/cwpsrv' ) ) {
			$add( 'cwp', 'high', '/usr/local/cwpsrv' );
		}

		if ( $dir( '/usr/local/ispconfig' ) ) {
			$add( 'ispconfig', 'high', '/usr/local/ispconfig' );
		}
		if ( $in_roots( '#^/var/www/clients/client\d+/web\d+/web/#' ) ) {
			$add( 'ispconfig', 'likely', 'site under /var/www/clients/client<N>/web<N>/web' );
		}

		if ( $dir( '/etc/webmin/virtual-server' ) ) {
			$add( 'virtualmin', 'high', '/etc/webmin/virtual-server' );
		} elseif ( $dir( '/etc/webmin' ) ) {
			$add( 'webmin', 'high', '/etc/webmin' );
		}

		if ( $file( '/usr/local/bin/mogwai' ) ) {
			$add( 'fastpanel', 'high', '/usr/local/bin/mogwai (FASTPANEL command line)' );
		}
		if ( $dir( '/usr/local/fastpanel2' ) ) {
			$add( 'fastpanel', 'high', '/usr/local/fastpanel2' );
		}
		if ( $file( '/usr/local/mgr5/etc/ispmgr.conf' ) ) {
			$add( 'ispmanager', 'high', '/usr/local/mgr5/etc/ispmgr.conf' );
		}
		if ( $in_roots( '#^/var/www/[^/]+/data/www/[^/]+/#' ) ) {
			$add( 'fastpanel', 'likely', 'site under /var/www/<user>/data/www/<domain>' );
			$add( 'ispmanager', 'likely', 'site under /var/www/<user>/data/www/<domain>' );
		}

		foreach ( array( '/RunCloud/Packages', '/etc/nginx-rc', '/etc/php-extra' ) as $path ) {
			if ( $dir( $path ) ) {
				$add( 'runcloud', 'high', $path );
			}
		}
		if ( $in_roots( '#^/home/[^/]+/webapps/[^/]+/#' ) ) {
			$add( 'runcloud', 'likely', 'site under /home/<user>/webapps/<app>' );
		}
		if ( $dir( '/opt/gridpane' ) ) {
			$add( 'gridpane', 'high', '/opt/gridpane' );
		}
		if ( $file( '/usr/local/bin/gp' ) && $in_roots( '#^/var/www/[^/]+/htdocs/#' ) ) {
			$add( 'gridpane', 'high', '/usr/local/bin/gp (GridPane command line)' );
		}
		if ( $in_roots( '#^/var/www/[^/]+/htdocs/#' ) ) {
			$add( 'gridpane', 'likely', 'site under /var/www/<site>/htdocs' );
		}
		if ( $in_roots( '#^/sites/[^/]+/files/#' ) ) {
			$add( 'spinupwp', 'likely', 'site under /sites/<domain>/files' );
		}
		if ( $in_roots( '#^/home/ploi/[^/]+/#' ) ) {
			$add( 'ploi', 'likely', 'site under /home/ploi/' );
		}
		if ( $in_roots( '#^/home/forge/[^/]+/#' ) ) {
			$add( 'forge', 'likely', 'site under /home/forge/' );
		}
		if ( $in_roots( '#^/home/master/applications/[^/]+/public_html/#' ) || $in_roots( '#^/home/\d+\.cloudwaysapps\.com/#' ) ) {
			$add( 'cloudways', 'likely', 'site under /home/master/applications/<app>/public_html' );
		}

		// Local development.
		$ddev = $this->ask( 'env', 'IS_DDEV_PROJECT' );
		if ( null !== $ddev && 'true' === strtolower( (string) $ddev ) ) {
			$add( 'ddev', 'high', 'environment variable IS_DDEV_PROJECT' );
		}
		if ( $env( 'LANDO' ) || $env( 'LANDO_INFO' ) ) {
			$add( 'lando', 'high', 'environment variable LANDO' );
		}
		if ( $in_roots( '#/Local Sites/[^/]+/app/public/#' ) ) {
			$add( 'localwp', 'likely', 'site under "Local Sites/<site>/app/public"' );
		}
		if ( $in_bins( '#/Local/lightning-services/#' ) ) {
			$add( 'localwp', 'likely', 'PHP from Local (lightning-services)' );
		}
		if ( $in_bins( '#^/Applications/MAMP/#' ) || $in_roots( '#^/Applications/MAMP/#' ) ) {
			$add( 'mamp', 'high', '/Applications/MAMP' );
		}
		if ( $in_bins( '#^(/opt/lampp|/Applications/XAMPP|[A-Za-z]:/xampp)/#i' ) || $in_roots( '#^(/opt/lampp|/Applications/XAMPP|[A-Za-z]:/xampp)/#i' ) ) {
			$add( 'xampp', 'high', 'XAMPP folder' );
		}
		if ( 'Darwin' === $os && $in_bins( '#^(/opt/homebrew|/usr/local/Cellar|/usr/local/opt)/#' ) ) {
			$add( 'homebrew', 'high', 'Homebrew PHP on macOS' );
		} elseif ( 'Darwin' === $os ) {
			$add( 'homebrew', 'likely', 'macOS' );
		}
		if ( $file( '/.dockerenv' ) ) {
			$add( 'docker', 'likely', '/.dockerenv' );
		} elseif ( $file( '/run/.containerenv' ) ) {
			$add( 'docker', 'likely', '/run/.containerenv (Podman)' );
		}

		// Winner: the first panel with a high signal (in the order of panels()),
		// else the one with the most likely signals (ties go to the first), else
		// the first with a weak one. A panel-specific marker beats any layout.
		// DDEV and Lando say so in the environment: they win over the files of a
		// managed host's mu-plugins copied along with a site.
		$order  = array_values( array_unique( array_merge( array( 'ddev', 'lando' ), array_keys( self::panels() ) ) ) );
		$winner = '';
		foreach ( $order as $id ) {
			if ( ! empty( $hits[ $id ]['high'] ) ) {
				$winner = $id;
				break;
			}
		}
		$confidence = '' !== $winner ? 'high' : '';
		foreach ( array( 'likely', 'weak' ) as $tier ) {
			if ( '' !== $winner ) {
				break;
			}
			$best = 0;
			foreach ( $order as $id ) {
				$count = isset( $hits[ $id ] ) ? count( $hits[ $id ][ $tier ] ) : 0;
				if ( $count > $best ) {
					$best   = $count;
					$winner = $id;
				}
			}
			$confidence = '' !== $winner ? 'likely' : '';
		}
		$panels  = self::panels();
		$signals = '' !== $winner ? array_merge( $hits[ $winner ]['high'], $hits[ $winner ]['likely'], $hits[ $winner ]['weak'] ) : array();
		$sapi    = (string) $this->ask( 'value', 'sapi' );
		$handler = self::php_handler( $sapi );
		$server  = self::web_server( $web, $edition );

		return array(
			'id'               => '' !== $winner ? $winner : 'unknown',
			'name'             => '' !== $winner ? $panels[ $winner ]['name'] : __( 'Unknown', 'qartvelo-guard' ),
			'kind'             => '' !== $winner ? $panels[ $winner ]['kind'] : 'unknown',
			'confidence'       => $confidence,
			'signals'          => $signals,
			'web_server'       => $server[0],
			'web_server_name'  => $server[1],
			'php_handler'      => $handler[0],
			'php_handler_name' => $handler[1],
			'sapi'             => $sapi,
			'all'              => $hits,
		);
	}

	/**
	 * PHP handler from PHP_SAPI.
	 *
	 * @param string $sapi PHP_SAPI.
	 * @return array { id fpm|lsapi|mod_php|cgi|cli|other, label }
	 */
	public static function php_handler( $sapi ) {
		switch ( (string) $sapi ) {
			case 'fpm-fcgi':
				return array( 'fpm', 'PHP-FPM' );
			case 'litespeed':
				return array( 'lsapi', 'lsphp' );
			case 'apache2handler':
				return array( 'mod_php', 'mod_php' );
			case 'cgi-fcgi':
			case 'cgi':
				return array( 'cgi', 'CGI/FastCGI' );
			case 'cli':
			case 'cli-server':
				return array( 'cli', 'cli' === $sapi ? __( 'command line', 'qartvelo-guard' ) : __( 'built-in server', 'qartvelo-guard' ) );
		}
		return array( 'other', (string) $sapi );
	}

	/**
	 * Web server id and name from Sysadmin_Tools::server_type() and
	 * Guard_Manager::litespeed_edition().
	 *
	 * @param string $type    apache | litespeed | nginx | iis | unknown.
	 * @param string $edition openlitespeed | enterprise | unknown | ''.
	 * @return array { id, name }
	 */
	public static function web_server( $type, $edition = '' ) {
		if ( 'litespeed' === $type || '' !== $edition ) {
			if ( 'openlitespeed' === $edition ) {
				return array( 'openlitespeed', 'OpenLiteSpeed' );
			}
			if ( 'enterprise' === $edition ) {
				return array( 'litespeed', 'LiteSpeed Enterprise' );
			}
			return array( 'litespeed', 'LiteSpeed' );
		}
		$names = array(
			'apache' => 'Apache',
			'nginx'  => 'nginx',
			'iis'    => 'IIS',
		);
		return isset( $names[ $type ] ) ? array( $type, $names[ $type ] ) : array( 'unknown', '' );
	}

	/* ------------------------------------------------------------------ */
	/* Cached result with the administrator's choice                       */
	/* ------------------------------------------------------------------ */

	/**
	 * The hosting this site runs on: the cached detection (refreshed every
	 * CACHE_TTL or with $fresh), with the hosting_panel setting applied.
	 * Only call this on pages that show instructions: it reads a
	 * non-autoloaded option.
	 *
	 * @param bool $fresh Detect again now.
	 * @return array detect() plus { detected_id, detected_name, detected_confidence, overridden (bool), at }
	 */
	public function current( $fresh = false ) {
		if ( null !== $this->current && ( ! $fresh || $this->fresh_done ) ) {
			return $this->current;
		}
		$this->fresh_done = $this->fresh_done || $fresh;
		$found = null;
		$at    = 0;
		if ( ! $this->probe && ! $fresh ) {
			$cache = Network::get_option( self::CACHE_OPTION, array() );
			if ( is_array( $cache ) && isset( $cache['v'], $cache['at'], $cache['result'] ) && self::RULES_VERSION === (int) $cache['v'] && (int) $cache['at'] > time() - self::CACHE_TTL && is_array( $cache['result'] ) ) {
				$found = $cache['result'];
				$at    = (int) $cache['at'];
			}
		}
		if ( null === $found ) {
			$found = $this->detect();
			unset( $found['all'] );
			$at = time();
			if ( ! $this->probe ) {
				Network::update_option(
					self::CACHE_OPTION,
					array(
						'v'      => self::RULES_VERSION,
						'at'     => $at,
						'result' => $found,
					),
					false
				);
			}
		}
		$result = array_merge(
			$found,
			array(
				'detected_id'         => $found['id'],
				'detected_name'       => $found['name'],
				'detected_confidence' => $found['confidence'],
				'overridden'          => false,
				'at'                  => $at,
			)
		);
		$choice = $this->choice();
		if ( '' !== $choice ) {
			$panels               = self::panels();
			$result['overridden'] = true;
			$result['id']         = $choice;
			$result['name']       = self::name( $choice );
			$result['kind']       = isset( $panels[ $choice ] ) ? $panels[ $choice ]['kind'] : 'unknown';
			$result['confidence'] = 'chosen';
		}
		$this->current = $result;
		return $result;
	}

	/**
	 * The administrator's choice ('' = detect).
	 *
	 * @return string
	 */
	private function choice() {
		$settings = function_exists( 'wpcybersec' ) && wpcybersec()->settings ? wpcybersec()->settings : null;
		$choice   = $settings ? (string) $settings->get( 'hosting_panel', '' ) : '';
		return in_array( $choice, self::ids(), true ) ? $choice : '';
	}

	/**
	 * Forgets the result of this request (after the setting changed).
	 */
	public function reset() {
		$this->current = null;
	}

	/**
	 * Id of the hosting the instructions follow ('' when unknown or "other").
	 *
	 * @return string
	 */
	public function id() {
		$current = $this->current();
		return isset( self::panels()[ $current['id'] ] ) ? $current['id'] : '';
	}

	/**
	 * "CyberPanel (OpenLiteSpeed, lsphp)", "Unknown (nginx, PHP-FPM)".
	 *
	 * @param array|null $info current() or detect().
	 * @return string
	 */
	public function label( $info = null ) {
		$info  = is_array( $info ) ? $info : $this->current();
		$parts = array_filter( array( (string) $info['web_server_name'], (string) $info['php_handler_name'] ) );
		$name  = (string) $info['name'];
		if ( $parts && ')' === substr( $name, -1 ) ) {
			// "Homebrew (macOS)" + "built-in server" reads "Homebrew (macOS, built-in server)".
			return substr( $name, 0, -1 ) . ', ' . implode( ', ', $parts ) . ')';
		}
		return $name . ( $parts ? ' (' . implode( ', ', $parts ) . ')' : '' );
	}

	/**
	 * One sentence on how sure the detection is.
	 *
	 * @param array|null $info current().
	 * @return string
	 */
	public function confidence_text( $info = null ) {
		$info = is_array( $info ) ? $info : $this->current();
		if ( ! empty( $info['overridden'] ) ) {
			/* translators: %s: detected hosting panel */
			return sprintf( __( 'Chosen in Settings > Advanced (detected: %s).', 'qartvelo-guard' ), '' !== $info['detected_confidence'] ? $info['detected_name'] : __( 'nothing', 'qartvelo-guard' ) );
		}
		if ( 'high' === $info['confidence'] ) {
			return __( 'Detected from files and settings that belong to it.', 'qartvelo-guard' );
		}
		if ( 'likely' === $info['confidence'] ) {
			return __( 'Likely: the folder layout of the site points to it, but no file that belongs only to this panel was found. Choose the panel in Settings > Advanced if this is wrong.', 'qartvelo-guard' );
		}
		return __( 'No known hosting panel was found. The instructions are generic; choose your panel in Settings > Advanced if it is listed.', 'qartvelo-guard' );
	}

	/**
	 * Settings link to the hosting choice.
	 *
	 * @return string Unescaped URL.
	 */
	public static function change_url() {
		return Sysadmin_Tools::settings_url( 'advanced', array( 'section' => 'health' ), 'wpcs-hosting' );
	}

	/* ------------------------------------------------------------------ */
	/* Panel-specific steps                                                */
	/* ------------------------------------------------------------------ */

	/** Tasks steps() knows. */
	const TASKS = array( 'cron', 'prepend', 'php_restart', 'clamav', 'maldet', 'web_rules', 'data_dir', 'permissions' );

	/**
	 * Steps of one task for the hosting this site runs on, in the step shape
	 * every by-hand instruction uses ({ text, code }). Empty when the panel has
	 * no steps of its own for the task (the generic steps apply then), when
	 * nothing was detected or "Other / not listed" is chosen.
	 *
	 * @param string     $task One of TASKS.
	 * @param array|null $info current() (default).
	 * @return array[]
	 */
	public function steps( $task, $info = null ) {
		$info = is_array( $info ) ? $info : $this->current();
		$id   = isset( $info['id'] ) ? (string) $info['id'] : '';
		if ( ! in_array( $task, self::TASKS, true ) || ! isset( self::panels()[ $id ] ) ) {
			return array();
		}
		try {
			$method = 'steps_' . $task;
			$steps  = $this->$method( $id, $info );
		} catch ( \Throwable $e ) {
			$steps = array();
		}
		/**
		 * Filters the hosting panel steps of one task.
		 *
		 * @param array[] $steps Steps { text, code }.
		 * @param string  $task  Task.
		 * @param string  $id    Panel id.
		 */
		$steps = apply_filters( 'wpcybersec_hosting_steps', $steps, $task, $id );
		return is_array( $steps ) ? array_values( $steps ) : array();
	}

	/**
	 * The panel's steps first, the generic ones folded under "Other ways"
	 * (Settings_Page::render_steps() and Developer_Instructions::as_text()
	 * understand the marker step). For data_dir the panel steps are notes in
	 * front of the generic procedure instead.
	 *
	 * @param string  $task    Task.
	 * @param array[] $generic Generic steps.
	 * @return array[]
	 */
	public function merge( $task, array $generic ) {
		$panel = $this->steps( $task );
		if ( 'prepend' === $task && $panel ) {
			$panel = array_merge( $panel, $this->steps( 'php_restart' ) );
		}
		if ( ! $panel ) {
			return $generic;
		}
		if ( 'data_dir' === $task || ! $generic ) {
			return array_merge( $panel, $generic );
		}
		return array_merge( $panel, array( self::other_ways() ), $generic );
	}

	/**
	 * The hosting panel's own file manager, for steps that upload, extract and
	 * delete files by hand (the core reinstall). Null when the panel has none
	 * or nothing was detected (SFTP steps apply then).
	 *
	 * @param array|null $info current() (default).
	 * @return array|null { name, open, upload, extract, move }
	 */
	public function file_manager( $info = null ) {
		$info = is_array( $info ) ? $info : $this->current();
		$id   = isset( $info['id'] ) ? (string) $info['id'] : '';
		$fm   = static function ( $name, $open, $extract, $move = '' ) {
			return array(
				'name'    => $name,
				'open'    => $open,
				/* translators: %s: file manager name */
				'upload'  => sprintf( __( 'Use the Upload button of %s.', 'qartvelo-guard' ), $name ),
				'extract' => $extract,
				'move'    => '' !== $move ? $move : __( 'Open the new "wordpress" folder, select everything in it and use Move to put it one folder up (into the WordPress folder).', 'qartvelo-guard' ),
			);
		};
		switch ( $id ) {
			case 'cpanel':
				return $fm( 'cPanel File Manager', __( 'In cPanel open Files > File Manager.', 'qartvelo-guard' ), __( 'Right-click the zip file and choose Extract, then confirm the folder shown.', 'qartvelo-guard' ) );
			case 'plesk':
				return $fm( 'Plesk File Manager', __( 'In Plesk open Websites & Domains > Files (File Manager).', 'qartvelo-guard' ), __( 'Open the menu of the zip file and choose Extract Files.', 'qartvelo-guard' ) );
			case 'directadmin':
				return $fm( 'DirectAdmin File Manager', __( 'In DirectAdmin open System Info & Files > File Manager.', 'qartvelo-guard' ), __( 'Select the zip file and choose Extract.', 'qartvelo-guard' ) );
			case 'cyberpanel':
				return $fm( 'CyberPanel File Manager', __( 'In CyberPanel open Websites > List Websites > Manage (this site) > File Manager.', 'qartvelo-guard' ), __( 'Right-click the zip file and choose Extract.', 'qartvelo-guard' ) );
			case 'aapanel':
				return $fm( 'aaPanel Files', __( 'In aaPanel open Files in the left menu.', 'qartvelo-guard' ), __( 'Click Unzip next to the zip file.', 'qartvelo-guard' ), __( 'Open the new "wordpress" folder, select everything, choose Cut and paste it one folder up (into the WordPress folder).', 'qartvelo-guard' ) );
			case 'hestia':
				return $fm( 'HestiaCP File Manager', __( 'In HestiaCP open Files at the top.', 'qartvelo-guard' ), __( 'Select the zip file and choose Extract from the menu.', 'qartvelo-guard' ) );
			case 'vesta':
				return $fm( 'VestaCP File Manager', __( 'In VestaCP open File Manager at the top.', 'qartvelo-guard' ), __( 'Select the zip file and choose Extract.', 'qartvelo-guard' ) );
			case 'cloudpanel':
				return $fm( 'CloudPanel File Manager', __( 'In CloudPanel open the site and choose File Manager.', 'qartvelo-guard' ), __( 'Right-click the zip file and choose Extract.', 'qartvelo-guard' ) );
			case 'cwp':
				return $fm( 'CWP File Manager', __( 'In the CWP user panel open File Management > File Manager.', 'qartvelo-guard' ), __( 'Select the zip file and choose Extract.', 'qartvelo-guard' ) );
			case 'virtualmin':
			case 'webmin':
				return $fm( 'Virtualmin File Manager', __( 'In Virtualmin open Tools > File Manager (Others > File Manager on older versions).', 'qartvelo-guard' ), __( 'Select the zip file and choose Extract from the File menu.', 'qartvelo-guard' ) );
			case 'fastpanel':
				return $fm( 'FASTPANEL File Manager', __( 'In FASTPANEL open the site and choose File Manager.', 'qartvelo-guard' ), __( 'Right-click the zip file and choose Extract.', 'qartvelo-guard' ) );
			case 'ispmanager':
				return $fm( 'ISPmanager File Manager', __( 'In ISPmanager open Files (File manager).', 'qartvelo-guard' ), __( 'Select the zip file and choose Extract.', 'qartvelo-guard' ) );
			case 'hostinger':
				return $fm( 'Hostinger File Manager', __( 'In hPanel open Websites > Manage (this site) > Files > File Manager.', 'qartvelo-guard' ), __( 'Right-click the zip file and choose Extract.', 'qartvelo-guard' ) );
			case 'siteground':
				return $fm( 'SiteGround File Manager', __( 'In Site Tools open Site > File Manager.', 'qartvelo-guard' ), __( 'Right-click the zip file and choose Extract.', 'qartvelo-guard' ) );
		}
		return null;
	}

	/**
	 * Hosts that manage WordPress core themselves (read-only or replaced by
	 * the host): a core reinstall goes through the host's own restore tools.
	 *
	 * @param array|null $info current() (default).
	 * @return string Host name, '' when the host lets the site owner replace core.
	 */
	public function manages_core( $info = null ) {
		$info = is_array( $info ) ? $info : $this->current();
		$id   = isset( $info['id'] ) ? (string) $info['id'] : '';
		return in_array( $id, array( 'wpengine', 'kinsta', 'pantheon', 'wpcom', 'pressable', 'flywheel' ), true ) ? self::name( $id ) : '';
	}

	/**
	 * Marker step: the steps after it are the generic "Other ways".
	 *
	 * @return array
	 */
	public static function other_ways() {
		return array(
			'text'  => __( 'Other ways', 'qartvelo-guard' ),
			'other' => true,
		);
	}

	/**
	 * The auto_prepend_file snippet this panel recommends, for
	 * Guard_Manager::snippets(), or null.
	 *
	 * @return array|null { id, label, file, code, help }
	 */
	public function prepend_snippet() {
		$steps = $this->steps( 'prepend' );
		$code  = '';
		$where = '';
		$help  = array();
		foreach ( $steps as $step ) {
			if ( '' === $code && ! empty( $step['code'] ) ) {
				$code  = (string) $step['code'];
				$where = isset( $step['text'] ) ? (string) $step['text'] : '';
				continue;
			}
			if ( ! empty( $step['text'] ) && '' !== $code ) {
				$help[] = (string) $step['text'];
			}
		}
		if ( '' === $code ) {
			return null;
		}
		foreach ( $this->steps( 'php_restart' ) as $step ) {
			if ( ! empty( $step['text'] ) ) {
				$help[] = (string) $step['text'] . ( ! empty( $step['code'] ) ? ' ' . str_replace( "\n", '; ', (string) $step['code'] ) : '' );
			}
		}
		$info = $this->current();
		return array(
			'id'    => 'panel',
			/* translators: %s: hosting panel name */
			'label' => sprintf( __( '%s (this site\'s hosting panel)', 'qartvelo-guard' ), $info['name'] ),
			'file'  => rtrim( $where, ': ' ),
			'code'  => $code,
			'help'  => implode( ' ', $help ),
		);
	}

	/* ------------------------------------------------------------------ */

	/**
	 * Values the steps use.
	 *
	 * @return array
	 */
	private function ctx() {
		$abspath = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$plugin  = function_exists( 'wpcybersec' ) ? wpcybersec() : null;
		$gm      = $plugin && $plugin->guard_manager ? $plugin->guard_manager : null;
		$boot    = $gm && method_exists( $gm, 'bootstrap_path' ) ? wp_normalize_path( $gm->bootstrap_path() ) : $abspath . '/wpcybersec-guard.php';
		$front   = $gm && method_exists( $gm, 'front_root' ) ? (string) $gm->front_root() : '';
		$dirs    = array( $abspath );
		if ( '' !== $front ) {
			$dirs[] = untrailingslashit( wp_normalize_path( $front ) );
		}
		$storage = $plugin && $plugin->storage ? $plugin->storage : new Storage();
		$home    = (string) wp_parse_url( Network::home_url(), PHP_URL_PATH );
		$user    = Developer_Instructions::web_user();
		$domain  = (string) wp_parse_url( Network::home_url(), PHP_URL_HOST );
		// Panel layouts name the account and the domain in the path: /home/<user>/web/<domain>/public_html
		// (Hestia, Vesta), /home/<user>/domains/<domain>/public_html (DirectAdmin), /home/<user>/public_html.
		$acct = preg_match( '#^/home\d*/([a-z0-9_][a-z0-9._-]*)/#i', $abspath . '/', $m ) && false === strpos( $m[1], '.' ) ? $m[1] : $user;
		$site = preg_match( '#^/home\d*/[^/]+/(?:web|domains)/([^/]+)/public_html/#', $abspath . '/', $m ) ? $m[1] : $domain;
		return array(
			'abspath'  => $abspath,
			'boot'     => $boot,
			'dirs'     => $dirs,
			'domain'   => $domain,
			'user'     => $user,
			'acct'     => $acct,
			'site'     => $site,
			'ver'      => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
			'ver_nd'   => PHP_MAJOR_VERSION . PHP_MINOR_VERSION,
			'data'     => $storage->data_dir(),
			'target'   => $storage->suggested_outside_dir(),
			'in_root'  => $storage->is_in_webroot( $storage->data_dir() ),
			'home'     => '/' . trim( $home, '/' ) . ( '' !== trim( $home, '/' ) ? '/' : '' ),
			'sh_boot'  => Sysadmin_Tools::shell_arg( $boot ),
		);
	}

	/**
	 * @param string $text Text.
	 * @param string $code Code.
	 * @return array
	 */
	private static function s( $text, $code = '' ) {
		return '' !== $code ? array(
			'text' => $text,
			'code' => $code,
		) : array( 'text' => $text );
	}

	/**
	 * CyberPanel and OpenLiteSpeed: the server's default php (and so wp) can be
	 * another PHP version than the site's lsphp. Other plugins' composer
	 * platform_check then stops WP-CLI with a fatal error, so WP-CLI runs with
	 * the site's own PHP binary (Sysadmin_Tools::wp_cli()).
	 *
	 * @return array { text, code }
	 */
	private static function wp_cli_note() {
		$bin = Sysadmin_Tools::php_binary();
		$wp  = Sysadmin_Tools::wp_cli_path();
		$cmd = 'php' === $bin ? 'wp' : Sysadmin_Tools::shell_arg( $bin ) . ' ' . ( '' !== $wp ? Sysadmin_Tools::shell_arg( $wp ) : '"$(command -v wp)"' );
		return self::s(
			__( 'WP-CLI: the server\'s default php (and with it wp) can be another PHP version than this site\'s lsphp, and plugins that need this PHP version then stop WP-CLI with a fatal error (composer platform_check). Start WP-CLI with the site\'s own PHP, as the commands of this plugin do:', 'qartvelo-guard' ),
			$cmd . ' --path=' . Sysadmin_Tools::shell_arg( untrailingslashit( wp_normalize_path( ABSPATH ) ) ) . ' core version'
		);
	}

	/**
	 * The three real cron jobs (Sysadmin_Tools::cron_jobs(), the one source),
	 * one step each, plus switching WP-Cron off.
	 *
	 * @param array[] $intro      Steps before the jobs.
	 * @param bool    $split      Show script and arguments apart (Plesk "Run a PHP script").
	 * @param bool    $scans_only Only the two scan jobs: the host already runs WordPress
	 *                            cron itself (GridPane GP-Cron, SpinupWP), so neither the
	 *                            WordPress cron job nor switching WP-Cron off is shown.
	 * @return array[]
	 */
	private static function cron_steps( array $intro, $split = false, $scans_only = false ) {
		$steps = $intro;
		foreach ( Sysadmin_Tools::cron_jobs() as $job ) {
			if ( $scans_only && 'wp_cron' === $job['id'] ) {
				continue;
			}
			if ( $split ) {
				if ( '' !== $job['url'] ) {
					/* translators: 1: what the job does and when, 2: cron schedule */
					$steps[] = self::s( sprintf( __( '%1$s. Schedule: %2$s. Task type "Fetch a URL", URL:', 'qartvelo-guard' ), $job['when'], $job['schedule'] ), $job['url'] );
					continue;
				}
				// Plesk takes the script path relative to the subscription folder.
				$script = preg_replace( '#^/var/www/vhosts/[^/]+/#', '', $job['script'] );
				/* translators: 1: what the job does and when, 2: cron schedule */
				$steps[] = self::s( sprintf( __( '%1$s. Schedule: %2$s. Task type "Run a PHP script", script path (in the subscription folder):', 'qartvelo-guard' ), $job['when'], $job['schedule'] ), $script );
				if ( '' !== $job['args'] ) {
					$steps[] = self::s( __( 'With these arguments:', 'qartvelo-guard' ), $job['args'] );
				}
				continue;
			}
			/* translators: 1: what the job does and when, 2: cron schedule */
			$steps[] = self::s( sprintf( __( '%1$s. Schedule: %2$s. Command:', 'qartvelo-guard' ), $job['when'], $job['schedule'] ), $job['command'] );
		}
		if ( ! $scans_only ) {
			$steps[] = Sysadmin_Tools::cron_disable_step();
		}
		return $steps;
	}

	/**
	 * What a managed host lets customers do, for every task.
	 *
	 * @param string $id   Host id.
	 * @param string $task cron | prepend | web_rules | clamav.
	 * @return array[]
	 */
	private function managed_steps( $id, $task ) {
		$name  = self::name( $id );
		$c     = $this->ctx();
		$tools = function_exists( 'wpcybersec' ) && wpcybersec()->sysadmin ? wpcybersec()->sysadmin : new Sysadmin_Tools();
		$nginx = Sysadmin_Tools::nginx_uploads_block();
		if ( $c['in_root'] ) {
			$nginx .= "\n" . $tools->nginx_data_rule();
		}
		$cli   = Sysadmin_Tools::wp_cli();
		$wpcli = $cli . " wpcybersec scan --quiet\n" . $cli . ' wpcybersec scan --full --quiet';
		$ping  = Network::home_url( 'wp-cron.php?doing_wp_cron' );
		/* translators: %s: host name */
		$support = sprintf( __( '%s manages the server, so this cannot be set from the site. Ask its support whether they can do it for you, or skip it: the plugin keeps protecting the site without it.', 'qartvelo-guard' ), $name );
		$key     = $id . ':' . $task;
		switch ( $key ) {
			case 'wpengine:cron':
				return array( self::s( __( 'WP Engine has no server cron jobs. Switch on Alternate Cron instead: User Portal > this environment > Utilities > Alternate cron. It runs due WordPress cron events every minute, which includes the scheduled scans of this plugin.', 'qartvelo-guard' ) ) );
			case 'wpengine:web_rules':
				return array( self::s( __( 'The Web Rules of the WP Engine User Portal cover IP rules, headers and redirects only. Ask WP Engine support to add this nginx rule for the site:', 'qartvelo-guard' ), $nginx ) );
			case 'wpengine:clamav':
				return array( self::s( __( 'ClamAV cannot be installed at WP Engine. WP Engine support runs a malware scan and cleanup on request.', 'qartvelo-guard' ) ) );
			case 'kinsta:cron':
				return self::cron_steps( array( self::s( __( 'Kinsta sites have their own crontab: connect with SSH and run crontab -e, then add the jobs below (5 minutes is the shortest interval), or ask Kinsta support to add them.', 'qartvelo-guard' ) ) ) );
			case 'kinsta:web_rules':
				return array( self::s( __( 'Kinsta does not use .htaccess and customers cannot edit nginx. Ask Kinsta support to add this rule for the site:', 'qartvelo-guard' ), $nginx ) );
			case 'kinsta:clamav':
				return array( self::s( __( 'ClamAV cannot be installed at Kinsta. Kinsta removes malware for eligible sites; ask its support for a scan.', 'qartvelo-guard' ) ) );
			case 'siteground:cron':
				return self::cron_steps( array( self::s( __( 'In SiteGround Site Tools open Devs > Cron Jobs and add one job per line below.', 'qartvelo-guard' ) ) ) );
			case 'siteground:prepend':
				return array( self::s( __( 'SiteGround sets PHP values in Site Tools > Devs > PHP Manager > PHP Variables. If auto_prepend_file is not offered there, ask SiteGround support to set it for the site to:', 'qartvelo-guard' ), $c['boot'] ) );
			case 'siteground:web_rules':
				return array( self::s( __( 'SiteGround runs Apache, which reads .htaccess: use the "Write uploads/.htaccess for me" button (Settings > Advanced > Web server), or add these lines to wp-content/uploads/.htaccess with File Manager:', 'qartvelo-guard' ), $tools->apache_uploads_rules() ) );
			case 'siteground:clamav':
				return array( self::s( __( 'ClamAV cannot be installed on SiteGround. Its Site Scanner add-on scans the site\'s files.', 'qartvelo-guard' ) ) );
			case 'pantheon:cron':
				return array( self::s( __( 'Pantheon runs WordPress cron itself (every hour, or on demand with Terminus) and its configuration switches off WP-Cron on page visits, so the scheduled scans run with it. Customers cannot add crontab lines; for more frequent scans let an external service fetch this address every few minutes:', 'qartvelo-guard' ), $ping ) );
			case 'pantheon:web_rules':
				return array( self::s( __( 'Pantheon ignores .htaccess files and its nginx configuration cannot be changed per site, so this rule cannot be added there.', 'qartvelo-guard' ) ) );
			case 'pressable:cron':
				return array( self::s( __( 'In MyPressable open Site Tools > Cron Jobs and add the quick scan as an hourly job and the full scan as a daily job, for example with these WP-CLI commands:', 'qartvelo-guard' ), $wpcli ) );
			case 'pressable:clamav':
				return array( self::s( __( 'ClamAV cannot be installed at Pressable. Jetpack Scan is included with every Pressable plan: switch it on for a second opinion.', 'qartvelo-guard' ) ) );
			case 'flywheel:cron':
				return array( self::s( __( 'Flywheel does not allow server cron jobs. Let an external service fetch this address every few minutes instead; it runs the scheduled scans with the rest of WordPress cron:', 'qartvelo-guard' ), $ping ) );
			case 'flywheel:prepend':
				return array( self::s( __( 'Flywheel locks the server configuration and wp-config.php. Ask Flywheel support whether they can set auto_prepend_file for the site to:', 'qartvelo-guard' ), $c['boot'] ) );
			case 'flywheel:web_rules':
				return array( self::s( __( 'Flywheel ignores .htaccess files; its support translates such rules for the server. Ask them to add:', 'qartvelo-guard' ), $nginx ) );
			case 'godaddy:prepend':
				/* translators: %s: file path */
				return array( self::s( sprintf( __( 'GoDaddy Managed WordPress reads a .user.ini file in the site root for per-folder PHP settings. Create %s and put this line in it:', 'qartvelo-guard' ), $c['dirs'][0] . '/.user.ini' ), 'auto_prepend_file = "' . $c['boot'] . '"' ) );
			case 'godaddy:web_rules':
				return array( self::s( __( 'GoDaddy Managed WordPress is moving to nginx, which reads only the .htaccess file in the site root, so a rule in uploads/.htaccess may be ignored. Ask GoDaddy support to block PHP in wp-content/uploads.', 'qartvelo-guard' ) ) );
			case 'wpcom:cron':
				return array( self::s( __( 'On a Business plan or higher open Settings > Cron (server cron jobs) and add the quick scan as an hourly job and the full scan as a daily job with these WP-CLI commands:', 'qartvelo-guard' ), $wpcli ) );
			case 'wpcom:clamav':
				return array( self::s( __( 'ClamAV cannot be installed on WordPress.com. Jetpack Scan is included with the plan: switch it on for a second opinion.', 'qartvelo-guard' ) ) );
		}
		return array( self::s( $support ) );
	}

	/* ---------- cron ---------- */

	/**
	 * @param string $id   Panel id.
	 * @param array  $info current().
	 * @return array[]
	 */
	private function steps_cron( $id, array $info ) {
		unset( $info );
		$c = $this->ctx();
		switch ( $id ) {
			case 'cpanel':
				return self::cron_steps(
					array(
						self::s( __( 'In cPanel open Advanced > Cron Jobs. If it is missing, your host has switched it off: send them the jobs below.', 'qartvelo-guard' ) ),
						self::s( __( 'Under "Add New Cron Job" enter the schedule of each job (or pick it under Common Settings), paste its command and click "Add New Cron Job". The jobs run as your cPanel account user, the owner of the site files.', 'qartvelo-guard' ) ),
					)
				);
			case 'directadmin':
				return self::cron_steps(
					array(
						self::s( __( 'In DirectAdmin, at User Level, open Cronjobs (Cron Jobs) and add the jobs below. DirectAdmin puts them in the crontab of your DirectAdmin user, the owner of the site files.', 'qartvelo-guard' ) ),
					)
				);
			case 'plesk':
				return self::cron_steps(
					array(
						self::s( __( 'In Plesk open Websites & Domains > Scheduled Tasks > Add Task. Tasks run as the system user of the subscription, the owner of the site files.', 'qartvelo-guard' ) ),
						self::s( __( 'The "Run a command" type uses a chrooted shell by default that may not find PHP, so add the scans as "Run a PHP script": enter the script path and the arguments shown, and pick the PHP version of the site.', 'qartvelo-guard' ) ),
					),
					true
				);
			case 'cyberpanel':
				return self::cron_steps(
					array(
						/* translators: %s: domain */
						self::s( sprintf( __( 'In CyberPanel open Websites > List Websites, click Manage next to %s and open Cron Jobs. The jobs run as the site\'s own user, the owner of the site files.', 'qartvelo-guard' ), $c['domain'] ) ),
						self::wp_cli_note(),
					)
				);
			case 'aapanel':
				return self::cron_steps(
					array(
						self::s( __( 'In aaPanel open Cron > Add Task, type "Shell Script". Set "Execute user" to the user that owns the site files (www on aaPanel); the default, root, would create files PHP cannot change later.', 'qartvelo-guard' ) ),
						self::s( __( 'Add one task per job below: pick the period that matches the schedule and paste the command as the script content.', 'qartvelo-guard' ) ),
					)
				);
			case 'hestia':
			case 'vesta':
				return self::cron_steps(
					array(
						/* translators: %s: panel name */
						self::s( sprintf( __( 'Log in to %s as the user that owns this site, open the Cron tab and add a job for each line below. Jobs run as that user.', 'qartvelo-guard' ), self::name( $id ) ) ),
					)
				);
			case 'cloudpanel':
				return self::cron_steps(
					array(
						self::s( __( 'In CloudPanel open this site and its Cron Jobs tab. Add a job for each line below (enter the schedule or pick a template, then the command). They run as the site user, the owner of the site files.', 'qartvelo-guard' ) ),
					)
				);
			case 'cwp':
				return self::cron_steps(
					array(
						self::s( __( 'In the CWP user panel of the account that owns this site, open the cron jobs page and add the jobs below. They run as that account user.', 'qartvelo-guard' ) ),
					)
				);
			case 'fastpanel':
				return self::cron_steps(
					array(
						self::s( __( 'In FASTPANEL open Control > Scheduler and add one task per line below, for the user that owns the site.', 'qartvelo-guard' ) ),
					)
				);
			case 'ispmanager':
				return self::cron_steps(
					array(
						self::s( __( 'In ISPmanager open the CRON jobs (Scheduler) of the user that owns the site and add one job per line below.', 'qartvelo-guard' ) ),
					)
				);
			case 'ispconfig':
				return self::cron_steps(
					array(
						self::s( __( 'In ISPConfig open Sites > Command Line > Cron Jobs and add a job for each line below, for this website. ISPConfig runs them as the website\'s own system user (web<N>).', 'qartvelo-guard' ) ),
					)
				);
			case 'virtualmin':
			case 'webmin':
				return self::cron_steps(
					array(
						/* translators: %s: user name */
						self::s( sprintf( __( 'In Webmin open System > Scheduled Cron Jobs > "Create a new scheduled cron job". Set "Execute cron job as" to the user that owns the site files (%s here) and add one job per line below.', 'qartvelo-guard' ), $c['user'] ) ),
					)
				);
			case 'runcloud':
				return self::cron_steps(
					array(
						/* translators: %s: user name */
						self::s( sprintf( __( 'In RunCloud open the server, then Cron Job > Add New Job. Pick the web application\'s owner (%s here) as the user, choose "Write your own, inside command" as the vendor binary and add one job per line below.', 'qartvelo-guard' ), $c['user'] ) ),
					)
				);
			case 'gridpane':
				return self::cron_steps(
					array(
						self::s( __( 'GridPane runs WordPress cron itself (GP-Cron, on by default on newer servers), so only the two scan jobs are needed. GridPane has no panel field for custom jobs: as the site\'s system user run "crontab -e" over SSH and add the scan lines below.', 'qartvelo-guard' ) ),
					),
					false,
					true
				);
			case 'spinupwp':
				return self::cron_steps(
					array(
						self::s( __( 'SpinupWP already runs WordPress cron for the site (site dashboard > Cron), so only the two scan jobs are needed. Add them with "crontab -e" as the site user over SSH, below the lines SpinupWP manages (do not change those).', 'qartvelo-guard' ) ),
					),
					false,
					true
				);
			case 'ploi':
				return self::cron_steps(
					array(
						self::s( __( 'In Ploi open the server, then Cron jobs, and add one job per line below with the user that owns the site (usually ploi).', 'qartvelo-guard' ) ),
					)
				);
			case 'forge':
				return self::cron_steps(
					array(
						self::s( __( 'In Forge open the server (or the site), then Processes > Scheduler > "Add scheduled job". Choose the user that owns the site (forge, or the isolated site user), a custom frequency, and add one job per line below.', 'qartvelo-guard' ) ),
					)
				);
			case 'cloudways':
				return self::cron_steps(
					array(
						self::s( __( 'In Cloudways open the application, then Cron Job Management, and add one job per line below (Advanced tab for your own commands).', 'qartvelo-guard' ) ),
					)
				);
			case 'hostinger':
				return self::cron_steps(
					array(
						self::s( __( 'In hPanel open the website dashboard, then Advanced > Cron Jobs, choose the type Custom and add one job per line below. hPanel shows the times in UTC.', 'qartvelo-guard' ) ),
					)
				);
			case 'ddev':
				return self::cron_steps( array( self::s( __( 'On a development machine the scheduled scans can run with WP-Cron on page visits. For real cron jobs inside DDEV, start the commands below from a web_extra_daemons entry in .ddev/config.yaml, or from your computer with "ddev exec".', 'qartvelo-guard' ) ) ) );
		}
		$panels = self::panels();
		if ( 'managed' === $panels[ $id ]['kind'] ) {
			return $this->managed_steps( $id, 'cron' );
		}
		return array();
	}

	/* ---------- prepend ---------- */

	/**
	 * auto_prepend_file for the early guard.
	 *
	 * @param string $id   Panel id.
	 * @param array  $info current().
	 * @return array[]
	 */
	private function steps_prepend( $id, array $info ) {
		$c    = $this->ctx();
		$ini  = 'auto_prepend_file = "' . $c['boot'] . '"';
		$fpm  = 'php_admin_value[auto_prepend_file] = ' . $c['boot'];
		$both = count( $c['dirs'] ) > 1
			/* translators: %s: folder list */
			? ' ' . sprintf( __( 'The site\'s front controller is in another folder, so do it for both: %s.', 'qartvelo-guard' ), implode( ', ', $c['dirs'] ) )
			: '';
		switch ( $id ) {
			case 'cpanel':
				return array(
					self::s( __( 'In cPanel open Software > MultiPHP INI Editor, switch to Editor Mode and select the domain of this site.', 'qartvelo-guard' ) . $both ),
					self::s( __( 'Add this line at the end and click Save:', 'qartvelo-guard' ), $ini ),
					self::s( __( 'cPanel writes it into that folder\'s php.ini, .user.ini and .htaccess, wherever the PHP handler of the site reads it, so it works with PHP-FPM, CGI and LiteSpeed alike.', 'qartvelo-guard' ) ),
				);
			case 'directadmin':
				return array(
					/* translators: %s: domain */
					self::s( sprintf( __( 'As the DirectAdmin administrator open Admin Level > Custom HTTPD Configurations, choose %s, then the php-fpm configuration. Add this line in the second text area (CUSTOM2) and save:', 'qartvelo-guard' ), $c['domain'] ), $fpm ),
					/* translators: %s: file path */
					self::s( sprintf( __( 'Without administrator access, create %s with File Manager (DirectAdmin reads .user.ini files by default) and put this line in it:', 'qartvelo-guard' ), $c['dirs'][0] . '/.user.ini' ), $ini ),
				);
			case 'plesk':
				return array(
					/* translators: %s: domain */
					self::s( sprintf( __( 'As the Plesk administrator open Websites & Domains > %s > PHP Settings. In "Additional directives" add this line and click OK (customers cannot edit this field: ask your host):', 'qartvelo-guard' ), $c['domain'] ), $ini ),
					self::s( __( 'The same from the command line, with the line saved in a file:', 'qartvelo-guard' ), 'echo ' . Sysadmin_Tools::shell_arg( $ini ) . " > /root/qartvelo-guard-php.ini\nplesk bin site --update-php-settings " . Sysadmin_Tools::shell_arg( $c['domain'] ) . ' -additional-settings /root/qartvelo-guard-php.ini' ),
				);
			case 'cyberpanel':
				return array(
					/* translators: %s: domain */
					self::s( sprintf( __( 'In CyberPanel open Websites > List Websites, click Manage next to %s and open "vHost Conf". Find the phpIniOverride block and put this line inside its braces, then Save (CyberPanel restarts OpenLiteSpeed):', 'qartvelo-guard' ), $c['domain'] ), "phpIniOverride  {\nphp_value auto_prepend_file " . $c['boot'] . "\n}" ),
					self::s( __( 'Keep any php_admin_value open_basedir line already in that block. Switching "open_basedir Protection" in CyberPanel rewrites this file, so check the line is still there afterwards.', 'qartvelo-guard' ) ),
				);
			case 'aapanel':
				$file = $c['dirs'][0] . '/.user.ini';
				return array(
					/* translators: %s: file path */
					self::s( sprintf( __( 'aaPanel keeps its own %s (with the open_basedir line of the site) and locks it with chattr +i, so PHP and File Manager cannot change it. As root, unlock it, add the line and lock it again; keep the open_basedir line:', 'qartvelo-guard' ), $file ), 'chattr -i ' . Sysadmin_Tools::shell_arg( $file ) . "\ngrep -q '^auto_prepend_file' " . Sysadmin_Tools::shell_arg( $file ) . ' || echo ' . Sysadmin_Tools::shell_arg( 'auto_prepend_file=' . $c['boot'] ) . ' >> ' . Sysadmin_Tools::shell_arg( $file ) . "\nchattr +i " . Sysadmin_Tools::shell_arg( $file ) . "\ncat " . Sysadmin_Tools::shell_arg( $file ) ),
					self::s( __( 'Switching "Anti-XSS attack" (Website > this site > Site directory) off and on again writes the file anew with only the open_basedir line: add the guard line again afterwards.', 'qartvelo-guard' ) . $both ),
				);
			case 'hestia':
				// One template per site: the guard line names this site's bootstrap, so
				// two sites of one server must not share (and overwrite) one template.
				$tpl = 'qartvelo-guard-' . preg_replace( '/[^A-Za-z0-9_-]+/', '-', $c['site'] );
				return array(
					self::s( __( 'As root, copy the PHP-FPM backend template the domain uses (shown in Web > edit domain > Backend Template; set TPL to it) under a new name and add the guard line to the copy. Hestia overwrites its own templates on updates, never a copy:', 'qartvelo-guard' ), "cd /usr/local/hestia/data/templates/web/php-fpm\nTPL=default\ncp \"\$TPL.tpl\" " . $tpl . ".tpl\necho " . Sysadmin_Tools::shell_arg( $fpm ) . ' >> ' . $tpl . '.tpl' ),
					/* translators: 1: template name, 2: domain */
					self::s( sprintf( __( 'Pick "%1$s" as the Backend Template of %2$s in Web > edit domain, or run (Hestia restarts PHP-FPM itself):', 'qartvelo-guard' ), $tpl, $c['site'] ), 'v-change-web-domain-backend-tpl ' . Sysadmin_Tools::shell_arg( $c['acct'] ) . ' ' . Sysadmin_Tools::shell_arg( $c['site'] ) . ' ' . $tpl ),
					/* translators: %s: file path */
					self::s( sprintf( __( 'Without root: put this line in %s instead:', 'qartvelo-guard' ), $c['dirs'][0] . '/.user.ini' ), $ini ),
				);
			case 'vesta':
				return array(
					/* translators: %s: file path */
					self::s( sprintf( __( 'VestaCP\'s PHP-FPM pools read .user.ini files: create %s and put this line in it:', 'qartvelo-guard' ), $c['dirs'][0] . '/.user.ini' ) . $both, $ini ),
				);
			case 'cloudpanel':
				return array(
					self::s( __( 'In CloudPanel open this site, then Settings > PHP Settings. Add this line to "Additional Configuration Directives" (one setting per line, like the lines already there) and save:', 'qartvelo-guard' ), 'auto_prepend_file=' . $c['boot'] . ';' ),
				);
			case 'cwp':
				return array(
					self::s( __( 'In the CWP user panel use "Edit php.ini" for this domain (it writes php.ini and .user.ini in the site folder) and add this line:', 'qartvelo-guard' ), $ini ),
				);
			case 'ispconfig':
				return array(
					self::s( __( 'In ISPConfig open Sites > this website > Options and add this line to "Custom php.ini settings", then Save. With PHP-FPM ISPConfig writes it into the site\'s pool as php_admin_value and reloads PHP-FPM itself:', 'qartvelo-guard' ), 'auto_prepend_file = ' . $c['boot'] ),
				);
			case 'virtualmin':
				return array(
					self::s( __( 'In Virtualmin select this domain, open Web Configuration > PHP-FPM Configuration (PHP-FPM mode) and add this line to the pool, then save and reload PHP-FPM:', 'qartvelo-guard' ), $fpm ),
					self::s( __( 'In FCGI or CGI mode use Web Configuration > PHP Configuration (the domain\'s own php.ini) and add:', 'qartvelo-guard' ), $ini ),
				);
			case 'runcloud':
				$app = basename( $c['abspath'] );
				return array(
					/* translators: %s: file path */
					self::s( sprintf( __( 'As root, add the line to the extra PHP-FPM settings of this web application (%s), which RunCloud keeps across updates:', 'qartvelo-guard' ), '/etc/php-extra/' . $app . '.conf' ), 'echo ' . Sysadmin_Tools::shell_arg( $fpm ) . ' >> ' . Sysadmin_Tools::shell_arg( '/etc/php-extra/' . $app . '.conf' ) ),
				);
			case 'spinupwp':
				return array(
					/* translators: %s: file path */
					self::s( sprintf( __( 'As root (sudo), add this line at the end of the site\'s PHP-FPM pool, %s:', 'qartvelo-guard' ), '/etc/php/' . $c['ver'] . '/fpm/pool.d/' . $c['user'] . '.conf' ), $fpm ),
				);
			case 'forge':
				return array(
					/* translators: %s: PHP version */
					self::s( sprintf( __( 'In Forge open the server, then PHP, choose PHP %s and "Edit PHP-FPM configuration". It applies to every site of that PHP version on the server; for this site alone use .user.ini (Other ways). Add:', 'qartvelo-guard' ), $c['ver'] ), $fpm ),
				);
			case 'ploi':
				return array(
					/* translators: %s: file path */
					self::s( sprintf( __( 'Ploi\'s "Edit FPM ini" (server > PHP) changes every site of that PHP version, so for this site create %s and put this line in it:', 'qartvelo-guard' ), $c['dirs'][0] . '/.user.ini' ), $ini ),
				);
			case 'cloudways':
				return array(
					self::s( __( 'In Cloudways open the application, then Application Settings > PHP Settings (older panels: PHP-FPM Settings), add this line and save:', 'qartvelo-guard' ), $fpm ),
				);
			case 'ddev':
				return array(
					self::s( __( 'DDEV loads extra PHP settings from .ddev/php/*.ini in the project. Create .ddev/php/qartvelo-guard.ini with this line, then run ddev restart:', 'qartvelo-guard' ), 'auto_prepend_file = "' . $c['boot'] . '"' ),
				);
			case 'hostinger':
				return array(
					/* translators: %s: file path */
					self::s( sprintf( __( 'hPanel\'s PHP Configuration has no field for this setting; Hostinger sets other PHP values with php_value lines in .htaccess (its servers run LiteSpeed). Add this to %s, above the WordPress block:', 'qartvelo-guard' ), $c['dirs'][0] . '/.htaccess' ), "<IfModule LiteSpeed>\n    php_value auto_prepend_file \"" . $c['boot'] . "\"\n</IfModule>" ),
					self::s( __( 'If Settings > Advanced > Early guard still says "Active in this request: No" after a few minutes, ask Hostinger support to set auto_prepend_file for the site.', 'qartvelo-guard' ) ),
				);
			case 'gridpane':
				return array(
					/* translators: %s: file path */
					self::s( sprintf( __( 'The PHP tab of GridPane\'s site customizer offers a fixed set of settings without this one. PHP-FPM reads .user.ini files: create %s and put this line in it:', 'qartvelo-guard' ), $c['dirs'][0] . '/.user.ini' ) . $both, $ini ),
					self::s( __( 'If Settings > Advanced > Early guard still says "Active in this request: No" after 5 minutes, ask GridPane support.', 'qartvelo-guard' ) ),
				);
			case 'fastpanel':
			case 'ispmanager':
				return array(
					/* translators: 1: panel name, 2: file path */
					self::s( sprintf( __( 'If the PHP settings of the site in %1$s do not offer auto_prepend_file, create %2$s (PHP-FPM reads .user.ini files) and put this line in it:', 'qartvelo-guard' ), self::name( $id ), $c['dirs'][0] . '/.user.ini' ) . $both, $ini ),
				);
		}
		$panels = self::panels();
		if ( 'managed' === $panels[ $id ]['kind'] ) {
			return $this->managed_steps( $id, 'prepend' );
		}
		unset( $info );
		return array();
	}

	/* ---------- php_restart ---------- */

	/**
	 * How PHP picks up a changed setting.
	 *
	 * @param string $id   Panel id.
	 * @param array  $info current().
	 * @return array[]
	 */
	private function steps_php_restart( $id, array $info ) {
		$c    = $this->ctx();
		$ttl  = max( 0, (int) ini_get( 'user_ini.cache_ttl' ) );
		/* translators: %d: seconds */
		$wait = sprintf( __( 'A .user.ini change needs no restart: PHP reads the file again within %d seconds.', 'qartvelo-guard' ), $ttl );
		switch ( $id ) {
			case 'cpanel':
				if ( 'lsapi' === $info['php_handler'] ) {
					return array( self::s( __( 'LiteSpeed keeps PHP running: restart this account\'s PHP processes (as root, or ask your host):', 'qartvelo-guard' ), 'touch ' . Sysadmin_Tools::shell_arg( '/home/' . $c['acct'] . '/.lsphp_restart.txt' ) ) );
				}
				return array( self::s( $wait . ' ' . __( 'With PHP-FPM, root can restart it at once:', 'qartvelo-guard' ), '/usr/local/cpanel/scripts/restartsrv_apache_php_fpm' ) );
			case 'directadmin':
				return array( self::s( __( 'Restart PHP-FPM of this PHP version (as root):', 'qartvelo-guard' ), 'systemctl restart php-fpm' . $c['ver_nd'] ), self::s( $wait ) );
			case 'cyberpanel':
				$root = dirname( $c['abspath'] );
				return array(
					self::s( __( 'lsphp keeps running in detached mode, so a restart of OpenLiteSpeed alone is not enough. As root, restart this site\'s PHP processes (or all of them with killall -9 lsphp):', 'qartvelo-guard' ), 'touch ' . Sysadmin_Tools::shell_arg( $root . '/.lsphp_restart.txt' ) . "\nsystemctl restart lsws" ),
				);
			case 'aapanel':
				return array( self::s( $wait . ' ' . __( 'A change of the PHP configuration itself needs a reload (as root):', 'qartvelo-guard' ), '/etc/init.d/php-fpm-' . $c['ver_nd'] . ' reload' ) );
			case 'hestia':
				return array( self::s( __( 'Changing the Backend Template restarts PHP-FPM. After a change of your own, restart it (as root):', 'qartvelo-guard' ), 'v-restart-service php' . $c['ver'] . '-fpm' ), self::s( $wait ) );
			case 'cwp':
				return array( self::s( __( 'Restart PHP-FPM of this PHP version (as root):', 'qartvelo-guard' ), 'service php-fpm' . $c['ver_nd'] . ' restart' ), self::s( $wait ) );
			case 'ispconfig':
				return array( self::s( __( 'ISPConfig writes the PHP-FPM pool and reloads PHP-FPM itself within a minute or two (its server job queue).', 'qartvelo-guard' ) ) );
			case 'runcloud':
				return array( self::s( __( 'Reload RunCloud\'s PHP-FPM of this PHP version (as root):', 'qartvelo-guard' ), 'systemctl reload php' . $c['ver_nd'] . 'rc-fpm' ) );
			case 'spinupwp':
				return array( self::s( __( 'Reload PHP-FPM (as root, or with sudo):', 'qartvelo-guard' ), 'sudo service php' . $c['ver'] . '-fpm reload' ) );
			case 'forge':
				return array( self::s( __( 'Reload PHP-FPM (as the forge user):', 'qartvelo-guard' ), 'sudo -S service php' . $c['ver'] . '-fpm reload' ), self::s( $wait ) );
			case 'virtualmin':
			case 'webmin':
				return array( self::s( __( 'Reload PHP-FPM of this PHP version as root (the service is php8.x-fpm on Debian and Ubuntu, php-fpm on RHEL family systems):', 'qartvelo-guard' ), 'systemctl reload php' . $c['ver'] . '-fpm' ), self::s( $wait ) );
			case 'vesta':
			case 'ploi':
			case 'gridpane':
			case 'hostinger':
			case 'fastpanel':
			case 'ispmanager':
				return array( self::s( $wait ) );
		}
		return array();
	}

	/* ---------- clamav / maldet ---------- */

	/**
	 * How to get ClamAV on this panel.
	 *
	 * @param string $id   Panel id.
	 * @param array  $info current().
	 * @return array[]
	 */
	private function steps_clamav( $id, array $info ) {
		unset( $info );
		$cgav = __( 'The easiest way is the cgav server script below: run cgav install-clamav as root. It installs the packages, starts the scanner service and keeps the signatures updated.', 'qartvelo-guard' );
		switch ( $id ) {
			case 'cpanel':
				return array(
					self::s( __( 'With root access: in WHM open cPanel > Manage Plugins and install ClamAV. It installs clamscan, clamdscan and freshclam in /usr/local/cpanel/3rdparty/bin, where this plugin looks for them. The cgav script does the same from the command line (cgav install-clamav uses cPanel\'s own package).', 'qartvelo-guard' ) ),
					self::s( __( 'Without root (shared hosting): ask your host to install the ClamAV plugin in WHM, and use cPanel\'s Virus Scanner or Imunify for a full scan.', 'qartvelo-guard' ) ),
				);
			case 'directadmin':
				return array(
					self::s( __( 'DirectAdmin installs ClamAV through CustomBuild (as root):', 'qartvelo-guard' ), "da build set clamav yes\nda build clamav" ),
					self::s( __( 'On older installs the same is: cd /usr/local/directadmin/custombuild, then ./build set clamav yes and ./build clamav. If clamd starts without a virus database, run freshclam -v once.', 'qartvelo-guard' ) ),
				);
			case 'plesk':
				return array(
					self::s( __( 'Plesk\'s own ClamAV comes with the Plesk Email Security extension and scans mail. For website files Plesk offers the Imunify extension (Extensions), which replaced ImunifyAV.', 'qartvelo-guard' ) ),
					self::s( __( 'For this plugin to scan uploads with ClamAV, install it from the system packages as root.', 'qartvelo-guard' ) . ' ' . $cgav ),
				);
			case 'cyberpanel':
				return array(
					self::s( __( 'CyberPanel uses ClamAV only for mail and offers ImunifyAV under Security for website files. For uploads, install ClamAV from the system packages as root.', 'qartvelo-guard' ) . ' ' . $cgav ),
				);
			case 'hestia':
			case 'vesta':
				return array(
					self::s( __( 'The installer adds ClamAV for mail unless it was started with --clamav no, so it may be running already: check with systemctl status clamav-daemon. Otherwise install it from the system packages as root.', 'qartvelo-guard' ) . ' ' . $cgav ),
				);
			case 'cwp':
				return array(
					self::s( __( 'CWP installs ClamAV together with its mail server (MailServer Manager). Without it, install ClamAV from the system packages as root.', 'qartvelo-guard' ) . ' ' . $cgav ),
				);
			case 'gridpane':
				return array(
					self::s( __( 'GridPane has Maldet and ClamAV built in (Panel and Developer plans, servers with 2 GB of memory or more): switch them on in the GridPane panel. They detect, they do not clean.', 'qartvelo-guard' ) ),
				);
			case 'aapanel':
			case 'cloudpanel':
			case 'ispconfig':
			case 'virtualmin':
			case 'webmin':
			case 'fastpanel':
			case 'ispmanager':
			case 'runcloud':
			case 'spinupwp':
			case 'ploi':
			case 'forge':
				/* translators: %s: panel name */
				return array( self::s( sprintf( __( '%s does not install ClamAV for website files. With root access, install it from the system packages.', 'qartvelo-guard' ), self::name( $id ) ) . ' ' . $cgav ) );
			case 'cloudways':
				return array( self::s( __( 'Cloudways gives no root access, so ClamAV cannot be installed. Its Malware Protection add-on (Imunify) scans the application instead.', 'qartvelo-guard' ) ) );
			case 'hostinger':
				return array( self::s( __( 'Shared hosting gives no root access, so ClamAV cannot be installed. Use the Malware Scanner in hPanel for a full scan.', 'qartvelo-guard' ) ) );
		}
		$panels = self::panels();
		if ( 'managed' === $panels[ $id ]['kind'] ) {
			return $this->managed_steps( $id, 'clamav' );
		}
		return array();
	}

	/**
	 * Linux Malware Detect on this panel.
	 *
	 * @param string $id   Panel id.
	 * @param array  $info current().
	 * @return array[]
	 */
	private function steps_maldet( $id, array $info ) {
		unset( $info );
		switch ( $id ) {
			case 'cwp':
				return array( self::s( __( 'CWP ships its own maldet installer (as root):', 'qartvelo-guard' ), '/scripts/install_maldet' ) );
			case 'gridpane':
				return $this->steps_clamav( $id, array() );
			case 'cloudways':
			case 'hostinger':
				return $this->steps_clamav( $id, array() );
		}
		$panels = self::panels();
		if ( 'managed' === $panels[ $id ]['kind'] ) {
			return $this->managed_steps( $id, 'clamav' );
		}
		return array();
	}

	/* ---------- web_rules ---------- */

	/**
	 * Where the rules that block PHP in uploads and the data folder go.
	 *
	 * @param string $id   Panel id.
	 * @param array  $info current().
	 * @return array[]
	 */
	private function steps_web_rules( $id, array $info ) {
		$c     = $this->ctx();
		$tools = function_exists( 'wpcybersec' ) && wpcybersec()->sysadmin ? wpcybersec()->sysadmin : new Sysadmin_Tools();
		$nginx = Sysadmin_Tools::nginx_uploads_block();
		if ( $c['in_root'] ) {
			$nginx .= "\n" . $tools->nginx_data_rule();
		}
		$apache = __( 'Apache and LiteSpeed read .htaccess: the "Write uploads/.htaccess for me" button (Settings > Advanced > Web server) adds and tests the rule. By hand, add these lines to wp-content/uploads/.htaccess with File Manager:', 'qartvelo-guard' );
		$ht     = $tools->apache_uploads_rules();
		$web    = isset( $info['web_server'] ) ? (string) $info['web_server'] : '';
		switch ( $id ) {
			case 'cpanel':
				return array(
					self::s( $apache, $ht ),
					self::s( __( 'When the server also runs cPanel\'s NGINX (ea-nginx), root can add the nginx rule as an include file for this domain, then rebuild and restart nginx:', 'qartvelo-guard' ), 'mkdir -p ' . Sysadmin_Tools::shell_arg( '/etc/nginx/conf.d/users/' . $c['acct'] . '/' . $c['domain'] ) . "\ncat > " . Sysadmin_Tools::shell_arg( '/etc/nginx/conf.d/users/' . $c['acct'] . '/' . $c['domain'] . '/qartvelo-guard.conf' ) . " <<'EOF'\n" . $nginx . "\nEOF\n/usr/local/cpanel/scripts/ea-nginx config --all\n/usr/local/cpanel/scripts/restartsrv_nginx" ),
				);
			case 'directadmin':
				return array(
					self::s( $apache, $ht ),
					/* translators: %s: domain */
					self::s( sprintf( __( 'On nginx: as administrator open Admin Level > Custom HTTPD Configurations > %s > nginx.conf > CUSTOMIZE, put the rule in the CUSTOM3 field (location blocks) and save, then rewrite the configuration:', 'qartvelo-guard' ), $c['domain'] ), $nginx . "\n\nda build rewrite_confs" ),
				);
			case 'plesk':
				return array(
					/* translators: %s: domain */
					self::s( sprintf( __( 'As the Plesk administrator open Websites & Domains > %s > Apache & nginx Settings and add this to "Additional nginx directives", then click OK (customers cannot edit this field):', 'qartvelo-guard' ), $c['domain'] ), $nginx ),
					self::s( __( 'While nginx passes PHP requests to Apache (the default proxy mode), the uploads .htaccess rule works too:', 'qartvelo-guard' ), $ht ),
				);
			case 'cyberpanel':
				$up   = ltrim( Sysadmin_Tools::uploads_url_path(), '/' );
				$rule = 'RewriteEngine On' . "\n" . 'RewriteRule ^' . preg_quote( $up, '#' ) . '.*\.(' . Sysadmin_Tools::UPLOADS_EXEC_PATTERN . ')$ - [F,L]';
				$data = Sysadmin_Tools::data_url_path();
				if ( '' !== $data ) {
					$rule .= "\n" . 'RewriteRule ^' . preg_quote( ltrim( $data, '/' ), '#' ) . ' - [F,L]';
				}
				return array(
					self::s( __( 'OpenLiteSpeed only reads rewrite rules from .htaccess files (the <FilesMatch> and php_flag lines of the Apache rule are ignored). In CyberPanel open Websites > List Websites > Manage > Rewrite Rules and add these lines above the WordPress rules, then Save:', 'qartvelo-guard' ), str_replace( '\\-', '-', $rule ) ),
					self::s( __( 'If a test PHP file in uploads still runs afterwards, restart OpenLiteSpeed (systemctl restart lsws) and run the live test again.', 'qartvelo-guard' ) ),
				);
			case 'aapanel':
				if ( 'apache' === $web || 'litespeed' === $web ) {
					return array( self::s( $apache, $ht ) );
				}
				return array(
					/* translators: %s: nginx include line */
					self::s( sprintf( __( 'In aaPanel open Website, click this site and open "Config file". Paste this above the line "%s" and Save:', 'qartvelo-guard' ), 'include enable-php-' . $c['ver_nd'] . '.conf;' ), $nginx ),
				);
			case 'hestia':
			case 'vesta':
				$conf = 'hestia' === $id ? '/home/' . $c['acct'] . '/conf/web/' . $c['site'] . '/nginx.conf_qartvelo_guard' : '/home/' . $c['acct'] . '/conf/web/nginx.' . $c['site'] . '.conf_qartvelo_guard';
				return array(
					/* translators: 1: panel name, 2: file path */
					self::s( sprintf( __( '%1$s includes extra nginx files of the domain in its server block. As root, write the rule to %2$s, then test and reload nginx:', 'qartvelo-guard' ), self::name( $id ), $conf ), 'cat > ' . Sysadmin_Tools::shell_arg( $conf ) . " <<'EOF'\n" . $nginx . "\nEOF\nnginx -t && systemctl reload nginx" ),
					self::s( __( 'The rule is a prefix location with the PHP block nested inside, so it works even though the include comes after the PHP location of the template. With Apache behind nginx the uploads .htaccess rule also works.', 'qartvelo-guard' ) ),
				);
			case 'cloudpanel':
				return array(
					self::s( __( 'In CloudPanel open this site and its Vhost editor. Paste this inside the server block that serves the site (CloudPanel checks the syntax and reverts a broken change), then save:', 'qartvelo-guard' ), $nginx ),
				);
			case 'ispconfig':
				return array(
					self::s( __( 'In ISPConfig open Sites > this website > Options and add this to "nginx Directives" (on Apache servers the field is "Apache Directives"; use the .htaccess rule there instead), then Save:', 'qartvelo-guard' ), $nginx ),
				);
			case 'runcloud':
				return array(
					self::s( __( 'In RunCloud open the web application, then NGINX Config, add a config of type location.main with this content and save, then reload nginx as root:', 'qartvelo-guard' ), $nginx . "\n\nsystemctl reload nginx-rc" ),
				);
			case 'gridpane':
				$file = '/var/www/' . $c['domain'] . '/nginx/qartvelo-guard-main-context.conf';
				/* translators: %s: file path */
				return array( self::s( sprintf( __( 'As root, put the rule in %s (GridPane includes *-main-context.conf files in the site\'s server block), then test and reload:', 'qartvelo-guard' ), $file ), 'cat > ' . Sysadmin_Tools::shell_arg( $file ) . " <<'EOF'\n" . $nginx . "\nEOF\nnginx -t && gp ngx reload" ) );
			case 'spinupwp':
				$file = '/etc/nginx/sites-available/' . $c['domain'] . '/server/qartvelo-guard.conf';
				/* translators: %s: file path */
				return array( self::s( sprintf( __( 'As root (sudo), put the rule in %s (SpinupWP includes the files of that folder in the server block), then test and reload:', 'qartvelo-guard' ), $file ), 'sudo tee ' . Sysadmin_Tools::shell_arg( $file ) . " > /dev/null <<'EOF'\n" . $nginx . "\nEOF\nsudo nginx -t && sudo service nginx reload" ) );
			case 'ploi':
				return array( self::s( __( 'In Ploi open the site, then Manage > "Edit NGINX configuration". Paste this inside the server block and save with the reload box ticked:', 'qartvelo-guard' ), $nginx ) );
			case 'forge':
				return array( self::s( __( 'In Forge open the site and edit its Nginx configuration. Paste this inside the server block and save (Forge reloads nginx):', 'qartvelo-guard' ), $nginx ) );
			case 'cloudways':
				return array( self::s( __( 'On the Hybrid stack (nginx with Apache behind it) the uploads .htaccess rule works: use the button or add these lines to wp-content/uploads/.htaccess with SFTP. The nginx-only Lightning stack ignores .htaccess and allows no custom nginx rules: ask Cloudways support.', 'qartvelo-guard' ), $ht ) );
			case 'hostinger':
				return array( self::s( $apache, $ht ) );
		}
		$panels = self::panels();
		if ( 'managed' === $panels[ $id ]['kind'] ) {
			return $this->managed_steps( $id, 'web_rules' );
		}
		return array();
	}

	/* ---------- data_dir ---------- */

	/**
	 * Where a folder outside the web root is allowed (notes in front of the
	 * generic move steps).
	 *
	 * @param string $id   Panel id.
	 * @param array  $info current().
	 * @return array[]
	 */
	private function steps_data_dir( $id, array $info ) {
		unset( $info );
		$c = $this->ctx();
		switch ( $id ) {
			case 'cpanel':
				/* translators: %s: folder */
				return array( self::s( sprintf( __( 'cPanel: create the folder in your home folder next to public_html, for example %s (with File Manager). It is outside the web root.', 'qartvelo-guard' ), $c['target'] ) ) );
			case 'directadmin':
				return array( self::s( __( 'DirectAdmin limits PHP to your home folder and /tmp (open_basedir), so create the folder in /home/<user>/ outside domains/<domain>/public_html.', 'qartvelo-guard' ) ) );
			case 'plesk':
				return array( self::s( __( 'Plesk limits PHP to the subscription folder and the temporary folder (open_basedir {WEBSPACEROOT}{/}{:}{TMP}{/} by default), so create the folder in the subscription folder next to httpdocs, not elsewhere. An administrator can change open_basedir in the domain\'s PHP Settings.', 'qartvelo-guard' ) ) );
			case 'cyberpanel':
				/* translators: %s: folder */
				return array( self::s( sprintf( __( 'With CyberPanel\'s "open_basedir Protection" on, PHP may use /tmp and the site\'s own folder (%s) only, so create the folder there, next to public_html.', 'qartvelo-guard' ), dirname( $c['abspath'] ) ) ) );
			case 'aapanel':
				$file = $c['dirs'][0] . '/.user.ini';
				return array(
					/* translators: %s: file path */
					self::s( sprintf( __( 'aaPanel limits PHP to the site folder and /tmp with the open_basedir line of %s (locked with chattr +i). A folder outside the site needs that line extended, as root (keep the rest of the line):', 'qartvelo-guard' ), $file ), 'chattr -i ' . Sysadmin_Tools::shell_arg( $file ) . "\nsed -i " . Sysadmin_Tools::shell_arg( 's#^open_basedir=\(.*\)$#open_basedir=\1:' . $c['target'] . '/#' ) . ' ' . Sysadmin_Tools::shell_arg( $file ) . "\nchattr +i " . Sysadmin_Tools::shell_arg( $file ) ),
				);
			case 'hestia':
				$private = '/home/' . $c['acct'] . '/web/' . $c['site'] . '/private';
				/* translators: %1$s: folder */
				return array( self::s( sprintf( __( 'Hestia\'s PHP-FPM pool lets PHP use the domain\'s private folder, which the web server does not serve: use a folder inside %1$s, for example %1$s/qartvelo-guard-data, in the steps below.', 'qartvelo-guard' ), $private ) ) );
			case 'vesta':
				return array( self::s( __( 'VestaCP\'s PHP-FPM pools set no open_basedir (its mod_php template does), so a folder in /home/<user>/ outside the web folder works with PHP-FPM.', 'qartvelo-guard' ) ) );
			case 'ispconfig':
				return array( self::s( __( 'ISPConfig limits PHP to the website folders (open_basedir), including its private folder /var/www/clients/client<N>/web<N>/private, which the web server does not serve: create the data folder there.', 'qartvelo-guard' ) ) );
			case 'cwp':
				return array( self::s( __( 'CWP recommends open_basedir = /home/<user>:/tmp per account, which allows a folder in /home/<user>/ outside public_html.', 'qartvelo-guard' ) ) );
			case 'cloudways':
				return array( self::s( __( 'Cloudways applications have a private_html folder next to public_html: create the data folder inside it.', 'qartvelo-guard' ) ) );
			case 'virtualmin':
				return array( self::s( __( 'Virtualmin sets no open_basedir, so a folder in the domain owner\'s home folder outside public_html works.', 'qartvelo-guard' ) ) );
		}
		return array();
	}

	/* ---------- permissions ---------- */

	/**
	 * Removing write access for other users (mode o+w) from code folders when
	 * PHP does not own them: the panel's file manager first.
	 *
	 * @param string $id   Panel id.
	 * @param array  $info current().
	 * @return array[]
	 */
	private function steps_permissions( $id, array $info ) {
		$fm = $this->file_manager( $info );
		if ( $fm ) {
			return array(
				self::s( $fm['open'] ),
				/* translators: %s: file manager name */
				self::s( sprintf( __( 'In %s select each folder listed above, open Permissions (Change Permissions) and untick Write for World (Public, Others), for example 777 becomes 775 and 757 becomes 755. Files the panel shows as owned by another user (often root) can only be changed with SSH as root.', 'qartvelo-guard' ), $fm['name'] ) ),
			);
		}
		$panels = self::panels();
		if ( isset( $panels[ $id ] ) && 'managed' === $panels[ $id ]['kind'] ) {
			/* translators: %s: host name */
			return array( self::s( sprintf( __( '%s manages the file permissions of the site. Send its support the folders listed above and ask them to remove write access for other users.', 'qartvelo-guard' ), self::name( $id ) ) ) );
		}
		return array();
	}
}
