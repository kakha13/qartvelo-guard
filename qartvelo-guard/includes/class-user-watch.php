<?php
/**
 * Administrator watch: new administrator accounts wait for review.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Attackers who get in usually create an administrator for themselves, often
 * straight in the database. This module keeps a list of trusted
 * administrators (option TRUSTED_OPTION, user ids) and reports every other
 * account that holds the administrator role (or, on multisite, super admin):
 *
 *   - in real time on user_register, set_user_role, add_user_role and
 *     grant_super_admin (who did it, the request and the IP are recorded);
 *   - during whole-site scans (check_all()), which catches accounts inserted
 *     directly into the database.
 *
 * Each account becomes a pending item of type "user" (Store::TYPE_USER, path
 * "user:<ID>") and is notified at once.
 *
 * Multisite: the trusted list is one network option and covers every site.
 * Administrators of all sites are found with one query on the shared
 * usermeta table (the "<prefix>capabilities" row of each site), so a scan
 * needs no switch_to_blog() per site however large the network is; items
 * record details.blog_id (the site where the account is administrator, or
 * where the change happened) and details.sites. Deny removes the role on
 * every site of the network. Decisions: approve adds the account to
 * the trusted list; deny removes the administrator role (the account becomes
 * a subscriber, super admin is revoked) and signs it out everywhere, never
 * for the current user or the last administrator. The trusted list is
 * created from the administrators present when it is first needed
 * (activation, upgrade, the first scan), so existing administrators are
 * trusted. Deleted accounts close their open item.
 */
class User_Watch {

	const TRUSTED_OPTION = 'wpcybersec_trusted_admins';
	const ROLE           = 'administrator';

	/** @var bool Role changes made by this module itself (deny) are not reported. */
	private $silent = false;

	/**
	 * Hooks.
	 */
	public function register() {
		add_action( 'user_register', array( $this, 'on_user_register' ), 20, 1 );
		add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 20, 3 );
		add_action( 'add_user_role', array( $this, 'on_add_user_role' ), 20, 2 );
		add_action( 'remove_user_role', array( $this, 'on_remove_user_role' ), 20, 2 );
		add_action( 'grant_super_admin', array( $this, 'on_grant_super_admin' ), 20, 1 );
		add_action( 'revoked_super_admin', array( $this, 'on_revoked_super_admin' ), 20, 1 );
		add_action( 'deleted_user', array( $this, 'on_deleted_user' ), 20, 1 );
		add_action( 'wpmu_delete_user', array( $this, 'on_deleted_user' ), 20, 1 );
	}

	/* ------------------------------------------------------------------ */
	/* Trusted list                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Creates the trusted list from the current administrators when it does
	 * not exist yet. Static and free of services: Installer calls it during
	 * activation, before the plugin is booted.
	 *
	 * @return bool True when the list was created now.
	 */
	public static function seed() {
		if ( is_array( Network::get_option( self::TRUSTED_OPTION, null ) ) ) {
			return false;
		}
		Network::update_option( self::TRUSTED_OPTION, self::current_admin_ids(), false );
		return true;
	}

	/**
	 * Trusted administrator ids (the list is created on first use).
	 *
	 * @return int[]
	 */
	public function trusted_ids() {
		self::seed();
		$ids = Network::get_option( self::TRUSTED_OPTION, array() );
		return array_values( array_unique( array_filter( array_map( 'intval', is_array( $ids ) ? $ids : array() ) ) ) );
	}

	/**
	 * @param int $user_id User id.
	 * @return bool
	 */
	public function is_trusted( $user_id ) {
		return in_array( (int) $user_id, $this->trusted_ids(), true );
	}

	/**
	 * @param int $user_id User id.
	 */
	public function trust( $user_id ) {
		$ids   = $this->trusted_ids();
		$ids[] = (int) $user_id;
		Network::update_option( self::TRUSTED_OPTION, array_values( array_unique( array_filter( $ids ) ) ), false );
	}

	/**
	 * @param int $user_id User id.
	 */
	public function untrust( $user_id ) {
		$ids = array_values( array_diff( $this->trusted_ids(), array( (int) $user_id ) ) );
		Network::update_option( self::TRUSTED_OPTION, $ids, false );
	}

	/**
	 * Ids of every account that is an administrator of this site (on
	 * multisite: of any site of the network, or a super admin).
	 *
	 * @return int[]
	 */
	public static function current_admin_ids() {
		if ( Network::active() ) {
			$ids = array_keys( self::network_admin_sites() );
			foreach ( (array) get_super_admins() as $login ) {
				$user = get_user_by( 'login', (string) $login );
				if ( $user ) {
					$ids[] = (int) $user->ID;
				}
			}
			$ids = array_values( array_unique( array_filter( array_map( 'intval', $ids ) ) ) );
			sort( $ids );
			return $ids;
		}
		$ids = array();
		if ( function_exists( 'get_users' ) ) {
			$ids = array_map(
				'intval',
				(array) get_users(
					array(
						'role'   => self::ROLE,
						'fields' => 'ID',
						'number' => -1,
					)
				)
			);
		}
		if ( function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'get_super_admins' ) ) {
			foreach ( (array) get_super_admins() as $login ) {
				$user = get_user_by( 'login', (string) $login );
				if ( $user ) {
					$ids[] = (int) $user->ID;
				}
			}
		}
		$ids = array_values( array_unique( array_filter( $ids ) ) );
		sort( $ids );
		return $ids;
	}

	/**
	 * Multisite: administrator accounts of every site of the network, from
	 * the capabilities rows in the shared usermeta table.
	 *
	 * @param int $user_id Only this account (0 for all).
	 * @return array user id => site ids where the account is administrator.
	 */
	public static function network_admin_sites( $user_id = 0 ) {
		global $wpdb;
		if ( ! Network::active() ) {
			return array();
		}
		$base  = $wpdb->base_prefix;
		$like  = $wpdb->esc_like( $base ) . '%' . $wpdb->esc_like( 'capabilities' );
		$role  = '%' . $wpdb->esc_like( '"' . self::ROLE . '"' ) . '%';
		if ( $user_id > 0 ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- core usermeta table across every site of the network; no API reads it this way.
			$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT user_id, meta_key, meta_value FROM {$wpdb->usermeta} WHERE meta_key LIKE %s AND meta_value LIKE %s AND user_id = %d LIMIT 20000", $like, $role, (int) $user_id ), ARRAY_A );
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- core usermeta table across every site of the network; no API reads it this way.
			$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT user_id, meta_key, meta_value FROM {$wpdb->usermeta} WHERE meta_key LIKE %s AND meta_value LIKE %s LIMIT 20000", $like, $role ), ARRAY_A );
		}
		$out   = array();
		$sites = array();
		foreach ( $rows as $row ) {
			$key = (string) $row['meta_key'];
			$mid = substr( $key, strlen( $base ), -strlen( 'capabilities' ) );
			if ( '' === $mid ) {
				$blog = 1; // "<base>capabilities" belongs to site 1.
			} elseif ( preg_match( '/^(\d+)_$/', $mid, $m ) ) {
				$blog = (int) $m[1];
			} else {
				continue; // Another table prefix that shares the users table.
			}
			if ( ! isset( $sites[ $blog ] ) ) {
				$site           = get_site( $blog );
				$sites[ $blog ] = $site && (int) $site->network_id === (int) get_current_network_id();
			}
			$caps = maybe_unserialize( $row['meta_value'] );
			if ( ! $sites[ $blog ] || ! is_array( $caps ) || empty( $caps[ self::ROLE ] ) ) {
				continue;
			}
			$out[ (int) $row['user_id'] ][] = $blog;
		}
		return $out;
	}

	/**
	 * Whether an account has administrator rights here (multisite: on any
	 * site of the network, or as super admin).
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public function is_admin_user( $user_id ) {
		$user = get_userdata( (int) $user_id );
		if ( ! $user ) {
			return false;
		}
		if ( in_array( self::ROLE, (array) $user->roles, true ) ) {
			return true;
		}
		if ( Network::active() && self::network_admin_sites( (int) $user_id ) ) {
			return true;
		}
		return $this->is_network_super_admin( $user );
	}

	/**
	 * Super admin on multisite (on a single site every administrator counts
	 * as one in is_super_admin(), so that function is not used there).
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	private function is_network_super_admin( $user ) {
		return function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'get_super_admins' ) && in_array( (string) $user->user_login, (array) get_super_admins(), true );
	}

	/* ------------------------------------------------------------------ */
	/* Real time                                                           */
	/* ------------------------------------------------------------------ */

	/** @var array<int,bool> Users created in this request (user_register fired). */
	private $registered_now = array();

	/** @var array<int,bool> Accounts created moments ago that were given the administrator role, waiting for the hook that knows their previous roles. */
	private $deferred = array();

	/**
	 * @param int $user_id New user.
	 */
	public function on_user_register( $user_id ) {
		// WP-CLI and some plugins create the account first and give it the
		// administrator role in a second step of the same request.
		$this->registered_now[ (int) $user_id ] = true;
		unset( $this->deferred[ (int) $user_id ] );
		if ( ! $this->silent && $this->is_admin_user( $user_id ) ) {
			$this->flag( $user_id, 'registered' );
		}
	}

	/**
	 * @param int      $user_id   User.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Roles before.
	 */
	public function on_set_user_role( $user_id, $role, $old_roles = array() ) {
		if ( $this->silent ) {
			return;
		}
		if ( self::ROLE === $role ) {
			unset( $this->deferred[ (int) $user_id ] );
			if ( ! in_array( self::ROLE, (array) $old_roles, true ) ) {
				// wp_insert_user() sets the role before user_register fires: an
				// account that had no role at all is a new registration.
				$this->flag( $user_id, ( empty( $old_roles ) || ! empty( $this->registered_now[ (int) $user_id ] ) ) ? 'registered' : 'role' );
			}
			return;
		}
		if ( in_array( self::ROLE, (array) $old_roles, true ) && ! $this->is_admin_user( $user_id ) ) {
			$this->close_open( $user_id, 'no_longer_admin' );
		}
	}

	/**
	 * @param int    $user_id User.
	 * @param string $role    Added role.
	 */
	public function on_add_user_role( $user_id, $role ) {
		if ( $this->silent || self::ROLE !== $role ) {
			return;
		}
		if ( $this->just_registered( $user_id ) ) {
			// WordPress fires this from set_role() too, before set_user_role and
			// user_register. For an account created moments ago the next hook
			// knows the previous roles and decides between "registered" and
			// "role"; a plain add_role() with no such hook is settled at shutdown.
			if ( ! $this->deferred ) {
				add_action( 'shutdown', array( $this, 'flag_deferred' ) );
			}
			$this->deferred[ (int) $user_id ] = true;
			return;
		}
		$this->flag( $user_id, 'role' );
	}

	/**
	 * Flags the accounts on_add_user_role() left for later when no other hook settled them.
	 */
	public function flag_deferred() {
		$ids            = array_keys( $this->deferred );
		$this->deferred = array();
		foreach ( $ids as $id ) {
			if ( ! $this->silent && $this->is_admin_user( $id ) ) {
				$this->flag( $id, 'role' );
			}
		}
	}

	/**
	 * Whether the account was created in this request (user_register fired,
	 * or its registration time is seconds old).
	 *
	 * @param int $user_id User.
	 * @return bool
	 */
	private function just_registered( $user_id ) {
		if ( ! empty( $this->registered_now[ (int) $user_id ] ) ) {
			return true;
		}
		$user = get_userdata( (int) $user_id );
		if ( ! $user || empty( $user->user_registered ) ) {
			return false;
		}
		$at = strtotime( (string) $user->user_registered . ' UTC' );
		return $at && time() - $at < MINUTE_IN_SECONDS;
	}

	/**
	 * @param int    $user_id User.
	 * @param string $role    Removed role.
	 */
	public function on_remove_user_role( $user_id, $role ) {
		if ( ! $this->silent && self::ROLE === $role && ! $this->is_admin_user( $user_id ) ) {
			$this->close_open( $user_id, 'no_longer_admin' );
		}
	}

	/**
	 * @param int $user_id User about to become super admin.
	 */
	public function on_grant_super_admin( $user_id ) {
		if ( ! $this->silent ) {
			$this->flag( $user_id, 'super_admin' );
		}
	}

	/**
	 * @param int $user_id User.
	 */
	public function on_revoked_super_admin( $user_id ) {
		if ( ! $this->silent && ! $this->is_admin_user( $user_id ) ) {
			$this->close_open( $user_id, 'no_longer_admin' );
		}
	}

	/**
	 * @param int $user_id Deleted user.
	 */
	public function on_deleted_user( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		if ( in_array( $user_id, $this->trusted_ids(), true ) ) {
			$this->untrust( $user_id );
		}
		$this->close_open( $user_id, 'user_deleted' );
	}

	/* ------------------------------------------------------------------ */
	/* Items                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * Reports an account with administrator rights that is not trusted
	 * (deduplicated: one open item per account).
	 *
	 * @param int    $user_id User.
	 * @param string $how     registered | role | super_admin | scan.
	 * @param string $source  Item source: "user" (real time) or "scan".
	 * @return int Item id, 0 when nothing was created.
	 */
	public function flag( $user_id, $how, $source = 'user' ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 || $this->is_trusted( $user_id ) ) {
			return 0;
		}
		$plugin = wpcybersec();
		$store  = $plugin->store;
		$path   = self::item_path( $user_id );
		if ( ! $store || $store->item_find_open( Store::TYPE_USER, $path ) ) {
			return 0;
		}
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return 0;
		}

		$actor_id = 'scan' === $source ? 0 : (int) get_current_user_id();
		$actor    = $actor_id ? get_userdata( $actor_id ) : false;
		$uri      = '';
		if ( 'scan' !== $source && isset( $_SERVER['REQUEST_URI'] ) ) {
			$uri = substr( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), 0, 300 );
		}
		$details = array(
			'user_login'       => Store::db_text( (string) $user->user_login ),
			'user_email'       => Store::db_text( (string) $user->user_email ),
			'display_name'     => Store::db_text( (string) $user->display_name ),
			'user_registered'  => (string) $user->user_registered,
			'roles'            => array_values( array_map( 'strval', (array) $user->roles ) ),
			'how'              => (string) $how,
			'granted_by'       => $actor_id,
			'granted_by_login' => $actor ? Store::db_text( (string) $actor->user_login ) : '',
			'request_uri'      => $uri,
			'context'          => 'scan' === $source ? 'scan' : self::request_context(),
		);
		if ( Network::active() ) {
			$found              = self::network_admin_sites( $user_id );
			$sites              = isset( $found[ $user_id ] ) ? array_values( array_unique( array_map( 'intval', $found[ $user_id ] ) ) ) : array();
			$details['sites']   = $sites;
			$details['blog_id'] = 'scan' !== $source || ! $sites ? (int) get_current_blog_id() : (int) $sites[0];
		}
		$id = $store->item_insert(
			array(
				'type'     => Store::TYPE_USER,
				'status'   => Store::STATUS_PENDING,
				'severity' => Store::SEV_HIGH,
				'path'     => $path,
				'source'   => 'scan' === $source ? 'scan' : 'user',
				'user_id'  => $actor_id,
				'ip'       => 'scan' === $source ? '' : Store::client_ip(),
				'details'  => $details,
			)
		);
		if ( ! $id ) {
			return 0;
		}
		$plugin->logger->log(
			'admin_added',
			'scan' === $source
				/* translators: 1: user login, 2: user id */
				? sprintf( __( 'A scan found an administrator that is not on the trusted list: %1$s (user #%2$d). Waiting for your review.', 'qartvelo-guard' ), $details['user_login'], $user_id )
				: sprintf(
					/* translators: 1: user login, 2: user id, 3: who made the change */
					__( '%1$s (user #%2$d) became an administrator (changed by %3$s). Waiting for your review.', 'qartvelo-guard' ),
					$details['user_login'],
					$user_id,
					$actor ? $details['granted_by_login'] : __( 'no logged-in user', 'qartvelo-guard' )
				),
			array(
				'item_id' => $id,
				'user'    => $user_id,
				'how'     => $how,
			)
		);
		if ( $plugin->notifier && method_exists( $plugin->notifier, 'item_created' ) ) {
			$plugin->notifier->item_created( $id );
		}
		return $id;
	}

	/**
	 * Scan step: reports every administrator that is not trusted. Creates the
	 * trusted list instead when it does not exist yet.
	 *
	 * @return int New items.
	 */
	public function check_all() {
		if ( self::seed() ) {
			return 0;
		}
		$new = 0;
		foreach ( self::current_admin_ids() as $user_id ) {
			if ( $this->flag( $user_id, 'scan', 'scan' ) ) {
				++$new;
			}
		}
		return $new;
	}

	/**
	 * Closes the open item of an account (deleted, or no longer an administrator).
	 *
	 * @param int    $user_id User.
	 * @param string $reason  user_deleted | no_longer_admin.
	 */
	private function close_open( $user_id, $reason ) {
		$store = wpcybersec()->store;
		if ( ! $store ) {
			return;
		}
		$open = $store->item_find_open( Store::TYPE_USER, self::item_path( $user_id ) );
		if ( ! $open ) {
			return;
		}
		$store->item_update(
			(int) $open['id'],
			array(
				'status'     => Store::STATUS_RESOLVED,
				'decided_at' => Store::now(),
				'decided_by' => (int) get_current_user_id(),
				'details'    => array( 'resolution' => $reason ),
			)
		);
		wpcybersec()->logger->log(
			'item_auto_resolved',
			'user_deleted' === $reason
				/* translators: %s: user login */
				? sprintf( __( 'Closed the administrator report for %s: the account was deleted.', 'qartvelo-guard' ), self::item_login( $open ) )
				/* translators: %s: user login */
				: sprintf( __( 'Closed the administrator report for %s: the account is no longer an administrator.', 'qartvelo-guard' ), self::item_login( $open ) ),
			array( 'item_id' => (int) $open['id'] )
		);
	}

	/* ------------------------------------------------------------------ */
	/* Decisions (called by Decisions)                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Allow: the account joins the trusted list.
	 *
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	public function approve_item( array $item ) {
		$user_id = self::item_user_id( $item );
		if ( $user_id <= 0 || ! get_userdata( $user_id ) ) {
			return new \WP_Error( 'wpcybersec_user_gone', __( 'This account no longer exists.', 'qartvelo-guard' ) );
		}
		$this->trust( $user_id );
		return true;
	}

	/**
	 * Remove admin role: the account becomes a subscriber, loses super admin
	 * and is signed out everywhere. Refused for the current user and for the
	 * last administrator.
	 *
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	public function deny_item( array $item ) {
		$user_id = self::item_user_id( $item );
		$user    = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user ) {
			return new \WP_Error( 'wpcybersec_user_gone', __( 'This account no longer exists.', 'qartvelo-guard' ) );
		}
		if ( (int) get_current_user_id() === $user_id ) {
			return new \WP_Error( 'wpcybersec_user_self', __( 'You cannot remove your own administrator role here. Ask another administrator to do it, or use Allow if this is your account.', 'qartvelo-guard' ) );
		}
		$is_admin = in_array( self::ROLE, (array) $user->roles, true );
		$is_super = $this->is_network_super_admin( $user );
		if ( $is_admin || $is_super ) {
			$others = array_diff( self::current_admin_ids(), array( $user_id ) );
			if ( ! $others ) {
				return new \WP_Error( 'wpcybersec_user_last', __( 'This is the only administrator left, so the role was not removed. Create or promote another administrator first.', 'qartvelo-guard' ) );
			}
		}

		$admin_sites = array();
		if ( Network::active() ) {
			$found       = self::network_admin_sites( $user_id );
			$admin_sites = isset( $found[ $user_id ] ) ? array_values( array_unique( $found[ $user_id ] ) ) : array();
			$is_admin    = $is_admin || (bool) $admin_sites;
			if ( ( $is_admin || $is_super ) && ! array_diff( self::current_admin_ids(), array( $user_id ) ) ) {
				return new \WP_Error( 'wpcybersec_user_last', __( 'This is the only administrator left, so the role was not removed. Create or promote another administrator first.', 'qartvelo-guard' ) );
			}
		}

		$this->silent = true;
		try {
			if ( $admin_sites ) {
				// Multisite: the administrator role is removed on every site of the network.
				foreach ( $admin_sites as $blog_id ) {
					Network::on_site(
						$blog_id,
						static function () use ( $user_id ) {
							$site_user = new \WP_User( $user_id );
							if ( in_array( self::ROLE, (array) $site_user->roles, true ) ) {
								$site_user->set_role( 'subscriber' );
							}
						}
					);
				}
			} elseif ( $is_admin ) {
				$user->set_role( 'subscriber' );
			}
			if ( $is_super ) {
				if ( ! function_exists( 'revoke_super_admin' ) && defined( 'ABSPATH' ) && is_readable( ABSPATH . 'wp-admin/includes/ms.php' ) ) {
					require_once ABSPATH . 'wp-admin/includes/ms.php';
				}
				if ( function_exists( 'revoke_super_admin' ) ) {
					revoke_super_admin( $user_id );
				}
			}
		} finally {
			$this->silent = false;
		}
		if ( class_exists( '\WP_Session_Tokens' ) ) {
			\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		}
		$this->untrust( $user_id );

		clean_user_cache( $user_id );
		if ( $this->is_admin_user( $user_id ) ) {
			return new \WP_Error( 'wpcybersec_user_still_admin', __( 'The administrator role could not be removed. Check the account on the Users screen.', 'qartvelo-guard' ) );
		}
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * @param int $user_id User id.
	 * @return string Item path.
	 */
	public static function item_path( $user_id ) {
		return 'user:' . (int) $user_id;
	}

	/**
	 * @param array $item Item.
	 * @return int User id of a user item (0 when not one).
	 */
	public static function item_user_id( array $item ) {
		$path = (string) $item['path'];
		return 0 === strpos( $path, 'user:' ) ? (int) substr( $path, 5 ) : 0;
	}

	/**
	 * Login of the account an item is about.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	public static function item_login( array $item ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		if ( ! empty( $details['user_login'] ) ) {
			return (string) $details['user_login'];
		}
		/* translators: %d: user id */
		return sprintf( __( 'user #%d', 'qartvelo-guard' ), self::item_user_id( $item ) );
	}

	/**
	 * Where the change came from: admin screen, REST, XML-RPC, WP-CLI, cron or front end.
	 *
	 * @return string
	 */
	private static function request_context() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'cli';
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return 'cron';
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
			return 'ajax';
		}
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			return 'admin';
		}
		return 'front';
	}
}
