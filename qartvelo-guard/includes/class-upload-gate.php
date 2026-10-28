<?php
/**
 * Upload gate: holds new uploads until an administrator approves them.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Hooks into WordPress's upload pipeline (wp_handle_upload_prefilter,
 * wp_handle_sideload_prefilter and wp_upload_bits, which XML-RPC media uploads
 * and some plugins use). Every upload whose SHA-256 is not in the allowlist is
 * checked against the upload policy (setting upload_mode):
 *
 *   hold_all    hold everything that is not allowlisted
 *   hold_risky  hold executable, script, archive, SVG and HTML files, files whose
 *               real type does not match the extension, and anything with hits
 *   scan_only   hold only uploads that look malicious (hits >= 2)
 *   off         do nothing
 *
 * Malicious uploads (hits >= 2) are always held unless allowlisted. Users with
 * a role in upload_bypass_roles pass when their upload is clean. A held upload
 * is copied into quarantine, recorded as a pending item, and WordPress shows the
 * uploader a short explanation instead of saving the file.
 *
 * Approving an item (Decisions -> on_approve) allowlists the hash and, for
 * Media Library uploads, imports the held copy into the Media Library. An
 * approval only covers executable names (x.php, x.php.jpg, .htaccess) when the
 * approved upload itself had such a name, so an approved image can never come
 * back as an approved script.
 */
class Upload_Gate {

	/** Extensions treated as risky by the hold_risky policy. */
	const RISKY_EXTENSIONS = array(
		'svg', 'svgz', 'html', 'htm', 'xhtml', 'shtml', 'xml', 'xsl', 'xslt', 'js', 'mjs', 'swf', 'hta',
		'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'jar', 'war', 'phar',
		'exe', 'dll', 'msi', 'bat', 'cmd', 'com', 'scr', 'ps1', 'vbs', 'sh', 'bash', 'py', 'pl', 'rb', 'cgi',
		'jsp', 'asp', 'aspx', 'htaccess', 'ini', 'config',
	);

	/** @var int Nesting counter for with_bypass(). */
	private $bypass = 0;

	/** @var string[] Routes of the REST requests being dispatched right now (nested requests stack). */
	private $rest_routes = array();

	/** @var int[] Number of held uploads when each REST request in $rest_routes started. */
	private $rest_held = array();

	/** @var string[] Messages of the uploads held in this PHP request. */
	private $held_messages = array();

	/**
	 * Nothing heavy here; see register().
	 */
	public function __construct() {}

	/**
	 * Hooks.
	 */
	public function register() {
		add_filter( 'wp_handle_upload_prefilter', array( $this, 'filter_upload' ), 1000 );
		add_filter( 'wp_handle_sideload_prefilter', array( $this, 'filter_sideload' ), 1000 );
		add_filter( 'wp_upload_bits', array( $this, 'filter_upload_bits' ), 1000 );
		add_filter( 'rest_request_before_callbacks', array( $this, 'rest_before' ), 10, 3 );
		add_filter( 'rest_request_after_callbacks', array( $this, 'rest_after' ), 10, 3 );
	}

	/**
	 * rest_request_before_callbacks: remembers the route being dispatched, so an
	 * upload can tell the Media Library route from other REST routes.
	 *
	 * @param mixed $response Response so far.
	 * @param mixed $handler  Route handler.
	 * @param mixed $request  WP_REST_Request.
	 * @return mixed Unchanged response.
	 */
	public function rest_before( $response, $handler = null, $request = null ) {
		$this->rest_routes[] = is_object( $request ) && method_exists( $request, 'get_route' ) ? (string) $request->get_route() : '';
		$this->rest_held[]   = count( $this->held_messages );
		return $response;
	}

	/**
	 * rest_request_after_callbacks: forgets the route again.
	 *
	 * @param mixed $response Response.
	 * @param mixed $handler  Route handler.
	 * @param mixed $request  WP_REST_Request.
	 * @return mixed Unchanged response.
	 */
	public function rest_after( $response, $handler = null, $request = null ) {
		array_pop( $this->rest_routes );
		$before = (int) array_pop( $this->rest_held );
		// The gate held an upload of this REST request: WordPress would answer
		// 500 rest_upload_sideload_error. Say what happened instead.
		if ( count( $this->held_messages ) > $before && is_wp_error( $response ) ) {
			$message = (string) end( $this->held_messages );
			return new \WP_Error(
				'wpcybersec_upload_held',
				$message,
				array(
					'status' => 403,
					'held'   => true,
				)
			);
		}
		return $response;
	}

	/**
	 * Runs a callback with the gate switched off (used when importing approved files).
	 *
	 * @param callable $fn Callback.
	 * @return mixed The callback's return value.
	 */
	public function with_bypass( callable $fn ) {
		++$this->bypass;
		try {
			return call_user_func( $fn );
		} finally {
			--$this->bypass;
		}
	}

	/**
	 * Whether the gate is currently bypassed.
	 *
	 * @return bool
	 */
	public function is_bypassed() {
		if ( $this->bypass > 0 ) {
			return true;
		}
		// Shell users can write files directly anyway; do not hold WP-CLI imports.
		$cli = defined( 'WP_CLI' ) && WP_CLI;

		/**
		 * Filters whether the upload gate is bypassed for the current request.
		 *
		 * @param bool $bypass Default: true for WP-CLI.
		 */
		return (bool) apply_filters( 'wpcybersec_upload_gate_bypass', $cli );
	}

	/**
	 * wp_handle_upload_prefilter callback.
	 *
	 * @param array $file $_FILES-like array (name, type, tmp_name, size, error).
	 * @return array
	 */
	public function filter_upload( $file ) {
		return $this->gate( $file, 'upload' );
	}

	/**
	 * wp_handle_sideload_prefilter callback.
	 *
	 * @param array $file $_FILES-like array.
	 * @return array
	 */
	public function filter_sideload( $file ) {
		return $this->gate( $file, 'sideload' );
	}

	/**
	 * wp_upload_bits callback (XML-RPC media uploads and plugins that write
	 * uploads directly). Returning a string makes wp_upload_bits() fail with
	 * that message.
	 *
	 * @param array|string $data { name, bits, time } or an earlier error message.
	 * @return array|string
	 */
	public function filter_upload_bits( $data ) {
		if ( ! is_array( $data ) || empty( $data['name'] ) || ! isset( $data['bits'] ) || ! $this->is_active() ) {
			return $data;
		}
		// XML-RPC media uploads always; files plugins write directly follow the
		// sideload switch, like files WordPress downloads.
		$check = ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || (bool) wpcybersec()->settings->get( 'gate_sideloads', true );

		/**
		 * Filters whether a file written through wp_upload_bits() is checked by the upload gate.
		 *
		 * @param bool  $check Default: true for XML-RPC, else the gate_sideloads setting.
		 * @param array $data  { name, bits, time }.
		 */
		if ( ! apply_filters( 'wpcybersec_gate_upload_bits', $check, $data ) ) {
			return $data;
		}
		$name = (string) $data['name'];
		$bits = (string) $data['bits'];
		$tmp  = $this->temp_file( $name );
		if ( '' === $tmp || strlen( $bits ) !== @file_put_contents( $tmp, $bits ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			if ( '' !== $tmp ) {
				Fs::delete( $tmp );
			}
			return __( 'This upload could not be checked right now (Qartvelo Guard). Please try again in a moment or contact the site administrator.', 'qartvelo-guard' );
		}
		$file = $this->gate(
			array(
				'name'     => $name,
				'type'     => '',
				'tmp_name' => $tmp,
				'error'    => 0,
				'size'     => strlen( $bits ),
			),
			'bits'
		);
		if ( @is_file( $tmp ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Fs::delete( $tmp );
		}
		if ( is_array( $file ) && ! empty( $file['error'] ) ) {
			return (string) $file['error'];
		}
		return $data;
	}

	/**
	 * Cheap check whether the gate would look at uploads at all.
	 *
	 * @return bool
	 */
	private function is_active() {
		if ( $this->is_bypassed() ) {
			return false;
		}
		$plugin = wpcybersec();
		if ( ! $plugin->is_booted() || ! $plugin->settings ) {
			return false;
		}
		return 'off' !== (string) $plugin->settings->get( 'upload_mode', 'hold_all' );
	}

	/**
	 * Logs (at most once an hour) that uploads pass unheld because the data
	 * folder cannot be written.
	 *
	 * @param string $name Upload name.
	 */
	private function note_storage_bypass( $name ) {
		if ( Network::get_transient( 'wpcybersec_storage_bypass' ) ) {
			return;
		}
		Network::set_transient( 'wpcybersec_storage_bypass', 1, HOUR_IN_SECONDS ); // One data folder per network: one note per hour for all sites.
		$this->log(
			'upload_not_held',
			/* translators: %s: file name */
			sprintf( __( 'Upload %s was not held because the plugin has no writable data folder. Until that is fixed, only uploads that look malicious are blocked.', 'qartvelo-guard' ), self::cut( sanitize_file_name( $name ), 200 ) )
		);
	}

	/**
	 * @param string $name File name (used for the temp name only).
	 * @return string Empty temp file, or '' on failure.
	 */
	private function temp_file( $name ) {
		if ( ! function_exists( 'wp_tempnam' ) && is_readable( ABSPATH . 'wp-admin/includes/file.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$tmp = function_exists( 'wp_tempnam' ) ? wp_tempnam( 'wpcs-' . sanitize_file_name( wp_basename( $name ) ) ) : @tempnam( get_temp_dir(), 'wpcs' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return is_string( $tmp ) ? $tmp : '';
	}

	/**
	 * Runs the policy and fails closed (blocks the upload) on internal errors.
	 *
	 * @param mixed  $file   File array.
	 * @param string $filter upload | sideload.
	 * @return mixed
	 */
	private function gate( $file, $filter ) {
		if ( ! is_array( $file ) ) {
			return $file;
		}
		try {
			return $this->evaluate( $file, $filter );
		} catch ( \Throwable $e ) {
			$this->log(
				'upload_gate_error',
				/* translators: %s: error message */
				sprintf( __( 'The upload gate could not check an upload: %s', 'qartvelo-guard' ), $e->getMessage() ),
				array( 'name' => isset( $file['name'] ) ? sanitize_file_name( (string) $file['name'] ) : '' )
			);
			$file['error'] = __( 'This upload could not be checked right now (Qartvelo Guard). Please try again in a moment or contact the site administrator.', 'qartvelo-guard' );
			return $file;
		}
	}

	/**
	 * Policy decision for one uploaded file.
	 *
	 * @param array  $file   File array.
	 * @param string $filter upload | sideload.
	 * @return array
	 */
	private function evaluate( array $file, $filter ) {
		if ( $this->is_bypassed() ) {
			return $file;
		}
		$plugin = wpcybersec();
		if ( ! $plugin->is_booted() || ! $plugin->settings ) {
			return $file;
		}
		$settings = $plugin->settings;
		$mode     = (string) $settings->get( 'upload_mode', 'hold_all' );
		if ( 'off' === $mode ) {
			return $file;
		}

		// Another prefilter already rejected it, or PHP reported an upload error.
		if ( ! empty( $file['error'] ) ) {
			return $file;
		}

		$tmp = isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '';
		if ( '' === $tmp || ! @is_file( $tmp ) || ! @is_readable( $tmp ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $file; // WordPress will report the missing file itself.
		}
		$name = isset( $file['name'] ) && '' !== (string) $file['name'] ? (string) $file['name'] : basename( $tmp );

		$sha256 = (string) @hash_file( 'sha256', $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( 64 !== strlen( $sha256 ) ) {
			throw new \RuntimeException( 'Could not hash the uploaded file.' );
		}

		// Allowed once, allowed always; executable names need an approval made under an executable name.
		$executable = self::name_is_executable( $name );
		if ( $plugin->allowlist->is_allowed_hash( $sha256, $executable ) ) {
			return $file;
		}

		$context   = $this->detect_context( $filter );
		$hits      = $this->scan( $tmp, $name );
		$severity  = $this->max_severity( $hits );
		$malicious = $severity >= Store::SEV_HIGH;
		$reasons   = array();

		// No writable data folder: work like scan_only, so a failure of the
		// plugin's own storage never blocks the site's uploads.
		if ( ! $malicious && ! $plugin->storage->available() ) {
			$this->note_storage_bypass( $name );
			return $file;
		}

		if ( $malicious ) {
			$reasons[] = 'malware';
		} else {
			// Sideloads (importers, media_sideload_image) follow the gate_sideloads switch.
			if ( 'sideload' === $context['context'] && ! $settings->get( 'gate_sideloads', true ) ) {
				return $file;
			}
			$bypass_role = $this->user_bypasses( (array) $settings->get( 'upload_bypass_roles', array() ) );

			if ( 'scan_only' === $mode ) {
				return $file;
			} elseif ( 'hold_risky' === $mode ) {
				$reasons = $this->risk_reasons( $tmp, $name );
				if ( $hits ) {
					$reasons[] = 'suspicious';
				}
				if ( ! $reasons || ( $bypass_role && ! $hits ) ) {
					return $file;
				}
			} else { // hold_all.
				if ( $bypass_role && ! $hits ) {
					return $file;
				}
				$reasons[] = $hits ? 'suspicious' : 'new_file';
			}

			// A clean file of a type WordPress refuses anyway: let WordPress show its own error.
			if ( $this->wordpress_rejects_type( $tmp, $name, $context['context'] ) ) {
				return $file;
			}
		}

		return $this->hold( $file, $tmp, $name, $sha256, $hits, $severity, $context, $reasons, $executable );
	}

	/**
	 * Copies the upload into quarantine, records the item and blocks the upload.
	 *
	 * @param array  $file       File array.
	 * @param string $tmp        Temp path.
	 * @param string $name       Original name.
	 * @param string $sha256     Hash.
	 * @param array  $hits       Scanner hits.
	 * @param int    $severity   Max severity.
	 * @param array  $context    { context, source, post_id }.
	 * @param array  $reasons    Why it was held.
	 * @param bool   $executable Whether the name is executable.
	 * @return array
	 */
	private function hold( array $file, $tmp, $name, $sha256, array $hits, $severity, array $context, array $reasons, $executable = false ) {
		$plugin    = wpcybersec();
		$safe_name = self::safe_name( $name, $sha256 );
		$malicious = $severity >= Store::SEV_HIGH;

		// The same bytes under the same kind of name are already waiting: do not create a second item.
		$existing = $this->find_open_by_hash( $sha256, $executable );
		if ( $existing ) {
			$update = array(
				'details' => array(
					'repeat_count' => ( isset( $existing['details']['repeat_count'] ) ? (int) $existing['details']['repeat_count'] : 0 ) + 1,
					'last_attempt' => Store::now(),
				),
			);
			if ( ! $plugin->quarantine->exists( $existing ) ) {
				$held = $plugin->quarantine->hold( $tmp, false );
				if ( ! is_wp_error( $held ) ) {
					$update['quarantine_path'] = $held['quarantine_path'];
				}
			}
			$plugin->store->item_update( $existing['id'], $update );
			$this->log(
				'upload_held',
				/* translators: %s: file name */
				sprintf( __( 'Upload %s is already waiting for approval; the new attempt was held too.', 'qartvelo-guard' ), $safe_name ),
				array(
					'item_id' => (int) $existing['id'],
					'sha256'  => $sha256,
					'source'  => $context['source'],
				)
			);
			$file['error'] = $this->hold_message( $safe_name, $context['context'], $malicious );
		$this->held_messages[] = $file['error'];
			return $file;
		}

		$held = $plugin->quarantine->hold( $tmp, false );
		if ( is_wp_error( $held ) ) {
			$this->log(
				'upload_hold_failed',
				$malicious
					/* translators: 1: file name, 2: error message */
					? sprintf( __( 'Could not keep a copy of upload %1$s: %2$s It looks malicious, so it was refused without a copy.', 'qartvelo-guard' ), $safe_name, $held->get_error_message() )
					/* translators: 1: file name, 2: error message */
					: sprintf( __( 'Could not hold upload %1$s: %2$s It was let through, because a storage problem of this plugin must not block uploads.', 'qartvelo-guard' ), $safe_name, $held->get_error_message() ),
				array(
					'sha256' => $sha256,
					'source' => $context['source'],
				)
			);
			if ( ! $malicious ) {
				return $file; // Scan-only behaviour while the data folder cannot be written.
			}
			// Refused without a copy; the item still lets an administrator allow the hash.
			$held = array(
				'quarantine_path' => '',
				'size'            => (int) @filesize( $tmp ), // phpcs:ignore WordPress.PHP.NoSilencedErrors
				'not_held'        => true,
			);
		}

		$details = array(
			'context'       => $context['context'],
			'post_id'       => (int) $context['post_id'],
			'hits'          => array_slice( $hits, 0, 50 ),
			'reasons'       => array_values( array_unique( $reasons ) ),
			'request_uri'   => self::request_uri(),
			'original_name' => self::cut( sanitize_text_field( $name ), 255 ),
			'executable'    => (bool) $executable,
		);
		if ( is_multisite() ) {
			// Approving imports it into this site's Media Library (Network::on_site()).
			$details['blog_id'] = (int) get_current_blog_id();
		}
		if ( ! empty( $held['not_held'] ) ) {
			$details['not_held'] = true; // No copy was kept: approving only allows the hash.
		}
		// Remember where this request would have stored the file (plugins such as
		// WooCommerce change the folder per request), so approval imports it there.
		$subdir = in_array( $context['context'], array( 'media', 'rest', 'sideload' ), true ) ? self::current_upload_subdir() : null;
		if ( null !== $subdir ) {
			$details['upload_subdir'] = $subdir;
		}

		$id = $plugin->store->item_insert(
			array(
				'type'            => Store::TYPE_UPLOAD,
				'status'          => Store::STATUS_PENDING,
				'severity'        => (int) $severity,
				'path'            => $safe_name,
				'original_path'   => '',
				'quarantine_path' => $held['quarantine_path'],
				'sha256'          => $sha256,
				'size'            => (int) $held['size'],
				'mime'            => $this->detect_mime( $tmp, $name, isset( $file['type'] ) ? (string) $file['type'] : '' ),
				'source'          => $context['source'],
				'details'         => $details,
			)
		);

		if ( ! $id ) {
			if ( '' !== $held['quarantine_path'] ) {
				$plugin->quarantine->purge( array( 'quarantine_path' => $held['quarantine_path'] ) );
			}
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( 'Qartvelo Guard: could not record a held upload in the database.' );
			$file['error'] = __( 'This upload could not be stored for review (Qartvelo Guard). Please ask the site administrator to check the plugin settings.', 'qartvelo-guard' );
			return $file;
		}

		$this->log(
			'upload_held',
			$malicious
				/* translators: %s: file name */
				? sprintf( __( 'Held upload %s: it looks malicious.', 'qartvelo-guard' ), $safe_name )
				/* translators: %s: file name */
				: sprintf( __( 'Held upload %s for administrator approval.', 'qartvelo-guard' ), $safe_name ),
			array(
				'item_id'  => $id,
				'sha256'   => $sha256,
				'source'   => $context['source'],
				'severity' => (int) $severity,
			)
		);

		if ( $plugin->notifier && method_exists( $plugin->notifier, 'item_created' ) ) {
			try {
				$plugin->notifier->item_created( $id );
			} catch ( \Throwable $e ) {
				// A failed notification must never break the upload response.
				unset( $e );
			}
		}

		$file['error'] = $this->hold_message( $safe_name, $context['context'], $malicious );
		$this->held_messages[] = $file['error'];
		return $file;
	}

	/**
	 * Called by Decisions when an upload item is approved.
	 *
	 * @param array $item Item row.
	 * @return true|\WP_Error
	 */
	public function on_approve( array $item ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$context = isset( $details['context'] ) ? (string) $details['context'] : self::context_from_source( (string) $item['source'] );
		$name    = self::safe_name( (string) $item['path'], (string) $item['sha256'] );

		switch ( $context ) {
			case 'plugin_zip':
			case 'theme_zip':
				return $this->approve_package( $item, $context, $name );
			case 'media':
			case 'rest':
			case 'sideload':
				$blog_id = isset( $details['blog_id'] ) ? (int) $details['blog_id'] : 0;
				if ( is_multisite() && $blog_id > 0 && ! get_site( $blog_id ) ) {
					// The site was deleted: allow the file, nothing to import into.
					return $this->approve_hash_only( $item, $name );
				}
				// Multisite: into the Media Library of the site it was uploaded to.
				return Network::on_site(
					$blog_id,
					function () use ( $item, $details, $name ) {
						return $this->approve_media( $item, $details, $name );
					}
				);
			default:
				return $this->approve_hash_only( $item, $name );
		}
	}

	/**
	 * Called by Decisions when an upload item is denied (the held copy is purged there).
	 *
	 * @param array $item Item row.
	 */
	public function on_deny( array $item ) {
		/**
		 * Fires when a held upload is denied.
		 *
		 * @param array $item Item row.
		 */
		do_action( 'wpcybersec_upload_denied', $item );
	}

	/* ------------------------------------------------------------------ */
	/* Approval                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Media Library uploads: allowlist and import the held copy.
	 *
	 * @param array  $item    Item.
	 * @param array  $details Details.
	 * @param string $name    Safe file name.
	 * @return true|\WP_Error
	 */
	private function approve_media( array $item, array $details, $name ) {
		$plugin = wpcybersec();
		$this->allow_item_hash( $item, $name );

		if ( ! $plugin->quarantine->exists( $item ) ) {
			$this->update_details(
				$item,
				array( 'approval_note' => __( 'The held copy was missing, so nothing was added to the Media Library. Upload the file again; it will pass now.', 'qartvelo-guard' ) ),
				array( 'quarantine_path' => '' )
			);
			return true;
		}

		if ( ! function_exists( 'wp_handle_sideload' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( ! function_exists( 'media_handle_sideload' ) ) {
			require_once ABSPATH . 'wp-admin/includes/media.php';
		}
		if ( ! function_exists( 'wp_generate_attachment_metadata' ) ) {
			require_once ABSPATH . 'wp-admin/includes/image.php';
		}

		$tmp = $plugin->quarantine->to_temp( $item );
		if ( is_wp_error( $tmp ) ) {
			return $tmp;
		}

		$post_id = isset( $details['post_id'] ) ? (int) $details['post_id'] : 0;
		if ( $post_id > 0 && ! get_post( $post_id ) ) {
			$post_id = 0;
		}
		$post_data = array();
		if ( ! empty( $item['user_id'] ) && get_userdata( (int) $item['user_id'] ) ) {
			$post_data['post_author'] = (int) $item['user_id'];
		}

		$file_array = array(
			'name'     => $name,
			'tmp_name' => $tmp,
		);

		// Store it in the folder the original request would have used.
		$subdir = isset( $details['upload_subdir'] ) && is_string( $details['upload_subdir'] ) && self::is_valid_subdir( $details['upload_subdir'] ) ? $details['upload_subdir'] : null;
		$force  = null;
		if ( null !== $subdir ) {
			$force = static function ( $dirs ) use ( $subdir ) {
				if ( is_array( $dirs ) && isset( $dirs['basedir'], $dirs['baseurl'] ) ) {
					$dirs['subdir'] = $subdir;
					$dirs['path']   = $dirs['basedir'] . $subdir;
					$dirs['url']    = $dirs['baseurl'] . $subdir;
				}
				return $dirs;
			};
			add_filter( 'upload_dir', $force, 999 );
		}
		try {
			$attachment = $this->with_bypass(
				static function () use ( $file_array, $post_id, $post_data ) {
					return media_handle_sideload( $file_array, $post_id, null, $post_data );
				}
			);
		} finally {
			if ( null !== $force ) {
				remove_filter( 'upload_dir', $force, 999 );
			}
		}

		if ( @is_file( $tmp ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Fs::delete( $tmp );
		}

		if ( is_wp_error( $attachment ) ) {
			return new \WP_Error(
				'wpcybersec_import',
				/* translators: 1: file name, 2: error message */
				sprintf( __( 'Could not add "%1$s" to the Media Library: %2$s The file is allowed now, so it can be uploaded again.', 'qartvelo-guard' ), $name, rtrim( $attachment->get_error_message(), '.' ) . '.' )
			);
		}

		$attachment = (int) $attachment;
		$this->trust_attachment_files( $attachment );
		$plugin->quarantine->purge( $item );
		$this->update_details(
			$item,
			array(
				'attachment_id' => $attachment,
				'approval_note' => __( 'Added to the Media Library.', 'qartvelo-guard' ),
			),
			array( 'quarantine_path' => '' )
		);
		$this->log(
			'upload_imported',
			/* translators: 1: file name, 2: attachment id */
			sprintf( __( 'Approved upload %1$s was added to the Media Library (attachment #%2$d).', 'qartvelo-guard' ), $name, $attachment ),
			array(
				'item_id'       => (int) $item['id'],
				'attachment_id' => $attachment,
			)
		);
		return true;
	}

	/**
	 * Plugin or theme ZIP: allowlist the hash and the install folder found in the ZIP.
	 *
	 * @param array  $item    Item.
	 * @param string $context plugin_zip | theme_zip.
	 * @param string $name    Safe file name.
	 * @return true
	 */
	private function approve_package( array $item, $context, $name ) {
		$plugin = wpcybersec();
		$type   = 'theme_zip' === $context ? 'theme' : 'plugin';
		$this->allow_item_hash( $item, $name );

		$folder = '';
		if ( $plugin->quarantine->exists( $item ) ) {
			$folder = self::zip_top_folder( (string) $item['quarantine_path'] );
		}
		if ( '' === $folder ) {
			// Same rule WordPress uses for archives without a single top folder: the ZIP name.
			$folder = preg_replace( '/\.zip$/i', '', $name );
		}
		$slug = sanitize_key( $folder );
		if ( '' !== $slug ) {
			$plugin->allowlist->allow_install(
				$type,
				$slug,
				/* translators: 1: folder name, 2: zip file name */
				self::cut( sprintf( __( '%1$s (from %2$s)', 'qartvelo-guard' ), $folder, $name ), 255 ),
				sprintf( 'upload item #%d', (int) $item['id'] )
			);
		}

		$plugin->quarantine->purge( $item );
		$note = 'theme' === $type
			/* translators: %s: zip file name */
			? sprintf( __( 'Upload %s again under Appearance > Themes > Add New Theme > Upload Theme. It will install without being held.', 'qartvelo-guard' ), $name )
			/* translators: %s: zip file name */
			: sprintf( __( 'Upload %s again under Plugins > Add New Plugin > Upload Plugin. It will install without being held.', 'qartvelo-guard' ), $name );
		$this->update_details(
			$item,
			array(
				'install_type'  => $type,
				'slug'          => $slug,
				'approval_note' => $note,
			),
			array( 'quarantine_path' => '' )
		);
		$this->log( 'upload_package_approved', $note, array( 'item_id' => (int) $item['id'] ) );
		return true;
	}

	/**
	 * Uploads to other places (early guard, importers, plugin forms): allowlist only.
	 * The sender uploads again and the file passes.
	 *
	 * @param array  $item Item.
	 * @param string $name Safe file name.
	 * @return true
	 */
	private function approve_hash_only( array $item, $name ) {
		$plugin = wpcybersec();
		$this->allow_item_hash( $item, $name );
		if ( '' !== (string) $item['quarantine_path'] ) {
			$plugin->quarantine->purge( $item );
		}
		$this->update_details(
			$item,
			array(
				/* translators: %s: file name */
				'approval_note' => sprintf( __( '%s is allowed now. Ask the sender to upload it again; identical files pass automatically.', 'qartvelo-guard' ), $name ),
			),
			array( 'quarantine_path' => '' )
		);
		return true;
	}

	/**
	 * Allowlists the item's hash. The approval covers executable names only when
	 * the held upload had one (recorded at hold time, or visible in the name).
	 *
	 * @param array  $item Item.
	 * @param string $name Label.
	 */
	private function allow_item_hash( array $item, $name ) {
		if ( empty( $item['sha256'] ) ) {
			return;
		}
		$details    = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$executable = ! empty( $details['executable'] ) || self::name_is_executable( $name ) || self::name_is_executable( (string) $item['path'] );
		wpcybersec()->allowlist->allow_hash( (string) $item['sha256'], self::cut( $name, 255 ), sprintf( 'upload item #%d', (int) $item['id'] ), $executable );
	}

	/**
	 * Merges details and extra columns into an item.
	 *
	 * @param array $item    Item.
	 * @param array $details Details to merge.
	 * @param array $columns Extra columns.
	 */
	private function update_details( array $item, array $details, array $columns = array() ) {
		$columns['details'] = $details;
		wpcybersec()->store->item_update( (int) $item['id'], $columns );
	}

	/**
	 * Marks an imported attachment and its generated sizes as trusted, so the
	 * file monitor does not report them as new files.
	 *
	 * @param int $attachment_id Attachment id.
	 */
	private function trust_attachment_files( $attachment_id ) {
		$monitor = wpcybersec()->file_monitor;
		if ( ! $monitor || ! method_exists( $monitor, 'trust_file' ) ) {
			return;
		}
		$main = get_attached_file( $attachment_id );
		if ( ! $main || ! is_file( $main ) ) {
			return;
		}
		$dir   = dirname( $main );
		$files = array( $main );
		$meta  = wp_get_attachment_metadata( $attachment_id );
		if ( is_array( $meta ) ) {
			if ( ! empty( $meta['original_image'] ) ) {
				$files[] = $dir . '/' . basename( (string) $meta['original_image'] );
			}
			if ( ! empty( $meta['sizes'] ) && is_array( $meta['sizes'] ) ) {
				foreach ( $meta['sizes'] as $size ) {
					if ( is_array( $size ) && ! empty( $size['file'] ) ) {
						$files[] = $dir . '/' . basename( (string) $size['file'] );
					}
				}
			}
		}
		foreach ( array_unique( $files ) as $path ) {
			if ( is_file( $path ) ) {
				try {
					$monitor->trust_file( $path );
				} catch ( \Throwable $e ) {
					unset( $e );
				}
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/* Image previews and clean images                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Raster image types that may be previewed: extension => { IMAGETYPE_*, MIME }.
	 * Never SVG (it can hold scripts).
	 *
	 * @return array
	 */
	public static function preview_types() {
		$types = array(
			'jpg'  => array( IMAGETYPE_JPEG, 'image/jpeg' ),
			'jpeg' => array( IMAGETYPE_JPEG, 'image/jpeg' ),
			'jpe'  => array( IMAGETYPE_JPEG, 'image/jpeg' ),
			'png'  => array( IMAGETYPE_PNG, 'image/png' ),
			'gif'  => array( IMAGETYPE_GIF, 'image/gif' ),
		);
		if ( defined( 'IMAGETYPE_WEBP' ) ) {
			$types['webp'] = array( IMAGETYPE_WEBP, 'image/webp' );
		}
		return $types;
	}

	/**
	 * Highest severity of an item: its own or that of its worst match.
	 *
	 * @param array $item Item.
	 * @return int 0-3.
	 */
	public static function risk_level( array $item ) {
		$level = isset( $item['severity'] ) ? (int) $item['severity'] : 0;
		$hits  = isset( $item['details']['hits'] ) && is_array( $item['details']['hits'] ) ? $item['details']['hits'] : array();
		foreach ( $hits as $hit ) {
			if ( is_array( $hit ) && isset( $hit['severity'] ) ) {
				$level = max( $level, (int) $hit['severity'] );
			}
		}
		return max( 0, min( 3, $level ) );
	}

	/**
	 * Whether a held upload may be shown as an image, and what it is.
	 *
	 * Only for uploads with a raster image extension whose held copy really is
	 * that kind of image (getimagesize() and finfo agree with the extension),
	 * and never for uploads flagged high or critical or held under an
	 * executable name: a polyglot such as a GIF that is also PHP must not be
	 * rendered, whatever a browser would make of it.
	 *
	 * @param array $item Item.
	 * @return array { ok: bool, reason: ''|not_image|risky|missing|mismatch, path, mime, ext, width, height }
	 */
	public function image_preview( array $item ) {
		static $cache = array();
		$key = isset( $item['id'] ) ? (int) $item['id'] . ':' . ( isset( $item['quarantine_path'] ) ? (string) $item['quarantine_path'] : '' ) : '';
		if ( '' !== $key && isset( $cache[ $key ] ) ) {
			return $cache[ $key ];
		}
		$result = $this->check_image_preview( $item );
		if ( '' !== $key ) {
			$cache[ $key ] = $result;
		}
		return $result;
	}

	/**
	 * @param array $item Item.
	 * @return array See image_preview().
	 */
	private function check_image_preview( array $item ) {
		$out   = array(
			'ok'     => false,
			'reason' => 'not_image',
			'path'   => '',
			'mime'   => '',
			'ext'    => '',
			'width'  => 0,
			'height' => 0,
		);
		$types = self::preview_types();
		$name  = isset( $item['path'] ) ? (string) $item['path'] : '';
		$ext   = strtolower( (string) pathinfo( $name, PATHINFO_EXTENSION ) );
		if ( ! isset( $item['type'] ) || Store::TYPE_UPLOAD !== $item['type'] || ! isset( $types[ $ext ] ) ) {
			return $out;
		}
		$out['ext'] = $ext;
		if ( self::risk_level( $item ) >= Store::SEV_HIGH || self::item_is_executable( $item ) || self::name_is_executable( $name ) ) {
			$out['reason'] = 'risky';
			return $out;
		}
		$out['reason'] = 'missing';
		if ( ! in_array( isset( $item['status'] ) ? (string) $item['status'] : '', array( Store::STATUS_PENDING, Store::STATUS_QUARANTINED ), true ) ) {
			return $out;
		}
		$path    = isset( $item['quarantine_path'] ) ? wp_normalize_path( (string) $item['quarantine_path'] ) : '';
		$plugin  = wpcybersec();
		$storage = $plugin->storage;
		if ( '' === $path || ! $plugin->quarantine->exists( $item ) || ! Storage::is_within( $path, $storage->quarantine_dir() ) || is_link( $path ) ) {
			return $out;
		}
		$out['reason'] = 'mismatch';
		$info          = @getimagesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- a broken file is simply not an image.
		if ( ! is_array( $info ) || (int) $info[2] !== (int) $types[ $ext ][0] || empty( $info[0] ) || empty( $info[1] ) ) {
			return $out;
		}
		$mime = '';
		if ( function_exists( 'finfo_open' ) ) {
			$finfo = finfo_open( FILEINFO_MIME_TYPE );
			if ( $finfo ) {
				$mime = (string) @finfo_file( $finfo, $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				finfo_close( $finfo );
			}
			if ( $mime !== $types[ $ext ][1] ) {
				return $out;
			}
		} elseif ( ! isset( $info['mime'] ) || $info['mime'] !== $types[ $ext ][1] ) {
			return $out;
		}
		$out['ok']     = true;
		$out['reason'] = '';
		$out['path']   = $path;
		$out['mime']   = $types[ $ext ][1];
		$out['width']  = (int) $info[0];
		$out['height'] = (int) $info[1];
		return $out;
	}

	/**
	 * Whether a pending upload is a clean image that "Allow all clean images"
	 * may approve: no matches at all, severity info, not held under an
	 * executable name, held from the Media Library, REST or a sideload (so
	 * approving imports it), and a held copy that image_preview() verified.
	 *
	 * @param array $item Item.
	 * @return bool
	 */
	public function is_clean_image( array $item ) {
		if ( ! isset( $item['type'], $item['status'] ) || Store::TYPE_UPLOAD !== $item['type'] || Store::STATUS_PENDING !== $item['status'] ) {
			return false;
		}
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		if ( (int) $item['severity'] > 0 || ! empty( $details['hits'] ) || ! empty( $details['not_held'] ) ) {
			return false;
		}
		// Only uploads that approving imports into the Media Library (early guard
		// uploads are only allowlisted; the sender has to send them again).
		$context = isset( $details['context'] ) ? (string) $details['context'] : self::context_from_source( (string) $item['source'] );
		if ( ! in_array( $context, array( 'media', 'rest', 'sideload' ), true ) ) {
			return false;
		}
		$preview = $this->image_preview( $item );
		return ! empty( $preview['ok'] );
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Where the upload came from.
	 *
	 * @param string $filter upload | sideload | bits.
	 * @return array { context, source, post_id }
	 */
	private function detect_context( $filter ) {
		global $pagenow;
		// phpcs:disable WordPress.Security.NonceVerification -- read-only context detection, WordPress verifies the request itself.
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) : '';
		$page   = is_string( $pagenow ) && '' !== $pagenow ? $pagenow : $script;
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';

		$post_id = 0;
		if ( isset( $_REQUEST['post_id'] ) && is_scalar( $_REQUEST['post_id'] ) ) {
			$post_id = absint( $_REQUEST['post_id'] );
		} elseif ( isset( $_REQUEST['post'] ) && is_scalar( $_REQUEST['post'] ) ) {
			$post_id = absint( $_REQUEST['post'] );
		}
		$is_import = isset( $_REQUEST['import'] );
		// phpcs:enable

		if ( 'update.php' === $page && in_array( $action, array( 'upload-plugin', 'upload-theme' ), true ) ) {
			$context = 'upload-theme' === $action ? 'theme_zip' : 'plugin_zip';
			return array(
				'context' => $context,
				'source'  => $context,
				'post_id' => 0,
			);
		}
		$route   = $this->current_rest_route();
		$in_rest = '' !== $route || $this->rest_routes || ( defined( 'REST_REQUEST' ) && REST_REQUEST );
		if ( 'bits' === $filter ) {
			// wp_upload_bits(): XML-RPC media uploads and plugins writing files directly.
			// The sender uploads again after approval.
			return array(
				'context' => defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ? 'xmlrpc' : 'other',
				'source'  => $in_rest ? 'rest' : 'media',
				'post_id' => $post_id,
			);
		}
		if ( '' !== $route && 0 === stripos( $route, '/wp/v2/media' ) ) {
			// Only the Media Library route is imported into the Media Library on approval.
			return array(
				'context' => 'rest',
				'source'  => 'rest',
				'post_id' => $post_id,
			);
		}
		if ( $in_rest ) {
			// Other REST routes (font library, plugin endpoints): allowlist only on
			// approval. Sideloads keep their own context (they end in the Media Library).
			return array(
				'context' => 'sideload' === $filter ? 'sideload' : 'other',
				'source'  => 'rest',
				'post_id' => $post_id,
			);
		}
		if ( 'sideload' === $filter ) {
			return array(
				'context' => 'sideload',
				'source'  => 'sideload',
				'post_id' => $post_id,
			);
		}

		$media_pages = array( 'async-upload.php', 'media-new.php', 'media-upload.php', 'upload.php', 'post.php', 'post-new.php', 'customize.php' );
		if ( in_array( $page, $media_pages, true ) || ( 'admin-ajax.php' === $page && 'upload-attachment' === $action ) ) {
			$context = 'media';
		} elseif ( 'admin.php' === $page && $is_import ) {
			$context = 'import';
		} else {
			$context = 'other';
		}
		return array(
			'context' => $context,
			'source'  => 'media',
			'post_id' => $post_id,
		);
	}

	/**
	 * Route of the REST request being dispatched, '' outside the REST API.
	 *
	 * @return string
	 */
	private function current_rest_route() {
		if ( $this->rest_routes ) {
			return (string) end( $this->rest_routes );
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST && isset( $GLOBALS['wp'] ) && is_object( $GLOBALS['wp'] ) && isset( $GLOBALS['wp']->query_vars['rest_route'] ) && is_string( $GLOBALS['wp']->query_vars['rest_route'] ) ) {
			return (string) $GLOBALS['wp']->query_vars['rest_route'];
		}
		return '';
	}

	/**
	 * Upload subfolder (for example "/2026/10" or "/woocommerce_uploads/2026/10")
	 * that WordPress would use for an upload in this request.
	 *
	 * @return string|null Null when unknown.
	 */
	private static function current_upload_subdir() {
		if ( ! function_exists( 'wp_upload_dir' ) ) {
			return null;
		}
		$dirs = wp_upload_dir( null, false );
		if ( ! is_array( $dirs ) || ! empty( $dirs['error'] ) || ! isset( $dirs['subdir'] ) || ! is_string( $dirs['subdir'] ) ) {
			return null;
		}
		return self::is_valid_subdir( $dirs['subdir'] ) ? $dirs['subdir'] : null;
	}

	/**
	 * @param string $subdir Upload subfolder.
	 * @return bool
	 */
	private static function is_valid_subdir( $subdir ) {
		$subdir = (string) $subdir;
		if ( '' === $subdir ) {
			return true;
		}
		return '/' === $subdir[0] && strlen( $subdir ) <= 500 && false === strpos( $subdir, '..' ) && false === strpos( $subdir, '\\' ) && ! preg_match( '/[\x00-\x1F]/', $subdir );
	}

	/**
	 * Context for items that have no details.context (older rows).
	 *
	 * @param string $source Source column.
	 * @return string
	 */
	private static function context_from_source( $source ) {
		switch ( $source ) {
			case 'plugin_zip':
			case 'theme_zip':
			case 'sideload':
			case 'rest':
			case 'guard':
				return $source;
			default:
				return 'media';
		}
	}

	/**
	 * Malware hits for an upload (empty when the engine is not available).
	 *
	 * @param string $tmp  Temp path.
	 * @param string $name Original name.
	 * @return array
	 */
	private function scan( $tmp, $name ) {
		$scanner = wpcybersec()->scanner;
		if ( ! $scanner || ! method_exists( $scanner, 'scan_upload' ) ) {
			return array();
		}
		$hits = $scanner->scan_upload( $tmp, $name );
		return is_array( $hits ) ? array_values( array_filter( $hits, 'is_array' ) ) : array();
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
			$max = max( $max, isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 );
		}
		return $max;
	}

	/**
	 * Why a file counts as risky under the hold_risky policy.
	 *
	 * @param string $tmp  Temp path.
	 * @param string $name Original name.
	 * @return string[]
	 */
	private function risk_reasons( $tmp, $name ) {
		$reasons = array();
		if ( self::name_is_executable( $name ) ) {
			$reasons[] = 'executable';
		}
		$parts = explode( '.', strtolower( basename( $name ) ) );
		array_shift( $parts );
		if ( array_intersect( $parts, self::RISKY_EXTENSIONS ) ) {
			$reasons[] = 'risky_type';
		}
		$by_name = wp_check_filetype( $name );
		if ( ! empty( $by_name['ext'] ) ) {
			$real = wp_check_filetype_and_ext( $tmp, $name );
			if ( empty( $real['ext'] ) || empty( $real['type'] ) || ! empty( $real['proper_filename'] ) ) {
				$reasons[] = 'type_mismatch';
			}
		} else {
			$reasons[] = 'unknown_type';
		}
		return array_values( array_unique( $reasons ) );
	}

	/**
	 * Mirrors WordPress's own type test so clean files that WordPress refuses
	 * anyway are not held for nothing.
	 *
	 * @param string $tmp     Temp path.
	 * @param string $name    Original name.
	 * @param string $context Context.
	 * @return bool
	 */
	private function wordpress_rejects_type( $tmp, $name, $context ) {
		if ( ! in_array( $context, array( 'media', 'rest', 'sideload' ), true ) ) {
			return false; // Unknown overrides (plugin ZIPs skip the type test, for example).
		}
		if ( current_user_can( 'unfiltered_upload' ) ) {
			return false;
		}
		$check = wp_check_filetype_and_ext( $tmp, $name );
		return empty( $check['ext'] ) || empty( $check['type'] );
	}

	/**
	 * @param string $tmp         Temp path.
	 * @param string $name        Original name.
	 * @param string $client_type Browser supplied type.
	 * @return string
	 */
	private function detect_mime( $tmp, $name, $client_type ) {
		$check = wp_check_filetype_and_ext( $tmp, $name );
		if ( ! empty( $check['type'] ) ) {
			return (string) $check['type'];
		}
		if ( function_exists( 'finfo_open' ) ) {
			$finfo = @finfo_open( FILEINFO_MIME_TYPE ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $finfo ) {
				$mime = @finfo_file( $finfo, $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				finfo_close( $finfo );
				if ( $mime ) {
					return substr( sanitize_mime_type( $mime ), 0, 100 );
				}
			}
		}
		$client_type = sanitize_mime_type( $client_type );
		return $client_type ? substr( $client_type, 0, 100 ) : 'application/octet-stream';
	}

	/**
	 * @param string[] $roles Bypass roles.
	 * @return bool
	 */
	private function user_bypasses( array $roles ) {
		if ( ! $roles || ! is_user_logged_in() ) {
			return false;
		}
		$user = wp_get_current_user();
		return (bool) array_intersect( $roles, (array) $user->roles );
	}

	/**
	 * Open (pending) upload item with the same content and the same kind of
	 * name (executable or not), if any. An executable attempt never merges into
	 * an item that was held under a harmless name, so approving that item cannot
	 * approve the script.
	 *
	 * @param string $sha256     Hash.
	 * @param bool   $executable Whether the new attempt has an executable name.
	 * @return array|null
	 */
	private function find_open_by_hash( $sha256, $executable = false ) {
		$result = wpcybersec()->store->items_query(
			array(
				'type'     => Store::TYPE_UPLOAD,
				'status'   => Store::STATUS_PENDING,
				'search'   => $sha256,
				'per_page' => 5,
			)
		);
		$blog_id = is_multisite() ? (int) get_current_blog_id() : 0;
		foreach ( $result['rows'] as $row ) {
			if ( $row['sha256'] !== $sha256 || self::item_is_executable( $row ) !== (bool) $executable ) {
				continue;
			}
			// Multisite: the same file held on another site is another import, so another item.
			$row_blog = isset( $row['details']['blog_id'] ) ? (int) $row['details']['blog_id'] : 0;
			if ( $blog_id && $row_blog && $row_blog !== $blog_id ) {
				continue;
			}
			return $row;
		}
		return null;
	}

	/**
	 * Whether an upload item was held under an executable name.
	 *
	 * @param array $item Item.
	 * @return bool
	 */
	public static function item_is_executable( array $item ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		if ( array_key_exists( 'executable', $details ) ) {
			return (bool) $details['executable'];
		}
		return self::name_is_executable( isset( $item['path'] ) ? (string) $item['path'] : '' );
	}

	/**
	 * Message shown in the uploader. Never contains internal paths.
	 *
	 * @param string $name      Safe file name.
	 * @param string $context   Context.
	 * @param bool   $malicious Whether hits >= 2.
	 * @return string
	 */
	private function hold_message( $name, $context, $malicious ) {
		if ( $malicious ) {
			/* translators: %s: file name */
			$message = sprintf( __( '"%s" was held because it looks unsafe (Qartvelo Guard). An administrator will review it.', 'qartvelo-guard' ), $name );
		} elseif ( in_array( $context, array( 'plugin_zip', 'theme_zip' ), true ) ) {
			/* translators: %s: file name */
			$message = sprintf( __( '"%s" is waiting for administrator approval (Qartvelo Guard). After approval, upload it again and it will install.', 'qartvelo-guard' ), $name );
		} elseif ( in_array( $context, array( 'media', 'rest', 'sideload' ), true ) ) {
			/* translators: %s: file name */
			$message = sprintf( __( '"%s" is waiting for administrator approval (Qartvelo Guard). After approval it appears in the Media Library automatically and identical files are allowed from then on.', 'qartvelo-guard' ), $name );
		} else {
			/* translators: %s: file name */
			$message = sprintf( __( '"%s" is waiting for administrator approval (Qartvelo Guard). After approval, upload it again and it will go through.', 'qartvelo-guard' ), $name );
		}
		if ( Admin\Admin::can() ) {
			$message .= ' ' . ( is_multisite()
				? __( 'Review it under Network Admin > Qartvelo Guard > Reports.', 'qartvelo-guard' )
				: __( 'Review it under Qartvelo Guard > Reports.', 'qartvelo-guard' ) );
		}
		return $message;
	}

	/**
	 * File name that is safe in HTML and plain text, never empty.
	 *
	 * @param string $name   Name.
	 * @param string $sha256 Hash for the fallback name.
	 * @return string
	 */
	public static function safe_name( $name, $sha256 = '' ) {
		$name = wp_check_invalid_utf8( (string) $name, true );
		$name = sanitize_file_name( wp_basename( str_replace( '\\', '/', (string) $name ) ) );
		if ( '' === $name ) {
			$name = 'upload-' . substr( (string) $sha256, 0, 8 );
		}
		return self::cut( $name, 200 );
	}

	/**
	 * Whether a client file name is executable on the server: Paths::is_executable()
	 * on the name and on the forms it is commonly turned into before it is stored
	 * (sanitized, cut at ":" or ";", trailing dots and spaces removed).
	 *
	 * @param string $name File name.
	 * @return bool
	 */
	public static function name_is_executable( $name ) {
		$base = wp_basename( str_replace( '\\', '/', (string) $name ) );
		if ( '' === $base ) {
			return false;
		}
		$candidates = array(
			$base,
			rtrim( $base, '. ' ),
			rtrim( (string) preg_replace( '/[:;\x00].*$/s', '', $base ), '. ' ),
			(string) preg_replace( '/[\s\x00-\x1F\x7F]+/', '', $base ),
			sanitize_file_name( $base ),
		);
		foreach ( array_unique( $candidates ) as $candidate ) {
			if ( '' !== $candidate && Paths::is_executable( $candidate ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Shortens text to at most $bytes bytes without cutting a UTF-8 character
	 * in half (a broken character makes the database refuse the whole row).
	 *
	 * @param string $text  Text.
	 * @param int    $bytes Maximum length in bytes.
	 * @return string
	 */
	public static function cut( $text, $bytes ) {
		$text  = (string) $text;
		$bytes = max( 0, (int) $bytes );
		if ( strlen( $text ) <= $bytes ) {
			return $text;
		}
		if ( function_exists( 'mb_strcut' ) ) {
			return (string) mb_strcut( $text, 0, $bytes, 'UTF-8' );
		}
		$text = substr( $text, 0, $bytes );
		if ( ! preg_match( '//u', $text ) ) {
			$text = (string) preg_replace( '/[\xC0-\xFF][\x80-\xBF]*$/', '', $text );
		}
		return $text;
	}

	/**
	 * Single top-level folder of a ZIP, the way WordPress picks the install folder.
	 *
	 * @param string $zip_path Path to the ZIP.
	 * @return string Folder name, or '' when there is not exactly one top-level folder.
	 */
	public static function zip_top_folder( $zip_path ) {
		if ( ! is_file( $zip_path ) ) {
			return '';
		}
		$names = self::zip_entry_names( $zip_path );
		if ( ! $names ) {
			return '';
		}
		$top    = array();
		$is_dir = array();
		foreach ( $names as $entry ) {
			$entry = ltrim( str_replace( '\\', '/', (string) $entry ), '/' );
			if ( '' === $entry || 0 === strpos( $entry, '__MACOSX/' ) ) {
				continue; // WordPress skips the macOS metadata folder too.
			}
			$parts = explode( '/', $entry, 2 );
			$first = $parts[0];
			if ( '' === $first || '.' === $first || '..' === $first ) {
				continue;
			}
			$top[ $first ] = true;
			if ( isset( $parts[1] ) ) {
				$is_dir[ $first ] = true;
			}
			if ( count( $top ) > 1 ) {
				break;
			}
		}
		if ( 1 !== count( $top ) ) {
			return '';
		}
		$folder = (string) key( $top );
		return isset( $is_dir[ $folder ] ) ? $folder : '';
	}

	/**
	 * Entry names of a ZIP (at most 100000): ZipArchive, or PclZip (bundled
	 * with WordPress) on servers without the zip extension.
	 *
	 * @param string $zip_path Path to the ZIP (any extension).
	 * @return string[] Empty when the archive cannot be read.
	 */
	private static function zip_entry_names( $zip_path ) {
		$names = array();
		if ( class_exists( '\ZipArchive' ) ) {
			$zip = new \ZipArchive();
			if ( true === $zip->open( $zip_path ) ) {
				$count = min( (int) $zip->numFiles, 100000 );
				for ( $i = 0; $i < $count; $i++ ) {
					$entry = $zip->getNameIndex( $i );
					if ( false !== $entry ) {
						$names[] = (string) $entry;
					}
				}
				$zip->close();
				return $names;
			}
		}
		// PclZip stops the whole request without zlib, so check that first.
		if ( ! function_exists( 'gzopen' ) ) {
			return array();
		}
		if ( ! class_exists( 'PclZip', false ) ) {
			$file = ABSPATH . 'wp-admin/includes/class-pclzip.php';
			if ( ! is_readable( $file ) ) {
				return array();
			}
			require_once $file;
		}
		try {
			$archive = new \PclZip( $zip_path );
			$list    = $archive->listContent();
		} catch ( \Throwable $e ) {
			return array();
		}
		if ( ! is_array( $list ) ) {
			return array();
		}
		foreach ( array_slice( $list, 0, 100000 ) as $entry ) {
			if ( is_array( $entry ) && isset( $entry['filename'] ) ) {
				// PclZip reports folders without the trailing slash ZipArchive keeps.
				$names[] = (string) $entry['filename'] . ( ! empty( $entry['folder'] ) ? '/' : '' );
			}
		}
		return $names;
	}

	/**
	 * @return string Request URI, trimmed and sanitized.
	 */
	private static function request_uri() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		return self::cut( $uri, 1000 );
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
