<?php
/**
 * Safe edits of define() constants in wp-config.php.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Adds, changes or removes define( 'NAME', value ); lines in wp-config.php.
 *
 * Every write is checked before it lands: the new file must parse as PHP
 * (token_get_all with TOKEN_PARSE; without the tokenizer nothing is written),
 * the changed define must be the active one, a constant already set by a file
 * that wp-config.php loads is never defined a second time,
 * it is written through a temp file + rename next to the real file (a
 * symlinked wp-config.php stays a symlink), and it keeps the original
 * permissions. A backup of the previous version is kept in the plugin's data
 * folder (never next to wp-config.php, where a .bak copy could be downloaded
 * as plain text), under a random name, and only when that folder cannot be
 * downloaded from the web. The newest few backups are kept.
 */
class Config_Editor {

	/** Marker WordPress puts above wp-settings.php. New lines go above it. */
	const STOP_MARKER = "/* That's all, stop editing!";

	/** Backups kept in <data>/backups. */
	const BACKUPS_KEEP = 5;

	/**
	 * Location of wp-config.php, using the same rule as wp-load.php.
	 *
	 * @return string Absolute path or '' when not found.
	 */
	public static function path() {
		$root = Paths::wp_root();
		if ( file_exists( $root . 'wp-config.php' ) ) {
			return $root . 'wp-config.php';
		}
		$up = dirname( $root ) . '/wp-config.php';
		if ( @file_exists( $up ) && ! @file_exists( dirname( $root ) . '/wp-settings.php' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return wp_normalize_path( $up );
		}
		return '';
	}

	/**
	 * The file that is really written: symlinks resolved (for example a
	 * deployment's release/wp-config.php -> shared/wp-config.php).
	 *
	 * @param string $path wp-config.php path.
	 * @return string
	 */
	private static function real_path( $path ) {
		$real = '' !== $path ? realpath( $path ) : false;
		return $real ? wp_normalize_path( $real ) : $path;
	}

	/**
	 * Whether PHP can rewrite wp-config.php (file and its folder writable).
	 *
	 * @return bool
	 */
	public static function is_writable() {
		$path = self::path();
		if ( ! $path ) {
			return false;
		}
		$real = self::real_path( $path );
		return is_readable( $real ) && Fs::is_writable( $real ) && Fs::is_writable( dirname( $real ) );
	}

	/**
	 * Whether this PHP can check an edited wp-config.php for syntax errors
	 * (tokenizer extension with TOKEN_PARSE). Without it nothing is edited.
	 *
	 * @return bool
	 */
	public static function can_check() {
		return function_exists( 'token_get_all' ) && defined( 'TOKEN_PARSE' );
	}

	/**
	 * Whether a one-click edit of wp-config.php can work here: writable and checkable.
	 *
	 * @return bool
	 */
	public static function can_edit() {
		return self::can_check() && self::is_writable();
	}

	/**
	 * Whether wp-config.php contains an active define for $name (lines in
	 * comments are ignored).
	 *
	 * @param string $name Constant.
	 * @return bool
	 */
	public static function has_constant( $name ) {
		$path = self::path();
		if ( ! $path || ! is_readable( $path ) ) {
			return false;
		}
		return (bool) self::define_spans( (string) file_get_contents( $path ), $name ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/**
	 * Adds or updates define( $name, $value ).
	 *
	 * @param string                $name  Constant name (A-Z, 0-9, _).
	 * @param string|int|float|bool $value Scalar value.
	 * @return true|\WP_Error
	 */
	public static function set_constant( $name, $value ) {
		if ( ! preg_match( '/^[A-Z][A-Z0-9_]*$/', $name ) || ! is_scalar( $value ) ) {
			return new \WP_Error( 'wpcybersec_config_name', __( 'Invalid constant.', 'qartvelo-guard' ) );
		}
		$path = self::path();
		if ( ! $path ) {
			return new \WP_Error( 'wpcybersec_config_missing', __( 'wp-config.php was not found.', 'qartvelo-guard' ) );
		}
		$define = 'define( ' . var_export( $name, true ) . ', ' . var_export( $value, true ) . ' );'; // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		if ( ! self::can_check() ) {
			return new \WP_Error(
				'wpcybersec_config_tokenizer',
				/* translators: %s: PHP line */
				sprintf( __( 'PHP\'s tokenizer extension is missing on this server, so the edited wp-config.php could not be checked for errors and nothing was changed. Add this line to wp-config.php by hand, above "That\'s all, stop editing!": %s', 'qartvelo-guard' ), $define )
			);
		}
		if ( ! self::is_writable() ) {
			return new \WP_Error( 'wpcybersec_config_readonly', __( 'wp-config.php is read-only for WordPress, so the line has to be added by hand.', 'qartvelo-guard' ) );
		}

		$code  = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$spans = self::define_spans( $code, $name );

		// Defined, but not in wp-config.php itself: a file it loads sets it
		// (Bedrock config/*.php, wp-config-local.php). A second define here
		// would only cause a warning, so say where to change it instead.
		if ( ! $spans && defined( $name ) ) {
			$current = constant( $name );
			if ( $current === $value || ( is_bool( $value ) && is_scalar( $current ) && (bool) $current === $value ) ) {
				return true;
			}
			return new \WP_Error(
				'wpcybersec_config_elsewhere',
				sprintf(
					/* translators: 1: constant name, 2: PHP line */
					__( '%1$s is already set in another file that wp-config.php loads (for example config/application.php on Bedrock, or a wp-config-local.php), so nothing was changed. Change it in that file to: %2$s', 'qartvelo-guard' ),
					$name,
					$define
				)
			);
		}

		if ( $spans ) {
			$new = substr( $code, 0, $spans[0][0] ) . $define . substr( $code, $spans[0][1] );
		} else {
			$block = '// Added by Qartvelo Guard on ' . gmdate( 'Y-m-d' ) . ".\n" . $define . "\n\n";
			$pos   = strpos( $code, self::STOP_MARKER );
			if ( false === $pos ) {
				$pos = self::settings_require_pos( $code );
			}
			if ( false === $pos ) {
				return new \WP_Error( 'wpcybersec_config_layout', __( 'wp-config.php has an unusual layout, so the line has to be added by hand.', 'qartvelo-guard' ) );
			}
			$new = substr( $code, 0, $pos ) . $block . substr( $code, $pos );
		}

		// The define PHP will actually run must be the new one.
		$check = self::define_spans( $new, $name );
		if ( ! $check || substr( $new, $check[0][0], $check[0][1] - $check[0][0] ) !== $define ) {
			return new \WP_Error( 'wpcybersec_config_layout', __( 'wp-config.php has an unusual layout, so the line has to be added by hand.', 'qartvelo-guard' ) );
		}

		return self::write( $path, $code, (string) $new, $name );
	}

	/**
	 * Removes define( $name, ... ) lines (only defines that stand alone on
	 * their line, plus the comment line this class adds above them).
	 *
	 * @param string $name Constant.
	 * @return true|\WP_Error
	 */
	public static function remove_constant( $name ) {
		$path = self::path();
		if ( ! self::can_check() ) {
			return new \WP_Error( 'wpcybersec_config_tokenizer', __( 'PHP\'s tokenizer extension is missing on this server, so the edited wp-config.php could not be checked for errors and nothing was changed. Remove the line from wp-config.php by hand.', 'qartvelo-guard' ) );
		}
		if ( ! $path || ! self::is_writable() ) {
			return new \WP_Error( 'wpcybersec_config_readonly', __( 'wp-config.php is read-only for WordPress.', 'qartvelo-guard' ) );
		}
		$code  = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$spans = self::define_spans( $code, $name );
		if ( ! $spans ) {
			return true;
		}
		$new = $code;
		foreach ( array_reverse( $spans ) as $span ) {
			list( $start, $end ) = $span;

			// The whole line when the define stands alone on it.
			$line_start = strrpos( substr( $new, 0, $start ), "\n" );
			$line_start = false === $line_start ? 0 : $line_start + 1;
			$eol        = strpos( $new, "\n", $end );
			$line_end   = false === $eol ? strlen( $new ) : $eol + 1;
			$before     = substr( $new, $line_start, $start - $line_start );
			$after      = substr( $new, $end, $line_end - $end );
			if ( '' !== trim( $before ) || '' !== trim( $after ) ) {
				continue; // Part of a longer line (for example after an if): left alone.
			}
			$start = $line_start;
			// Our own comment line right above it.
			if ( $line_start > 0 ) {
				$prev_start = strrpos( substr( $new, 0, $line_start - 1 ), "\n" );
				$prev_start = false === $prev_start ? 0 : $prev_start + 1;
				if ( preg_match( '#^// Added by (?:Qartvelo Guard|CyberGate Security|WP Cyber Security) on [0-9-]+\.\r?\n\z#', substr( $new, $prev_start, $line_start - $prev_start ) ) ) {
					$start = $prev_start;
				}
			}
			$new = substr( $new, 0, $start ) . substr( $new, $line_end );
		}
		if ( $new === $code ) {
			return true;
		}
		return self::write( $path, $code, (string) $new, $name );
	}

	/**
	 * Removes only the define( $name, ... ) lines this plugin added: a define
	 * alone on its line right below the "// Added by Qartvelo Guard on
	 * <date>." comment (set_constant() writes both). A define written by hand,
	 * or one set_constant() replaced in place, has no such comment and stays.
	 * Nothing is written unless wp-config.php parses before and after.
	 *
	 * @param string $name Constant.
	 * @return bool|\WP_Error True when lines were removed, false when there were none.
	 */
	public static function remove_marked_constant( $name ) {
		$path = self::path();
		if ( ! $path || ! is_readable( $path ) ) {
			return false;
		}
		$code  = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$spans = self::define_spans( $code, $name );
		if ( ! $spans ) {
			return false;
		}
		if ( ! self::can_check() || ! self::parses( $code ) ) {
			return new \WP_Error( 'wpcybersec_config_parse', __( 'wp-config.php could not be checked for errors, so it was not changed.', 'qartvelo-guard' ) );
		}
		if ( ! self::is_writable() ) {
			return new \WP_Error( 'wpcybersec_config_readonly', __( 'wp-config.php is read-only for WordPress.', 'qartvelo-guard' ) );
		}
		$new = $code;
		foreach ( array_reverse( $spans ) as $span ) {
			list( $start, $end ) = $span;
			$line_start = strrpos( substr( $new, 0, $start ), "\n" );
			$line_start = false === $line_start ? 0 : $line_start + 1;
			$eol        = strpos( $new, "\n", $end );
			$line_end   = false === $eol ? strlen( $new ) : $eol + 1;
			if ( '' !== trim( substr( $new, $line_start, $start - $line_start ) ) || '' !== trim( substr( $new, $end, $line_end - $end ) ) || 0 === $line_start ) {
				continue;
			}
			$prev_start = strrpos( substr( $new, 0, $line_start - 1 ), "\n" );
			$prev_start = false === $prev_start ? 0 : $prev_start + 1;
			if ( ! preg_match( '#^// Added by (?:Qartvelo Guard|CyberGate Security|WP Cyber Security) on [0-9-]+\.\r?\n\z#', substr( $new, $prev_start, $line_start - $prev_start ) ) ) {
				continue; // Not ours.
			}
			// The blank line set_constant() leaves after the block goes too.
			if ( "\n" === substr( $new, $line_end, 1 ) ) {
				++$line_end;
			} elseif ( "\r\n" === substr( $new, $line_end, 2 ) ) {
				$line_end += 2;
			}
			$new = substr( $new, 0, $prev_start ) . substr( $new, $line_end );
		}
		if ( $new === $code ) {
			return false;
		}
		$written = self::write( $path, $code, (string) $new, $name );
		return is_wp_error( $written ) ? $written : true;
	}

	/**
	 * Byte ranges of the define( 'NAME', ... ); statements PHP would run: a
	 * define inside a comment, a string or inline HTML does not count.
	 *
	 * @param string $code PHP source.
	 * @param string $name Constant.
	 * @return array[] Each array( start, end ), end just after the ";".
	 */
	private static function define_spans( $code, $name ) {
		if ( ! function_exists( 'token_get_all' ) ) {
			return self::define_spans_regex( $code, $name );
		}
		try {
			$tokens = token_get_all( $code );
		} catch ( \Throwable $e ) {
			return self::define_spans_regex( $code, $name );
		}
		$list   = array();
		$offset = 0;
		foreach ( $tokens as $token ) {
			$text   = is_array( $token ) ? $token[1] : $token;
			$list[] = array( is_array( $token ) ? $token[0] : null, $text, $offset );
			$offset += strlen( $text );
		}
		$count     = count( $list );
		$not_after = array( T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_CONST );
		if ( defined( 'T_NULLSAFE_OBJECT_OPERATOR' ) ) {
			$not_after[] = T_NULLSAFE_OBJECT_OPERATOR;
		}
		$spans = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$id   = $list[ $i ][0];
			$text = strtolower( $list[ $i ][1] );
			$is_define = ( T_STRING === $id && 'define' === $text )
				|| ( defined( 'T_NAME_FULLY_QUALIFIED' ) && T_NAME_FULLY_QUALIFIED === $id && '\\define' === $text );
			if ( ! $is_define ) {
				continue;
			}
			$prev = self::code_token( $list, $i, -1 );
			if ( null !== $prev && in_array( $list[ $prev ][0], $not_after, true ) ) {
				continue; // A method or a function declaration named define.
			}
			$open = self::code_token( $list, $i, 1 );
			if ( null === $open || '(' !== $list[ $open ][1] ) {
				continue;
			}
			$arg = self::code_token( $list, $open, 1 );
			if ( null === $arg || T_CONSTANT_ENCAPSED_STRING !== $list[ $arg ][0] || substr( $list[ $arg ][1], 1, -1 ) !== $name ) {
				continue;
			}
			// The parenthesis that closes the call.
			$depth = 0;
			$close = null;
			for ( $j = $open; $j < $count; $j++ ) {
				if ( null !== $list[ $j ][0] ) {
					continue;
				}
				if ( '(' === $list[ $j ][1] ) {
					++$depth;
				} elseif ( ')' === $list[ $j ][1] ) {
					--$depth;
					if ( 0 === $depth ) {
						$close = $j;
						break;
					}
				}
			}
			if ( null === $close ) {
				continue;
			}
			$semi = self::code_token( $list, $close, 1 );
			if ( null === $semi || ';' !== $list[ $semi ][1] ) {
				continue;
			}
			$spans[] = array( $list[ $i ][2], $list[ $semi ][2] + 1 );
			$i       = $semi;
		}
		return $spans;
	}

	/**
	 * Index of the nearest token in $dir direction that is not whitespace or a comment.
	 *
	 * @param array[] $list  Tokens { id, text, offset }.
	 * @param int     $index Start index.
	 * @param int     $dir   1 forward, -1 backward.
	 * @return int|null
	 */
	private static function code_token( array $list, $index, $dir ) {
		$skip = array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT );
		for ( $i = $index + $dir; $i >= 0 && $i < count( $list ); $i += $dir ) {
			if ( ! in_array( $list[ $i ][0], $skip, true ) ) {
				return $i;
			}
		}
		return null;
	}

	/**
	 * Fallback without the tokenizer: defines at the start of a line outside
	 * block comments.
	 *
	 * @param string $code PHP source.
	 * @param string $name Constant.
	 * @return array[]
	 */
	private static function define_spans_regex( $code, $name ) {
		// Blank out block comments (same length, so offsets stay valid).
		$masked = preg_replace_callback(
			'#/\*.*?\*/#s',
			static function ( $m ) {
				return preg_replace( '/[^\n]/', ' ', $m[0] );
			},
			$code
		);
		$spans = array();
		if ( preg_match_all( '#^[ \t]*(define\(\s*[\'"]' . preg_quote( $name, '#' ) . '[\'"]\s*,[^;]*\)\s*;)#m', (string) $masked, $matches, PREG_OFFSET_CAPTURE ) ) {
			foreach ( $matches[1] as $match ) {
				$spans[] = array( $match[1], $match[1] + strlen( $match[0] ) );
			}
		}
		return $spans;
	}

	/**
	 * Start of the line that requires wp-settings.php.
	 *
	 * @param string $code File content.
	 * @return int|false
	 */
	private static function settings_require_pos( $code ) {
		// The line wp-config-sample.php ends with: require_once, a constant name, 'wp-settings.php'.
		if ( preg_match( '#^[ \t]*require(_once)?[\s(]*[A-Z][A-Z0-9_]*\s*\.\s*[\'"]wp-settings\.php#m', $code, $m, PREG_OFFSET_CAPTURE ) ) {
			return $m[0][1];
		}
		return false;
	}

	/**
	 * Validates, backs up and atomically replaces wp-config.php.
	 *
	 * @param string $path Target.
	 * @param string $old  Current content (for the backup).
	 * @param string $new  New content.
	 * @param string $name Constant (for messages).
	 * @return true|\WP_Error
	 */
	private static function write( $path, $old, $new, $name ) {
		if ( ! self::parses( $new ) ) {
			return new \WP_Error( 'wpcybersec_config_parse', __( 'The change would break wp-config.php, so nothing was written.', 'qartvelo-guard' ) );
		}

		$backed_up = self::backup( $old );

		// Write next to the real file: renaming over a symlink would turn it into
		// a plain file and the shared original would never get the change.
		$real      = self::real_path( $path );
		$perms     = fileperms( $real ) & 0777;
		$tmp       = dirname( $real ) . '/.wpcybersec-config-' . wp_generate_password( 8, false ) . '.tmp';
		$old_umask = umask( 0077 );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		$written = @file_put_contents( $tmp, $new, LOCK_EX );
		umask( $old_umask );
		if ( false === $written ) {
			Fs::delete( $tmp );
			return new \WP_Error( 'wpcybersec_config_write', __( 'Could not write wp-config.php.', 'qartvelo-guard' ) );
		}
		Fs::chmod( $tmp, $perms );
		if ( ! Fs::replace( $tmp, $real ) ) {
			Fs::delete( $tmp );
			return new \WP_Error( 'wpcybersec_config_write', __( 'Could not replace wp-config.php.', 'qartvelo-guard' ) );
		}
		if ( function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $path, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $real !== $path ) {
				@opcache_invalidate( $real, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
		}

		// The rewritten file is ours: keep the file monitor from reporting it.
		$plugin = wpcybersec();
		if ( $plugin->is_booted() && is_object( $plugin->file_monitor ) && method_exists( $plugin->file_monitor, 'trust_file' ) ) {
			$plugin->file_monitor->trust_file( $path );
		}
		if ( $plugin->is_booted() && is_object( $plugin->logger ) ) {
			if ( $backed_up ) {
				/* translators: %s: constant name */
				$message = sprintf( __( 'Updated %s in wp-config.php (a backup was saved first).', 'qartvelo-guard' ), $name );
			} else {
				/* translators: %s: constant name */
				$message = sprintf( __( 'Updated %s in wp-config.php. No backup was kept because the plugin\'s data folder can be downloaded from the web.', 'qartvelo-guard' ), $name );
			}
			$plugin->logger->log( 'wp_config_changed', $message );
		}
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Backups                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Saves $old as a backup when the backups folder cannot be downloaded.
	 *
	 * @param string $old Previous content of wp-config.php.
	 * @return bool Whether a backup was written.
	 */
	private static function backup( $old ) {
		$storage = new Storage();
		$dir     = $storage->path( 'backups' );
		if ( ! self::backups_hidden( $storage ) ) {
			// A copy there could be downloaded with the database password in it.
			// The change itself is still protected by the parse check and the
			// atomic replace; the old content only lives in memory.
			self::secure_backups();
			return false;
		}
		$storage->ensure();
		$written   = false;
		$old_umask = umask( 0077 );
		try {
			if ( is_dir( $dir ) || wp_mkdir_p( $dir ) ) {
				$storage->protect( $dir );
				$now   = microtime( true );
				$micro = min( 999999, (int) floor( ( $now - floor( $now ) ) * 1000000 ) );
				$file  = $dir . '/' . self::backup_name( gmdate( 'Ymd-His', (int) floor( $now ) ) . '-' . sprintf( '%06d', $micro ) );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				$written = false !== @file_put_contents( $file, $old, LOCK_EX );
				if ( $written ) {
					Fs::chmod( $file, 0600 );
				} else {
					Fs::delete( $file );
				}
			}
		} finally {
			umask( $old_umask );
		}
		self::secure_backups();
		return $written;
	}

	/**
	 * Whether files in the data folder cannot be downloaded: the folder is
	 * outside the web root, or the live web test was refused by the server.
	 *
	 * @param Storage $storage Storage.
	 * @return bool
	 */
	private static function backups_hidden( Storage $storage ) {
		if ( ! $storage->is_in_webroot( $storage->data_dir() ) ) {
			return true;
		}
		$tools = Sysadmin_Tools::service( 'sysadmin' );
		$tools = $tools ? $tools : new Sysadmin_Tools();
		if ( ! method_exists( $tools, 'probe_quarantine_web' ) ) {
			return false;
		}
		try {
			$probe = $tools->probe_quarantine_web( false ); // Cached for an hour.
		} catch ( \Throwable $e ) {
			return false;
		}
		return is_array( $probe ) && isset( $probe['result'] ) && in_array( $probe['result'], array( 'blocked', 'outside' ), true );
	}

	/**
	 * Unguessable backup file name: a timestamp alone can be found by trying.
	 *
	 * @param string $stamp Ymd-His-microseconds (sorts oldest first).
	 * @return string
	 */
	private static function backup_name( $stamp ) {
		try {
			$random = bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable $e ) {
			$random = strtolower( wp_generate_password( 32, false ) );
		}
		return 'wp-config-' . $stamp . '-' . $random . '.bak';
	}

	/**
	 * Gives backups with a guessable name (older versions used the timestamp
	 * only) a random one, and keeps only the newest BACKUPS_KEEP.
	 */
	public static function secure_backups() {
		$dir = ( new Storage() )->path( 'backups' );
		if ( ! @is_dir( $dir ) || @is_link( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return;
		}
		$names = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $names ) ) {
			return;
		}
		$keep = array();
		foreach ( $names as $name ) {
			$file = $dir . '/' . $name;
			if ( is_link( $file ) || ! is_file( $file ) ) {
				continue;
			}
			if ( preg_match( '/^wp-config-(\d{8}-\d{6})\.php\.bak$/', $name, $m ) ) {
				$new = self::backup_name( $m[1] . '-000000' );
				if ( Fs::move( $file, $dir . '/' . $new ) ) {
					Fs::chmod( $dir . '/' . $new, 0600 );
					$keep[] = $new;
				} else {
					Fs::delete( $file );
				}
				continue;
			}
			if ( preg_match( '/^wp-config-\d{8}-\d{6}-\d{6}-[a-z0-9]{32}\.bak$/', $name ) ) {
				$keep[] = $name;
			}
		}
		// Names start with the UTC time (to the microsecond), so they sort oldest first.
		sort( $keep );
		foreach ( array_slice( $keep, 0, max( 0, count( $keep ) - self::BACKUPS_KEEP ) ) as $name ) {
			Fs::delete( $dir . '/' . $name );
		}
	}

	/**
	 * Whether a PHP source string has no syntax errors.
	 *
	 * @param string $code PHP source.
	 * @return bool
	 */
	public static function parses( $code ) {
		if ( ! self::can_check() ) {
			return false; // Nothing can prove the file still works, so never write it unchecked.
		}
		try {
			token_get_all( $code, TOKEN_PARSE );
			return true;
		} catch ( \Throwable $e ) {
			return false;
		}
	}
}
