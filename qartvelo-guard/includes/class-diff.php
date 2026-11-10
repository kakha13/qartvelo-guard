<?php
/**
 * What changed in a reported file: base and current version, redaction, diff rendering.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Builds the "View changes" screen data for a report item.
 *
 *   Base     details.previous_sha256 copy (the last trusted version), else the
 *            official original for WordPress core and wordpress.org plugin
 *            files (Originals), else none: the full content is shown instead.
 *   Current  the live file (up to 4 MB), else the held quarantine copy, else
 *            the copy saved when the item was reported.
 *
 * Both texts are redacted before anything is compared or shown: secret values
 * (database password, keys, salts, tokens) never leave the server.
 *
 * Lines are compared with the Text_Diff engine that ships with WordPress
 * (wp-includes/Text/Diff.php). wp_text_diff() itself is not used: it runs
 * normalize_whitespace(), which removes indentation and blank lines (wrong
 * line numbers, unreadable code) and always prints the whole file. This
 * renderer keeps every byte, numbers the lines, shows only the changed parts
 * with a few lines of context (git style hunks), marks malware matches, and
 * escapes every line itself (esc_html).
 */
class Diff {

	/** Largest file read for this view. */
	const LIVE_MAX = 4194304;

	/** Above this size (either version) the files are not compared line by line. */
	const DIFF_MAX = 1048576;

	/**
	 * PHP up to this size is redacted token by token (token_get_all() needs
	 * up to about 100 bytes of memory per byte of dense code, and admin-ajax
	 * runs with the default memory limit). Larger PHP, and PHP on servers
	 * without the tokenizer extension, is redacted line by line.
	 */
	const PHP_TOKEN_MAX = 262144;

	/** Content view: lines shown before the rest is cut off. */
	const CONTENT_LINES = 3000;

	/** Above this many lines on either side the files are not compared line by line. */
	const MAX_LINES = 20000;

	/** Rendered table rows at most. */
	const MAX_ROWS = 6000;

	/** Unchanged lines shown around a change, and around a malware match. */
	const CONTEXT     = 3;
	const HIT_CONTEXT = 2;

	/** Characters of one line shown before it is shortened. */
	const LONG_LINE = 2000;

	/** Replacement for secret values. */
	const MASK = '********';

	/** Constants whose values are secret (define() and const). */
	const CONST_PATTERN = '/(PASSWORD|PASS|SECRET|TOKEN|_KEY|_SALT|^DB_USER$|^DB_NAME$|AUTH|NONCE)/i';

	/**
	 * Array keys, variables and config keys whose values are secret (matched
	 * on the snake_case key). password, pwd, secret, token and credential
	 * count anywhere in the key ("dbpassword", "mysqlpwd"), "pass" at the end
	 * of a word ("smtppass", "db.pass"). Some over-masking is accepted.
	 */
	const KEY_PATTERN = '/pass(?:word|wd|phrase)|pwd|secret|token|credential|pass(?:[^a-z]|$)|(?:^|[^a-z])(?:pw|salt|auth|authorization|dsn)(?:[^a-z]|$)|(?:api|app|auth|access|private|secret|client|license|encryption|signing|master)_?key/';

	/** Extensions handled as PHP code. */
	const PHP_EXTENSIONS = array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'inc' );

	/** Extensions handled as key = value configuration. */
	const CONFIG_EXTENSIONS = array( 'ini', 'env', 'conf', 'cnf', 'cfg', 'properties', 'yml', 'yaml', 'toml' );

	/** Scripts whose NAME=value lines are read like configuration (export API_TOKEN=...). */
	const SCRIPT_EXTENSIONS = array( 'sh', 'bash', 'zsh', 'ksh', 'py', 'pl', 'cgi', 'rb' );

	/** XML files whose <add key="..." value="..."> pairs are read. */
	const XML_EXTENSIONS = array( 'config', 'xml' );

	/** Functions and classes whose positional arguments are database credentials (0-based). */
	const CONNECT_ARGS = array(
		'wpdb'                => array( 0, 1, 2 ),
		'mysqli'              => array( 1, 2, 3 ),
		'pdo'                 => array( 1, 2 ),
		'mysqli_connect'      => array( 1, 2, 3 ),
		'mysqli_real_connect' => array( 2, 3, 4 ),
		'real_connect'        => array( 1, 2, 3 ),
		'mysql_connect'       => array( 1, 2 ),
		'mysql_pconnect'      => array( 1, 2 ),
	);

	/** Of CONNECT_ARGS, the classes (only after "new"). */
	const CONNECT_CLASSES = array( 'wpdb', 'mysqli', 'pdo' );

	/**
	 * Well known secret formats, hidden in every kind of file. Group 1, when
	 * present, is the secret part; otherwise the whole match is.
	 */
	const TOKEN_PATTERNS = array(
		'AWS access key ID' => '/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b/',
		'Stripe key'        => '/\b(?:(?:sk|rk)_(?:live|test)|whsec)_[0-9A-Za-z]{10,}+/',
		'SendGrid key'      => '/\bSG\.[A-Za-z0-9_\-]{16,}+\.[A-Za-z0-9_\-]{16,}+/',
		'Slack token'       => '/\bxox[abposr]-[A-Za-z0-9\-]{10,}+/',
		'Slack webhook'     => '~hooks\.slack\.com/services/([A-Za-z0-9/_\-]{20,}+)~',
		'GitHub token'      => '/\b(?:gh[pousr]_[A-Za-z0-9]{30,}+|github_pat_[A-Za-z0-9_]{30,}+)/',
		'Google API key'    => '/\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])/',
		'API key'           => '/\bsk-(?=[A-Za-z_\-]*+[0-9])[A-Za-z0-9_\-]{20,}+/',
		'Mailgun key'       => '/\bkey-[0-9a-f]{32}\b/',
		'JWT'               => '/\beyJ[A-Za-z0-9_\-]{8,}+\.eyJ[A-Za-z0-9_\-]{8,}+\.[A-Za-z0-9_\-]{8,}+/',
	);

	/* ------------------------------------------------------------------ */
	/* Entry points                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Everything the changes screen shows for one item.
	 *
	 * @param array $item Item row (Store::item_get()).
	 * @param array $args {
	 *     @type string $layout  unified | split. Default unified.
	 *     @type bool   $network Allow downloading the official original. Default true.
	 *     @type bool   $render  Build the HTML (false: counts only). Default true.
	 *     @type bool   $texts   With render false: still read and redact the current
	 *                           version when there is nothing to compare with (for
	 *                           excerpt()). Default false.
	 * }
	 * @return array {
	 *     mode: diff|content|unavailable, reason: string code, reason_text, base_label,
	 *     current_label, base, current (both redacted), added, removed, html, notes
	 *     (list of { tone, text }), secrets (names of hidden values that differ),
	 *     base_source (previous|official|''), current_source (live|held|copy|''),
	 *     hit_lines (line => redacted line text), layout
	 * }
	 */
	public static function for_item( array $item, array $args = array() ) {
		$args = array_merge(
			array(
				'layout'  => 'unified',
				'network' => true,
				'render'  => true,
				'texts'   => false,
			),
			$args
		);
		$layout  = 'split' === $args['layout'] ? 'split' : 'unified';
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$name    = basename( (string) $item['path'] );
		$out     = array(
			'mode'           => 'unavailable',
			'reason'         => '',
			'reason_text'    => '',
			'base_label'     => '',
			'current_label'  => '',
			'base'           => '',
			'current'        => '',
			'added'          => 0,
			'removed'        => 0,
			'html'           => '',
			'notes'          => array(),
			'secrets'        => array(),
			'base_source'    => '',
			'current_source' => '',
			'hit_lines'      => array(),
			'layout'         => $layout,
		);

		if ( Store::TYPE_INSTALL === $item['type'] ) {
			return self::unavailable( $out, 'install' );
		}
		if ( Store::TYPE_USER === $item['type'] || Db_Scanner::is_db_item( $item ) ) {
			return self::unavailable( $out, 'not_a_file' );
		}

		$current = self::current_text( $item );
		if ( null === $current['text'] ) {
			return self::unavailable( $out, $current['reason'] );
		}
		if ( Snapshots::is_binary( $current['text'] ) ) {
			return self::unavailable( $out, 'binary' );
		}
		$out['current_label']  = $current['label'];
		$out['current_source'] = $current['source'];
		if ( $current['changed'] ) {
			$out['notes'][] = array( 'warn', __( 'The file changed again after it was reported. You are looking at its content now, so the line numbers of the matches may be off.', 'qartvelo-guard' ) );
		}

		$hits = self::hit_line_numbers( $details );
		$base = self::base_text( $item, (bool) $args['network'] );
		if ( '' !== $base['note'] ) {
			$out['notes'][] = array( 'info', $base['note'] );
		}
		if ( null !== $base['text'] && Snapshots::is_binary( $base['text'] ) ) {
			$base['text'] = null;
		}
		// Redacting and comparing very large files would exhaust the memory
		// limit (admin-ajax does not raise it): show the content instead.
		$too_long = null !== $base['text'] && max( strlen( $base['text'] ), strlen( $current['text'] ) ) > self::DIFF_MAX;
		if ( $too_long ) {
			$base['text'] = null;
		}

		// Counts only and nothing to compare with: the content is not needed.
		if ( null === $base['text'] && ! $args['render'] && ! $args['texts'] ) {
			$out['mode']        = 'content';
			$out['reason']      = $too_long ? 'too_large_to_diff' : self::no_base_reason( $item, $details );
			$out['reason_text'] = self::reason_text( $out['reason'] );
			return $out;
		}

		// Both versions are read the same way, so unchanged lines stay equal.
		$bytes = max( strlen( $current['text'] ), null === $base['text'] ? 0 : strlen( $base['text'] ) );
		$php   = function_exists( 'token_get_all' ) && $bytes <= self::PHP_TOKEN_MAX ? 'tokens' : 'lines';

		$found_current = array();
		$current_red   = self::redact( $current['text'], $name, $found_current, $php );
		if ( is_array( $current['found'] ) ) {
			// A copy stored redacted: the fingerprints were taken from the real values.
			$found_current = $current['found'];
		}
		$current_sha     = $current['sha'];
		$current['text'] = null;
		$current_lines   = self::lines( $current_red );
		foreach ( $hits as $line ) {
			if ( isset( $current_lines[ $line - 1 ] ) ) {
				$out['hit_lines'][ $line ] = $current_lines[ $line - 1 ];
			}
		}
		$out['current'] = $current_red;

		$found_base = array();
		$base_red   = null;
		if ( null !== $base['text'] ) {
			$base_red     = self::redact( $base['text'], $name, $found_base, $php );
			$base['text'] = null;
			if ( is_array( $base['found'] ) ) {
				$found_base = $base['found'];
			}
		}
		if ( $found_current || $found_base || is_array( $current['found'] ) || is_array( $base['found'] ) ) {
			$out['notes'][] = array( 'info', __( 'Passwords, keys, salts and tokens are replaced with ******** on this page. They are never shown.', 'qartvelo-guard' ) );
		}

		$base_lines = null === $base_red ? array() : self::lines( $base_red );
		if ( null !== $base_red && ( count( $base_lines ) > self::MAX_LINES || count( $current_lines ) > self::MAX_LINES ) ) {
			$too_long = true;
			$base_red = null;
		}

		if ( null === $base_red ) {
			$out['mode']        = 'content';
			$out['reason']      = $too_long ? 'too_large_to_diff' : self::no_base_reason( $item, $details );
			$out['reason_text'] = self::reason_text( $out['reason'] );
			if ( $args['render'] ) {
				$label       = '' !== $out['current_label'] ? $out['current_label'] : $name;
				$out['html'] = self::render_content( $current_lines, $hits, $label, $out['notes'] );
			}
			return $out;
		}

		$ops = self::compute( $base_lines, $current_lines );
		if ( null === $ops ) {
			return self::unavailable( $out, 'engine' );
		}
		foreach ( $ops as $op ) {
			if ( $op instanceof \Text_Diff_Op_add ) {
				$out['added'] += count( (array) $op->final );
			} elseif ( $op instanceof \Text_Diff_Op_delete ) {
				$out['removed'] += count( (array) $op->orig );
			} elseif ( $op instanceof \Text_Diff_Op_change ) {
				$out['added']   += count( (array) $op->final );
				$out['removed'] += count( (array) $op->orig );
			}
		}

		$out['mode']        = 'diff';
		$out['base']        = $base_red;
		$out['base_label']  = $base['label'];
		$out['base_source'] = $base['source'];
		$comparable = $current['key'] === $base['key'] || ( ! $found_base && ! $found_current );
		if ( ! $comparable ) {
			// Fingerprints taken with different WordPress keys cannot be compared.
			$out['notes'][] = array( 'info', __( 'The security keys in wp-config.php changed after the earlier version was saved, so it cannot be told which hidden values differ.', 'qartvelo-guard' ) );
		} else {
			$out['secrets'] = self::changed_secrets( $found_base, $found_current );
		}
		if ( $out['secrets'] ) {
			$out['notes'][] = array(
				'warn',
				sprintf(
					/* translators: %s: comma separated names such as DB_PASSWORD */
					__( 'Hidden values that differ between the two versions: %s.', 'qartvelo-guard' ),
					implode( ', ', $out['secrets'] )
				),
			);
		}
		if ( 0 === $out['added'] + $out['removed'] ) {
			if ( '' !== $current_sha && $base['sha'] === $current_sha ) {
				$out['notes'][] = array( 'ok', __( 'This file is identical to the version it is compared with.', 'qartvelo-guard' ) );
			} elseif ( ! $out['secrets'] && $comparable ) {
				$out['notes'][] = array( 'info', __( 'The two versions differ only in line endings or in the line break at the end of the file.', 'qartvelo-guard' ) );
			}
		}
		if ( $args['render'] ) {
			$out['html'] = self::render_diff( $ops, $hits, $layout, $out['base_label'], $out['current_label'], $out['notes'] );
		}
		return $out;
	}

	/**
	 * Cheap one-line summary for the expandable details on the Reports page:
	 * never downloads anything and builds no HTML.
	 *
	 * @param array $item Item.
	 * @return array { mode, added, removed, base_label, text }
	 */
	public static function summary( array $item ) {
		$result = self::for_item(
			$item,
			array(
				'network' => false,
				'render'  => false,
			)
		);
		if ( 'diff' === $result['mode'] ) {
			$text = sprintf(
				/* translators: 1: lines added, 2: lines removed, 3: what the file is compared with */
				__( 'Changes: +%1$s -%2$s lines vs %3$s', 'qartvelo-guard' ),
				number_format_i18n( $result['added'] ),
				number_format_i18n( $result['removed'] ),
				$result['base_label']
			);
		} elseif ( 'content' === $result['mode'] && in_array( $result['reason'], array( 'too_large_to_diff', 'unapproved' ), true ) ) {
			$text = $result['reason_text'];
		} elseif ( 'content' === $result['mode'] ) {
			$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
			$text    = isset( $details['checksum'] ) && 'mismatch' === $details['checksum']
				? __( 'Changes: compare with the official file', 'qartvelo-guard' )
				: __( 'No earlier version is stored; the full content can be viewed.', 'qartvelo-guard' );
		} else {
			$text = $result['reason_text'];
		}
		return array(
			'mode'       => $result['mode'],
			'added'      => (int) $result['added'],
			'removed'    => (int) $result['removed'],
			'base_label' => (string) $result['base_label'],
			'text'       => (string) $text,
		);
	}

	/**
	 * Plain rows of what changed (or of the content around the matches) for
	 * places that cannot use the screen HTML, such as the downloadable report.
	 * Every line comes from the redacted texts of for_item().
	 *
	 * @param array $item Item (a real one, or a file description with id 0).
	 * @param int   $max  Rows at most (hunk separators included).
	 * @param bool  $network Allow downloading the official original.
	 * @return array {
	 *     mode: diff|content|unavailable, reason_text, base_label, current_label,
	 *     added, removed, notes (plain texts), truncated (bool), total (lines of the
	 *     current version), rows: list of { kind: ' '|'+'|'-'|'@'|'!', old: int, new: int, text }
	 * }
	 */
	public static function excerpt( array $item, $max = 200, $network = false ) {
		$max    = max( 10, (int) $max );
		$result = self::for_item(
			$item,
			array(
				'network' => (bool) $network,
				'render'  => false,
				'texts'   => true,
			)
		);
		$out    = array(
			'mode'          => (string) $result['mode'],
			'reason_text'   => (string) $result['reason_text'],
			'base_label'    => (string) $result['base_label'],
			'current_label' => (string) $result['current_label'],
			'added'         => (int) $result['added'],
			'removed'       => (int) $result['removed'],
			'notes'         => array(),
			'truncated'     => false,
			'total'         => 0,
			'rows'          => array(),
		);
		foreach ( (array) $result['notes'] as $note ) {
			if ( isset( $note[1] ) && '' !== (string) $note[1] ) {
				$out['notes'][] = (string) $note[1];
			}
		}
		$short = static function ( $text ) {
			$text = (string) $text;
			if ( strlen( $text ) > 500 ) {
				$text = ( function_exists( 'mb_strcut' ) ? mb_strcut( $text, 0, 500, 'UTF-8' ) : substr( $text, 0, 500 ) ) . ' ...';
			}
			return $text;
		};

		$current = self::lines( (string) $result['current'] );
		$out['total'] = count( $current );

		if ( 'diff' === $out['mode'] ) {
			$ops = self::compute( self::lines( (string) $result['base'] ), $current );
			if ( null === $ops ) {
				$out['mode'] = 'unavailable';
				return $out;
			}
			// Flatten to one entry per line, then keep the changes with CONTEXT lines around them.
			$flat = array();
			$o    = 1;
			$n    = 1;
			foreach ( $ops as $op ) {
				$orig  = isset( $op->orig ) && is_array( $op->orig ) ? $op->orig : array();
				$final = isset( $op->final ) && is_array( $op->final ) ? $op->final : array();
				if ( $op instanceof \Text_Diff_Op_copy ) {
					foreach ( $final as $line ) {
						$flat[] = array( ' ', $o++, $n++, $line );
					}
					continue;
				}
				foreach ( $orig as $line ) {
					$flat[] = array( '-', $o++, 0, $line );
				}
				foreach ( $final as $line ) {
					$flat[] = array( '+', 0, $n++, $line );
				}
			}
			$keep  = array();
			$count = count( $flat );
			foreach ( $flat as $i => $entry ) {
				if ( ' ' !== $entry[0] ) {
					for ( $j = max( 0, $i - self::CONTEXT ); $j <= min( $count - 1, $i + self::CONTEXT ); $j++ ) {
						$keep[ $j ] = true;
					}
				}
			}
			ksort( $keep );
			$last = -2;
			foreach ( array_keys( $keep ) as $i ) {
				if ( count( $out['rows'] ) >= $max ) {
					$out['truncated'] = true;
					break;
				}
				if ( $i !== $last + 1 ) {
					$out['rows'][] = array(
						'kind' => '@',
						'old'  => $flat[ $i ][1],
						'new'  => $flat[ $i ][2],
						'text' => '',
					);
				}
				$out['rows'][] = array(
					'kind' => $flat[ $i ][0],
					'old'  => $flat[ $i ][1],
					'new'  => $flat[ $i ][2],
					'text' => $short( $flat[ $i ][3] ),
				);
				$last = $i;
			}
			return $out;
		}

		if ( 'content' !== $out['mode'] ) {
			return $out;
		}

		// Content: the lines around every match, else the start of the file.
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$hits    = array_flip( self::hit_line_numbers( $details ) );
		$keep    = array();
		foreach ( array_keys( $hits ) as $line ) {
			for ( $j = max( 1, $line - 5 ); $j <= min( $out['total'], $line + 5 ); $j++ ) {
				$keep[ $j ] = true;
			}
		}
		if ( ! $keep ) {
			for ( $j = 1; $j <= min( $out['total'], $max ); $j++ ) {
				$keep[ $j ] = true;
			}
		}
		ksort( $keep );
		$last = 0;
		foreach ( array_keys( $keep ) as $line ) {
			if ( count( $out['rows'] ) >= $max ) {
				$out['truncated'] = true;
				break;
			}
			if ( $line !== $last + 1 ) {
				$out['rows'][] = array(
					'kind' => '@',
					'old'  => 0,
					'new'  => $line,
					'text' => '',
				);
			}
			$out['rows'][] = array(
				'kind' => isset( $hits[ $line ] ) ? '!' : ' ',
				'old'  => 0,
				'new'  => $line,
				'text' => $short( $current[ $line - 1 ] ),
			);
			$last = $line;
		}
		if ( $last < $out['total'] ) {
			$out['truncated'] = true;
		}
		return $out;
	}

	/**
	 * Which button the Reports table shows for an item.
	 *
	 * @param array $item Item.
	 * @param bool  $held Whether a held copy exists.
	 * @return array|null { kind: changes|code, label, title } or null for no button.
	 */
	public static function view_button( array $item, $held ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		if ( Db_Scanner::is_db_item( $item ) ) {
			return null; // A database value: the matches with their snippets are the whole story.
		}
		if ( in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) {
			$modified = ( isset( $details['change'] ) && 'modified' === $details['change'] ) || ( isset( $details['checksum'] ) && 'mismatch' === $details['checksum'] );
			if ( $modified ) {
				return array(
					'kind'  => 'changes',
					'label' => __( 'Changes', 'qartvelo-guard' ),
					'title' => __( 'See exactly which lines changed', 'qartvelo-guard' ),
				);
			}
			return array(
				'kind'  => 'code',
				'label' => __( 'View code', 'qartvelo-guard' ),
				'title' => __( 'Read the file with the matched lines highlighted', 'qartvelo-guard' ),
			);
		}
		if ( Store::TYPE_UPLOAD === $item['type'] && $held && self::is_text_like( (string) $item['path'], (string) $item['mime'] ) ) {
			return array(
				'kind'  => 'code',
				'label' => __( 'View code', 'qartvelo-guard' ),
				'title' => __( 'Read the held file without downloading it', 'qartvelo-guard' ),
			);
		}
		return null;
	}

	/**
	 * Whether a file name or MIME type is text that can be read on screen.
	 *
	 * @param string $name File name.
	 * @param string $mime MIME type.
	 * @return bool
	 */
	public static function is_text_like( $name, $mime = '' ) {
		if ( Snapshots::is_diffable_name( $name ) ) {
			return true;
		}
		$ext = Paths::ext( $name );
		if ( in_array( $ext, array_merge( self::CONFIG_EXTENSIONS, array( 'txt', 'css', 'json', 'xml', 'csv', 'md', 'log', 'sql' ) ), true ) ) {
			return true;
		}
		$mime = strtolower( (string) $mime );
		return 0 === strpos( $mime, 'text/' ) || in_array( $mime, array( 'application/json', 'application/xml', 'application/javascript', 'image/svg+xml' ), true );
	}

	/* ------------------------------------------------------------------ */
	/* Versions                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * The version to show as "now".
	 *
	 * @param array $item Item.
	 * @return array { text: string|null, label, source, changed: bool, reason, sha: string,
	 *                 found: array|null (fingerprints of a copy stored redacted), key: string }
	 */
	private static function current_text( array $item ) {
		$out = array(
			'text'    => null,
			'label'   => '',
			'source'  => '',
			'changed' => false,
			'reason'  => 'gone',
			'sha'     => '',
			'found'   => null,
			'key'     => self::fingerprint_key_id(),
		);
		$sha = strtolower( (string) $item['sha256'] );

		// 1. The live file.
		if ( in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) {
			$abs = wp_normalize_path( (string) ( '' !== (string) $item['original_path'] ? $item['original_path'] : Paths::abs( (string) $item['path'] ) ) );
			if ( '' !== $abs && @is_file( $abs ) && self::readable_live_path( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( false !== $size && $size > self::LIVE_MAX ) {
					$out['reason'] = 'too_large';
					return $out;
				}
				$text = @file_get_contents( $abs, false, null, 0, self::LIVE_MAX + 1 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
				if ( is_string( $text ) && strlen( $text ) <= self::LIVE_MAX ) {
					$out['text']    = $text;
					$out['label']   = __( 'Current file on the server', 'qartvelo-guard' );
					$out['source']  = 'live';
					$out['sha']     = hash( 'sha256', $text );
					$out['changed'] = Snapshots::is_sha( $sha ) && ! hash_equals( $sha, $out['sha'] );
					return $out;
				}
			}
		}

		// 2. The held copy.
		if ( '' !== (string) $item['quarantine_path'] ) {
			$quarantine = wpcybersec()->quarantine;
			$text       = $quarantine ? $quarantine->read( $item, self::LIVE_MAX ) : null;
			if ( is_string( $text ) ) {
				$out['text']   = $text;
				$out['label']  = __( 'Held copy in quarantine', 'qartvelo-guard' );
				$out['source'] = 'held';
				$out['sha']    = hash( 'sha256', $text );
				return $out;
			}
			if ( is_wp_error( $text ) && 'wpcybersec_q_large' === $text->get_error_code() ) {
				$out['reason'] = 'too_large';
				return $out;
			}
		}

		// 3. The copy saved when it was reported.
		$entry = Snapshots::is_sha( $sha ) ? wpcybersec()->snapshots->get_entry( $sha ) : null;
		if ( is_array( $entry ) ) {
			$out['text']   = $entry['text'];
			$out['label']  = __( 'Copy saved when it was reported', 'qartvelo-guard' );
			$out['source'] = 'copy';
			$out['sha']    = $sha;
			if ( $entry['redacted'] ) {
				$out['found'] = $entry['found'];
				$out['key']   = $entry['key'];
			}
		}
		return $out;
	}

	/**
	 * The version to compare with.
	 *
	 * @param array $item          Item.
	 * @param bool  $allow_network Allow downloading the official original.
	 * @return array { text: string|null, label, source, note, sha: string, found: array|null, key: string }
	 */
	private static function base_text( array $item, $allow_network ) {
		$out       = array(
			'text'   => null,
			'label'  => '',
			'source' => '',
			'note'   => '',
			'sha'    => '',
			'found'  => null,
			'key'    => self::fingerprint_key_id(),
		);
		$details   = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$snapshots = wpcybersec()->snapshots;
		$previous  = isset( $details['previous_sha256'] ) ? strtolower( (string) $details['previous_sha256'] ) : '';

		// 1. The last trusted version.
		if ( Snapshots::is_sha( $previous ) ) {
			$entry = $snapshots->get_entry( $previous );
			if ( is_array( $entry ) ) {
				$when          = $snapshots->stored_at( $previous );
				$out['text']   = $entry['text'];
				$out['sha']    = $previous;
				$out['source'] = 'previous';
				$out['label']  = $when
					/* translators: %s: date */
					? sprintf( __( 'Last approved version, %s', 'qartvelo-guard' ), wp_date( get_option( 'date_format' ), $when ) )
					: __( 'Last approved version', 'qartvelo-guard' );
				if ( $entry['redacted'] ) {
					$out['found'] = $entry['found'];
					$out['key']   = $entry['key'];
				}
				return $out;
			}
		}
		if ( ! in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) {
			return $out;
		}

		// 2. The official original found earlier for this item, while the
		// installed WordPress or plugin version is still the one it belongs to.
		$originals = new Originals();
		$cached    = isset( $details['base_sha256'] ) ? strtolower( (string) $details['base_sha256'] ) : '';
		$version   = isset( $details['base_version'] ) ? (string) $details['base_version'] : '';
		$source    = isset( $details['base_source'] ) ? (string) $details['base_source'] : '';
		if ( Snapshots::is_sha( $cached ) && '' !== $version && $version === $originals->installed_version( (string) $item['path'], $source ) ) {
			$text = $snapshots->get( $cached );
			if ( is_string( $text ) ) {
				$out['text']   = $text;
				$out['sha']    = $cached;
				$out['source'] = 'official';
				$out['label']  = ! empty( $details['base_label'] ) ? (string) $details['base_label'] : __( 'Official file', 'qartvelo-guard' );
			}
		}

		// 3. Download and verify it.
		if ( null === $out['text'] ) {
			$original = $originals->fetch( (string) $item['path'], $allow_network );
			if ( $original ) {
				$out['text']   = $original['content'];
				$out['sha']    = $original['sha256'];
				$out['source'] = 'official';
				$out['label']  = $original['label'];
				if ( ! empty( $item['id'] ) && ( $original['sha256'] !== $cached || $original['version'] !== $version ) && wpcybersec()->snapshots->has( $original['sha256'] ) ) {
					// Remembered on the item: Snapshots::prune() keeps it, and the next view needs no download.
					wpcybersec()->store->item_update(
						(int) $item['id'],
						array(
							'details' => array(
								'base_sha256'  => $original['sha256'],
								'base_label'   => $original['label'],
								'base_source'  => $original['source'],
								'base_version' => $original['version'],
							),
						)
					);
				}
			}
		}

		if ( null !== $out['text'] && Snapshots::is_sha( $previous ) ) {
			$out['note'] = __( 'No copy of the last approved version was kept, so the file is compared with the official release instead.', 'qartvelo-guard' );
		}
		return $out;
	}

	/**
	 * Only files a whole-site scan covers are read (Paths::in_scope(): the
	 * scan root plus the WordPress folders outside it).
	 *
	 * @param string $abs Path.
	 * @return bool
	 */
	private static function readable_live_path( $abs ) {
		if ( ! @is_readable( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		return Paths::in_scope( $abs );
	}

	/**
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return string new_file | upload | unapproved | no_copy
	 */
	private static function no_base_reason( array $item, array $details ) {
		if ( Store::TYPE_UPLOAD === $item['type'] ) {
			return 'upload';
		}
		if ( empty( $details['previous_sha256'] ) && ! empty( $details['previous_state'] ) ) {
			return 'unapproved';
		}
		if ( isset( $details['change'] ) && 'new' === $details['change'] && empty( $details['previous_sha256'] ) ) {
			return 'new_file';
		}
		return 'no_copy';
	}

	/**
	 * @param array  $out    Result so far.
	 * @param string $reason Reason code.
	 * @return array
	 */
	private static function unavailable( array $out, $reason ) {
		$out['mode']        = 'unavailable';
		$out['reason']      = $reason;
		$out['reason_text'] = self::reason_text( $reason );
		return $out;
	}

	/**
	 * Explanation for a reason code.
	 *
	 * @param string $reason Code.
	 * @return string
	 */
	public static function reason_text( $reason ) {
		switch ( $reason ) {
			case 'not_a_file':
				return __( 'This report is not about a file (a database value or a user account), so there is no file to show.', 'qartvelo-guard' );
			case 'new_file':
				return __( 'No earlier version was stored. This file was not part of the baseline, so the full content is shown instead.', 'qartvelo-guard' );
			case 'upload':
				return __( 'This upload was held before it reached the site, so there is no earlier version. Its full content is shown instead.', 'qartvelo-guard' );
			case 'unapproved':
				return __( 'The earlier versions of this file were reported but never approved, so there is no approved version to compare with. The full content is shown instead.', 'qartvelo-guard' );
			case 'too_large_to_diff':
				return __( 'The file is too large to compare line by line (more than 1 MB or 20,000 lines), so its content is shown instead.', 'qartvelo-guard' );
			case 'no_copy':
				return sprintf(
					/* translators: %s: size such as 256 KB */
					__( 'No earlier version was stored, so the full content is shown instead. Copies are kept for PHP and configuration files up to %s, starting from when this feature was turned on, and official WordPress.org files are compared with the original release when it can be downloaded.', 'qartvelo-guard' ),
					size_format( wpcybersec()->snapshots->max_bytes() )
				);
			case 'binary':
				return __( 'This file is binary, so it cannot be shown as text. Download the held copy to inspect it on your computer.', 'qartvelo-guard' );
			case 'too_large':
				return __( 'This file is larger than 4 MB, so it is not shown here.', 'qartvelo-guard' );
			case 'install':
				return __( 'Plugin and theme installs are packages of many files. Their malware matches are listed above.', 'qartvelo-guard' );
			case 'engine':
				return __( 'The WordPress comparison engine (wp-includes/Text/Diff.php) could not be loaded.', 'qartvelo-guard' );
			default:
				return __( 'The file no longer exists and no copy of it was kept, so there is nothing to show.', 'qartvelo-guard' );
		}
	}

	/**
	 * Line numbers of the malware matches.
	 *
	 * @param array $details Details.
	 * @return int[]
	 */
	private static function hit_line_numbers( array $details ) {
		$lines = array();
		foreach ( isset( $details['hits'] ) && is_array( $details['hits'] ) ? $details['hits'] : array() as $hit ) {
			if ( is_array( $hit ) && ! empty( $hit['line'] ) && (int) $hit['line'] > 0 ) {
				$lines[] = (int) $hit['line'];
			}
		}
		$lines = array_values( array_unique( $lines ) );
		sort( $lines );
		return $lines;
	}

	/**
	 * Names of hidden values that differ (or exist in one version only).
	 *
	 * @param array $base    name => fingerprint.
	 * @param array $current name => fingerprint.
	 * @return string[]
	 */
	private static function changed_secrets( array $base, array $current ) {
		$names = array();
		foreach ( array_unique( array_merge( array_keys( $base ), array_keys( $current ) ) ) as $name ) {
			if ( ! isset( $base[ $name ], $current[ $name ] ) || $base[ $name ] !== $current[ $name ] ) {
				$names[] = (string) $name;
			}
		}
		sort( $names, SORT_STRING );
		return $names;
	}

	/* ------------------------------------------------------------------ */
	/* Redaction                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Replaces secret values with ******** while keeping quotes, line breaks
	 * and the shape of every line:
	 *
	 *   - PHP: define() and const whose name matches CONST_PATTERN (every
	 *     literal of the value, also when the name is concatenated),
	 *     'password' => '...' entries and $password = '...' assignments whose
	 *     value holds literals (KEY_PATTERN), putenv( 'NAME=value' ), and the
	 *     credential arguments of new wpdb(), new mysqli(), new PDO(),
	 *     mysqli_connect() and similar. Read token by token (escaped quotes and
	 *     line breaks inside values are handled) up to PHP_TOKEN_MAX, line by
	 *     line above that and on servers without the tokenizer extension.
	 *   - NAME=value lines in .ini/.env/.user.ini and shell style scripts,
	 *     SetEnv in .htaccess, <add key="..." value="..."> in web.config and
	 *     XML, and "password": "..." / password: '...' pairs anywhere.
	 *   - Anywhere: private key blocks, passwords in URLs and connection
	 *     strings, Bearer/Basic authorization values, and well known key
	 *     formats (TOKEN_PATTERNS).
	 *
	 * Fails closed: when a pattern cannot be applied (PCRE backtrack, recursion
	 * or JIT stack limits), every quoted value on the lines concerned is
	 * hidden. Non-empty input never comes back empty.
	 *
	 * @param string $text  Content.
	 * @param string $name  File name (decides how it is read).
	 * @param array  $found Receives name => fingerprint of every hidden value.
	 * @param string $php   PHP reading: tokens | lines | '' (by size and the tokenizer extension).
	 * @return string
	 */
	public static function redact( $text, $name = '', &$found = null, $php = '' ) {
		$found = array();
		$text  = (string) $text;
		if ( '' === $text ) {
			return $text;
		}
		$name = (string) $name;
		if ( self::is_php( $name, $text ) ) {
			$done = null;
			if ( 'lines' !== $php && function_exists( 'token_get_all' ) && strlen( $text ) <= self::PHP_TOKEN_MAX ) {
				$done = self::redact_php( $text, $found );
			}
			$text = null !== $done ? $done : self::redact_php_lines( $text, $found );
		}
		return self::redact_lines( $text, $name, $found );
	}

	/**
	 * Redacts a short excerpt (a malware match snippet: one line, at most 160
	 * characters, which may start in the middle of a statement). Fails closed
	 * where the excerpt alone cannot tell what a value is:
	 *
	 *   - an excerpt that starts inside a quoted string (the name before it
	 *     was cut off) hides that part and every value of its first statement;
	 *   - a quoted name matching CONST_PATTERN followed by a comma hides the
	 *     values after it (a define() whose start was cut off);
	 *   - in configuration files that hold secrets (.env, .ini, ...) every
	 *     NAME=value and NAME: value is hidden.
	 *
	 * @param string $snippet Excerpt.
	 * @param string $name    File name.
	 * @return string
	 */
	public static function redact_snippet( $snippet, $name = '' ) {
		$snippet = (string) $snippet;
		if ( '' === $snippet ) {
			return $snippet;
		}
		$name  = (string) $name;
		$found = array();
		// The hidden start of an excerpt that begins inside a string stays out of the rest.
		list( $lead, $snippet ) = self::split_cut_start( $snippet, $found, Snapshots::is_secret_name( $name ) );
		$snippet                = self::mask_after_secret_names( $snippet, $found );
		$php     = self::is_php( $name, $snippet );
		if ( $php ) {
			$prefix = false === stripos( $snippet, '<?php' ) ? "<?php\n" : '';
			$code   = $prefix . $snippet;
			$out    = function_exists( 'token_get_all' ) ? self::redact_php( $code, $found ) : null;
			$out    = null !== $out ? $out : self::redact_php_lines( $code, $found );
			if ( '' === $prefix ) {
				$snippet = $out;
			} elseif ( 0 === strpos( $out, $prefix ) ) {
				$snippet = (string) substr( $out, strlen( $prefix ) );
			} else {
				$snippet = self::mask_line( $snippet, $found );
			}
		} elseif ( Snapshots::is_secret_name( $name ) ) {
			// A configuration file that holds secrets: no value is shown.
			$snippet = self::mask_config_excerpt( $snippet, $found );
		}
		return $lead . self::redact_lines( $snippet, $name, $found );
	}

	/**
	 * @param string $name File name.
	 * @param string $text Content.
	 * @return bool Whether the content is read as PHP.
	 */
	private static function is_php( $name, $text ) {
		if ( in_array( Paths::ext( (string) $name ), self::PHP_EXTENSIONS, true ) ) {
			return true;
		}
		$head = substr( (string) $text, 0, 2048 );
		return false !== stripos( $head, '<?php' ) || 0 === strpos( ltrim( $head ), '<?=' );
	}

	/**
	 * Snake case lowercase form of a key ("dbPassword" -> "db_password").
	 *
	 * @param string $key Key.
	 * @return string
	 */
	private static function normalize_key( $key ) {
		$key = ltrim( (string) $key, '$' );
		$key = (string) preg_replace( '/([a-z0-9])([A-Z])/', '$1_$2', $key );
		return strtolower( str_replace( '-', '_', $key ) );
	}

	/**
	 * @param string $key Array key, variable or config key.
	 * @return bool
	 */
	private static function secret_key( $key ) {
		return 1 === preg_match( self::KEY_PATTERN, self::normalize_key( $key ) );
	}

	/**
	 * @param string $name Constant name.
	 * @return bool
	 */
	private static function secret_constant( $name ) {
		return 1 === preg_match( self::CONST_PATTERN, (string) $name );
	}

	/**
	 * Remembers a hidden value (only a keyed fingerprint) under a name.
	 *
	 * @param array  $found Collected values.
	 * @param string $label Name.
	 * @param string $value Raw value.
	 */
	private static function remember( array &$found, $label, $value ) {
		$label           = (string) $label;
		$found[ $label ] = hash_hmac( 'sha256', ( isset( $found[ $label ] ) ? $found[ $label ] : '' ) . "\0" . (string) $value, self::fingerprint_key() );
	}

	/**
	 * Key of the value fingerprints. It comes from the keys in wp-config.php
	 * (not from the database), so fingerprints kept next to a redacted copy
	 * cannot be used to test password guesses by someone who only has the
	 * database.
	 *
	 * @return string
	 */
	private static function fingerprint_key() {
		static $key = null;
		if ( null === $key ) {
			$parts = '';
			foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT' ) as $constant ) {
				if ( defined( $constant ) ) {
					$parts .= (string) constant( $constant ) . "\0";
				}
			}
			if ( '' === $parts && function_exists( 'wp_salt' ) ) {
				$parts = (string) wp_salt( 'secure_auth' );
			}
			$key = hash( 'sha256', 'wpcybersec-redaction|' . $parts );
		}
		return $key;
	}

	/**
	 * Short id of the fingerprint key: fingerprints with different ids cannot
	 * be compared (the keys in wp-config.php changed in between).
	 *
	 * @return string
	 */
	public static function fingerprint_key_id() {
		return substr( hash( 'sha256', 'id|' . self::fingerprint_key() ), 0, 12 );
	}

	/* -------- PHP, token by token -------------------------------------- */

	/**
	 * @param array|string $token Token from token_get_all().
	 * @return int|null Token id, null for a single character.
	 */
	private static function tid( $token ) {
		return is_array( $token ) ? $token[0] : null;
	}

	/**
	 * @param array|string $token Token from token_get_all().
	 * @return string Token text.
	 */
	private static function txt( $token ) {
		return is_array( $token ) ? $token[1] : $token;
	}

	/**
	 * Token based redaction of PHP code. Walks the token_get_all() result in
	 * place (no second copy: dense code needs about 100 bytes per byte).
	 *
	 * @param string $text  Code.
	 * @param array  $found Collected values.
	 * @return string|null Null when the code could not be tokenized.
	 */
	private static function redact_php( $text, array &$found ) {
		$t = @token_get_all( $text ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $t ) || ! $t ) {
			return null;
		}
		$n      = count( $t );
		$mask   = array();
		$fq     = defined( 'T_NAME_FULLY_QUALIFIED' ) ? T_NAME_FULLY_QUALIFIED : -1;
		$arrows = array( T_OBJECT_OPERATOR );
		if ( defined( 'T_NULLSAFE_OBJECT_OPERATOR' ) ) {
			$arrows[] = T_NULLSAFE_OBJECT_OPERATOR;
		}

		for ( $i = 0; $i < $n; $i++ ) {
			if ( ! is_array( $t[ $i ] ) ) {
				continue;
			}
			$id  = $t[ $i ][0];
			$str = $t[ $i ][1];

			if ( T_STRING === $id || $fq === $id ) {
				$fn = strtolower( ltrim( $str, '\\' ) );
				if ( 'define' === $fn ) {
					self::mask_define( $t, $i, $mask, $found );
					continue;
				}
				if ( 'putenv' === $fn ) {
					self::mask_putenv( $t, $i, $mask, $found );
					continue;
				}
				if ( array_key_exists( $fn, self::CONNECT_ARGS ) ) {
					self::mask_connect( $t, $i, $fn, $arrows, $mask, $found );
					continue;
				}
				// $this->password = 'value'.
				if ( T_STRING === $id && self::secret_key( $str ) ) {
					$prev = self::prev_token( $t, $i );
					$eq   = self::next_token( $t, $i );
					if ( null !== $prev && in_array( self::tid( $t[ $prev ] ), $arrows, true ) && null !== $eq && self::is_assign( $t[ $eq ] ) ) {
						self::mark_value( $t, $eq + 1, array( ',' ), false, true, $mask, $found, $str );
					}
				}
				continue;
			}

			// const NAME = value[, NAME2 = value2];
			if ( T_CONST === $id ) {
				$j = $i;
				for ( $guard = 0; $guard < 50; $guard++ ) {
					$cname = self::next_token( $t, $j );
					if ( null === $cname ) {
						break;
					}
					// Typed class constants (PHP 8.3): "const string NAME = ...".
					$after = self::next_token( $t, $cname );
					if ( null !== $after && T_STRING === self::tid( $t[ $after ] ) ) {
						$cname = $after;
						$after = self::next_token( $t, $cname );
					}
					if ( T_STRING !== self::tid( $t[ $cname ] ) || null === $after || '=' !== self::txt( $t[ $after ] ) ) {
						break;
					}
					$end = self::secret_constant( $t[ $cname ][1] )
						? self::mark_value( $t, $after + 1, array( ',' ), true, false, $mask, $found, $t[ $cname ][1] )
						: self::skip_value( $t, $after + 1, array( ',' ) );
					if ( null === $end || ',' !== self::txt( $t[ $end ] ) ) {
						break;
					}
					$j = $end;
				}
				continue;
			}

			// 'password' => 'value' and $options['password'] = 'value'.
			if ( T_CONSTANT_ENCAPSED_STRING === $id ) {
				$key  = self::unquote( $str );
				$next = self::next_token( $t, $i );
				if ( null === $next || ! self::secret_key( $key ) ) {
					continue;
				}
				if ( T_DOUBLE_ARROW === self::tid( $t[ $next ] ) ) {
					self::mark_value( $t, $next + 1, array( ',' ), false, true, $mask, $found, $key );
				} elseif ( ']' === self::txt( $t[ $next ] ) ) {
					$eq = self::next_token( $t, $next );
					if ( null !== $eq && self::is_assign( $t[ $eq ] ) ) {
						self::mark_value( $t, $eq + 1, array( ',' ), false, true, $mask, $found, $key );
					}
				}
				continue;
			}

			// $password = 'value'; (also class properties).
			if ( T_VARIABLE === $id && self::secret_key( $str ) ) {
				$eq = self::next_token( $t, $i );
				if ( null !== $eq && self::is_assign( $t[ $eq ] ) ) {
					self::mark_value( $t, $eq + 1, array( ',' ), false, true, $mask, $found, $str );
				}
			}
		}

		if ( ! $mask ) {
			return $text;
		}
		$out = '';
		foreach ( $t as $i => $token ) {
			$str = is_array( $token ) ? $token[1] : $token;
			$out .= isset( $mask[ $i ] ) ? self::masked_token( $str, $mask[ $i ] ) : $str;
		}
		return $out;
	}

	/**
	 * @param array|string $token Token.
	 * @return bool "=" or ".=".
	 */
	private static function is_assign( $token ) {
		return '=' === self::txt( $token ) || ( defined( 'T_CONCAT_EQUAL' ) && T_CONCAT_EQUAL === self::tid( $token ) );
	}

	/**
	 * A token with its value hidden (quotes and line breaks kept).
	 *
	 * @param string       $str Token text.
	 * @param string|array $how 'string', 'raw', or array( 'keep', n ): keep the first n characters of the literal.
	 * @return string
	 */
	private static function masked_token( $str, $how ) {
		if ( 'raw' === $how ) {
			return self::MASK . str_repeat( "\n", substr_count( $str, "\n" ) );
		}
		$prefix = '';
		if ( '' !== $str && 'b' === strtolower( $str[0] ) ) {
			$prefix = $str[0];
			$str    = substr( $str, 1 );
		}
		$quote = '' !== $str ? $str[0] : '\'';
		$inner = (string) substr( $str, 1, -1 );
		$keep  = is_array( $how ) ? (int) $how[1] : 0;
		$tail  = (string) substr( $inner, $keep );
		return $prefix . $quote . substr( $inner, 0, $keep ) . self::MASK . str_repeat( "\n", substr_count( $tail, "\n" ) ) . $quote;
	}

	/**
	 * define( NAME, value ): hides the value when the name (all its literals
	 * joined, for 'DB_' . 'PASSWORD') or any literal of it is secret.
	 *
	 * @param array $t     Tokens.
	 * @param int   $i     Index of "define".
	 * @param array $mask  Masks.
	 * @param array $found Collected values.
	 */
	private static function mask_define( array $t, $i, array &$mask, array &$found ) {
		$open = self::next_token( $t, $i );
		if ( null === $open || '(' !== self::txt( $t[ $open ] ) ) {
			return;
		}
		$n     = count( $t );
		$depth = 0;
		$parts = array();
		$comma = null;
		for ( $j = $open + 1; $j < $n && $j < $open + 500; $j++ ) {
			$id  = self::tid( $t[ $j ] );
			$str = self::txt( $t[ $j ] );
			if ( null === $id ) {
				if ( in_array( $str, array( '(', '[', '{' ), true ) ) {
					++$depth;
				} elseif ( in_array( $str, array( ')', ']', '}' ), true ) ) {
					if ( 0 === $depth ) {
						return;
					}
					--$depth;
				} elseif ( ';' === $str ) {
					return;
				} elseif ( ',' === $str && 0 === $depth ) {
					$comma = $j;
					break;
				}
			} elseif ( T_CURLY_OPEN === $id || T_DOLLAR_OPEN_CURLY_BRACES === $id ) {
				++$depth;
			} elseif ( T_CONSTANT_ENCAPSED_STRING === $id ) {
				$parts[] = self::unquote( $str );
			}
		}
		if ( null === $comma || ! $parts ) {
			return;
		}
		$label  = implode( '', $parts );
		$secret = self::secret_constant( $label );
		foreach ( $parts as $part ) {
			$secret = $secret || self::secret_constant( $part );
		}
		if ( $secret ) {
			self::mark_value( $t, $comma + 1, array( ',' ), true, false, $mask, $found, $label );
		}
	}

	/**
	 * putenv( 'DB_PASSWORD=value' ): keeps "DB_PASSWORD=", hides the rest.
	 *
	 * @param array $t     Tokens.
	 * @param int   $i     Index of "putenv".
	 * @param array $mask  Masks.
	 * @param array $found Collected values.
	 */
	private static function mask_putenv( array $t, $i, array &$mask, array &$found ) {
		$open = self::next_token( $t, $i );
		if ( null === $open || '(' !== self::txt( $t[ $open ] ) ) {
			return;
		}
		$arg = self::next_token( $t, $open );
		if ( null === $arg || T_CONSTANT_ENCAPSED_STRING !== self::tid( $t[ $arg ] ) ) {
			return;
		}
		$inner = self::unquote( $t[ $arg ][1] );
		$eq    = strpos( $inner, '=' );
		$name  = false === $eq ? $inner : substr( $inner, 0, $eq );
		if ( ! self::secret_constant( $name ) && ! self::secret_key( $name ) ) {
			return;
		}
		if ( false !== $eq && $eq < strlen( $inner ) - 1 ) {
			$mask[ $arg ] = array( 'keep', $eq + 1 );
			self::remember( $found, $name, substr( $inner, $eq + 1 ) );
		}
		// 'DB_PASSWORD=' . 'rest': the other literals of the argument.
		self::mark_value( $t, $arg + 1, array( ',' ), false, false, $mask, $found, $name );
	}

	/**
	 * new wpdb( user, password, name, host ), mysqli_connect( host, user,
	 * password, name ) and similar: hides the credential arguments.
	 *
	 * @param array  $t      Tokens.
	 * @param int    $i      Index of the function or class name.
	 * @param string $fn     Lowercase name.
	 * @param array  $arrows Object operator token ids.
	 * @param array  $mask   Masks.
	 * @param array  $found  Collected values.
	 */
	private static function mask_connect( array $t, $i, $fn, array $arrows, array &$mask, array &$found ) {
		$prev = self::prev_token( $t, $i );
		if ( null !== $prev && defined( 'T_NS_SEPARATOR' ) && T_NS_SEPARATOR === self::tid( $t[ $prev ] ) ) {
			$prev = self::prev_token( $t, $prev );
		}
		$prev_id = null === $prev ? null : self::tid( $t[ $prev ] );
		if ( in_array( $fn, self::CONNECT_CLASSES, true ) ) {
			if ( T_NEW !== $prev_id ) {
				return;
			}
		} elseif ( T_FUNCTION === $prev_id || ( 'real_connect' === $fn && ! in_array( $prev_id, $arrows, true ) ) ) {
			return;
		}
		$open = self::next_token( $t, $i );
		if ( null === $open || '(' !== self::txt( $t[ $open ] ) ) {
			return;
		}
		$args = self::CONNECT_ARGS[ $fn ];
		$pos  = $open + 1;
		for ( $k = 0; $k <= max( $args ); $k++ ) {
			$end = in_array( $k, $args, true )
				? self::mark_value( $t, $pos, array( ',' ), true, false, $mask, $found, $fn . '() #' . ( $k + 1 ) )
				: self::skip_value( $t, $pos, array( ',' ) );
			if ( null === $end || ',' !== self::txt( $t[ $end ] ) ) {
				break;
			}
			$pos = $end + 1;
		}
	}

	/**
	 * Index of the next token that is not whitespace or a comment.
	 *
	 * @param array $t Tokens.
	 * @param int   $i Current index.
	 * @return int|null
	 */
	private static function next_token( array $t, $i ) {
		$n = count( $t );
		for ( $j = $i + 1; $j < $n && $j < $i + 200; $j++ ) {
			if ( ! in_array( self::tid( $t[ $j ] ), array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
				return $j;
			}
		}
		return null;
	}

	/**
	 * Index of the previous token that is not whitespace or a comment.
	 *
	 * @param array $t Tokens.
	 * @param int   $i Current index.
	 * @return int|null
	 */
	private static function prev_token( array $t, $i ) {
		for ( $j = $i - 1; $j >= 0 && $j > $i - 200; $j-- ) {
			if ( ! in_array( self::tid( $t[ $j ] ), array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
				return $j;
			}
		}
		return null;
	}

	/**
	 * Marks the literals of a value expression for masking. The value ends at
	 * a terminator or ";" outside brackets, or at the closing bracket of the
	 * enclosing call or array.
	 *
	 * With $require_literal the value must start with a literal, or join
	 * literals with "." at its top level ($prefix . 'secret'); then only those
	 * top level literals are hidden.
	 *
	 * @param array    $t               Tokens.
	 * @param int      $start           First token of the value.
	 * @param string[] $terminators     Single characters that end the value at depth 0.
	 * @param bool     $numbers         Also mask numbers.
	 * @param bool     $require_literal See above.
	 * @param array    $mask            Receives index => string|raw.
	 * @param array    $found           Collected values.
	 * @param string   $label           Name of the value.
	 * @return int|null Index where the value ended (terminator or bracket), null at the end of the code.
	 */
	private static function mark_value( array $t, $start, array $terminators, $numbers, $require_literal, array &$mask, array &$found, $label ) {
		$n       = count( $t );
		$depth   = 0;
		$first   = null;
		$concat  = false;
		$marks   = array();
		$top     = array();
		$values  = array();
		$end     = null;
		for ( $i = $start; $i < $n && $i < $start + 5000; $i++ ) {
			$id  = self::tid( $t[ $i ] );
			$str = self::txt( $t[ $i ] );
			if ( in_array( $id, array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
				continue;
			}
			if ( null === $first ) {
				$first = T_CONSTANT_ENCAPSED_STRING === $id || T_START_HEREDOC === $id || ( null === $id && '"' === $str );
			}
			if ( null === $id ) {
				if ( in_array( $str, array( '(', '[', '{' ), true ) ) {
					++$depth;
				} elseif ( in_array( $str, array( ')', ']', '}' ), true ) ) {
					if ( 0 === $depth ) {
						$end = $i;
						break;
					}
					--$depth;
				} elseif ( ';' === $str || ( 0 === $depth && in_array( $str, $terminators, true ) ) ) {
					$end = $i;
					break;
				} elseif ( '.' === $str && 0 === $depth ) {
					$concat = true;
				}
				continue;
			}
			if ( T_CURLY_OPEN === $id || T_DOLLAR_OPEN_CURLY_BRACES === $id ) {
				++$depth;
				continue;
			}
			if ( T_CONSTANT_ENCAPSED_STRING === $id ) {
				$inner = self::unquote( $str );
				if ( '' !== $inner ) {
					$marks[ $i ]  = 'string';
					$values[ $i ] = $inner;
					$top[ $i ]    = 0 === $depth;
				}
			} elseif ( T_ENCAPSED_AND_WHITESPACE === $id ) {
				$marks[ $i ]  = 'raw';
				$values[ $i ] = $str;
				$top[ $i ]    = 0 === $depth;
			} elseif ( $numbers && ( T_LNUMBER === $id || T_DNUMBER === $id ) ) {
				$marks[ $i ]  = 'raw';
				$values[ $i ] = $str;
				$top[ $i ]    = 0 === $depth;
			}
		}
		if ( $require_literal && true !== $first ) {
			// Only "$x . 'literal'" style values: their top level literals.
			if ( ! $concat ) {
				return $end;
			}
			foreach ( array_keys( $marks ) as $i ) {
				if ( ! $top[ $i ] || 'string' !== $marks[ $i ] ) {
					unset( $marks[ $i ] );
				}
			}
		}
		if ( $marks ) {
			$mask  = $mask + $marks;
			$value = '';
			foreach ( array_keys( $marks ) as $i ) {
				$value .= $values[ $i ] . "\0";
			}
			self::remember( $found, $label, $value );
		}
		return $end;
	}

	/**
	 * Finds where a value ends without masking it.
	 *
	 * @param array    $t           Tokens.
	 * @param int      $start       First token.
	 * @param string[] $terminators Terminators at depth 0.
	 * @return int|null
	 */
	private static function skip_value( array $t, $start, array $terminators ) {
		$n     = count( $t );
		$depth = 0;
		for ( $i = $start; $i < $n && $i < $start + 5000; $i++ ) {
			$id  = self::tid( $t[ $i ] );
			$str = self::txt( $t[ $i ] );
			if ( null === $id ) {
				if ( in_array( $str, array( '(', '[', '{' ), true ) ) {
					++$depth;
				} elseif ( in_array( $str, array( ')', ']', '}' ), true ) ) {
					if ( 0 === $depth ) {
						return $i;
					}
					--$depth;
				} elseif ( ';' === $str || ( 0 === $depth && in_array( $str, $terminators, true ) ) ) {
					return $i;
				}
			} elseif ( T_CURLY_OPEN === $id || T_DOLLAR_OPEN_CURLY_BRACES === $id ) {
				++$depth;
			}
		}
		return null;
	}

	/**
	 * Inner text of a PHP string literal (no unescaping beyond the quotes).
	 *
	 * @param string $literal Literal with quotes.
	 * @return string
	 */
	private static function unquote( $literal ) {
		$literal = (string) $literal;
		if ( '' !== $literal && 'b' === strtolower( $literal[0] ) ) {
			$literal = substr( $literal, 1 );
		}
		if ( strlen( $literal ) >= 2 && ( '\'' === $literal[0] || '"' === $literal[0] ) && substr( $literal, -1 ) === $literal[0] ) {
			return substr( $literal, 1, -1 );
		}
		return $literal;
	}

	/* -------- PHP, line by line ---------------------------------------- */

	/** Words on a line that may set a secret (fail closed check). */
	const SECRET_WORDS = '/pass|pwd|secret|token|key|salt|auth|nonce|credential|connect|wpdb|putenv/i';

	/**
	 * PHP redaction without tokens: for files above PHP_TOKEN_MAX and servers
	 * without the tokenizer extension. A small lexer follows strings, comments,
	 * heredocs and inline HTML across lines, and the statements redact_php()
	 * knows are recognized on the code that is left (a value that continues on
	 * the next lines is followed). It hides more rather than less: every
	 * literal and number of a secret value, also inside calls. When the lexer
	 * ends inside a string (it lost track), every line that mentions a secret
	 * also loses all its quoted values.
	 *
	 * @param string $text  Code.
	 * @param array  $found Collected values.
	 * @return string
	 */
	private static function redact_php_lines( $text, array &$found ) {
		$text  = (string) $text;
		$lines = explode( "\n", $text );
		$state = ( false !== stripos( $text, '<?php' ) || false !== strpos( $text, '<?=' ) ) ? 'x' : '';
		$carry = null;
		foreach ( $lines as $k => $line ) {
			$cr = '';
			if ( '' !== $line && "\r" === substr( $line, -1 ) ) {
				$cr   = "\r";
				$line = (string) substr( $line, 0, -1 );
			}
			$ranges = array();
			$from   = 0;
			if ( '' !== $state ) {
				$was                = $state;
				list( $from, $end ) = self::php_resume( $line, $state );
				if ( null !== $carry && isset( $carry['label'] ) && 'x' !== $was && '*' !== $was && $end > 0 ) {
					// The rest of a string or heredoc that belongs to a secret value.
					$ranges[] = array( 0, $end );
					self::remember( $found, $carry['label'], substr( $line, 0, $end ) );
				}
			}
			if ( $from >= 0 ) {
				list( $code, $spans ) = self::php_scan( $line, $from, $state );
				if ( null !== $carry ) {
					$from = self::php_carry( $code, $spans, $from, $carry, $ranges, $found );
				}
				if ( $from >= 0 && $from < strlen( $code ) ) {
					self::php_line( $code, $spans, $from, $ranges, $found, $carry );
				}
			} elseif ( null !== $carry && --$carry['left'] <= 0 ) {
				$carry = null;
			}
			if ( $ranges ) {
				$lines[ $k ] = self::apply_ranges( $line, $ranges ) . $cr;
			}
		}
		if ( '\'' === $state || '"' === $state ) {
			// A string that never ends: the lexer lost track somewhere.
			foreach ( $lines as $k => $line ) {
				if ( preg_match( self::SECRET_WORDS, $line ) ) {
					$lines[ $k ] = self::mask_line( $line, $found );
				}
			}
		}
		return implode( "\n", $lines );
	}

	/**
	 * Start of a line that continues a string, comment, heredoc or inline HTML.
	 *
	 * @param string $line  Line.
	 * @param string $state ' or " (string), * (comment), h:NAME (heredoc), x (HTML); '' when it ends here.
	 * @return array { 0: offset where code resumes, -1 when the whole line is inside;
	 *                 1: end of the string or heredoc text on this line }
	 */
	private static function php_resume( $line, &$state ) {
		$len = strlen( $line );
		if ( '\'' === $state || '"' === $state ) {
			$j = 0;
			while ( $j < $len ) {
				$j += strcspn( $line, $state . '\\', $j );
				if ( $j >= $len ) {
					break;
				}
				if ( '\\' === $line[ $j ] ) {
					$j += 2;
					continue;
				}
				$state = '';
				return array( $j + 1, $j );
			}
			return array( -1, $len );
		}
		if ( '*' === $state ) {
			$close = strpos( $line, '*/' );
			if ( false === $close ) {
				return array( -1, 0 );
			}
			$state = '';
			return array( $close + 2, 0 );
		}
		if ( 0 === strpos( $state, 'h:' ) ) {
			if ( preg_match( '/^[ \t]*+' . preg_quote( substr( $state, 2 ), '/' ) . '\b/', $line, $m ) ) {
				$state = '';
				return array( strlen( $m[0] ), 0 );
			}
			return array( -1, $len );
		}
		$open = self::php_open_tag( $line, 0 );
		if ( $open < 0 ) {
			return array( -1, 0 );
		}
		$state = '';
		return array( $open, 0 );
	}

	/**
	 * @param string $line Line.
	 * @param int    $at   Offset.
	 * @return int Offset after the next PHP opening tag, -1 when there is none.
	 */
	private static function php_open_tag( $line, $at ) {
		if ( $at >= strlen( $line ) || ! preg_match( '/<\?(?:php(?![A-Za-z0-9_])|=|(?=\s|$))/i', $line, $m, PREG_OFFSET_CAPTURE, $at ) ) {
			return -1;
		}
		return (int) $m[0][1] + strlen( $m[0][0] );
	}

	/**
	 * Lexes the code part of a line: strings, and comments and inline HTML
	 * blanked out with spaces (offsets stay the same).
	 *
	 * @param string $line  Line.
	 * @param int    $from  Offset where code starts.
	 * @param string $state Receives the state at the end of the line (see php_resume()).
	 * @return array { 0: code (same length as the line), 1: strings: start => array( start, end, closed ) }
	 */
	private static function php_scan( $line, $from, &$state ) {
		$len   = strlen( $line );
		$code  = $from > 0 ? str_repeat( ' ', $from ) . (string) substr( $line, $from ) : $line;
		$spans = array();
		$state = '';
		$i     = $from;
		while ( $i < $len ) {
			$i += strcspn( $line, '\'"/#?<', $i );
			if ( $i >= $len ) {
				break;
			}
			$c   = $line[ $i ];
			$two = (string) substr( $line, $i, 2 );
			if ( '\'' === $c || '"' === $c ) {
				$j    = $i + 1;
				$open = true;
				while ( $j < $len ) {
					$j += strcspn( $line, $c . '\\', $j );
					if ( $j >= $len ) {
						break;
					}
					if ( '\\' === $line[ $j ] ) {
						$j += 2;
						continue;
					}
					$open = false;
					break;
				}
				$end         = $open ? $len : $j + 1;
				$spans[ $i ] = array( $i, $end, ! $open );
				if ( $open ) {
					$state = $c;
					break;
				}
				$i = $end;
				continue;
			}
			if ( '//' === $two || ( '#' === $c && '[' !== substr( $line, $i + 1, 1 ) ) ) {
				// A line comment ends at the line end or at the closing tag.
				$close = strpos( $line, '?>', $i );
				$stop  = false === $close ? $len : $close;
				$code  = substr_replace( $code, str_repeat( ' ', $stop - $i ), $i, $stop - $i );
				$i     = $stop;
				continue;
			}
			if ( '/*' === $two ) {
				$close = strpos( $line, '*/', $i + 2 );
				$stop  = false === $close ? $len : $close + 2;
				$code  = substr_replace( $code, str_repeat( ' ', $stop - $i ), $i, $stop - $i );
				if ( false === $close ) {
					$state = '*';
					break;
				}
				$i = $stop;
				continue;
			}
			if ( '?>' === $two ) {
				$open = self::php_open_tag( $line, $i + 2 );
				$stop = $open < 0 ? $len : $open;
				$code = substr_replace( $code, str_repeat( ' ', $stop - $i ), $i, $stop - $i );
				if ( $open < 0 ) {
					$state = 'x';
					break;
				}
				$i = $stop;
				continue;
			}
			if ( '<' === $c && preg_match( '/\G<<<[ \t]*+(["\']?)([A-Za-z_][A-Za-z0-9_]*+)\1/', $line, $h, 0, $i ) ) {
				// Heredoc or nowdoc: its text starts on the next line.
				$state = 'h:' . $h[2];
				$i    += strlen( $h[0] );
				continue;
			}
			++$i;
		}
		return array( $code, $spans );
	}

	/**
	 * Statements that may set a secret, found on one line of PHP.
	 */
	const PHP_TRIGGERS = '/(?<def>(?<![\w$>:])\\\\?define\s*+\()|(?<const>(?<![\w$>:])const\s++)|(?<put>(?<![\w$>:])\\\\?putenv\s*+\()|(?<conn>(?:(?<![\w$>:])new\s++\\\\?(?<cls>wpdb|mysqli|pdo)|(?<![\w$>:])\\\\?(?<fn>mysqli_real_connect|mysqli_connect|mysql_p?connect)|->\s*+(?<meth>real_connect))\s*+\()|(?<key>"[^"\\\\\r\n]{1,100}+"|\'[^\'\\\\\r\n]{1,100}+\')\s*+(?:=>|\]\s*+\.?=(?![=>]))|(?<var>(?:\$|->\s*+)(?<vn>[A-Za-z_][A-Za-z0-9_]*+)\s*+\.?=(?![=>]))/i';

	/**
	 * Hides the secret values that start on one line of PHP.
	 *
	 * @param string     $code   Code of the line (php_scan()).
	 * @param array      $spans  Strings of the line (php_scan()).
	 * @param int        $from   Offset to start at.
	 * @param array      $ranges Receives [start, end) ranges to hide.
	 * @param array      $found  Collected values.
	 * @param array|null $carry  Set when a value continues on the next line.
	 */
	private static function php_line( $code, array $spans, $from, array &$ranges, array &$found, &$carry ) {
		$matched = preg_match_all( self::PHP_TRIGGERS, $code, $all, PREG_SET_ORDER | PREG_OFFSET_CAPTURE, $from );
		if ( false === $matched ) {
			$ranges = array_merge( $ranges, self::span_ranges( $code, $found ) );
			return;
		}
		$done = $from;
		foreach ( (array) $all as $m ) {
			$at = (int) $m[0][1];
			if ( $at < $done ) {
				continue;
			}
			$is = static function ( $group ) use ( $m ) {
				return isset( $m[ $group ] ) && -1 !== $m[ $group ][1] && '' !== $m[ $group ][0];
			};
			if ( $is( 'key' ) ) {
				if ( ! isset( $spans[ $at ] ) ) {
					continue;
				}
				$key = substr( $m['key'][0], 1, -1 );
				if ( self::secret_key( $key ) ) {
					$done = self::php_value( $code, $spans, $at + strlen( $m[0][0] ), ',', false, $key, $ranges, $found, $carry, true );
				}
			} elseif ( self::in_span( $spans, $at ) ) {
				continue;
			} elseif ( $is( 'var' ) ) {
				$name = $m['vn'][0];
				if ( self::secret_key( $name ) ) {
					$done = self::php_value( $code, $spans, $at + strlen( $m[0][0] ), ',', false, ( '$' === $m['var'][0][0] ? '$' : '' ) . $name, $ranges, $found, $carry, true );
				}
			} elseif ( $is( 'def' ) ) {
				$done = self::php_define_line( $code, $spans, $at + strlen( $m[0][0] ), $ranges, $found, $carry );
			} elseif ( $is( 'const' ) ) {
				$done = self::php_const_line( $code, $spans, $at + strlen( $m[0][0] ), $ranges, $found, $carry );
			} elseif ( $is( 'put' ) ) {
				$done = self::php_putenv_line( $code, $spans, $at + strlen( $m[0][0] ), $ranges, $found, $carry );
			} elseif ( $is( 'conn' ) ) {
				$fn   = strtolower( $is( 'cls' ) ? $m['cls'][0] : ( $is( 'fn' ) ? $m['fn'][0] : $m['meth'][0] ) );
				$done = self::php_connect_line( $code, $spans, $at + strlen( $m[0][0] ), $fn, $ranges, $found, $carry );
			}
			if ( $done < 0 ) {
				return; // The rest of the line belongs to a value that continues.
			}
		}
	}

	/**
	 * Hides one value (from $pos to its end) on a line of PHP.
	 *
	 * @param string     $code    Code of the line.
	 * @param array      $spans   Strings of the line.
	 * @param int        $pos     Start of the value.
	 * @param string     $stops   Characters ending it outside brackets.
	 * @param bool       $numbers Also hide numbers.
	 * @param string     $label   Name.
	 * @param array      $ranges  Ranges to hide.
	 * @param array      $found   Collected values.
	 * @param array|null $carry   Set when the value continues on the next line.
	 * @param bool       $literal Like redact_php(): only a value that starts with a
	 *                            string, or joins strings with "." (then only those).
	 * @return int Offset where the value ended, -1 when it continues.
	 */
	private static function php_value( $code, array $spans, $pos, $stops, $numbers, $label, array &$ranges, array &$found, &$carry, $literal = false ) {
		$values = '';
		$depth  = 0;
		$top    = false;
		$at     = $pos + strspn( $code, " \t", $pos );
		if ( $literal && $at < strlen( $code ) && ! isset( $spans[ $at ] ) && '<<<' !== substr( $code, $at, 3 ) ) {
			$none   = null;
			$concat = false;
			$end    = self::walk_value( $code, $spans, $pos, $stops, false, $none, $values, $depth, false, $concat );
			if ( ! $concat ) {
				return $end < 0 ? strlen( $code ) : $end;
			}
			$top    = true;
			$values = '';
			$depth  = 0;
		}
		$end = self::walk_value( $code, $spans, $pos, $stops, $numbers, $ranges, $values, $depth, $top );
		if ( '' !== $values ) {
			self::remember( $found, $label, $values );
		}
		if ( $end < 0 ) {
			$carry = array(
				'label'   => $label,
				'stops'   => $stops,
				'numbers' => $numbers,
				'depth'   => $depth,
				'left'    => 5000,
			);
		}
		return $end;
	}

	/**
	 * Continues a value (or the name of a define()) from an earlier line.
	 *
	 * @param string $code   Code of the line.
	 * @param array  $spans  Strings of the line.
	 * @param int    $from   Offset where the code starts.
	 * @param array  $carry  State (cleared when the value ends).
	 * @param array  $ranges Ranges to hide.
	 * @param array  $found  Collected values.
	 * @return int Offset after the end of the value, -1 when the rest of the line belongs to it.
	 */
	private static function php_carry( $code, array $spans, $from, &$carry, array &$ranges, array &$found ) {
		$state = $carry;
		if ( isset( $state['define'] ) ) {
			// The name of a define() that started on an earlier line.
			$carry = null;
			$end   = self::php_define_line( $code, $spans, $from, $ranges, $found, $carry, $state['define'], $state['depth'] );
		} else {
			$values = '';
			$depth  = $state['depth'];
			$end    = self::walk_value( $code, $spans, $from, $state['stops'], $state['numbers'], $ranges, $values, $depth );
			if ( '' !== $values ) {
				self::remember( $found, $state['label'], $values );
			}
			$carry = null;
			if ( $end < 0 ) {
				$carry          = $state;
				$carry['depth'] = $depth;
			}
		}
		if ( null !== $carry && $end < 0 ) {
			$carry['left'] = $state['left'] - 1;
			if ( $carry['left'] <= 0 ) {
				$carry = null;
			}
		}
		return $end;
	}

	/**
	 * define( NAME, value ) on a line.
	 *
	 * @param string     $line   Line.
	 * @param array      $spans  Strings of the line (php_scan()).
	 * @param int        $pos    Offset after "define(" (or the line start for a continued name).
	 * @param array      $ranges Ranges to hide.
	 * @param array      $found  Collected values.
	 * @param array|null $carry  Continuation.
	 * @param string[]   $parts  Literals of the name found on earlier lines.
	 * @param int        $depth  Bracket depth carried over from earlier lines.
	 * @return int Offset where the statement part ended, -1 when it continues.
	 */
	private static function php_define_line( $line, array $spans, $pos, array &$ranges, array &$found, &$carry, array $parts = array(), $depth = 0 ) {
		$none  = null;
		$names = '';
		$comma = self::walk_value( $line, $spans, $pos, ',', false, $none, $names, $depth );
		foreach ( $spans as $start => $span ) {
			if ( $start >= $pos && ( $comma < 0 || $start < $comma ) ) {
				$parts[] = self::span_inner( $line, $span );
			}
		}
		if ( $comma < 0 ) {
			// The name continues on the next line (define(\n 'NAME',\n 'value' )).
			$carry = array(
				'define' => $parts,
				'depth'  => $depth,
				'left'   => 20,
			);
			return -1;
		}
		$label  = implode( '', $parts );
		$secret = '' !== $label && self::secret_constant( $label );
		foreach ( $parts as $part ) {
			$secret = $secret || self::secret_constant( $part );
		}
		if ( ! $secret || ',' !== $line[ $comma ] ) {
			return $comma;
		}
		return self::php_value( $line, $spans, $comma + 1, '', true, $label, $ranges, $found, $carry );
	}

	/**
	 * const NAME = value[, NAME2 = value2]; on a line.
	 *
	 * @param string     $line   Line.
	 * @param array      $spans  Strings of the line (php_scan()).
	 * @param int        $pos    Offset after "const".
	 * @param array      $ranges Ranges to hide.
	 * @param array      $found  Collected values.
	 * @param array|null $carry  Continuation.
	 * @return int
	 */
	private static function php_const_line( $line, array $spans, $pos, array &$ranges, array &$found, &$carry ) {
		$pattern = '/\G(?:[A-Za-z_\\\\?][A-Za-z0-9_\\\\|?]*+\s++(?=[A-Za-z_][A-Za-z0-9_]*+\s*+=))?([A-Za-z_][A-Za-z0-9_]*+)\s*+=(?![=>])/';
		for ( $guard = 0; $guard < 50; $guard++ ) {
			if ( ! preg_match( $pattern, $line, $m, 0, $pos ) ) {
				return $pos;
			}
			$start = $pos + strlen( $m[0] );
			if ( self::secret_constant( $m[1] ) ) {
				$end = self::php_value( $line, $spans, $start, ',', true, $m[1], $ranges, $found, $carry );
			} else {
				$none   = null;
				$values = '';
				$depth  = 0;
				$end    = self::walk_value( $line, $spans, $start, ',', false, $none, $values, $depth );
			}
			if ( $end < 0 || ',' !== $line[ $end ] ) {
				return $end;
			}
			$pos = $end + 1;
			$pos += strspn( $line, " \t", $pos );
		}
		return $pos;
	}

	/**
	 * putenv( 'NAME=value' ) on a line.
	 *
	 * @param string     $line   Line.
	 * @param array      $spans  Strings of the line (php_scan()).
	 * @param int        $pos    Offset after "putenv(".
	 * @param array      $ranges Ranges to hide.
	 * @param array      $found  Collected values.
	 * @param array|null $carry  Continuation.
	 * @return int
	 */
	private static function php_putenv_line( $line, array $spans, $pos, array &$ranges, array &$found, &$carry ) {
		$at = $pos + strspn( $line, " \t", $pos );
		if ( ! isset( $spans[ $at ] ) ) {
			return $pos;
		}
		$span  = $spans[ $at ];
		$inner = self::span_inner( $line, $span );
		$eq    = strpos( $inner, '=' );
		$name  = false === $eq ? $inner : substr( $inner, 0, $eq );
		if ( ! self::secret_constant( $name ) && ! self::secret_key( $name ) ) {
			return $span[1];
		}
		if ( false !== $eq && $eq < strlen( $inner ) - 1 ) {
			$ranges[] = array( $at + 1 + $eq + 1, $at + 1 + strlen( $inner ) );
			self::remember( $found, $name, substr( $inner, $eq + 1 ) );
		}
		return self::php_value( $line, $spans, $span[1], '', false, $name, $ranges, $found, $carry );
	}

	/**
	 * new wpdb( ... ), mysqli_connect( ... ) and similar on a line.
	 *
	 * @param string     $line   Line.
	 * @param array      $spans  Strings of the line (php_scan()).
	 * @param int        $pos    Offset after the opening bracket.
	 * @param string     $fn     Lowercase function or class name.
	 * @param array      $ranges Ranges to hide.
	 * @param array      $found  Collected values.
	 * @param array|null $carry  Continuation.
	 * @return int
	 */
	private static function php_connect_line( $line, array $spans, $pos, $fn, array &$ranges, array &$found, &$carry ) {
		$args = self::CONNECT_ARGS[ $fn ];
		for ( $k = 0; $k <= max( $args ); $k++ ) {
			if ( in_array( $k, $args, true ) ) {
				$end = self::php_value( $line, $spans, $pos, ',', true, $fn . '() #' . ( $k + 1 ), $ranges, $found, $carry );
				if ( $end < 0 ) {
					// The call continues on the next lines: hide every value up to its end.
					$carry['stops'] = '';
					return -1;
				}
			} else {
				$none   = null;
				$values = '';
				$depth  = 0;
				$end    = self::walk_value( $line, $spans, $pos, ',', false, $none, $values, $depth );
				if ( $end < 0 ) {
					$carry = array(
						'label'   => $fn . '()',
						'stops'   => '',
						'numbers' => true,
						'depth'   => $depth,
						'left'    => 50,
					);
					return -1;
				}
			}
			if ( ',' !== $line[ $end ] ) {
				return $end;
			}
			$pos = $end + 1;
		}
		return $pos;
	}

	/**
	 * Walks a value on one line, from $pos to the first terminator outside
	 * quoted strings and brackets, collecting the parts to hide.
	 *
	 * @param string     $line    Line.
	 * @param array      $spans   Strings of the line (php_scan() or quoted_spans()).
	 * @param int        $pos     Start.
	 * @param string     $stops   Characters that end the value outside brackets (";" always does).
	 * @param bool       $numbers Also hide numbers.
	 * @param array|null $ranges  Receives [start, end) ranges to hide (null: only find the end).
	 * @param string     $values  Receives the hidden text.
	 * @param int        $depth   Bracket depth (carried over lines).
	 * @param bool       $top     Only hide strings outside brackets.
	 * @param bool|null  $concat  When given: set to true when "." joins values outside brackets.
	 * @return int Offset of the terminator, -1 when the line ends first.
	 */
	private static function walk_value( $line, array $spans, $pos, $stops, $numbers, &$ranges, &$values, &$depth, $top = false, &$concat = null ) {
		$len  = strlen( $line );
		$stop = '"\'()[]{};' . $stops . ( $numbers ? '0123456789' : '' ) . ( null !== $concat ? '.' : '' );
		while ( $pos < $len ) {
			$pos += strcspn( $line, $stop, $pos );
			if ( $pos >= $len ) {
				break;
			}
			$c = $line[ $pos ];
			if ( '.' === $c ) {
				// String concatenation, not a decimal point.
				if ( 0 === $depth && ! ( $pos > 0 && $pos + 1 < $len && false !== strpos( '0123456789', $line[ $pos - 1 ] ) && false !== strpos( '0123456789', $line[ $pos + 1 ] ) ) ) {
					$concat = true;
				}
				++$pos;
				continue;
			}
			if ( isset( $spans[ $pos ] ) ) {
				if ( null !== $ranges && ( ! $top || 0 === $depth ) ) {
					$span  = $spans[ $pos ];
					$inner = self::span_inner( $line, $span );
					if ( '' !== $inner ) {
						$ranges[] = array( $pos + 1, $pos + 1 + strlen( $inner ) );
						$values  .= $inner . "\0";
					}
				}
				$pos = $spans[ $pos ][1];
				continue;
			}
			if ( '"' === $c || '\'' === $c ) {
				++$pos;
				continue;
			}
			if ( $c >= '0' && $c <= '9' ) {
				$run  = strspn( $line, '0123456789abcdefABCDEFxXoO._', $pos );
				$prev = $pos > 0 ? $line[ $pos - 1 ] : ' ';
				if ( null !== $ranges && ! preg_match( '/[A-Za-z0-9_$]/', $prev ) ) {
					$ranges[] = array( $pos, $pos + $run );
					$values  .= substr( $line, $pos, $run ) . "\0";
				}
				$pos += $run;
				continue;
			}
			if ( '(' === $c || '[' === $c || '{' === $c ) {
				++$depth;
			} elseif ( ')' === $c || ']' === $c || '}' === $c ) {
				if ( 0 === $depth ) {
					return $pos;
				}
				--$depth;
			} elseif ( ';' === $c || ( 0 === $depth && false !== strpos( $stops, $c ) ) ) {
				return $pos;
			}
			++$pos;
		}
		return -1;
	}

	/* -------- Quoted strings on a line ---------------------------------- */

	/**
	 * Quoted strings on one line ('...' and "...", backslash escapes). A
	 * string that is not closed runs to the end of the line.
	 *
	 * @param string $line Line.
	 * @return array start offset => array( start, end (after the closing quote), closed )
	 */
	private static function quoted_spans( $line ) {
		$spans = array();
		$len   = strlen( $line );
		$i     = 0;
		while ( $i < $len ) {
			$i += strcspn( $line, '"\'', $i );
			if ( $i >= $len ) {
				break;
			}
			$quote = $line[ $i ];
			$j     = $i + 1;
			$open  = true;
			while ( $j < $len ) {
				$j += strcspn( $line, $quote . '\\', $j );
				if ( $j >= $len ) {
					break;
				}
				if ( '\\' === $line[ $j ] ) {
					$j += 2;
					continue;
				}
				$open = false;
				break;
			}
			$end         = $open ? $len : $j + 1;
			$spans[ $i ] = array( $i, $end, ! $open );
			$i           = $end;
		}
		return $spans;
	}

	/**
	 * @param string $line Line.
	 * @param array  $span quoted_spans() entry.
	 * @return string Text between the quotes.
	 */
	private static function span_inner( $line, array $span ) {
		$length = $span[1] - $span[0] - ( $span[2] ? 2 : 1 );
		return $length > 0 ? (string) substr( $line, $span[0] + 1, $length ) : '';
	}

	/**
	 * @param array $spans Strings of a line (php_scan() or quoted_spans()).
	 * @param int   $at    Offset.
	 * @return bool Whether the offset is inside (or at the quote of) a string.
	 */
	private static function in_span( array $spans, $at ) {
		foreach ( $spans as $span ) {
			if ( $at >= $span[0] && $at < $span[1] ) {
				return true;
			}
			if ( $span[0] > $at ) {
				break;
			}
		}
		return false;
	}

	/**
	 * Ranges of the inner text of every quoted string on a line.
	 *
	 * @param string $line  Line.
	 * @param array  $found Collected values.
	 * @return array
	 */
	private static function span_ranges( $line, array &$found ) {
		$ranges = array();
		foreach ( self::quoted_spans( $line ) as $span ) {
			$inner = self::span_inner( $line, $span );
			if ( '' !== $inner && self::MASK !== $inner ) {
				$ranges[] = array( $span[0] + 1, $span[0] + 1 + strlen( $inner ) );
				self::remember( $found, '(unreadable line)', $inner );
			}
		}
		return $ranges;
	}

	/**
	 * Replaces [start, end) ranges of a line with the mask.
	 *
	 * @param string $line   Line.
	 * @param array  $ranges Ranges (may overlap).
	 * @return string
	 */
	private static function apply_ranges( $line, array $ranges ) {
		usort(
			$ranges,
			static function ( $a, $b ) {
				return $a[0] - $b[0];
			}
		);
		$out = '';
		$pos = 0;
		foreach ( $ranges as $range ) {
			if ( $range[0] < $pos || $range[1] <= $range[0] ) {
				continue;
			}
			$out .= substr( $line, $pos, $range[0] - $pos ) . self::MASK;
			$pos  = $range[1];
		}
		return $out . substr( $line, $pos );
	}

	/**
	 * Fail closed for a line no pattern could be applied to: every quoted
	 * string is hidden, or everything after "=" or ":" when it has none.
	 *
	 * @param string $line  Line (without "\n").
	 * @param array  $found Collected values.
	 * @return string
	 */
	private static function mask_line( $line, array &$found ) {
		$line = (string) $line;
		$cr   = '';
		if ( '' !== $line && "\r" === substr( $line, -1 ) ) {
			$cr   = "\r";
			$line = (string) substr( $line, 0, -1 );
		}
		$ranges = self::span_ranges( $line, $found );
		if ( ! $ranges ) {
			$sep  = strcspn( $line, '=:' );
			$from = $sep + 1 + strspn( $line, " \t", min( strlen( $line ), $sep + 1 ) );
			if ( $sep < strlen( $line ) && $from < strlen( $line ) ) {
				$ranges[] = array( $from, strlen( $line ) );
				self::remember( $found, '(unreadable line)', substr( $line, $from ) );
			}
		}
		return ( $ranges ? self::apply_ranges( $line, $ranges ) : $line ) . $cr;
	}

	/* -------- Excerpts --------------------------------------------------- */

	/**
	 * An excerpt that starts inside a quoted string (the start of the string
	 * and of its statement were cut off, as in "ORD', 'secret' );"): hides that
	 * part and every string and number up to the end of the statement.
	 *
	 * In a file that holds secrets any start that is not code (no bracket,
	 * "=", ";" or include/require/echo before the first quote) counts as cut.
	 *
	 * @param string $snippet Excerpt.
	 * @param array  $found   Collected values.
	 * @param bool   $strict  The file holds secrets.
	 * @return array { 0: hidden start including the closing quote ('' when the
	 *                 excerpt starts normally), 1: the rest, its first statement redacted }
	 */
	private static function split_cut_start( $snippet, array &$found, $strict = false ) {
		$q = strcspn( $snippet, '"\'' );
		if ( $q >= strlen( $snippet ) ) {
			return array( '', $snippet );
		}
		$head = (string) substr( $snippet, 0, $q );
		$rest = (string) substr( $snippet, $q + 1 );
		if ( '' !== trim( $head ) ) {
			$cut = $strict
				? ! preg_match( '/[(=;{}\[]|^\s*+@?(?:include|require)(?:_once)?\b|^\s*+(?:echo|print|return)\b/i', $head )
				: (bool) preg_match( '~^[A-Za-z0-9_.\-/\\\\]++$~', $head );
			if ( ! $cut ) {
				return array( '', $snippet ); // Code before the first quote: that quote opens a string.
			}
		} elseif ( ! preg_match( '/^\s*+(?:,|=>|\]|\))/', $rest ) ) {
			return array( '', $snippet );
		}
		$spans  = self::quoted_spans( $rest );
		$ranges = array();
		$values = '';
		$depth  = 0;
		self::walk_value( $rest, $spans, 0, '', true, $ranges, $values, $depth );
		self::remember( $found, '(excerpt)', $head . "\0" . $values );
		return array( ( '' === $head ? '' : self::MASK ) . $snippet[ $q ], $ranges ? self::apply_ranges( $rest, $ranges ) : $rest );
	}

	/**
	 * 'DB_PASSWORD', 'value' in an excerpt (a define() whose start was cut
	 * off, or any call or list): hides the values after a quoted secret name.
	 *
	 * @param string $snippet Excerpt.
	 * @param array  $found   Collected values.
	 * @return string
	 */
	private static function mask_after_secret_names( $snippet, array &$found ) {
		$spans  = self::quoted_spans( $snippet );
		$ranges = array();
		$skip   = -1;
		foreach ( $spans as $start => $span ) {
			if ( $start < $skip || ! $span[2] ) {
				continue;
			}
			$inner = self::span_inner( $snippet, $span );
			if ( '' === $inner || ! self::secret_constant( $inner ) || ! preg_match( '/\G\s*+,/', $snippet, $m, 0, $span[1] ) ) {
				continue;
			}
			$values = '';
			$depth  = 0;
			$end    = self::walk_value( $snippet, $spans, $span[1] + strlen( $m[0] ), '', true, $ranges, $values, $depth );
			if ( '' !== $values ) {
				self::remember( $found, $inner, $values );
			}
			$skip = $end < 0 ? strlen( $snippet ) : $end;
		}
		return $ranges ? self::apply_ranges( $snippet, $ranges ) : $snippet;
	}

	/**
	 * An excerpt of a configuration file that holds secrets: every value of
	 * NAME=value and NAME: value, and a leading word that may be the end of a
	 * value whose name was cut off.
	 *
	 * @param string $snippet Excerpt.
	 * @param array  $found   Collected values.
	 * @return string
	 */
	private static function mask_config_excerpt( $snippet, array &$found ) {
		$out = preg_replace_callback(
			'/((?:^|[\s;&,])[A-Za-z_][A-Za-z0-9_.\-]*+[ \t]*+[=:][ \t]*+)("[^"]*+"?|\'[^\']*+\'?|[^\s"\';&,]++)/',
			static function ( $m ) use ( &$found ) {
				self::remember( $found, '(excerpt)', $m[2] );
				$quote = '"' === $m[2][0] || '\'' === $m[2][0] ? $m[2][0] : '';
				return $m[1] . $quote . self::MASK . $quote;
			},
			$snippet
		);
		if ( ! is_string( $out ) ) {
			return self::mask_line( $snippet, $found );
		}
		$out = preg_replace( '/^[^\s=:]++(?=\s|$)/', self::MASK, $out );
		return is_string( $out ) ? $out : self::mask_line( $snippet, $found );
	}

	/* -------- Every kind of file ---------------------------------------- */

	/**
	 * preg_replace_callback() that fails closed: when PCRE gives up (backtrack,
	 * recursion or JIT stack limit) the text is done line by line, and a line
	 * that still fails loses every quoted value (mask_line()).
	 *
	 * @param string   $pattern  Pattern.
	 * @param callable $callback Callback.
	 * @param string   $text     Text.
	 * @param array    $found    Collected values.
	 * @return string
	 */
	private static function replace_safe( $pattern, $callback, $text, array &$found ) {
		$out = preg_replace_callback( $pattern, $callback, $text );
		if ( is_string( $out ) ) {
			return $out;
		}
		$lines = explode( "\n", $text );
		foreach ( $lines as $k => $line ) {
			$one         = preg_replace_callback( $pattern, $callback, $line );
			$lines[ $k ] = is_string( $one ) ? $one : self::mask_line( $line, $found );
		}
		return implode( "\n", $lines );
	}

	/**
	 * Line based redaction for every kind of file.
	 *
	 * @param string $text  Content.
	 * @param string $name  File name.
	 * @param array  $found Collected values.
	 * @return string
	 */
	private static function redact_lines( $text, $name, array &$found ) {
		$base = strtolower( basename( wp_normalize_path( $name ) ) );
		$ext  = Paths::ext( $base );

		// NAME=value configuration and shell style scripts: the whole value is hidden.
		if ( in_array( $ext, self::CONFIG_EXTENSIONS, true ) || in_array( $ext, self::SCRIPT_EXTENSIONS, true ) || 0 === strpos( $base, '.env' ) || in_array( $base, array( '.user.ini', 'php.ini' ), true ) ) {
			$text = self::replace_safe(
				'/^([ \t]*+(?:export[ \t]++)?)([A-Za-z_][A-Za-z0-9_.\-]*+)([ \t]*+[=:][ \t]*+)([^\r\n]*+)/m',
				static function ( $m ) use ( &$found ) {
					return self::mask_assignment( $m, $found );
				},
				$text,
				$found
			);
		}

		// SetEnv NAME value in .htaccess.
		if ( '.htaccess' === $base ) {
			$text = self::replace_safe(
				'/^([ \t]*+SetEnv[ \t]++)(\S++)([ \t]++)([^\r\n]*+)/mi',
				static function ( $m ) use ( &$found ) {
					return self::mask_assignment( $m, $found );
				},
				$text,
				$found
			);
		}

		// <add key="DB_PASSWORD" value="..." /> in web.config and other XML.
		if ( 'web.config' === $base || in_array( $ext, self::XML_EXTENSIONS, true ) ) {
			$text = self::replace_safe(
				'/<[A-Za-z][^<>]*+>/',
				static function ( $m ) use ( &$found ) {
					return self::mask_xml_tag( $m[0], $found );
				},
				$text,
				$found
			);
		}

		// "key": "value", key: 'value', key = "value" (JSON, JavaScript, HTML attributes, PHP named arguments).
		$text = self::replace_safe(
			'/(?<![A-Za-z0-9_$"\'])(["\']?)([A-Za-z_$][A-Za-z0-9_$.\-]{0,100}+)\1([ \t]*+(?::|=(?![=>]))[ \t]*+)("(?:[^"\\\\\r\n]++|\\\\.)*+"|\'(?:[^\'\\\\\r\n]++|\\\\.)*+\')/',
			static function ( $m ) use ( &$found ) {
				$quote = $m[4][0];
				$inner = (string) substr( $m[4], 1, -1 );
				if ( '' === $inner || self::MASK === $inner || ! self::secret_key( $m[2] ) ) {
					return $m[0];
				}
				self::remember( $found, $m[2], $inner );
				return $m[1] . $m[2] . $m[1] . $m[3] . $quote . self::MASK . $quote;
			},
			$text,
			$found
		);

		// define( 'DB_PASSWORD', 'value' ) that is not live PHP code: a commented
		// out statement (old credentials left in wp-config.php) or a text copy of
		// a configuration file. Live code was handled by the PHP reading above (its
		// values are the mask already and stay as they are). Every literal of the
		// value is hidden up to the bracket that closes the define or the end of
		// the statement, also when it continues on the next lines: a value put
		// together from parts, or a fallback after a function call. A JavaScript
		// module definition (define( "name", [ ... ], function ...)) is not one.
		$quoted = '"(?:[^"\\\\]++|\\\\.)*+"|\'(?:[^\'\\\\]++|\\\\.)*+\'';
		$text   = self::replace_safe(
			'/(\bdefine\s*+\(\s*+)(["\'])([A-Za-z_][A-Za-z0-9_]{0,100}+)\2(\s*+,)((?:[^"\'();]++|' . $quoted . '|(\((?:[^"\'()]++|' . $quoted . '|(?6))*+\)))*+)/is',
			static function ( $m ) use ( &$found, $quoted ) {
				if ( ! preg_match( self::CONST_PATTERN, $m[3] ) || preg_match( '/^\s*+(?:\[|function\b)/i', $m[5] ) ) {
					return $m[0];
				}
				$name  = $m[3];
				$value = preg_replace_callback(
					'/' . $quoted . '/s',
					static function ( $q ) use ( &$found, $name ) {
						$inner = (string) substr( $q[0], 1, -1 );
						if ( '' === $inner || self::MASK === $inner ) {
							return $q[0];
						}
						self::remember( $found, $name, $inner );
						return $q[0][0] . self::MASK . str_repeat( "\n", substr_count( $inner, "\n" ) ) . $q[0][0];
					},
					$m[5]
				);
				// Fail closed: a value that could not be read is hidden as a whole.
				return $m[1] . $m[2] . $m[3] . $m[2] . $m[4] . ( is_string( $value ) ? $value : ' ' . self::MASK );
			},
			$text,
			$found
		);

		return self::redact_formats( $text, $found );
	}

	/**
	 * Secrets recognized by their form in every kind of file.
	 *
	 * @param string $text  Content.
	 * @param array  $found Collected values.
	 * @return string
	 */
	private static function redact_formats( $text, array &$found ) {
		// Private keys: the key material (line breaks kept).
		if ( false !== strpos( $text, 'PRIVATE KEY' ) ) {
			$text = self::replace_safe(
				'/(-----BEGIN [A-Z0-9 ]{0,40}?PRIVATE KEY(?: BLOCK)?-----)((?:(?!-----)(?:[A-Za-z0-9+\/=:,.\- \t\r\n]|\\\\[nr]))*+)(-----END )/',
				static function ( $m ) use ( &$found ) {
					$lead = strspn( $m[2], "\r\n" );
					$body = (string) substr( $m[2], $lead );
					if ( '' === trim( $body ) || self::MASK === trim( $body ) ) {
						return $m[0];
					}
					self::remember( $found, 'private key', $body );
					return $m[1] . substr( $m[2], 0, $lead ) . self::MASK . str_repeat( "\n", substr_count( $body, "\n" ) ) . $m[3];
				},
				$text,
				$found
			);
		}

		// Passwords in URLs (scheme://user:password@host).
		if ( false !== strpos( $text, '://' ) ) {
			$text = self::replace_safe(
				'~\b([a-z][a-z0-9+.\-]{1,30}+://[^\s:/?#@"\'<>]{1,256}+:)([^\s/?#@"\'<>]{1,256}+)@~i',
				static function ( $m ) use ( &$found ) {
					if ( self::MASK === $m[2] ) {
						return $m[0];
					}
					self::remember( $found, 'URL password', $m[2] );
					return $m[1] . self::MASK . '@';
				},
				$text,
				$found
			);
		}

		// Connection strings and query strings: ;Password=...; ?pwd=...&.
		$text = self::replace_safe(
			'/(?<=[;"\'?&])([ \t]*+(?:password|passwd|pwd|user[ \t]?password)[ \t]*+=[ \t]*+)([^;"\'&\s<>]++)/i',
			static function ( $m ) use ( &$found ) {
				if ( self::MASK === $m[2] ) {
					return $m[0];
				}
				self::remember( $found, 'connection string password', $m[2] );
				return $m[1] . self::MASK;
			},
			$text,
			$found
		);

		// Authorization: Bearer ... / Basic ... (not plain words such as "Basic authentication").
		$text = self::replace_safe(
			'/\b(Bearer|Basic)([ \t]++)((?![A-Z]?[a-z]++(?![A-Za-z0-9\-._~+\/=]))[A-Za-z0-9\-._~+\/]{8,}+=*+)/',
			static function ( $m ) use ( &$found ) {
				self::remember( $found, $m[1] . ' token', $m[3] );
				return $m[1] . $m[2] . self::MASK;
			},
			$text,
			$found
		);

		foreach ( self::TOKEN_PATTERNS as $label => $pattern ) {
			$text = self::replace_safe(
				$pattern,
				static function ( $m ) use ( &$found, $label ) {
					$secret = isset( $m[1] ) && '' !== $m[1] ? $m[1] : $m[0];
					self::remember( $found, $label, $secret );
					$at = strrpos( $m[0], $secret );
					return substr( $m[0], 0, (int) $at ) . self::MASK . substr( $m[0], (int) $at + strlen( $secret ) );
				},
				$text,
				$found
			);
		}
		return $text;
	}

	/**
	 * NAME=value (configuration line) or SetEnv NAME value: hides the value
	 * when the name is secret.
	 *
	 * @param array $m     Match: 1 lead, 2 name, 3 separator, 4 value and trailing blanks.
	 * @param array $found Collected values.
	 * @return string
	 */
	private static function mask_assignment( array $m, array &$found ) {
		$value = rtrim( $m[4], " \t" );
		if ( '' === $value || ( ! self::secret_key( $m[2] ) && ! self::secret_constant( $m[2] ) ) ) {
			return $m[0];
		}
		return $m[1] . $m[2] . $m[3] . self::mask_scalar( $value, $m[2], $found ) . substr( $m[4], strlen( $value ) );
	}

	/**
	 * An XML tag: when its key, name or id attribute is a secret name, the
	 * value attribute is hidden (<add key="DB_PASSWORD" value="..." />).
	 *
	 * @param string $tag   Tag.
	 * @param array  $found Collected values.
	 * @return string
	 */
	private static function mask_xml_tag( $tag, array &$found ) {
		if ( ! preg_match_all( '/([A-Za-z_:][A-Za-z0-9_:.\-]*+)[ \t\r\n]*+=[ \t\r\n]*+("[^"]*+"|\'[^\']*+\')/', $tag, $attrs, PREG_SET_ORDER | PREG_OFFSET_CAPTURE ) ) {
			return $tag;
		}
		$label = '';
		foreach ( $attrs as $attr ) {
			$inner = (string) substr( $attr[2][0], 1, -1 );
			if ( in_array( strtolower( $attr[1][0] ), array( 'key', 'name', 'id' ), true ) && '' !== $inner && ( self::secret_key( $inner ) || self::secret_constant( $inner ) ) ) {
				$label = $inner;
				break;
			}
		}
		if ( '' === $label ) {
			return $tag;
		}
		foreach ( array_reverse( $attrs ) as $attr ) {
			$inner = (string) substr( $attr[2][0], 1, -1 );
			if ( 'value' !== strtolower( $attr[1][0] ) || '' === $inner || self::MASK === $inner ) {
				continue;
			}
			self::remember( $found, $label, $inner );
			$quote = $attr[2][0][0];
			$tag   = substr_replace( $tag, $quote . self::MASK . str_repeat( "\n", substr_count( $inner, "\n" ) ) . $quote, $attr[2][1], strlen( $attr[2][0] ) );
		}
		return $tag;
	}

	/**
	 * Masks a configuration value, keeping surrounding quotes.
	 *
	 * @param string $value Raw value.
	 * @param string $label Key.
	 * @param array  $found Collected values.
	 * @return string
	 */
	private static function mask_scalar( $value, $label, array &$found ) {
		$value = (string) $value;
		if ( self::MASK === $value || self::MASK === trim( $value, '"\'' ) ) {
			return $value;
		}
		self::remember( $found, $label, $value );
		$first = $value[0];
		if ( strlen( $value ) >= 2 && ( '"' === $first || '\'' === $first ) && substr( $value, -1 ) === $first ) {
			return $first . self::MASK . $first;
		}
		return self::MASK;
	}

	/* ------------------------------------------------------------------ */
	/* Comparing                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Splits text into display lines: "\r\n" and "\n" end a line, a trailing
	 * line break adds no empty line, bytes that are not UTF-8 become "?", and a
	 * stray "\r" is shown as a visible symbol (browsers would break the line).
	 *
	 * @param string $text Text.
	 * @return string[]
	 */
	public static function lines( $text ) {
		$text = str_replace( "\r\n", "\n", (string) $text );
		if ( '' === $text ) {
			return array();
		}
		$lines = explode( "\n", $text );
		if ( '' === end( $lines ) ) {
			array_pop( $lines );
		}
		foreach ( $lines as $i => $line ) {
			if ( '' === $line ) {
				continue;
			}
			$line = Store::db_text( $line );
			if ( false !== strpos( $line, "\r" ) ) {
				$line = str_replace( "\r", "\xE2\x90\x8D", $line );
			}
			$lines[ $i ] = $line;
		}
		return $lines;
	}

	/**
	 * Line edits from $old to $new, with core's Text_Diff (no WordPress
	 * renderer is needed).
	 *
	 * @param string[] $old Old lines.
	 * @param string[] $new New lines.
	 * @return array|null Text_Diff_Op objects.
	 */
	private static function compute( array $old, array $new ) {
		try {
			if ( ! class_exists( 'Text_Diff', false ) ) {
				require_once ABSPATH . WPINC . '/Text/Diff.php';
			}
			$diff = new \Text_Diff( 'auto', array( $old, $new ) );
			return (array) $diff->getDiff();
		} catch ( \Throwable $e ) {
			return null;
		}
	}

	/* ------------------------------------------------------------------ */
	/* Rendering                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Diff table (unified or split) with numbered lines and hunks.
	 *
	 * @param array    $ops      Text_Diff ops.
	 * @param int[]    $hits     Line numbers (current version) of malware matches.
	 * @param string   $layout   unified | split.
	 * @param string   $left     Base label.
	 * @param string   $right    Current label.
	 * @param array    $notes    Receives notes.
	 * @return string HTML.
	 */
	private static function render_diff( array $ops, array $hits, $layout, $left, $right, array &$notes ) {
		// Entries: one per unchanged line, one per block of changed lines.
		$entries = array();
		$o       = 1;
		$n       = 1;
		foreach ( $ops as $op ) {
			$orig  = isset( $op->orig ) && is_array( $op->orig ) ? array_values( $op->orig ) : array();
			$final = isset( $op->final ) && is_array( $op->final ) ? array_values( $op->final ) : array();
			if ( $op instanceof \Text_Diff_Op_copy ) {
				foreach ( $final as $line ) {
					$entries[] = array(
						'type' => 'ctx',
						'o'    => $o++,
						'n'    => $n++,
						'text' => $line,
					);
				}
				continue;
			}
			$entries[] = array(
				'type' => 'chg',
				'o'    => $o,
				'n'    => $n,
				'del'  => $orig,
				'add'  => $final,
			);
			$o += count( $orig );
			$n += count( $final );
		}

		// Which entries to show: changes, malware matches, and their context.
		$hit_set = array_flip( $hits );
		$count   = count( $entries );
		$show    = array_fill( 0, $count, false );
		foreach ( $entries as $i => $entry ) {
			$radius = 0;
			if ( 'chg' === $entry['type'] ) {
				$radius = self::CONTEXT;
			} elseif ( isset( $hit_set[ $entry['n'] ] ) ) {
				$radius = self::HIT_CONTEXT;
			} else {
				continue;
			}
			for ( $j = max( 0, $i - $radius ); $j <= min( $count - 1, $i + $radius ); $j++ ) {
				$show[ $j ] = true;
			}
		}

		$split = 'split' === $layout;
		$cols  = $split ? 4 : 3;
		$html  = '<table class="diff wpcs-diff wpcs-diff--' . ( $split ? 'split is-split-view' : 'unified' ) . '">';
		$html .= $split
			? '<colgroup><col class="wpcs-diff__num"><col class="wpcs-diff__half"><col class="wpcs-diff__num"><col class="wpcs-diff__half"></colgroup>'
			: '<colgroup><col class="wpcs-diff__num"><col class="wpcs-diff__num"><col></colgroup>';
		$html .= '<thead><tr>';
		if ( $split ) {
			$html .= '<th scope="col" colspan="2" class="wpcs-diff__title wpcs-diff__title--del">' . esc_html( $left ) . '</th>';
			$html .= '<th scope="col" colspan="2" class="wpcs-diff__title wpcs-diff__title--add">' . esc_html( $right ) . '</th>';
		} else {
			$html .= '<th scope="col" colspan="3" class="wpcs-diff__title"><span class="wpcs-diff__label wpcs-diff__label--del">' . esc_html( $left ) . '</span><span class="wpcs-diff__label wpcs-diff__label--add">' . esc_html( $right ) . '</span></th>';
		}
		$html .= '</tr></thead><tbody>';

		$rows    = 0;
		$skipped = 0;
		$ids     = array();
		$i       = 0;
		$stopped = false;
		while ( $i < $count ) {
			if ( ! $show[ $i ] ) {
				++$skipped;
				++$i;
				continue;
			}
			// A hunk: consecutive shown entries.
			$start = $i;
			while ( $i < $count && $show[ $i ] ) {
				++$i;
			}
			$html .= self::hunk_header( array_slice( $entries, $start, $i - $start ), $skipped, $cols );
			$skipped = 0;
			for ( $k = $start; $k < $i; $k++ ) {
				$entry = $entries[ $k ];
				if ( 'ctx' === $entry['type'] ) {
					$html .= self::context_row( $entry, isset( $hit_set[ $entry['n'] ] ), $split, $ids );
					++$rows;
				} else {
					$html .= $split ? self::split_rows( $entry, $hit_set, $ids, $rows ) : self::unified_rows( $entry, $hit_set, $ids, $rows );
				}
				if ( $rows >= self::MAX_ROWS ) {
					$stopped = true;
					break 2;
				}
			}
		}
		if ( $stopped ) {
			$html   .= '<tr class="wpcs-diff-hunk"><td colspan="' . $cols . '">' . esc_html__( 'The rest of the changes are not shown: there are too many to display here.', 'qartvelo-guard' ) . '</td></tr>';
			$notes[] = array( 'warn', __( 'Only the first part of the changes is shown because there are too many to display on one page.', 'qartvelo-guard' ) );
		} elseif ( $skipped > 0 ) {
			$html .= '<tr class="wpcs-diff-hunk wpcs-diff-hunk--end"><td colspan="' . $cols . '"><span class="wpcs-diff-hunk__skip">' . esc_html(
				sprintf(
					/* translators: %s: number of lines */
					_n( '%s unchanged line', '%s unchanged lines', $skipped, 'qartvelo-guard' ),
					number_format_i18n( $skipped )
				)
			) . '</span></td></tr>';
		}
		$html .= '</tbody></table>';
		return $html;
	}

	/**
	 * "@@ -12,7 +12,9 @@" row with the number of hidden unchanged lines above.
	 *
	 * @param array $entries Entries of the hunk.
	 * @param int   $skipped Unchanged lines hidden before it.
	 * @param int   $cols    Columns.
	 * @return string
	 */
	private static function hunk_header( array $entries, $skipped, $cols ) {
		$first = reset( $entries );
		$old   = 0;
		$new   = 0;
		foreach ( $entries as $entry ) {
			if ( 'ctx' === $entry['type'] ) {
				++$old;
				++$new;
			} else {
				$old += count( $entry['del'] );
				$new += count( $entry['add'] );
			}
		}
		$range = sprintf( '@@ -%d,%d +%d,%d @@', $old ? $first['o'] : max( 0, $first['o'] - 1 ), $old, $new ? $first['n'] : max( 0, $first['n'] - 1 ), $new );
		$html  = '<tr class="wpcs-diff-hunk"><td colspan="' . (int) $cols . '"><span class="wpcs-diff-hunk__range">' . esc_html( $range ) . '</span>';
		if ( $skipped > 0 ) {
			$html .= '<span class="wpcs-diff-hunk__skip">' . esc_html(
				sprintf(
					/* translators: %s: number of lines */
					_n( '%s unchanged line hidden', '%s unchanged lines hidden', $skipped, 'qartvelo-guard' ),
					number_format_i18n( $skipped )
				)
			) . '</span>';
		}
		return $html . '</td></tr>';
	}

	/**
	 * @param array $entry Context entry.
	 * @param bool  $hit   Malware match on this line.
	 * @param bool  $split Split layout.
	 * @param array $ids   Line ids already used.
	 * @return string
	 */
	private static function context_row( array $entry, $hit, $split, array &$ids ) {
		$id    = self::row_id( $entry['n'], $ids );
		$class = 'wpcs-diff-row is-context' . ( $hit ? ' is-hit' : '' );
		$code  = self::code_html( $entry['text'] );
		if ( $split ) {
			return '<tr class="' . $class . '"' . $id . '>' . self::num_cell( $entry['o'] ) . '<td class="diff-context wpcs-code">' . $code . '</td>' . self::num_cell( $entry['n'], '' !== $id ) . '<td class="diff-context wpcs-code">' . $code . '</td></tr>';
		}
		return '<tr class="' . $class . '"' . $id . '>' . self::num_cell( $entry['o'] ) . self::num_cell( $entry['n'], '' !== $id ) . '<td class="diff-context wpcs-code">' . $code . '</td></tr>';
	}

	/**
	 * Unified rows of a change block: removed lines, then added lines.
	 *
	 * @param array $entry   Change entry.
	 * @param array $hit_set Hit line numbers (flipped).
	 * @param array $ids     Line ids already used.
	 * @param int   $rows    Row counter.
	 * @return string
	 */
	private static function unified_rows( array $entry, array $hit_set, array &$ids, &$rows ) {
		$html  = '';
		$pairs = min( count( $entry['del'] ), count( $entry['add'] ) );
		foreach ( $entry['del'] as $k => $line ) {
			$code  = $k < $pairs ? self::pair_html( $line, $entry['add'][ $k ], 'del' ) : self::code_html( $line );
			$html .= '<tr class="wpcs-diff-row is-del">' . self::num_cell( $entry['o'] + $k ) . self::num_cell( 0 ) . '<td class="diff-deletedline wpcs-code">' . $code . '</td></tr>';
			++$rows;
		}
		foreach ( $entry['add'] as $k => $line ) {
			$n     = $entry['n'] + $k;
			$id    = self::row_id( $n, $ids );
			$code  = $k < $pairs ? self::pair_html( $line, $entry['del'][ $k ], 'ins' ) : self::code_html( $line );
			$html .= '<tr class="wpcs-diff-row is-add' . ( isset( $hit_set[ $n ] ) ? ' is-hit' : '' ) . '"' . $id . '>' . self::num_cell( 0 ) . self::num_cell( $n, '' !== $id ) . '<td class="diff-addedline wpcs-code">' . $code . '</td></tr>';
			++$rows;
		}
		return $html;
	}

	/**
	 * Split rows of a change block: removed and added lines side by side.
	 *
	 * @param array $entry   Change entry.
	 * @param array $hit_set Hit line numbers (flipped).
	 * @param array $ids     Line ids already used.
	 * @param int   $rows    Row counter.
	 * @return string
	 */
	private static function split_rows( array $entry, array $hit_set, array &$ids, &$rows ) {
		$html  = '';
		$total = max( count( $entry['del'] ), count( $entry['add'] ) );
		for ( $k = 0; $k < $total; $k++ ) {
			$del = isset( $entry['del'][ $k ] ) ? $entry['del'][ $k ] : null;
			$add = isset( $entry['add'][ $k ] ) ? $entry['add'][ $k ] : null;
			$n   = null === $add ? 0 : $entry['n'] + $k;
			$id  = $n ? self::row_id( $n, $ids ) : '';
			$hit = $n && isset( $hit_set[ $n ] );

			$html .= '<tr class="wpcs-diff-row is-change' . ( $hit ? ' is-hit' : '' ) . '"' . $id . '>';
			if ( null === $del ) {
				$html .= self::num_cell( 0 ) . '<td class="wpcs-diff-empty"></td>';
			} else {
				$html .= self::num_cell( $entry['o'] + $k ) . '<td class="diff-deletedline wpcs-code">' . ( null === $add ? self::code_html( $del ) : self::pair_html( $del, $add, 'del' ) ) . '</td>';
			}
			if ( null === $add ) {
				$html .= self::num_cell( 0 ) . '<td class="wpcs-diff-empty"></td>';
			} else {
				$html .= self::num_cell( $n, '' !== $id ) . '<td class="diff-addedline wpcs-code">' . ( null === $del ? self::code_html( $add ) : self::pair_html( $add, $del, 'ins' ) ) . '</td>';
			}
			$html .= '</tr>';
			++$rows;
		}
		return $html;
	}

	/**
	 * Full content with numbered lines and highlighted malware matches.
	 *
	 * @param string[] $lines Redacted lines.
	 * @param int[]    $hits  Hit line numbers.
	 * @param string   $label Column label.
	 * @param array    $notes Receives notes.
	 * @return string HTML.
	 */
	private static function render_content( array $lines, array $hits, $label, array &$notes ) {
		$total   = count( $lines );
		$hit_set = array_flip( $hits );
		$html    = '<table class="wpcs-codeview"><colgroup><col class="wpcs-diff__num"><col></colgroup>';
		$html   .= '<thead><tr><th scope="col" colspan="2" class="wpcs-diff__title">' . esc_html( $label ) . '</th></tr></thead><tbody>';
		if ( 0 === $total ) {
			$html .= '<tr class="wpcs-diff-hunk"><td colspan="2">' . esc_html__( 'The file is empty.', 'qartvelo-guard' ) . '</td></tr>';
		}

		$ids   = array();
		$limit = min( $total, self::CONTENT_LINES );
		for ( $i = 0; $i < $limit; $i++ ) {
			$html .= self::content_row( $i + 1, $lines[ $i ], isset( $hit_set[ $i + 1 ] ), $ids );
		}

		if ( $total > $limit ) {
			// Lines after the cut: only the parts around malware matches.
			$ranges = array();
			foreach ( $hits as $line ) {
				if ( $line > $limit && $line <= $total ) {
					$from = max( $limit + 1, $line - 5 );
					$to   = min( $total, $line + 5 );
					$last = count( $ranges ) - 1;
					if ( $last >= 0 && $from <= $ranges[ $last ][1] + 1 ) {
						$ranges[ $last ][1] = max( $ranges[ $last ][1], $to );
					} else {
						$ranges[] = array( $from, $to );
					}
				}
			}
			$shown = $limit;
			foreach ( $ranges as $range ) {
				$html .= '<tr class="wpcs-diff-hunk"><td colspan="2"><span class="wpcs-diff-hunk__skip">' . esc_html(
					sprintf(
						/* translators: 1: first line, 2: last line */
						__( 'Lines %1$s to %2$s are not shown', 'qartvelo-guard' ),
						number_format_i18n( $shown + 1 ),
						number_format_i18n( $range[0] - 1 )
					)
				) . '</span></td></tr>';
				for ( $line = $range[0]; $line <= $range[1]; $line++ ) {
					$html .= self::content_row( $line, $lines[ $line - 1 ], isset( $hit_set[ $line ] ), $ids );
				}
				$shown = $range[1];
			}
			if ( $shown < $total ) {
				$html .= '<tr class="wpcs-diff-hunk wpcs-diff-hunk--end"><td colspan="2"><span class="wpcs-diff-hunk__skip">' . esc_html(
					sprintf(
						/* translators: 1: first line, 2: last line */
						__( 'Lines %1$s to %2$s are not shown', 'qartvelo-guard' ),
						number_format_i18n( $shown + 1 ),
						number_format_i18n( $total )
					)
				) . '</span></td></tr>';
			}
			$notes[] = array(
				'info',
				sprintf(
					/* translators: 1: lines shown, 2: total lines */
					__( 'The file has %2$s lines. The first %1$s are shown, plus the lines around every match further down. Download the file to read all of it.', 'qartvelo-guard' ),
					number_format_i18n( $limit ),
					number_format_i18n( $total )
				),
			);
		}
		return $html . '</tbody></table>';
	}

	/**
	 * @param int    $n    Line number.
	 * @param string $text Line.
	 * @param bool   $hit  Malware match.
	 * @param array  $ids  Line ids already used.
	 * @return string
	 */
	private static function content_row( $n, $text, $hit, array &$ids ) {
		$id = self::row_id( $n, $ids );
		return '<tr class="wpcs-diff-row' . ( $hit ? ' is-hit' : '' ) . '"' . $id . '>' . self::num_cell( $n, '' !== $id ) . '<td class="wpcs-code">' . self::code_html( $text ) . '</td></tr>';
	}

	/**
	 * Anchor attribute for a line of the current version (first row only).
	 *
	 * @param int   $n   Line number.
	 * @param array $ids Used ids.
	 * @return string ' id="L12"' or ''.
	 */
	private static function row_id( $n, array &$ids ) {
		$n = (int) $n;
		if ( $n < 1 || isset( $ids[ $n ] ) ) {
			return '';
		}
		$ids[ $n ] = true;
		return ' id="L' . $n . '"';
	}

	/**
	 * Line number cell (a link when the row carries the anchor).
	 *
	 * @param int  $n    Line number (0 for none).
	 * @param bool $link Link to the row.
	 * @return string
	 */
	private static function num_cell( $n, $link = false ) {
		$n = (int) $n;
		if ( $n < 1 ) {
			return '<td class="wpcs-ln"></td>';
		}
		if ( $link ) {
			return '<td class="wpcs-ln"><a href="#L' . $n . '">' . $n . '</a></td>';
		}
		return '<td class="wpcs-ln">' . $n . '</td>';
	}

	/**
	 * One escaped line, shortened when very long.
	 *
	 * @param string $line Line.
	 * @return string
	 */
	private static function code_html( $line ) {
		$line = (string) $line;
		if ( strlen( $line ) <= self::LONG_LINE ) {
			return esc_html( $line );
		}
		$head = self::cut_head( $line, self::LONG_LINE );
		return esc_html( $head ) . self::more_html( strlen( $line ) - strlen( $head ) );
	}

	/**
	 * A changed line with the changed part marked (common prefix and suffix
	 * with its counterpart stay unmarked). Very long lines show a window
	 * around the change.
	 *
	 * @param string $line  This line.
	 * @param string $other Counterpart in the other version.
	 * @param string $tag   del | ins.
	 * @return string
	 */
	private static function pair_html( $line, $other, $tag ) {
		$line  = (string) $line;
		$other = (string) $other;
		$len   = strlen( $line );
		$olen  = strlen( $other );
		$max   = min( $len, $olen );

		$p = 0;
		while ( $p < $max && $line[ $p ] === $other[ $p ] ) {
			++$p;
		}
		while ( $p > 0 && ( ( $p < $len && 0x80 === ( ord( $line[ $p ] ) & 0xC0 ) ) || ( $p < $olen && 0x80 === ( ord( $other[ $p ] ) & 0xC0 ) ) ) ) {
			--$p;
		}
		$s = 0;
		while ( $s < $max - $p && $line[ $len - 1 - $s ] === $other[ $olen - 1 - $s ] ) {
			++$s;
		}
		while ( $s > 0 && ( 0x80 === ( ord( $line[ $len - $s ] ) & 0xC0 ) || 0x80 === ( ord( $other[ $olen - $s ] ) & 0xC0 ) ) ) {
			--$s;
		}
		$mid = substr( $line, $p, $len - $p - $s );
		$pre = substr( $line, 0, $p );
		$suf = $s > 0 ? substr( $line, $len - $s ) : '';

		if ( $len <= self::LONG_LINE ) {
			// Mostly different lines read better without inner marks.
			if ( '' === $mid || ( $p + $s ) < 0.25 * max( $len, $olen ) ) {
				return esc_html( $line );
			}
			return esc_html( $pre ) . '<' . $tag . '>' . esc_html( $mid ) . '</' . $tag . '>' . esc_html( $suf );
		}

		// Long line (minified code): a window around the change.
		$html = '';
		if ( strlen( $pre ) > 300 ) {
			$tail  = self::cut_tail( $pre, 300 );
			$html .= self::more_html( strlen( $pre ) - strlen( $tail ) ) . esc_html( $tail );
		} else {
			$html .= esc_html( $pre );
		}
		if ( '' !== $mid ) {
			$part  = strlen( $mid ) > 1500 ? self::cut_head( $mid, 1500 ) : $mid;
			$html .= '<' . $tag . '>' . esc_html( $part ) . '</' . $tag . '>';
			if ( strlen( $part ) < strlen( $mid ) ) {
				$html .= self::more_html( strlen( $mid ) - strlen( $part ) );
			}
		}
		if ( strlen( $suf ) > 300 ) {
			$head  = self::cut_head( $suf, 300 );
			$html .= esc_html( $head ) . self::more_html( strlen( $suf ) - strlen( $head ) );
		} else {
			$html .= esc_html( $suf );
		}
		return $html;
	}

	/**
	 * Marker for characters left out of a long line.
	 *
	 * @param int $bytes Bytes left out.
	 * @return string
	 */
	private static function more_html( $bytes ) {
		return '<span class="wpcs-diff-more">' . esc_html(
			sprintf(
				/* translators: %s: number of characters */
				__( '[%s more characters]', 'qartvelo-guard' ),
				number_format_i18n( (int) $bytes )
			)
		) . '</span>';
	}

	/**
	 * First $bytes bytes, never cutting a UTF-8 character.
	 *
	 * @param string $text  Text.
	 * @param int    $bytes Bytes.
	 * @return string
	 */
	private static function cut_head( $text, $bytes ) {
		$text = (string) $text;
		if ( strlen( $text ) <= $bytes ) {
			return $text;
		}
		$cut = $bytes;
		while ( $cut > 0 && 0x80 === ( ord( $text[ $cut ] ) & 0xC0 ) ) {
			--$cut;
		}
		return substr( $text, 0, $cut );
	}

	/**
	 * Last $bytes bytes, never cutting a UTF-8 character.
	 *
	 * @param string $text  Text.
	 * @param int    $bytes Bytes.
	 * @return string
	 */
	private static function cut_tail( $text, $bytes ) {
		$text = (string) $text;
		$len  = strlen( $text );
		if ( $len <= $bytes ) {
			return $text;
		}
		$start = $len - $bytes;
		while ( $start < $len && 0x80 === ( ord( $text[ $start ] ) & 0xC0 ) ) {
			++$start;
		}
		return substr( $text, $start );
	}
}
