<?php
/**
 * Malware signatures and the pure-string matching engine.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Every signature:
 *
 *   id        Stable machine name (stored in item details).
 *   title     Human title.
 *   severity  1 medium, 2 high, 3 critical (Store::SEV_*).
 *   pattern   PCRE with delimiters and flags. Never uses the "u" flag, so
 *             invalid UTF-8 in a file never disables a signature.
 *   targets   php | js | html | any | image | htaccess. What each file kind runs:
 *               php files       php + js + html + any (PHP often echoes injected scripts)
 *               js files        js + any
 *               html/svg files  html + js + any
 *               .htaccess,
 *               .user.ini,
 *               php.ini         htaccess + any
 *               images          image (head and tail of the file only)
 *               other text      any
 *
 * Optional keys understood by match():
 *   needle    Lowercase literal(s). The pattern only runs when one of them occurs
 *             in the file (cheap prefilter).
 *   requires  PCRE that must ALSO match somewhere in the file.
 *   unless    PCRE tested against the line around a match; a match there is dropped.
 *             ("exclude" is still read for signatures added through the filter.)
 *   min_count The pattern must match at least this many times.
 *   skip_comments Drop matches on PHP comment lines.
 *   decode    escapes | chr | concat. The match is decoded and kept only when the
 *             decoded text matches "decoded".
 *   decoded   PCRE tested against the decoded text.
 *   skip_path PCRE tested against "/" + the file's relative path; the signature
 *             does not run for a path that matches (bundled libraries).
 *
 * Rules of thumb used to keep false positives near zero on mainstream code
 * (WordPress core, WooCommerce, Elementor, Yoast, Polylang, Revolution Slider):
 * every critical signature needs request input, decoded data or a known
 * malware marker next to an execution sink. Generic "dangerous function"
 * signatures are deliberately absent.
 *
 * This class has no WordPress dependency except __() so it can be unit tested alone.
 */
class Signatures {

	/** Bump when signatures change (shown in the UI and logs). */
	const VERSION = '2026.10.3';

	const KIND_PHP      = 'php';
	const KIND_JS       = 'js';
	const KIND_HTML     = 'html';
	const KIND_IMAGE    = 'image';
	const KIND_HTACCESS = 'htaccess';
	const KIND_TEXT     = 'text';
	const KIND_BINARY   = 'binary';

	/** Bytes read from the start and the end of images. */
	const IMAGE_SLICE = 8192;

	/** Hits kept per signature (distinct lines) and per file. */
	const MAX_PER_SIG  = 3;
	const MAX_PER_FILE = 20;

	/** @var array|null */
	private static $cache = null;

	/** @var array|null */
	private static $path_cache = null;

	/** @var string|null The content comment_ranges() was last built for (compared by identity, so no copy is made). */
	private static $ranges_for = null;

	/** @var array|null Sorted [start, end] byte ranges of that content's comments; null when the tokenizer could not be used. */
	private static $ranges = null;

	/**
	 * Extensions treated as PHP source.
	 *
	 * @return string[]
	 */
	public static function php_extensions() {
		return array( 'php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps', 'inc' );
	}

	/**
	 * Image extensions (only head and tail are checked).
	 *
	 * @return string[]
	 */
	public static function image_extensions() {
		return array( 'jpg', 'jpeg', 'jpe', 'jfif', 'png', 'gif', 'ico', 'bmp', 'webp', 'tif', 'tiff', 'avif', 'heic', 'heif' );
	}

	/**
	 * Binary formats that are never content scanned.
	 *
	 * @return string[]
	 */
	public static function binary_extensions() {
		return array(
			'pdf', 'zip', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'tar', 'jar', 'war', 'apk',
			'mp3', 'mp4', 'm4a', 'm4v', 'mov', 'avi', 'wmv', 'flv', 'webm', 'ogg', 'ogv', 'oga', 'wav', 'flac', 'aac', 'mkv', 'mpg', 'mpeg',
			'woff', 'woff2', 'ttf', 'otf', 'eot', 'mo', 'psd', 'ai', 'eps', 'sketch', 'fig', 'xcf',
			'sqlite', 'db', 'mmdb', 'dat', 'swf', 'exe', 'dll', 'so', 'dylib', 'bin', 'class', 'wasm', 'node',
			'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'key', 'numbers', 'pages',
			'ds_store', 'icns', 'cur', 'ani', 'pyc',
		);
	}

	/**
	 * Decides how a file is scanned from its name.
	 *
	 * @param string $name File name or path.
	 * @return string One of the KIND_* constants.
	 */
	public static function kind_for( $name ) {
		$base = strtolower( basename( str_replace( '\\', '/', (string) $name ) ) );
		if ( in_array( $base, array( '.htaccess', '.user.ini', 'php.ini', '.htaccess.bak' ), true ) ) {
			return self::KIND_HTACCESS;
		}
		$pos = strrpos( $base, '.' );
		$ext = false === $pos ? '' : substr( $base, $pos + 1 );
		if ( in_array( $ext, self::php_extensions(), true ) ) {
			return self::KIND_PHP;
		}
		if ( in_array( $ext, array( 'js', 'mjs', 'cjs' ), true ) ) {
			return self::KIND_JS;
		}
		if ( in_array( $ext, array( 'html', 'htm', 'xhtml', 'shtml', 'svg', 'svgz' ), true ) ) {
			return 'svgz' === $ext ? self::KIND_BINARY : self::KIND_HTML;
		}
		if ( in_array( $ext, self::image_extensions(), true ) ) {
			return self::KIND_IMAGE;
		}
		if ( in_array( $ext, self::binary_extensions(), true ) ) {
			return self::KIND_BINARY;
		}
		return self::KIND_TEXT;
	}

	/**
	 * Signature targets each kind runs.
	 *
	 * @param string $kind KIND_*.
	 * @return string[]
	 */
	public static function targets_for_kind( $kind ) {
		switch ( $kind ) {
			case self::KIND_PHP:
				return array( 'php', 'js', 'html', 'any' );
			case self::KIND_JS:
				return array( 'js', 'any' );
			case self::KIND_HTML:
				return array( 'html', 'js', 'any' );
			case self::KIND_HTACCESS:
				return array( 'htaccess', 'any' );
			case self::KIND_IMAGE:
				return array( 'image' );
			case self::KIND_TEXT:
				return array( 'any' );
			default:
				return array();
		}
	}

	/**
	 * True when text content is really PHP code (for files with a non-PHP name,
	 * such as "x.txt" or "x.suspected" included by a loader).
	 *
	 * @param string $content File content.
	 * @return bool
	 */
	public static function looks_like_php( $content ) {
		$head = ltrim( substr( (string) $content, 0, 2048 ), "\xEF\xBB\xBF \t\r\n" );
		return 1 === preg_match( '~^<\?(?:php\b|=)~i', $head );
	}

	/**
	 * All content signatures.
	 *
	 * @return array[]
	 */
	public static function all() {
		if ( null !== self::$cache ) {
			return self::$cache;
		}

		// Shared fragments. Request input is also read through $GLOBALS['_POST'].
		$glob     = '\$GLOBALS\s*\[\s*["\x27]_(?:GET|POST|REQUEST|COOKIE)["\x27]\s*\]';
		$req      = '(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER\s*\[\s*["\x27]HTTP_)|' . $glob . ')';
		$req_core = '(?:\$_(?:GET|POST|REQUEST|COOKIE)|' . $glob . ')';
		$decoders = 'base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|urldecode|hex2bin|convert_uudecode|bzdecompress|lzf_decompress';
		$wrap     = '(?:@\s*)?(?:\x5c?[a-z_][a-z0-9_]*\s*\(\s*(?:@\s*)?){0,3}';
		$not_obj  = '(?<![\w$\x5c])(?<!->)(?<!::)';
		$sinks    = 'system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|assert|eval|create_function';
		$danger   = 'eval|assert|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|create_function|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|file_put_contents|fwrite|fputs|move_uploaded_file|fsockopen|pfsockopen|convert_uudecode|preg_replace|call_user_func|call_user_func_array|hex2bin|curl_exec|unserialize|chmod|_POST|_GET|_REQUEST|_COOKIE|_SERVER|_FILES|GLOBALS';
		$img_ext  = 'ico|png|jpe?g|gif|bmp|webp|tiff?';

		$sigs = array(

			/* ---------------- PHP: execution of decoded or request data ---------------- */

			array(
				'id'       => 'php_eval_decoded',
				'title'    => __( 'Runs hidden code: eval or assert of decoded data', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'eval', 'assert' ),
				'pattern'  => '~' . $not_obj . '(?:eval|assert)\s*\(\s*(?:@\s*)?(?:["\x27]\?>["\x27]\s*\.\s*)?(?:@\s*)?\x5c?(?:' . $decoders . ')\s*\(~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_exec_request',
				'title'    => __( 'Executes commands or code sent in the request (web shell)', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( '$_', '$globals' ),
				'pattern'  => '~' . $not_obj . '(?:' . $sinks . ')\s*\(\s*(?:' . $wrap . $req . '|["\x27][^"\x27\n;]{0,80}["\x27]\s*\.\s*' . $wrap . $req . ')~i',
				'unless'   => '~escapeshellarg\s*\(~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_backtick_request',
				'title'    => __( 'Runs a shell command taken from the request', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( '`' ),
				'pattern'  => '~(?:[=(,.]|\b(?:echo|print|return))\s*+(?:@\s*+)?`\s*+(?:\{\s*+)?' . $req_core . '\s*+\[[^\]`\n]{1,40}\]\s*+(?:\}\s*+)?`\s*+[;),.]~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_request_as_function',
				'title'    => __( 'Calls a function whose name comes from the request', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( '$_', '$globals' ),
				'pattern'  => '~(?<!["\x27{])\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[\s*[^\]\n]{1,40}\]\s*\(\s*[^)\s]~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_callback_request',
				'title'    => __( 'Calls a function named by the request through a callback (web shell)', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( '$_', '$globals' ),
				'pattern'  => '~\b(?:call_user_func(?:_array)?|array_map|register_shutdown_function|register_tick_function|ob_start|forward_static_call(?:_array)?|set_error_handler|set_exception_handler|spl_autoload_register)\s*+\(\s*+(?:@\s*+)?' . $req_core . '\s*+\[~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_callback_request_arg',
				'title'    => __( 'Passes a request value as the callback of an array or sort function (web shell)', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( '$_', '$globals' ),
				'pattern'  => '~\b(?:array_filter|array_walk(?:_recursive)?|usort|uasort|uksort|array_reduce|iterator_apply|preg_replace_callback)\s*+\(\s*+[^,;\n()]{1,80}(?:\([^()\n]{0,80}\))?\s*+,\s*+(?:@\s*+)?' . $req_core . '\s*+\[~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_superglobal_copy_exec',
				'title'    => __( 'Copies a request array and executes a value from it (web shell)', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( '$_', '$globals' ),
				'pattern'  => '~\$(\w+)\s*+=\s*+(?:@\s*+)?' . $req_core . '\s*+;(?:[^\n]{0,200}+\n){0,4}?[^\n]{0,200}?(?<![\w$\x5c])(?<!->)(?<!::)(?:' . $sinks . ')\s*+\(\s*+(?:@\s*+)?(?:' . $wrap . ')?\$\1\s*+\[~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_request_var_function',
				'title'    => __( 'Stores a request value and calls it as a function', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( '$_', '$globals' ),
				'pattern'  => '~\$(\w+)\s*+=\s*+(?:@\s*+)?(?:trim\s*+\(\s*+|stripslashes\s*+\(\s*+)?' . $req_core . '\s*+\[[^\]\n]{1,40}\]\s*+(?:\)\s*+)?;(?:[^\n]{0,200}+\n){0,4}?[^\n]{0,200}?(?<![\w>:$])\$\1\s*\(~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_variable_superglobal',
				'title'    => __( 'Hides access to request data behind a computed name', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( '${' ),
				'pattern'  => '~\$\{\s*["\x27]_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)["\x27]\s*\}~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_eval_remote',
				'title'    => __( 'Downloads code from another server and runs it', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'eval', 'assert' ),
				'pattern'  => '~' . $not_obj . '(?:eval|assert)\s*\(\s*(?:["\x27]\?>["\x27]\s*\.\s*)?(?:@\s*)?(?:file_get_contents|curl_exec|wp_remote_retrieve_body|stream_get_contents|fread|fgets)\s*\(~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_include_remote',
				'title'    => __( 'Includes code from a URL or the raw request body', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'include', 'require' ),
				'pattern'  => '~(?<![\w"\x27$>:/.-])(?:include|require)(?:_once)?\b\s*+(?:\(\s*+)?["\x27](?:https?|ftps?|php|data|expect|zip|compress\.zlib)://~i',
				'unless'   => '~php://(?:filter/read=|memory|temp)~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_include_request',
				'title'    => __( 'Includes a file named by the request (file inclusion backdoor)', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'include', 'require' ),
				'pattern'  => '~(?<![\w"\x27$>:/.-])(?:include|require)(?:_once)?\b\s*+(?:\(\s*+)?' . $wrap . $req_core . '\s*\[~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_include_obfuscated',
				'title'    => __( 'Includes a file whose path is hidden with escape codes', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'include', 'require' ),
				'pattern'  => '~(?<![\w"\x27$>:/.-])(?:include|require)(?:_once)?\b\s*+(?:\(\s*+)?"(?:[^"\n]{0,24}?\x5c(?:x[0-9a-f]{2}|[0-7]{3})){3}~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_include_image',
				'title'    => __( 'Loads PHP code from an image file', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'include', 'require' ),
				'pattern'  => '~(?<![\w"\x27$>:/.-])(?:include|require)(?:_once)?\b\s*+(?:\(\s*+)?[^;\n]{0,160}?\.(?:' . $img_ext . ')\s*+["\x27]\s*+(?:\)\s*+)?;~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_preg_e',
				'title'    => __( 'Runs code through preg_replace with the /e modifier', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'preg_replace' ),
				'pattern'  => '~\bpreg_replace\s*\(\s*(["\x27])\s*(?:([/#\~|!@%])[^\n]{0,200}?\2|\{[^\n]{0,200}?\})[imsxuADSUX]*e[imsxuADSUX]*\1\s*,~',
			),
			array(
				'id'       => 'php_exif_loader',
				'title'    => __( 'Runs code hidden in image EXIF data', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'preg_replace' ),
				'pattern'  => '~\bpreg_replace\s*\(\s*\$\w+\s*\[\s*["\x27](?:Make|Model|Software|Artist|Copyright|ImageDescription|Comment|UserComment)["\x27]\s*\]~i',
			),
			array(
				'id'       => 'php_create_function_payload',
				'title'    => __( 'Builds a function from decoded or request data', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'create_function' ),
				'pattern'  => '~\bcreate_function\s*\([^,;]{0,60},\s*(?:@\s*)?(?:\x5c?(?:' . $decoders . ')\s*\(|' . $req_core . ')~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_dangerous_callback',
				'title'    => __( 'Passes a code execution function as a callback', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'assert', 'eval', 'system', 'exec', 'passthru', 'popen', 'create_function' ),
				'pattern'  => '~\b(?:array_map|call_user_func(?:_array)?|register_shutdown_function|register_tick_function|ob_start|forward_static_call(?:_array)?|array_walk(?:_recursive)?|array_filter|usort|uasort|uksort|iterator_apply|array_reduce)\s*+\(\s*+(?:[^,;()]{1,80},\s*+)?["\x27](?:assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function)["\x27]\s*[,)]~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_extract_call',
				'title'    => __( 'Imports request variables and calls one as a function', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'extract' ),
				'pattern'  => '~\bextract\s*+\(\s*+' . $req_core . '\s*+\)\s*+;\s*+(?:@\s*+)?(?:(?:die|exit|print|echo)\s*+(?:\(\s*+)?)?\$\w+\s*\(\s*\$\w+~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_eval_variable_decoded',
				'title'    => __( 'Decodes data into a variable and runs it', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'eval', 'assert' ),
				'pattern'  => '~' . $not_obj . '(?:eval|assert)\s*\(\s*(?:["\x27]\?>["\x27]\s*\.\s*)?\$\w+\s*\)~i',
				'requires' => '~\$\w+\s*=\s*(?:@\s*)?\x5c?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|convert_uudecode|hex2bin|rawurldecode)\s*\(~i',
				'skip_comments' => true,
			),

			/* ---------------- PHP: obfuscation ---------------- */

			array(
				'id'       => 'php_obfuscated_names',
				'title'    => __( 'Function name hidden with ROT13 or reversed text', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'onfr64', 'tmvasyngr', 'tmhapbzcerff', 'fge_ebg13', 'pbairg_hhqrpbqr', 'perngr_shapgvba', 'str_rot13', 'strrev', 'edoced_46esab', 'etalfnizg' ),
				'pattern'  => '~["\x27](?:onfr64_qrpbqr|tmvasyngr|tmhapbzcerff|fge_ebg13|pbairg_hhqrpbqr|perngr_shapgvba|edoced_46esab|etalfnizg|sserpmocnuzg|noitcnuf_etaerc|cexe_llehs)["\x27]|\bstr_rot13\s*\(\s*["\x27](?:riny|nffreg|flfgrz|cnffgueh|rkrp|onfr64_qrpbqr|tmvasyngr)["\x27]|\bstrrev\s*\(\s*["\x27](?:lave|tressa|metsys|urhtssap|cexe|edoced_46esab|etalfnizg)["\x27]~i',
			),
			array(
				'id'       => 'php_escaped_function',
				'title'    => __( 'Function or variable name hidden with escape codes', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( '\\x', '\\1', '\\0', '\\5', '\\6', '\\7' ),
				// Possessive quantifiers: an unterminated run of escapes cannot backtrack.
				'pattern'  => '~"((?:[^"\x5c\n]{0,40}+\x5c(?:x[0-9a-f]{1,2}+|[0-7]{2,3}+)){2,}+[^"\x5c\n]{0,40}+)"~i',
				'decode'   => 'escapes',
				'decoded'  => '~^\s*\$?(?:' . $danger . ')\s*$|\b(?:eval|assert|base64_decode|gzinflate|str_rot13|system|shell_exec|passthru|create_function)\s*\(|\$_(?:POST|GET|REQUEST|COOKIE)\b~i',
			),
			array(
				'id'       => 'php_chr_function',
				'title'    => __( 'Function name assembled from character codes', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'chr' ),
				// Bounded chain with atomic pieces: a long run of chr() calls cannot
				// exhaust the PCRE stack (that used to switch the signature off).
				'pattern'  => '~(?:\bchr\s*+\(\s*+(?:\d{1,3}+|0x[0-9a-f]{1,2}+)\s*+\)\s*+\.\s*+){3,200}\bchr\s*+\(\s*+(?:\d{1,3}+|0x[0-9a-f]{1,2}+)\s*+\)~i',
				'decode'   => 'chr',
				'decoded'  => '~^\s*\$?(?:' . $danger . ')\s*$|\b(?:eval|assert|base64_decode|gzinflate|system|shell_exec|passthru)\s*\(~i',
			),
			array(
				'id'       => 'php_concat_function',
				'title'    => __( 'Dangerous function name split into pieces', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( '.' ),
				'pattern'  => '~(?:(["\x27])[a-z0-9_]{1,10}\1\s*\.\s*){1,8}(["\x27])[a-z0-9_]{1,10}\2~i',
				'decode'   => 'concat',
				'decoded'  => '~^(?:eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|system|shell_exec|passthru|popen|proc_open|pcntl_exec|exec|_POST|_GET|_REQUEST|_COOKIE)$~i',
			),
			array(
				'id'       => 'php_long_base64_exec',
				'title'    => __( 'Large encoded payload next to code execution', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'eval', 'assert', 'create_function', 'base64_decode', 'gzinflate' ),
				'pattern'  => '~["\x27][A-Za-z0-9+/]{3000,}+={0,2}+["\x27]~',
				'requires' => '~' . $not_obj . '(?:eval|assert)\s*\(|\bcreate_function\s*\(|\$\w+\s*\(\s*\x5c?(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(|\b(?:gzinflate|gzuncompress|gzdecode)\s*\(\s*\x5c?(?:base64_decode|str_rot13|strrev)\s*\(~i',
			),
			array(
				'id'       => 'php_globals_obfuscation',
				'title'    => __( 'Obfuscated calls through the $GLOBALS array', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'globals' ),
				'pattern'  => '~\$GLOBALS\s*\[\s*["\x27][^"\x27\n]{1,40}["\x27]\s*\]\s*\[\s*["\x27]?\d+["\x27]?\s*\]\s*\(|\$\{\s*["\x27]GLOBALS["\x27]\s*\}~',
			),
			array(
				'id'        => 'php_goto_obfuscation',
				'title'     => __( 'Code scrambled with goto jumps (obfuscation)', 'qartvelo-guard' ),
				'severity'  => 1,
				'targets'   => 'php',
				'needle'    => array( 'goto' ),
				'pattern'   => '~\bgoto\s+[a-z_\x80-\xff][\w\x80-\xff]*\s*;~i',
				'min_count' => 40,
			),

			/* ---------------- PHP: file droppers, shells, backdoors ---------------- */

			array(
				'id'       => 'php_file_write_request',
				'title'    => __( 'Writes request data straight into a file (uploader)', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'file_put_contents', 'fwrite', 'fputs' ),
				'pattern'  => '~\b(?:file_put_contents|fwrite|fputs)\s*+\(\s*+(?:' . $wrap . $req_core . '\s*+\[[^\]\n]{1,40}\]\s*+\)*+\s*+(?:\.[^,;\n]{1,80})?,|[^,;\n]{1,200},\s*+' . $wrap . $req_core . '\s*\[)~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_upload_client_name',
				'title'    => __( 'Saves an uploaded file under the name the visitor chose', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'move_uploaded_file' ),
				'pattern'  => '~\bmove_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]\n]+\]\s*\[\s*["\x27]tmp_name["\x27]\s*\]\s*,\s*[^;\n]{0,80}?\$_FILES\s*\[[^\]\n]+\]\s*\[\s*["\x27]name["\x27]\s*\]\s*\)*\s*\)\s*;?~i',
				'unless'   => '~sanitize|wp_unique_filename|preg_replace|md5|sha1|uniqid|time\s*\(|rand|wp_check_filetype|pathinfo~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_reverse_shell',
				'title'    => __( 'Reverse shell: connects out and hands over a system shell', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( '/bin/sh', '/bin/bash', 'cmd.exe', 'proc_open' ),
				// Up to 8 lines apart. Whole lines are taken possessively and only the
				// last line is searched, so there is no nested backtracking.
				'pattern'  => '~\bp?fsockopen\s*\((?:[^\n]{0,200}+\n){0,8}?[^\n]{0,200}?(?:/bin/(?:ba)?sh|cmd\.exe)|(?:/bin/(?:ba)?sh|cmd\.exe)(?:[^\n]{0,200}+\n){0,8}?[^\n]{0,200}?\bp?fsockopen\s*\(|\bproc_open\s*\(\s*["\x27](?:/bin/(?:ba)?sh|sh|bash|cmd(?:\.exe)?)(?:\s+-i)?["\x27]~i',
			),
			array(
				'id'       => 'php_webshell_wso',
				'title'    => __( 'WSO / FilesMan web shell', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'filesman', 'wso' ),
				'pattern'  => '~["\x27]FilesMan["\x27]|\bfunction\s+wso[A-Z]\w*\s*\(|\bWSOsetcookie\b|\$wso_version\b|\bwsoEx\s*\(~',
			),
			array(
				'id'       => 'php_webshell_known',
				'title'    => __( 'Known web shell marker', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'php',
				'needle'   => array( 'c99', 'r57', 'b374k', 'indoxploit', 'anonymousfox', 'alfa', '0byt3m1n1', 'webshellorb', 'gel4y', 'leafmailer', 'leaf phpmailer', 'sec-shell', 'ani-shell', 'locus7', 'foxwso', 'priv8', 'mini shell', 'minishell', 'bypass sh' ),
				'pattern'  => '~\b(?:c99shell|c99_sess_put|c99sh_\w+|r57shell|r57_pwd_hash|b374k|IndoXploit|AnonymousFox|ALFA_DATA|AlfaCgiShell|alfacgiapi|ALFA_TEAM_\d|0byt3m1n1|WebShellOrb|Gel4y|LeafMailer|Leaf\s+PHPMailer|Sec-Shell|Ani-Shell|Locus7(?:s|Shell)|FoxWSO|Priv8\s{0,3}+(?:Shell|Uploader)|Mini\s?Shell\s{1,3}+(?:By|v\d)|Bypass\s{1,3}+Sh[e3]ll)\b~i',
				'unless'   => '~wfWAFRuleComparison~',
			),
			array(
				'id'       => 'php_globals_hex_key',
				'title'    => __( 'Global variable name hidden with escape codes', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'globals' ),
				// $GLOBALS['\x61\x62...'] or $GLOBALS["\141..."]: at least two escapes
				// at the start of the key. Every piece is bounded, so it stays linear.
				'pattern'  => '~\$GLOBALS\s{0,8}+\[\s{0,8}+["\x27]\x5c(?:x[0-9a-f]{2}|[0-7]{3})[^"\x27\x5c\n]{0,4}+\x5c(?:x[0-9a-f]{2}|[0-7]{3})~i',
				'skip_comments' => true,
			),
			array(
				'id'        => 'any_hex_escape_run',
				'title'     => __( 'Long run of hex escape codes (heavy obfuscation)', 'qartvelo-guard' ),
				'severity'  => 1,
				'targets'   => array( 'php', 'js' ),
				'needle'    => array( '\\x' ),
				// 30 escapes in a row, no repetition of a variable piece: linear.
				'pattern'   => '~(?:\x5cx[0-9a-f]{2}){30}~i',
				// Bundled libraries (fonts, binary tables) legitimately hold such data.
				'skip_path' => '~/(?:vendor|vendor-patched|vendor_prefixed|sodium_compat)/~i',
			),
			array(
				'id'       => 'defacement_hacked_by',
				'title'    => __( 'Defacement page marker ("Hacked By")', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => array( 'php', 'html', 'js' ),
				'needle'   => array( 'hacked by' ),
				// Only as a page title or heading (how defacements look), or set as the
				// document title by a script; never plain sentences in text.
				'pattern'  => '~<(?:title|h[1-6]|center|marquee|font|b|strong|span|div|p)\b[^>\n]{0,200}+>\s{0,40}+(?:<[a-z][^>\n]{0,200}+>\s{0,40}+){0,3}hacked\s{1,5}+by\b|document\.title\s{0,8}+=\s{0,8}+["\x27]\s{0,8}+hacked\s{1,5}+by\b~i',
			),
			array(
				'id'       => 'php_shell_banner',
				'title'    => __( 'Web shell status panel (safe mode / uname banner)', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'safe' ),
				'pattern'  => '~(?i:safe[_ ]?mode)\s*+(?::\s*+)?(?:<[^>\n]{0,80}>\s*+){0,3}(?:ON|OFF)\b~',
				'requires' => '~\b(?:php_uname|posix_getpwuid|disk_free_space|getmyuid)\s*\(~i',
			),
			array(
				'id'       => 'php_uname_exec',
				'title'    => __( 'Runs "uname -a" through a shell', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'uname -a' ),
				'pattern'  => '~\b(?:shell_exec|system|exec|passthru|popen)\s*\(\s*["\x27]uname\s+-a["\x27]~i',
			),
			array(
				'id'       => 'php_password_backdoor',
				'title'    => __( 'Hidden password check guarding code (backdoor)', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'md5', 'sha1' ),
				'pattern'  => '~\b(?:md5|sha1)\s*\(\s*' . $req_core . '\s*\[[^\]\n]{1,40}\]\s*\)\s*[!=]==?\s*["\x27][a-f0-9]{32,40}["\x27]~i',
				'skip_comments' => true,
			),
			array(
				'id'       => 'php_hidden_admin',
				'title'    => __( 'Hides an administrator account or logs in a fixed user', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'php',
				'needle'   => array( 'query_where', 'wp_set_auth_cookie' ),
				'pattern'  => '~\$user_search\s*->\s*query_where\s*=\s*str_replace\s*\(\s*["\x27]WHERE 1=1["\x27]|\bwp_set_auth_cookie\s*\(\s*\d+\s*[,)]~i',
				'skip_comments' => true,
			),

			/* ---------------- Images ---------------- */

			array(
				'id'       => 'image_php_code',
				'title'    => __( 'PHP code hidden in an image file', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'image',
				'pattern'  => '~<\?php|<\?=\s*+[\$@`]|<script\s++language\s*+=\s*+["\x27]?php~i',
			),
			array(
				'id'       => 'image_code_payload',
				'title'    => __( 'Executable code stored inside an image', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'image',
				'pattern'  => '~\b(?:eval|assert|base64_decode|gzinflate|str_rot13|shell_exec|passthru)\s*\(\s*["\x27$@]|/\.\*/e~',
			),

			/* ---------------- Server config (.htaccess, .user.ini, php.ini) ---------------- */

			array(
				'id'       => 'htaccess_php_handler_image',
				'title'    => __( 'Server told to run images or text files as PHP', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'htaccess',
				'needle'   => array( 'add' ),
				// The handler token is checked with a lookahead and taken whole
				// (possessive); the extension is found by a lazy scan of the line for
				// "<space>.ext", capped at 8192 bytes (Apache rejects longer lines).
				// Neither a long token nor many tokens can cause heavy backtracking.
				'pattern'  => '~^[ \t]*+Add(?:Handler|Type)[ \t]++(?=\S{0,8192}?ph(?:p|tml))\S++[^\r\n]{0,8192}?[ \t]\.?(?:' . $img_ext . '|txt|css|js|svg|pdf|log)\b~im',
			),
			array(
				'id'       => 'htaccess_php_handler',
				'title'    => __( 'Server told to run non-PHP files as PHP', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'htaccess',
				'needle'   => array( 'add' ),
				'pattern'  => '~^[ \t]*+Add(?:Handler|Type)[ \t]++(?=\S{0,8192}?ph(?:p|tml))\S++(?:[ \t]++\.?(?:php\d*+|phtml|pht|phps|phar|html?|shtml)\b)*+[ \t]++\.?(?!(?:php\d*|phtml|pht|phps|phar|html?|shtml|' . $img_ext . '|txt|css|js|svg|pdf|log)\b)[\w-]++~im',
				'unless'   => '~x-httpd-php-source~i',
			),
			array(
				'id'       => 'htaccess_php_handler_html',
				'title'    => __( 'HTML pages are run as PHP', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => 'htaccess',
				'needle'   => array( 'add' ),
				'pattern'  => '~^[ \t]*+Add(?:Handler|Type)[ \t]++(?=\S{0,8192}?ph(?:p|tml))\S++[^\r\n]{0,8192}?[ \t]\.?(?:html?|shtml)\b~im',
				'unless'   => '~x-httpd-php-source~i',
			),
			array(
				'id'       => 'htaccess_files_handler',
				'title'    => __( 'Image or text files mapped to the PHP handler', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'htaccess',
				'needle'   => array( 'files' ),
				// Only a <Files> line that starts the line is a live directive. Blank and
				// comment lines up to the next directive are consumed possessively (the
				// handler can only be that directive), so the pattern stays linear.
				'pattern'  => '~^[ \t]*+<Files(?:Match)?[ \t]++(?=[^>\n]{0,8192}?(?:' . $img_ext . '|txt|css|svg|log))[^>\n]*+>(?:[ \t\r]*+(?:#[^\n]*+)?\n)*+[ \t]*+(?:SetHandler|ForceType|AddHandler|AddType)[ \t]++\S{0,8192}?ph(?:p|tml)~im',
			),
			array(
				'id'       => 'htaccess_auto_prepend',
				'title'    => __( 'Unknown file loaded before every PHP request (auto_prepend_file)', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'htaccess',
				'needle'   => array( 'auto_prepend_file', 'auto_append_file' ),
				'pattern'  => '~auto_(?:prepend|append)_file[ \t]*+(?:=[ \t]*+)?["\x27]?(?!none\b|["\x27]|$)[^\s"\x27]++~im',
				'unless'   => '~wordfence-waf\.php|wpcybersec-guard\.php|\.htninja|ninjafirewall|malcare-waf\.php|aios-bootstrap\.php|bv_firewall|sucuri~i',
			),
			array(
				'id'       => 'htaccess_search_redirect',
				'title'    => __( 'Visitors from search engines redirected to another site (SEO spam)', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'htaccess',
				'needle'   => array( 'http_referer' ),
				// Directives start their line; each line is read once, so the
				// pattern stays linear even on one huge line of repeated conditions.
				'pattern'  => '~^[ \t]*+RewriteCond[ \t]++%\{HTTP_REFERER\}(?=[^\n]{0,8192}?(?:google|bing|yahoo|yandex|baidu|aol))[^\n]*+\n(?:[ \t]*+RewriteCond[^\n]*+\n){0,6}[ \t]*+RewriteRule[ \t]++\S++[ \t]++https?://~im',
			),

			/* ---------------- JavaScript injections (also checked in PHP and HTML) ---------------- */

			array(
				'id'       => 'js_eval_fromcharcode',
				'title'    => __( 'JavaScript runs code built from character codes', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => 'js',
				'needle'   => array( 'fromcharcode' ),
				'pattern'  => '~\beval\s*\(\s*String\.fromCharCode\s*\(~',
			),
			array(
				'id'       => 'js_docwrite_unescape',
				'title'    => __( 'JavaScript writes a hidden, escaped script into the page', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => 'js',
				'needle'   => array( 'unescape' ),
				'pattern'  => '~document\.write\s*\(\s*unescape\s*\(\s*["\x27]%3C(?:script|iframe)~i',
				'unless'   => '~google-analytics\.com|googletagmanager\.com~i',
			),
			array(
				'id'       => 'js_eval_atob',
				'title'    => __( 'JavaScript runs base64 encoded code', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => 'js',
				'needle'   => array( 'atob' ),
				'pattern'  => '~\b(?:eval|Function)\s*\(\s*(?:window\.)?atob\s*\(\s*["\x27][A-Za-z0-9+/=]{40,}~',
			),
			array(
				'id'       => 'js_charcode_payload',
				'title'    => __( 'Long JavaScript payload hidden in character codes', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => 'js',
				'needle'   => array( 'fromcharcode' ),
				'pattern'  => '~String\.fromCharCode\s*+\(\s*+(?:\d{2,3}+\s*+,\s*+){40}~',
			),
			array(
				'id'        => 'js_obfuscated_loader',
				'title'     => __( 'Obfuscated JavaScript that loads a script from another site', 'qartvelo-guard' ),
				'severity'  => 1,
				'targets'   => 'js',
				'needle'    => array( '_0x' ),
				'pattern'   => '~\b_0x[0-9a-f]{4,6}\b~',
				'min_count' => 30,
				'requires'  => '~createElement\s*\(\s*["\x27]script|["\x27]createElement["\x27]|document\.write\s*\(|\.src\s*=\s*["\x27]https?:~',
			),
			array(
				'id'       => 'js_known_injection',
				'title'    => __( 'Known malicious script domain', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'js',
				'needle'   => array( 'lowerbeforwarden', 'trackstatisticsss', 'dontkinhooot', 'destinyfernandi', 'statisticscripts' ),
				'pattern'  => '~\b(?:lowerbeforwarden|trackstatisticsss|dontkinhooot|destinyfernandi|statisticscripts)\b~i',
			),

			/* ---------------- Any text file ---------------- */

			array(
				'id'       => 'any_reverse_shell_tcp',
				'title'    => __( 'Reverse shell command (bash /dev/tcp)', 'qartvelo-guard' ),
				'severity' => 3,
				'targets'  => 'any',
				'needle'   => array( '/dev/tcp/' ),
				'pattern'  => '~\b(?:ba)?sh\s+-i\s*[>&]+\s*/dev/tcp/[\w.\-]+/\d+~i',
			),
		);

		/**
		 * Filters the signature list. Add your own signatures here.
		 *
		 * @param array[] $sigs Signatures.
		 */
		if ( function_exists( 'apply_filters' ) ) {
			$sigs = (array) apply_filters( 'wpcybersec_signatures', $sigs );
		}

		self::$cache = $sigs;
		return $sigs;
	}

	/**
	 * Rules on the relative path (no content needed).
	 *
	 * @return array[] Same shape as all(), pattern applies to the relative path.
	 */
	public static function path_rules() {
		if ( null !== self::$path_cache ) {
			return self::$path_cache;
		}
		$exec = 'php\d?|phtml|pht|phar|phps';
		self::$path_cache = array(
			array(
				'id'       => 'path_php_in_uploads',
				'title'    => __( 'PHP file inside the uploads folder', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => 'path',
				'pattern'  => '~(?:^|/)wp-content/uploads/(?:[^/]+/)*[^/]+\.(?:' . $exec . ')$~i',
			),
			array(
				'id'       => 'path_double_extension',
				'title'    => __( 'Script disguised with a media style double extension', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => 'path',
				'pattern'  => '~\.(?:jpe?g|png|gif|ico|bmp|webp)\.(?:' . $exec . ')$~i',
			),
			array(
				'id'       => 'path_hidden_script',
				'title'    => __( 'Hidden script file (name starts with a dot)', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => 'path',
				'pattern'  => '~(?:^|/)\.(?!php[-_]cs|phpstorm|phpunit|phpcs|php-cs|php_cs|github|gitlab|wp-env|stubs\.|ide-helper|phan|psalm|rector)[^/]+\.(?:' . $exec . ')$~i',
			),
			array(
				'id'       => 'path_hidden_ico',
				'title'    => __( 'Hidden icon file with a random name (common malware loader)', 'qartvelo-guard' ),
				'severity' => 1,
				'targets'  => 'path',
				'pattern'  => '~(?:^|/)\.[a-z0-9]{6,}\.ico$~i',
			),
			array(
				// A line break in a name splits it in two in most tools and logs, so
				// such names hide files. macOS "Icon\r" folder icon files are harmless.
				'id'       => 'path_control_chars',
				'title'    => __( 'File name contains a line break (hidden file name)', 'qartvelo-guard' ),
				'severity' => 2,
				'targets'  => 'path',
				'pattern'  => '~\n|\r(?!\z)|(?:^|/)(?!Icon\r\z)[^/]*\r\z~',
			),
		);
		return self::$path_cache;
	}

	/**
	 * Runs every signature that applies to a kind of file.
	 *
	 * @param string $content      Content (or the head + tail slice for images).
	 * @param string $kind         KIND_*.
	 * @param int    $min_severity Hits below are dropped.
	 * @param int    $line_offset  Added to reported line numbers (0 for whole files).
	 * @param string $path         Relative path of the file ('' when unknown), for skip_path.
	 * @return array[] Hits { sig, title, severity, line, snippet }.
	 */
	public static function match( $content, $kind, $min_severity = 1, $line_offset = 0, $path = '' ) {
		$content = (string) $content;
		if ( '' === $content ) {
			return array();
		}
		$targets = self::targets_for_kind( $kind );
		if ( ! $targets ) {
			return array();
		}

		$lower = strtolower( $content );
		$hits  = array();
		$path  = '' !== (string) $path ? '/' . ltrim( str_replace( '\\', '/', (string) $path ), '/' ) : '';

		foreach ( self::all() as $sig ) {
			if ( empty( $sig['pattern'] ) || empty( $sig['id'] ) ) {
				continue;
			}
			$severity = isset( $sig['severity'] ) ? (int) $sig['severity'] : 1;
			if ( $severity < $min_severity ) {
				continue;
			}
			$sig_targets = isset( $sig['targets'] ) ? (array) $sig['targets'] : array( 'any' );
			if ( ! array_intersect( $sig_targets, $targets ) ) {
				continue;
			}
			if ( ! empty( $sig['needle'] ) && ! self::has_needle( $lower, (array) $sig['needle'] ) ) {
				continue;
			}
			if ( ! empty( $sig['skip_path'] ) && '' !== $path && 1 === @preg_match( $sig['skip_path'], $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}

			foreach ( self::run_signature( $sig, $content ) as $hit ) {
				if ( $line_offset && $hit['line'] > 0 ) {
					$hit['line'] += $line_offset;
				}
				$hits[] = $hit;
			}
		}
		// Every signature runs (at most MAX_PER_SIG hits each); the cap keeps the
		// most severe hits, so a noisy medium signature never hides a critical one.
		return self::unique( $hits );
	}

	/**
	 * Path rules for a relative path.
	 *
	 * @param string $rel          Relative path.
	 * @param int    $min_severity Minimum severity.
	 * @return array[] Hits (line 0).
	 */
	public static function match_path( $rel, $min_severity = 1 ) {
		$rel  = str_replace( '\\', '/', (string) $rel );
		$hits = array();
		foreach ( self::path_rules() as $rule ) {
			if ( (int) $rule['severity'] < $min_severity ) {
				continue;
			}
			if ( 1 === @preg_match( $rule['pattern'], $rel ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$hits[] = array(
					'sig'      => $rule['id'],
					'title'    => $rule['title'],
					'severity' => (int) $rule['severity'],
					'line'     => 0,
					'snippet'  => self::clean_snippet( $rel ),
				);
			}
		}
		return $hits;
	}

	/**
	 * Reads a file the way the scanner does and runs every rule that applies.
	 * Pure PHP (no WordPress), so it can be tested outside a site.
	 *
	 *   - binary formats (archives, video, fonts) are skipped;
	 *   - images: only the first and last 8 KB are checked for hidden PHP; when PHP
	 *     is found, the whole file (up to $max_bytes) is checked as PHP too;
	 *   - other files larger than $max_bytes are not content scanned;
	 *   - text files that are really PHP (start with "<?php") are checked as PHP.
	 *
	 * @param string $abs          Absolute path.
	 * @param string $rel          Relative path for path rules ('' to skip them).
	 * @param int    $min_severity Minimum severity.
	 * @param int    $max_bytes    Content limit.
	 * @param string $name         Name used to pick the file kind (default: basename of $abs).
	 * @return array[] Hits.
	 */
	public static function inspect_file( $abs, $rel = '', $min_severity = 1, $max_bytes = 10485760, $name = '' ) {
		$name = '' !== $name ? $name : basename( $abs );
		$kind = self::kind_for( $name );
		$path = '' !== (string) $rel ? (string) $rel : (string) $abs;
		$hits = '' !== $rel ? self::match_path( $rel, $min_severity ) : array();
		$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || ! @is_readable( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $hits;
		}
		$max_bytes = max( 1024, (int) $max_bytes );

		// "Silence is golden" index.php files in uploads are harmless.
		if ( $hits && 'index.php' === strtolower( basename( $name ) ) && $size < 400 ) {
			$tiny = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
			if ( false === strpos( $tiny, '<?' ) || preg_match( '~^\s*<\?php\s*(?://[^\n]*\n?|#[^\n]*\n?|/\*.*?\*/|\s+)*(?:\?>\s*)?$~s', $tiny ) ) {
				$hits = array();
			}
		}

		if ( self::KIND_BINARY === $kind || 0 === (int) $size ) {
			return $hits;
		}

		if ( self::KIND_IMAGE === $kind ) {
			$head = self::read_slice( $abs, 0, self::IMAGE_SLICE );
			$tail = $size > self::IMAGE_SLICE ? self::read_slice( $abs, max( self::IMAGE_SLICE, $size - self::IMAGE_SLICE ), self::IMAGE_SLICE ) : '';
			$img  = array_merge( self::match( $head, self::KIND_IMAGE, $min_severity ), self::match( $tail, self::KIND_IMAGE, $min_severity ) );
			if ( $img && $size <= $max_bytes && false !== stripos( $head . $tail, '<?' ) ) {
				$php = self::match( (string) self::read_slice( $abs, 0, $max_bytes ), self::KIND_PHP, $min_severity, 0, $path );
				$img = array_merge( $img, $php );
			}
			foreach ( $img as &$hit ) {
				$hit['line'] = 0; // Line numbers mean nothing in binary data.
			}
			unset( $hit );
			return self::unique( array_merge( $hits, $img ) );
		}

		if ( $size > $max_bytes ) {
			return $hits;
		}
		$content = self::read_slice( $abs, 0, $max_bytes );
		if ( '' === $content ) {
			return $hits;
		}
		if ( self::KIND_TEXT === $kind && ( self::looks_like_php( $content ) || false !== stripos( $content, '<?php' ) ) ) {
			$kind = self::KIND_PHP;
		}
		return self::unique( array_merge( $hits, self::match( $content, $kind, $min_severity, 0, $path ) ) );
	}

	/**
	 * @param string $abs    File.
	 * @param int    $offset Start.
	 * @param int    $length Bytes.
	 * @return string
	 */
	private static function read_slice( $abs, $offset, $length ) {
		$data = @file_get_contents( $abs, false, null, max( 0, (int) $offset ), max( 1, (int) $length ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file; WP_Filesystem may ask for FTP credentials, which a scan or cron run cannot answer.
		return false === $data ? '' : $data;
	}

	/**
	 * Drops duplicate hits and caps the list.
	 *
	 * A signature is reported once per line (several matches on one line are
	 * one finding). Hits without a line number (path rules, ClamAV, images)
	 * are told apart by their snippet. When more than $max hits remain, the
	 * most severe ones are kept, in their original order.
	 *
	 * @param array[] $hits Hits.
	 * @param int     $max  Cap (default MAX_PER_FILE).
	 * @return array[]
	 */
	public static function unique( array $hits, $max = self::MAX_PER_FILE ) {
		$out  = array();
		$seen = array();
		foreach ( $hits as $hit ) {
			if ( ! is_array( $hit ) || ! isset( $hit['sig'] ) ) {
				continue;
			}
			$line    = isset( $hit['line'] ) ? (int) $hit['line'] : 0;
			$snippet = isset( $hit['snippet'] ) ? (string) $hit['snippet'] : '';
			$key     = $hit['sig'] . ':' . $line . ( $line > 0 ? '' : ':' . md5( $snippet ) );
			if ( isset( $seen[ $key ] ) ) {
				// Keep the more severe variant of a duplicate.
				$idx = $seen[ $key ];
				if ( (int) $hit['severity'] > (int) $out[ $idx ]['severity'] ) {
					$out[ $idx ] = $hit;
				}
				continue;
			}
			$seen[ $key ] = count( $out );
			$out[]        = $hit;
		}

		$max = max( 1, (int) $max );
		if ( count( $out ) <= $max ) {
			return $out;
		}
		$order = array_keys( $out );
		usort(
			$order,
			static function ( $a, $b ) use ( $out ) {
				$diff = (int) $out[ $b ]['severity'] - (int) $out[ $a ]['severity'];
				return 0 !== $diff ? $diff : $a - $b;
			}
		);
		$keep = array_slice( $order, 0, $max );
		sort( $keep );
		$capped = array();
		foreach ( $keep as $idx ) {
			$capped[] = $out[ $idx ];
		}
		return $capped;
	}

	/**
	 * Highest severity among hits.
	 *
	 * @param array[] $hits Hits.
	 * @return int
	 */
	public static function max_severity( array $hits ) {
		$max = 0;
		foreach ( $hits as $hit ) {
			if ( is_array( $hit ) && isset( $hit['severity'] ) ) {
				$max = max( $max, (int) $hit['severity'] );
			}
		}
		return $max;
	}

	/* ------------------------------------------------------------------ */
	/* Engine                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string   $lower   Lowercased content.
	 * @param string[] $needles Lowercase needles.
	 * @return bool
	 */
	private static function has_needle( $lower, array $needles ) {
		foreach ( $needles as $needle ) {
			if ( '' !== $needle && false !== strpos( $lower, strtolower( $needle ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Runs one signature.
	 *
	 * @param array  $sig     Signature.
	 * @param string $content Content.
	 * @return array[] Hits.
	 */
	private static function run_signature( array $sig, $content ) {
		$min_count = isset( $sig['min_count'] ) ? max( 1, (int) $sig['min_count'] ) : 1;
		// Matches examined. Comment, unless and decode filters drop candidates, so
		// a few decoys (commented copies, the same match repeated on one line)
		// must not push the real match out of the window.
		$limit = isset( $sig['decode'] ) ? 400 : max( 50, $min_count );

		// Candidate matches. Only the first $limit are ever examined, so they are
		// fetched one by one: a file with hundreds of thousands of matches costs
		// no more than one with $limit (never a list of every match, which on a
		// large minified bundle can take more memory than the host allows).
		// $limit is at least min_count, so counting stops once a min_count
		// signature has enough matches.
		$candidates = array();
		$failed     = false;
		$from       = 0;
		$size       = strlen( $content );
		while ( count( $candidates ) < $limit && $from <= $size ) {
			$m  = array();
			$ok = @preg_match( $sig['pattern'], $content, $m, PREG_OFFSET_CAPTURE, $from ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $ok ) {
				$failed = true;
				break;
			}
			if ( 1 !== $ok ) {
				break;
			}
			$candidates[] = $m[0];
			$end          = $m[0][1] + strlen( $m[0][0] );
			$from         = $end > $m[0][1] ? $end : $end + 1;
		}
		$count = count( $candidates );
		$more  = $count >= $limit && $from <= $size;
		if ( $min_count > 1 ) {
			if ( $failed ) {
				// A PCRE limit was hit: fail closed instead of reporting the file clean.
				return array( self::incomplete_hit( $sig ) );
			}
			if ( $count < $min_count ) {
				return array();
			}
		} elseif ( ! $count ) {
			// A PCRE limit was hit: fail closed instead of reporting the file clean.
			return $failed ? array( self::incomplete_hit( $sig ) ) : array();
		}
		if ( ! empty( $sig['requires'] ) ) {
			$required = @preg_match( $sig['requires'], $content ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $required ) {
				return array( self::incomplete_hit( $sig ) );
			}
			if ( 1 !== $required ) {
				return array();
			}
		}

		$hits     = array();
		$lines    = array();
		$seen     = 0;
		$line     = 1;
		$line_pos = 0;
		foreach ( $candidates as $match ) {
			if ( ++$seen > $limit ) {
				break;
			}
			list( $text, $offset ) = $match;

			// Line number, counted incrementally (matches come in offset order).
			if ( $offset > $line_pos ) {
				$line    += substr_count( $content, "\n", $line_pos, $offset - $line_pos );
				$line_pos = $offset;
			}
			if ( isset( $lines[ $line ] ) ) {
				continue; // One finding per signature and line.
			}

			if ( ! empty( $sig['skip_comments'] ) && self::in_comment_line( $content, $offset ) ) {
				continue;
			}
			$unless = ! empty( $sig['unless'] ) ? $sig['unless'] : ( ! empty( $sig['exclude'] ) ? $sig['exclude'] : '' );
			if ( '' !== $unless ) {
				$context = self::line_text( $content, $offset, strlen( $text ) );
				if ( 1 === @preg_match( $unless, $context ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					continue;
				}
			}

			$decoded = '';
			if ( ! empty( $sig['decode'] ) ) {
				$decoded = self::decode( $sig['decode'], $text );
				if ( '' === $decoded || empty( $sig['decoded'] ) || 1 !== @preg_match( $sig['decoded'], $decoded ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					continue;
				}
			}

			$snippet = self::snippet( $content, $offset, strlen( $text ) );
			if ( '' !== $decoded ) {
				$snippet = self::clean_snippet( substr( $text, 0, 90 ) . ' => ' . $decoded );
			}
			if ( $min_count > 1 ) {
				$snippet = self::clean_snippet(
					( $more
						/* translators: %d: number of occurrences counted before counting stopped */
						? sprintf( __( '%d or more occurrences, first:', 'qartvelo-guard' ), $count )
						/* translators: %d: number of occurrences */
						: sprintf( __( '%d occurrences, first:', 'qartvelo-guard' ), $count ) ) . ' ' . $snippet
				);
			}

			$lines[ $line ] = true;
			$hits[]         = array(
				'sig'      => (string) $sig['id'],
				'title'    => isset( $sig['title'] ) ? (string) $sig['title'] : (string) $sig['id'],
				'severity' => (int) $sig['severity'],
				'line'     => $line,
				'snippet'  => $snippet,
			);
			if ( count( $hits ) >= self::MAX_PER_SIG || $min_count > 1 ) {
				break;
			}
		}
		if ( $failed && ! $hits ) {
			// The rest of the file was never searched: fail closed.
			return array( self::incomplete_hit( $sig ) );
		}
		return $hits;
	}

	/**
	 * Hit reported when a signature could not finish (backtrack, recursion or
	 * JIT stack limit). Malware can pad a file to trip these limits, so the file
	 * is never reported clean in that case.
	 *
	 * @param array $sig Signature.
	 * @return array Hit.
	 */
	private static function incomplete_hit( array $sig ) {
		return array(
			'sig'      => 'scan_incomplete',
			'title'    => __( 'This file could not be fully checked (pattern limit reached)', 'qartvelo-guard' ),
			'severity' => 2,
			'line'     => 0,
			'snippet'  => self::clean_snippet( (string) $sig['id'] ),
		);
	}

	/**
	 * Decodes an obfuscated literal.
	 *
	 * @param string $mode escapes | chr | concat.
	 * @param string $text Matched text.
	 * @return string
	 */
	private static function decode( $mode, $text ) {
		switch ( $mode ) {
			case 'escapes':
				$inner = trim( $text, '"' );
				$out   = preg_replace_callback(
					'~\x5c(x[0-9a-fA-F]{1,2}|[0-7]{1,3})~',
					static function ( $m ) {
						return 'x' === strtolower( $m[1][0] ) ? chr( hexdec( substr( $m[1], 1 ) ) ) : chr( octdec( $m[1] ) & 255 );
					},
					$inner
				);
				return is_string( $out ) ? $out : '';
			case 'chr':
				if ( ! preg_match_all( '~chr\s*\(\s*(\d{1,3}|0x[0-9a-f]{1,2})\s*\)~i', $text, $m ) ) {
					return '';
				}
				$out = '';
				foreach ( $m[1] as $num ) {
					$out .= chr( ( 0 === stripos( $num, '0x' ) ? hexdec( substr( $num, 2 ) ) : (int) $num ) & 255 );
				}
				return $out;
			case 'concat':
				if ( ! preg_match_all( '~(["\x27])([a-z0-9_]*)\1~i', $text, $m ) ) {
					return '';
				}
				return implode( '', $m[2] );
		}
		return '';
	}

	/**
	 * 1-based line number of an offset.
	 *
	 * @param string $content Content.
	 * @param int    $offset  Byte offset.
	 * @return int
	 */
	public static function line_at( $content, $offset ) {
		$offset = max( 0, min( (int) $offset, strlen( $content ) ) );
		return 1 + ( $offset > 0 ? substr_count( $content, "\n", 0, $offset ) : 0 );
	}

	/**
	 * Byte ranges of the comments in PHP content, from the tokenizer. The
	 * line heuristic below cannot tell a "/*" inside a string from a comment
	 * opener, so code after such a string could be skipped as a comment.
	 * Built once per content (the last one is kept), null when there is no
	 * PHP open tag, the content is very large or ext/tokenizer is missing.
	 *
	 * @param string $content Content.
	 * @return array|null
	 */
	private static function comment_ranges( $content ) {
		if ( null !== self::$ranges_for && $content === self::$ranges_for ) {
			return self::$ranges;
		}
		self::$ranges_for = $content;
		self::$ranges     = null;
		if ( ! function_exists( 'token_get_all' ) || strlen( $content ) > 2097152 || false === strpos( $content, '<?' ) ) {
			return null;
		}
		try {
			$tokens = @token_get_all( $content ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		} catch ( \Throwable $e ) {
			return null;
		}
		if ( ! is_array( $tokens ) ) {
			return null;
		}
		$ranges = array();
		$pos    = 0;
		foreach ( $tokens as $token ) {
			if ( is_array( $token ) ) {
				$len = strlen( (string) $token[1] );
				if ( T_COMMENT === $token[0] || T_DOC_COMMENT === $token[0] ) {
					$ranges[] = array( $pos, $pos + $len );
				}
				$pos += $len;
			} else {
				$pos += strlen( (string) $token );
			}
		}
		self::$ranges = $ranges;
		return $ranges;
	}

	/**
	 * True when the match sits on a line that is a PHP comment ("// ...", "# ..."
	 * or a docblock line "* ..."). Lines that also close a comment or leave PHP
	 * mode are not treated as comments, so "*" + "/ eval(...)" still counts.
	 *
	 * @param string $content Content.
	 * @param int    $offset  Match offset.
	 * @return bool
	 */
	private static function in_comment_line( $content, $offset ) {
		$ranges = self::comment_ranges( $content );
		if ( null !== $ranges ) {
			// The tokenizer knows exactly where the comments are.
			foreach ( $ranges as $range ) {
				if ( $range[0] > $offset ) {
					break;
				}
				if ( $offset < $range[1] ) {
					return true;
				}
			}
			return false;
		}
		$total = strlen( $content );
		$start = 0;
		if ( $offset > 0 ) {
			$prev  = strrpos( $content, "\n", $offset - $total - 1 );
			$start = false === $prev ? 0 : $prev + 1;
		}
		$end  = strpos( $content, "\n", $offset );
		$line = substr( $content, $start, ( false === $end ? $total : $end ) - $start );
		if ( false !== strpos( $line, '*/' ) || false !== strpos( $line, '?>' ) ) {
			return false;
		}
		if ( 1 === preg_match( '~^\s*(?://|#(?!\[))~', $line ) ) {
			return true;
		}
		if ( 1 !== preg_match( '~^\s*\*~', $line ) ) {
			return false;
		}
		// A line starting with "*" is a comment only inside an open /* block.
		$from   = max( 0, $start - 30000 );
		$before = substr( $content, $from, $start - $from );
		$open   = strrpos( $before, '/*' );
		$close  = strrpos( $before, '*/' );
		return false !== $open && ( false === $close || $open > $close );
	}

	/**
	 * Up to 500 bytes of the line around a match.
	 *
	 * @param string $content Content.
	 * @param int    $offset  Match offset.
	 * @param int    $length  Match length.
	 * @return string
	 */
	private static function line_text( $content, $offset, $length ) {
		$total = strlen( $content );
		$start = 0;
		if ( $offset > 0 ) {
			$prev  = strrpos( $content, "\n", $offset - $total - 1 );
			$start = false === $prev ? 0 : $prev + 1;
		}
		$start = max( $start, $offset - 250 );
		$end   = strpos( $content, "\n", $offset + $length );
		$end   = false === $end ? $total : $end;
		$end   = min( $end, $offset + $length + 250 );
		return substr( $content, $start, max( 0, $end - $start ) );
	}

	/**
	 * Readable one-line excerpt around a match, at most 160 characters.
	 *
	 * @param string $content Content.
	 * @param int    $offset  Match offset.
	 * @param int    $length  Match length.
	 * @return string
	 */
	public static function snippet( $content, $offset, $length ) {
		$total = strlen( $content );
		$start = 0;
		if ( $offset > 0 ) {
			$prev  = strrpos( $content, "\n", $offset - $total - 1 );
			$start = false === $prev ? 0 : $prev + 1;
		}
		// Keep a little context before the match, but never more than 40 bytes.
		$start = max( $start, $offset - 40 );
		$text  = substr( $content, $start, 220 );
		$nl    = strpos( $text, "\n", max( 0, $offset - $start + min( $length, 120 ) ) );
		if ( false !== $nl ) {
			$text = substr( $text, 0, $nl );
		}
		return self::clean_snippet( $text );
	}

	/**
	 * Collapses whitespace, replaces control and non-ASCII bytes, trims to 160 chars.
	 *
	 * @param string $text Raw text.
	 * @return string
	 */
	public static function clean_snippet( $text ) {
		$text = preg_replace( '~\s+~', ' ', (string) $text );
		$text = preg_replace( '~[^\x20-\x7E]~', '?', (string) $text );
		$text = trim( (string) $text );
		if ( strlen( $text ) > 160 ) {
			$text = rtrim( substr( $text, 0, 157 ) ) . '...';
		}
		return $text;
	}

	/**
	 * Drops the cached signature list (after the filter changed).
	 */
	public static function flush() {
		self::$cache      = null;
		self::$path_cache = null;
	}
}
