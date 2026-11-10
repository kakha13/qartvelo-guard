<?php
/**
 * The HTML the plugin itself prints, as an allowed list for wp_kses().
 *
 * Helper methods of the admin pages return ready HTML (badges, buttons,
 * table cells, code blocks, whole rows). They escape every value they put
 * into it, and the statement that prints it filters it once more:
 *
 *     echo wp_kses( $this->type_badge( $type ), Kses::allowed() );
 *
 * so anything that is not the plugin's own markup (a script, an event
 * handler attribute, an unknown tag) cannot reach the page even when a
 * helper has a mistake. The lists name every tag and attribute explicitly;
 * nothing here adds URL protocols or CSS properties to the WordPress defaults.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Allowed tags and attributes of the plugin's own markup.
 */
final class Kses {

	/**
	 * @var array|null
	 */
	private static $allowed = null;

	/**
	 * @var array|null
	 */
	private static $document = null;

	/**
	 * Tags and attributes of the admin pages (Dashboard, Reports, Settings,
	 * the setup wizard and the admin notices).
	 *
	 * @return array Second argument of wp_kses().
	 */
	public static function allowed() {
		if ( null !== self::$allowed ) {
			return self::$allowed;
		}

		// Attributes any element of the plugin may carry. WordPress 6.2 has no
		// wildcard for aria-*, so each one is named; data-* is a core wildcard.
		$global = array(
			'class'            => true,
			'id'               => true,
			'style'            => true,
			'title'            => true,
			'role'             => true,
			'hidden'           => true,
			'tabindex'         => true,
			'lang'             => true,
			'dir'              => true,
			'aria-atomic'      => true,
			'aria-busy'        => true,
			'aria-checked'     => true,
			'aria-controls'    => true,
			'aria-current'     => true,
			'aria-describedby' => true,
			'aria-disabled'    => true,
			'aria-expanded'    => true,
			'aria-haspopup'    => true,
			'aria-hidden'      => true,
			'aria-invalid'     => true,
			'aria-label'       => true,
			'aria-labelledby'  => true,
			'aria-live'        => true,
			'aria-pressed'     => true,
			'aria-required'    => true,
			'aria-selected'    => true,
			'aria-sort'        => true,
			'aria-valuemax'    => true,
			'aria-valuemin'    => true,
			'aria-valuenow'    => true,
			'data-*'           => true,
		);

		// Elements that only take the global attributes.
		$plain = array(
			'div',
			'span',
			'p',
			'h1',
			'h2',
			'h3',
			'h4',
			'h5',
			'h6',
			'hr',
			'br',
			'strong',
			'em',
			'b',
			'i',
			'u',
			's',
			'small',
			'mark',
			'sub',
			'sup',
			'abbr',
			'kbd',
			'samp',
			'var',
			'code',
			'pre',
			'ul',
			'dl',
			'dt',
			'dd',
			'nav',
			'section',
			'article',
			'header',
			'footer',
			'main',
			'aside',
			'figure',
			'figcaption',
			'summary',
			'legend',
			'table',
			'caption',
			'thead',
			'tbody',
			'tfoot',
			'tr',
		);

		$allowed = array();
		foreach ( $plain as $tag ) {
			$allowed[ $tag ] = $global;
		}

		// Elements with attributes of their own.
		$specific = array(
			'a'        => array( 'href', 'target', 'rel', 'download' ),
			'img'      => array( 'src', 'alt', 'width', 'height', 'loading', 'decoding' ),
			'time'     => array( 'datetime' ),
			'ins'      => array( 'datetime' ),
			'del'      => array( 'datetime' ),
			'ol'       => array( 'start', 'reversed', 'type' ),
			'li'       => array( 'value' ),
			'details'  => array( 'open' ),
			'td'       => array( 'colspan', 'rowspan', 'headers' ),
			'th'       => array( 'colspan', 'rowspan', 'headers', 'scope', 'abbr' ),
			'col'      => array( 'span' ),
			'colgroup' => array( 'span' ),
			'form'     => array( 'method', 'action', 'enctype', 'novalidate', 'autocomplete', 'name', 'target', 'accept-charset' ),
			'fieldset' => array( 'disabled', 'form', 'name' ),
			'label'    => array( 'for', 'form' ),
			'button'   => array( 'type', 'name', 'value', 'disabled', 'form', 'formnovalidate', 'autofocus' ),
			'input'    => array(
				'type',
				'name',
				'value',
				'placeholder',
				'checked',
				'disabled',
				'readonly',
				'required',
				'multiple',
				'min',
				'max',
				'step',
				'size',
				'maxlength',
				'minlength',
				'pattern',
				'autocomplete',
				'autofocus',
				'accept',
				'form',
				'inputmode',
				'spellcheck',
			),
			'select'   => array( 'name', 'disabled', 'required', 'multiple', 'size', 'form', 'autocomplete' ),
			'optgroup' => array( 'label', 'disabled' ),
			'option'   => array( 'value', 'selected', 'disabled', 'label' ),
			'textarea' => array(
				'name',
				'rows',
				'cols',
				'placeholder',
				'readonly',
				'disabled',
				'required',
				'maxlength',
				'minlength',
				'autocomplete',
				'spellcheck',
				'wrap',
				'form',
			),
		);
		foreach ( $specific as $tag => $names ) {
			$allowed[ $tag ] = $global + array_fill_keys( $names, true );
		}

		self::$allowed = $allowed;
		return self::$allowed;
	}

	/**
	 * The admin list plus the tags of a whole HTML document, for the
	 * downloadable security report (Site_Report). The stylesheet of the report
	 * is not part of it: WordPress prints that through wp_print_styles().
	 *
	 * @return array Second argument of wp_kses().
	 */
	public static function document() {
		if ( null !== self::$document ) {
			return self::$document;
		}
		$document         = self::allowed();
		$document['html'] = array(
			'lang' => true,
			'dir'  => true,
		);
		$document['head'] = array();
		$document['body'] = array(
			'class' => true,
		);
		$document['title'] = array();
		$document['meta']  = array(
			'charset' => true,
			'name'    => true,
			'content' => true,
		);

		self::$document = $document;
		return self::$document;
	}
}
