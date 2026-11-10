<?php
/**
 * Downloadable security report: one self-contained HTML file an owner can
 * send to a developer.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Builds the report (Reports > Download report, Dashboard, and
 * `wp wpcybersec report`). Inline CSS, no external assets and no JavaScript,
 * so it opens anywhere and prints well.
 *
 * Never included: secret values (code and snippets go through Diff::redact()
 * and Diff::redact_snippet(); a final pass replaces every known secret value
 * such as DB_PASSWORD, the keys and salts and WPCYBERSEC_HMAC_KEY), wp-config.php
 * content beyond redacted excerpts, nonces, the data folder path and its file
 * names (held copies, snapshots), webhook addresses, or full email addresses
 * (masked as j***@example.com).
 *
 * Created on demand (new Site_Report()); not a service.
 */
class Site_Report {

	/** Open items listed at most. */
	const MAX_ITEMS = 300;

	/** File and threat items that get a code excerpt, and of those, how many may download the official original. */
	const MAX_EXCERPTS = 40;
	const MAX_NETWORK  = 15;

	/** Lines per excerpt. */
	const EXCERPT_LINES = 200;

	/** Activity log entries. */
	const LOG_ENTRIES = 100;

	/** Replacement for hidden values. */
	const MASK = '********';

	/** First line of the report file. */
	const DOCTYPE = '<!DOCTYPE html>';

	/** @var string[] Known secret values (longest first) for the final pass. */
	private $secrets = array();

	/** @var string Data folder path, replaced in every text. */
	private $data_dir = '';

	/**
	 * File name for the download: <host>-security-report-<date>.html.
	 *
	 * @return string
	 */
	public static function filename() {
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$host = trim( (string) preg_replace( '/[^a-z0-9.\-]+/', '-', $host ), '-.' );
		return ( '' !== $host ? $host : 'site' ) . '-security-report-' . wp_date( 'Y-m-d' ) . '.html';
	}

	/**
	 * j***@example.com.
	 *
	 * @param string $email Address.
	 * @return string
	 */
	public static function mask_email( $email ) {
		$email = (string) $email;
		$at    = strrpos( $email, '@' );
		if ( false === $at || 0 === $at ) {
			return '' === $email ? '' : self::MASK;
		}
		return substr( $email, 0, 1 ) . '***' . substr( $email, $at );
	}

	/**
	 * Masks every email address inside a text.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	public static function mask_emails( $text ) {
		$out = preg_replace_callback(
			'/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/',
			static function ( $m ) {
				return self::mask_email( $m[0] );
			},
			(string) $text
		);
		return is_string( $out ) ? $out : (string) $text;
	}

	/**
	 * The whole report as one string (the WP-CLI command writes it to a file).
	 * The same pieces, in the same order, as the browser download sends:
	 * the doctype, parts()['head'], the stylesheet, parts()['body'].
	 *
	 * @return string HTML document.
	 */
	public function build() {
		$parts = $this->parts();
		return self::DOCTYPE . $parts['head'] . $this->style_tag() . $parts['body'];
	}

	/**
	 * The report in the two pieces around its stylesheet, so the download
	 * handler can print each one through wp_kses() and let WordPress print
	 * the stylesheet in between (print_style()).
	 *
	 * @return array { head: string, body: string } 'head' opens the document
	 *               up to the title; 'body' runs from the end of the head to
	 *               the end of the document.
	 */
	public function parts() {
		$this->collect_secrets();

		$plugin  = wpcybersec();
		$title   = sprintf(
			/* translators: %s: site address */
			__( 'Security report for %s', 'qartvelo-guard' ),
			home_url()
		);
		$counts  = $plugin->store->counts();
		$last    = (array) $plugin->scan_job->last_result();
		$baseline = (int) Network::get_option( 'wpcybersec_baseline_at', 0 );

		$head  = '<html lang="' . esc_attr( str_replace( '_', '-', get_locale() ) ) . '"><head><meta charset="utf-8">';
		$head .= '<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">';
		$head .= '<title>' . $this->t( $title ) . '</title>';

		$html = '</head><body><main>';

		$html .= '<header><p class="kicker">Qartvelo Guard</p><h1>' . $this->t( $title ) . '</h1>';
		$html .= '<p class="muted">' . $this->t(
			sprintf(
				/* translators: %s: date and time */
				__( 'Created %s. This file is safe to send to your developer or host: passwords, keys and other secret values are hidden as ********, and email addresses are shortened.', 'qartvelo-guard' ),
				$this->when( time() )
			)
		) . '</p></header>';

		$html .= $this->section_overview( $counts, $last, $baseline );
		$html .= $this->section_scan( $last, $baseline );
		$html .= $this->section_core();
		$html .= $this->section_items();
		$html .= $this->section_admins();
		$html .= $this->section_settings();
		$html .= $this->section_environment();
		$html .= $this->section_log();

		$html .= '<footer class="muted">' . $this->t(
			sprintf(
				/* translators: %s: plugin version */
				__( 'Generated by Qartvelo Guard %s. Line numbers refer to the file as it was when this report was created.', 'qartvelo-guard' ),
				WPCYBERSEC_VERSION
			)
		) . '</footer>';
		$html .= '</main></body></html>';

		return array(
			'head' => $this->scrub( $head ),
			'body' => $this->scrub( $html ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* Sections                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array $counts   Store::counts().
	 * @param array $last     Last scan.
	 * @param int   $baseline Baseline time.
	 * @return string
	 */
	private function section_overview( array $counts, array $last, $baseline ) {
		global $wp_version;
		$rows = array(
			__( 'Site address', 'qartvelo-guard' )        => home_url(),
			__( 'WordPress address', 'qartvelo-guard' )   => site_url(),
			__( 'WordPress version', 'qartvelo-guard' )   => (string) $wp_version . ( is_multisite() ? ' (' . __( 'multisite', 'qartvelo-guard' ) . ')' : '' ),
			__( 'PHP version', 'qartvelo-guard' )         => PHP_VERSION,
			__( 'Plugin version', 'qartvelo-guard' )      => WPCYBERSEC_VERSION,
			__( 'Waiting for a decision', 'qartvelo-guard' ) => number_format_i18n( isset( $counts['pending'] ) ? (int) $counts['pending'] : 0 ),
			__( 'Open threats', 'qartvelo-guard' )        => number_format_i18n( isset( $counts['threats'] ) ? (int) $counts['threats'] : 0 ),
			__( 'Held in quarantine', 'qartvelo-guard' )  => number_format_i18n( isset( $counts['quarantined'] ) ? (int) $counts['quarantined'] : 0 ),
			__( 'Allowlist entries', 'qartvelo-guard' )   => $this->allowlist_summary(),
			__( 'Baseline recorded', 'qartvelo-guard' )   => $baseline ? $this->when( $baseline ) : __( 'Not yet', 'qartvelo-guard' ),
			__( 'Last scan', 'qartvelo-guard' )           => ! empty( $last['finished_at'] ) ? $this->when( (int) $last['finished_at'] ) : __( 'Never', 'qartvelo-guard' ),
		);
		$hosting = wpcybersec()->hosting;
		if ( is_object( $hosting ) && method_exists( $hosting, 'current' ) ) {
			try {
				$info = $hosting->current();
				$rows[ __( 'Hosting', 'qartvelo-guard' ) ] = $hosting->label( $info ) . '. ' . $hosting->confidence_text( $info )
					/* translators: %s: list of what was found */
					. ( ! empty( $info['signals'] ) ? ' ' . sprintf( __( 'Found: %s.', 'qartvelo-guard' ), implode( '; ', (array) $info['signals'] ) ) : '' );
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}
		if ( is_multisite() && function_exists( 'get_sites' ) ) {
			// One report covers the whole network: files, approvals and scans are shared.
			$rows[ __( 'Sites in the network', 'qartvelo-guard' ) ] = number_format_i18n( (int) get_sites( array( 'count' => true ) ) );
		}
		return '<section><h2>' . $this->t( __( 'Overview', 'qartvelo-guard' ) ) . '</h2>' . $this->kv( $rows ) . '</section>';
	}

	/**
	 * @return string "123 (100 files, 20 plugins and themes, 3 database values)".
	 */
	private function allowlist_summary() {
		$allow = wpcybersec()->allowlist;
		$total = (int) $allow->count();
		$parts = array();
		foreach (
			array(
				/* translators: %s: number of entries */
				'hash'    => __( 'files: %s', 'qartvelo-guard' ),
				/* translators: %s: number of entries */
				'install' => __( 'plugins and themes: %s', 'qartvelo-guard' ),
				/* translators: %s: number of entries */
				'db'      => __( 'database values: %s', 'qartvelo-guard' ),
			) as $kind => $label
		) {
			$result = $allow->query(
				array(
					'kind'     => $kind,
					'per_page' => 1,
				)
			);
			$n = isset( $result['total'] ) ? (int) $result['total'] : 0;
			if ( $n ) {
				$parts[] = sprintf( $label, number_format_i18n( $n ) );
			}
		}
		return number_format_i18n( $total ) . ( $parts ? ' (' . implode( ', ', $parts ) . ')' : '' );
	}

	/**
	 * @param array $last     Last scan.
	 * @param int   $baseline Baseline time.
	 * @return string
	 */
	private function section_scan( array $last, $baseline ) {
		$html = '<section><h2>' . $this->t( __( 'Last scan', 'qartvelo-guard' ) ) . '</h2>';
		if ( empty( $last['finished_at'] ) ) {
			return $html . '<p>' . $this->t( __( 'No scan has finished yet.', 'qartvelo-guard' ) ) . '</p></section>';
		}
		$modes = array(
			'incremental' => __( 'Quick scan (new and changed files)', 'qartvelo-guard' ),
			'full'        => __( 'Full malware scan', 'qartvelo-guard' ),
			'baseline'    => __( 'Baseline (every file trusted, malware still reported)', 'qartvelo-guard' ),
		);
		$mode  = isset( $last['mode'] ) ? (string) $last['mode'] : '';
		$rows  = array(
			__( 'Kind', 'qartvelo-guard' )            => isset( $modes[ $mode ] ) ? $modes[ $mode ] : $mode,
			__( 'Result', 'qartvelo-guard' )          => isset( $last['state'] ) ? (string) $last['state'] : '',
			__( 'Started', 'qartvelo-guard' )         => ! empty( $last['started_at'] ) ? $this->when( (int) $last['started_at'] ) : '',
			__( 'Finished', 'qartvelo-guard' )        => $this->when( (int) $last['finished_at'] ),
			__( 'Malware signatures', 'qartvelo-guard' ) => ! empty( $last['malware'] ) ? __( 'Yes', 'qartvelo-guard' ) : __( 'No', 'qartvelo-guard' ),
			__( 'Files checked', 'qartvelo-guard' )   => number_format_i18n( isset( $last['files_done'] ) ? (int) $last['files_done'] : 0 ),
			__( 'New files', 'qartvelo-guard' )       => number_format_i18n( isset( $last['new'] ) ? (int) $last['new'] : 0 ),
			__( 'Modified files', 'qartvelo-guard' )  => number_format_i18n( isset( $last['modified'] ) ? (int) $last['modified'] : 0 ),
			__( 'Deleted files', 'qartvelo-guard' )   => number_format_i18n( isset( $last['deleted'] ) ? (int) $last['deleted'] : 0 ),
			__( 'Threats', 'qartvelo-guard' )         => number_format_i18n( isset( $last['threats'] ) ? (int) $last['threats'] : 0 ),
			__( 'Quarantined', 'qartvelo-guard' )     => number_format_i18n( isset( $last['quarantined'] ) ? (int) $last['quarantined'] : 0 ),
			__( 'Skipped', 'qartvelo-guard' )         => number_format_i18n( isset( $last['skipped'] ) ? (int) $last['skipped'] : 0 ),
		);
		if ( isset( $last['missing_core'] ) && (int) $last['missing_core'] >= 0 ) {
			$rows[ __( 'Missing core files', 'qartvelo-guard' ) ] = number_format_i18n( (int) $last['missing_core'] );
		}
		if ( ! empty( $last['database'] ) ) {
			$rows[ __( 'Database findings', 'qartvelo-guard' ) ] = number_format_i18n( isset( $last['db_findings'] ) ? (int) $last['db_findings'] : 0 );
		}
		if ( isset( $last['new_admins'] ) ) {
			$rows[ __( 'New administrators found', 'qartvelo-guard' ) ] = number_format_i18n( (int) $last['new_admins'] );
		}
		$db = Network::get_option( Db_Scanner::LAST_OPTION, array() );
		if ( is_array( $db ) && ! empty( $db['finished_at'] ) ) {
			$rows[ __( 'Last database scan', 'qartvelo-guard' ) ] = sprintf(
				/* translators: 1: date, 2: options, 3: posts, 4: findings */
				__( '%1$s: %2$s options and %3$s posts checked, %4$s suspicious values', 'qartvelo-guard' ),
				$this->when( (int) $db['finished_at'] ),
				number_format_i18n( isset( $db['options_total'] ) ? (int) $db['options_total'] : 0 ),
				number_format_i18n( isset( $db['posts_total'] ) ? (int) $db['posts_total'] : 0 ),
				number_format_i18n( isset( $db['findings'] ) ? (int) $db['findings'] : 0 )
			);
		}
		$rows[ __( 'Files monitored', 'qartvelo-guard' ) ] = number_format_i18n( (int) wpcybersec()->store->manifest_count() );
		if ( ! empty( $last['message'] ) ) {
			$rows[ __( 'Message', 'qartvelo-guard' ) ] = (string) $last['message'];
		}
		return $html . $this->kv( $rows ) . '</section>';
	}

	/**
	 * The core reinstall suggestion (Core_Repair) when the core looks damaged:
	 * counts, the reinstall by WordPress's own updater and every step by hand.
	 *
	 * @return string
	 */
	private function section_core() {
		$repair = wpcybersec()->core_repair;
		if ( ! $repair instanceof Core_Repair ) {
			return '';
		}
		try {
			$damage = $repair->damage();
			if ( ! $damage['show'] ) {
				return '';
			}
			$auto  = $repair->auto_status();
			$steps = $repair->manual_steps();
		} catch ( \Throwable $e ) {
			return '';
		}
		$html  = '<section><h2>' . $this->t( __( 'WordPress core looks damaged', 'qartvelo-guard' ) ) . ' <span class="count">' . esc_html( number_format_i18n( $damage['total'] ) ) . '</span></h2>';
		$html .= $this->kv(
			array(
				__( 'Changed core files', 'qartvelo-guard' )      => number_format_i18n( $damage['modified'] ),
				__( 'Threats in core files', 'qartvelo-guard' )   => number_format_i18n( $damage['threats'] ),
				__( 'Extra files in wp-admin or wp-includes', 'qartvelo-guard' ) => sprintf(
					/* translators: 1: number of files, 2: number that can run code */
					__( '%1$s (%2$s can run code)', 'qartvelo-guard' ),
					number_format_i18n( $damage['unknown'] ),
					number_format_i18n( $damage['unknown_exec'] )
				),
				__( 'Missing core files', 'qartvelo-guard' )      => number_format_i18n( $damage['missing'] ),
			)
		);
		$html .= '<p>' . $this->t(
			Core_Repair::is_localized()
				? sprintf(
					/* translators: %s: WordPress version */
					__( 'Recommended: reinstall WordPress core, which restores every core file from the official package of version %s, instead of reviewing changed core files one by one. wp-config.php, .htaccess, plugins, themes, uploads and the other files that were added are not touched. Files in wp-admin or wp-includes that are not part of WordPress are not removed by a reinstall: review them in Reports.', 'qartvelo-guard' ),
					$damage['version']
				) . ' ' . Core_Repair::languages_text()
				: sprintf(
					/* translators: %s: WordPress version */
					__( 'Recommended: reinstall WordPress core, which restores every core file from the official package of version %s, instead of reviewing changed core files one by one. wp-config.php, wp-content, .htaccess and the other files that were added stay as they are. Files in wp-admin or wp-includes that are not part of WordPress are not removed by a reinstall: review them in Reports.', 'qartvelo-guard' ),
					$damage['version']
				)
		) . '</p>';
		$html .= '<p>' . $this->t(
			$auto['ok']
				? __( 'From the plugin: Dashboard > "Reinstall WordPress core" starts the updater that is built into WordPress (the same as Dashboard > Updates > Re-install): WordPress downloads its official package and overwrites its own files.', 'qartvelo-guard' )
				: __( 'Starting the reinstall from the plugin is not available on this site:', 'qartvelo-guard' ) . ' ' . $auto['reason']
		) . '</p>';
		$html .= '<p><strong>' . $this->t( __( 'By hand:', 'qartvelo-guard' ) ) . '</strong></p><ol>';
		foreach ( $steps as $step ) {
			if ( ! empty( $step['other'] ) ) {
				$html .= '</ol><p><strong>' . $this->t( (string) $step['text'] ) . ':</strong></p><ol>';
				continue;
			}
			$html .= '<li>' . $this->t( isset( $step['text'] ) ? (string) $step['text'] : '' );
			if ( ! empty( $step['code'] ) ) {
				$html .= '<pre>' . $this->t( (string) $step['code'] ) . '</pre>';
			}
			$html .= '</li>';
		}
		return $html . '</ol></section>';
	}

	/**
	 * Every open item with its matches and a code excerpt.
	 *
	 * @return string
	 */
	private function section_items() {
		$store  = wpcybersec()->store;
		$result = $store->items_query(
			array(
				'status'   => Store::STATUS_PENDING,
				'orderby'  => 'severity',
				'order'    => 'DESC',
				'per_page' => self::MAX_ITEMS,
				'page'     => 1,
			)
		);
		$items = (array) $result['rows'];
		$total = (int) $result['total'];

		$html = '<section><h2>' . $this->t( __( 'Open items', 'qartvelo-guard' ) ) . ' <span class="count">' . esc_html( number_format_i18n( $total ) ) . '</span></h2>';
		if ( ! $items ) {
			return $html . '<p>' . $this->t( __( 'Nothing is waiting for a decision.', 'qartvelo-guard' ) ) . '</p></section>';
		}
		$html .= '<p class="muted">' . $this->t( __( 'Held uploads, plugin and theme installs, unknown or changed files, new administrator accounts and threats that wait for an administrator. Most serious first.', 'qartvelo-guard' ) ) . '</p>';
		if ( $total > count( $items ) ) {
			$html .= '<p class="note">' . $this->t(
				sprintf(
					/* translators: 1: listed, 2: total */
					__( 'The first %1$s of %2$s items are listed.', 'qartvelo-guard' ),
					number_format_i18n( count( $items ) ),
					number_format_i18n( $total )
				)
			) . '</p>';
		}

		$excerpts = 0;
		foreach ( $items as $item ) {
			$with = false;
			if ( in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) && ! Db_Scanner::is_db_item( $item ) && $excerpts < self::MAX_EXCERPTS ) {
				$with = true;
				++$excerpts;
			}
			$html .= $this->item_html( $item, $with, $excerpts <= self::MAX_NETWORK );
		}
		if ( $excerpts >= self::MAX_EXCERPTS ) {
			$html .= '<p class="note">' . $this->t(
				sprintf(
					/* translators: %s: number */
					__( 'Code excerpts are included for the first %s files only.', 'qartvelo-guard' ),
					number_format_i18n( self::MAX_EXCERPTS )
				)
			) . '</p>';
		}
		return $html . '</section>';
	}

	/**
	 * @param array $item    Item.
	 * @param bool  $excerpt Include a code excerpt.
	 * @param bool  $network Allow downloading the official original.
	 * @return string
	 */
	private function item_html( array $item, $excerpt, $network ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$types   = array(
			Store::TYPE_UPLOAD  => __( 'Upload', 'qartvelo-guard' ),
			Store::TYPE_INSTALL => __( 'Install', 'qartvelo-guard' ),
			Store::TYPE_FILE    => __( 'File', 'qartvelo-guard' ),
			Store::TYPE_THREAT  => __( 'Threat', 'qartvelo-guard' ),
			Store::TYPE_USER    => __( 'New administrator', 'qartvelo-guard' ),
		);
		$type    = isset( $types[ $item['type'] ] ) ? $types[ $item['type'] ] : (string) $item['type'];
		if ( Db_Scanner::is_db_item( $item ) ) {
			$type = __( 'Database', 'qartvelo-guard' );
		}
		$sev = max( 0, min( 3, (int) $item['severity'] ) );

		if ( Store::TYPE_USER === $item['type'] ) {
			$name = User_Watch::item_login( $item ) . ' (#' . User_Watch::item_user_id( $item ) . ')';
		} elseif ( Db_Scanner::is_db_item( $item ) ) {
			$name = Db_Scanner::location_label( $item );
		} elseif ( Store::TYPE_INSTALL === $item['type'] ) {
			$name = ! empty( $details['name'] ) ? (string) $details['name'] : (string) $item['path'];
		} else {
			$name = (string) $item['path'];
		}

		$html  = '<article class="item sev-' . $sev . '"><div class="item-head"><span class="badge type">' . $this->t( $type ) . '</span> ';
		$html .= '<span class="badge sev sev-' . $sev . '">' . $this->t( Store::severity_label( $sev ) ) . '</span> ';
		$html .= '<code class="path">' . $this->t( $name ) . '</code></div>';

		$rows = array(
			__( 'Item', 'qartvelo-guard' )     => '#' . (int) $item['id'],
			__( 'Detected', 'qartvelo-guard' ) => $this->when( (int) strtotime( (string) $item['created_at'] . ' UTC' ) ),
		);
		$site = isset( $details['blog_id'] ) ? Network::site_label( (int) $details['blog_id'] ) : '';
		if ( '' !== $site ) {
			$rows[ __( 'Site', 'qartvelo-guard' ) ] = $site;
		}
		if ( Store::TYPE_USER === $item['type'] ) {
			if ( ! empty( $details['user_email'] ) ) {
				$rows[ __( 'Email', 'qartvelo-guard' ) ] = self::mask_email( (string) $details['user_email'] );
			}
			if ( ! empty( $details['user_registered'] ) ) {
				$rows[ __( 'Registered', 'qartvelo-guard' ) ] = (string) $details['user_registered'] . ' UTC';
			}
			if ( ! empty( $details['roles'] ) && is_array( $details['roles'] ) ) {
				$rows[ __( 'Roles', 'qartvelo-guard' ) ] = implode( ', ', array_map( 'strval', $details['roles'] ) );
			}
		}
		if ( Store::TYPE_INSTALL === $item['type'] ) {
			foreach ( array( 'version' => __( 'Version', 'qartvelo-guard' ), 'slug' => __( 'Folder', 'qartvelo-guard' ), 'install_source' => __( 'Installed from', 'qartvelo-guard' ) ) as $key => $label ) {
				if ( ! empty( $details[ $key ] ) ) {
					$rows[ $label ] = (string) $details[ $key ];
				}
			}
		}
		if ( Store::TYPE_UPLOAD === $item['type'] && ! empty( $item['source'] ) ) {
			$rows[ __( 'Received through', 'qartvelo-guard' ) ] = (string) $item['source'];
		}
		if ( ! empty( $details['change'] ) && Store::TYPE_USER !== $item['type'] ) {
			$rows[ __( 'Change', 'qartvelo-guard' ) ] = 'modified' === $details['change'] ? __( 'Modified file', 'qartvelo-guard' ) : __( 'New file', 'qartvelo-guard' );
		}
		if ( isset( $details['checksum'] ) && 'mismatch' === $details['checksum'] ) {
			$rows[ __( 'Official checksum', 'qartvelo-guard' ) ] = __( 'Differs from the official file', 'qartvelo-guard' );
		}
		if ( (int) $item['size'] > 0 ) {
			$rows[ __( 'Size', 'qartvelo-guard' ) ] = size_format( (int) $item['size'], 1 );
		}
		if ( '' !== (string) $item['sha256'] && ! Db_Scanner::is_db_item( $item ) ) {
			$rows['SHA-256'] = (string) $item['sha256'];
		}
		if ( '' !== (string) $item['quarantine_path'] ) {
			$rows[ __( 'Held copy', 'qartvelo-guard' ) ] = __( 'Yes, in quarantine', 'qartvelo-guard' );
		}
		if ( 'review' === (string) $item['source'] ) {
			$rows[ __( 'Reported', 'qartvelo-guard' ) ] = __( 'By an administrator from Recent changes', 'qartvelo-guard' );
		}
		$html .= $this->kv( $rows );

		$hits = isset( $details['hits'] ) && is_array( $details['hits'] ) ? $details['hits'] : array();
		if ( $hits ) {
			$html .= '<h3>' . $this->t(
				sprintf(
					/* translators: %s: number of matches */
					_n( '%s malware signature match', '%s malware signature matches', count( $hits ), 'qartvelo-guard' ),
					number_format_i18n( count( $hits ) )
				)
			) . '</h3><ol class="hits">';
			$base = basename( (string) $item['path'] );
			foreach ( array_slice( $hits, 0, 25 ) as $hit ) {
				if ( ! is_array( $hit ) ) {
					continue;
				}
				$title   = ! empty( $hit['title'] ) ? (string) $hit['title'] : __( 'Suspicious code', 'qartvelo-guard' );
				$snippet = isset( $hit['snippet'] ) ? Diff::redact_snippet( (string) $hit['snippet'], ! empty( $hit['file'] ) ? basename( (string) $hit['file'] ) : $base ) : '';
				if ( strlen( $snippet ) > 400 ) {
					$snippet = ( function_exists( 'mb_strcut' ) ? mb_strcut( $snippet, 0, 400, 'UTF-8' ) : substr( $snippet, 0, 400 ) ) . ' ...';
				}
				$html .= '<li><span class="badge sev sev-' . max( 0, min( 3, isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 ) ) . '">' . $this->t( Store::severity_label( isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 ) ) . '</span> <strong>' . $this->t( $title ) . '</strong>';
				if ( ! empty( $hit['file'] ) ) {
					$html .= ' <code>' . $this->t( (string) $hit['file'] ) . '</code>';
				}
				if ( ! empty( $hit['line'] ) ) {
					/* translators: %s: line number */
					$html .= ' <span class="muted">' . $this->t( sprintf( __( 'line %s', 'qartvelo-guard' ), number_format_i18n( (int) $hit['line'] ) ) ) . '</span>';
				}
				if ( ! empty( $hit['sig'] ) ) {
					$html .= ' <code class="muted">' . $this->t( (string) $hit['sig'] ) . '</code>';
				}
				if ( '' !== $snippet ) {
					$html .= '<pre>' . $this->t( $snippet ) . '</pre>';
				}
				$html .= '</li>';
			}
			$html .= '</ol>';
			if ( count( $hits ) > 25 ) {
				$html .= '<p class="muted">' . $this->t(
					sprintf(
						/* translators: %s: number */
						__( '%s more matches are not listed.', 'qartvelo-guard' ),
						number_format_i18n( count( $hits ) - 25 )
					)
				) . '</p>';
			}
		}

		if ( $excerpt ) {
			$html .= $this->excerpt_html( $item, $network );
		}
		return $html . '</article>';
	}

	/**
	 * @param array $item    Item.
	 * @param bool  $network Allow downloading the official original.
	 * @return string
	 */
	private function excerpt_html( array $item, $network ) {
		try {
			$ex = Diff::excerpt( $item, self::EXCERPT_LINES, $network );
		} catch ( \Throwable $e ) {
			return '<p class="note">' . $this->t( __( 'The code of this file could not be read for the report.', 'qartvelo-guard' ) ) . '</p>';
		}
		if ( 'diff' === $ex['mode'] ) {
			$head = sprintf(
				/* translators: 1: lines added, 2: lines removed, 3: what it is compared with, 4: current version */
				__( 'What changed: +%1$s -%2$s lines, %3$s compared with %4$s', 'qartvelo-guard' ),
				number_format_i18n( $ex['added'] ),
				number_format_i18n( $ex['removed'] ),
				$ex['base_label'],
				$ex['current_label']
			);
		} elseif ( 'content' === $ex['mode'] ) {
			$head = sprintf(
				/* translators: %s: which version, such as "Current file on the server" */
				__( 'Code excerpt (%s)', 'qartvelo-guard' ),
				$ex['current_label']
			);
		} else {
			return '<p class="note">' . $this->t( '' !== $ex['reason_text'] ? $ex['reason_text'] : __( 'There is no code to show for this item.', 'qartvelo-guard' ) ) . '</p>';
		}

		$html = '<h3>' . $this->t( $head ) . '</h3>';
		if ( 'content' === $ex['mode'] && '' !== $ex['reason_text'] ) {
			$html .= '<p class="muted">' . $this->t( $ex['reason_text'] ) . '</p>';
		}
		foreach ( $ex['notes'] as $note ) {
			$html .= '<p class="muted">' . $this->t( $note ) . '</p>';
		}
		$diff  = 'diff' === $ex['mode'];
		$html .= '<table class="code"><colgroup>' . ( $diff ? '<col class="n"><col class="n">' : '<col class="n">' ) . '<col></colgroup><tbody>';
		foreach ( $ex['rows'] as $row ) {
			if ( '@' === $row['kind'] ) {
				$html .= '<tr class="hunk"><td colspan="' . ( $diff ? 3 : 2 ) . '">...</td></tr>';
				continue;
			}
			$class = array(
				'+' => 'add',
				'-' => 'del',
				'!' => 'hit',
				' ' => '',
			);
			$html .= '<tr class="' . esc_attr( isset( $class[ $row['kind'] ] ) ? $class[ $row['kind'] ] : '' ) . '">';
			if ( $diff ) {
				$html .= '<td class="n">' . ( $row['old'] ? (int) $row['old'] : '' ) . '</td><td class="n">' . ( $row['new'] ? (int) $row['new'] : '' ) . '</td>';
				$sign  = '+' === $row['kind'] ? '+' : ( '-' === $row['kind'] ? '-' : ' ' );
			} else {
				$html .= '<td class="n">' . (int) $row['new'] . '</td>';
				$sign  = '';
			}
			$html .= '<td class="c">' . $this->t( $sign . $row['text'] ) . '</td></tr>';
		}
		$html .= '</tbody></table>';
		if ( $ex['truncated'] ) {
			$html .= '<p class="muted">' . $this->t(
				sprintf(
					/* translators: %s: number of lines */
					__( 'Shortened to %s lines. Open the file on the Reports page to see all of it.', 'qartvelo-guard' ),
					number_format_i18n( self::EXCERPT_LINES )
				)
			) . '</p>';
		}
		return $html;
	}

	/**
	 * Administrator accounts, emails masked.
	 *
	 * @return string
	 */
	private function section_admins() {
		$watch = wpcybersec()->user_watch;
		$ids   = User_Watch::current_admin_ids();
		$html  = '<section><h2>' . $this->t( __( 'Administrator accounts', 'qartvelo-guard' ) ) . ' <span class="count">' . esc_html( number_format_i18n( count( $ids ) ) ) . '</span></h2>';
		$html .= '<p class="muted">' . $this->t( __( 'Every account that can change the site. Make sure you recognise each one; "Not reviewed" accounts became administrators after the plugin was set up and wait for a decision.', 'qartvelo-guard' ) ) . '</p>';
		$html .= '<table class="list"><thead><tr><th>' . $this->t( __( 'Login', 'qartvelo-guard' ) ) . '</th><th>' . $this->t( __( 'Email', 'qartvelo-guard' ) ) . '</th><th>' . $this->t( __( 'Registered', 'qartvelo-guard' ) ) . '</th><th>' . $this->t( __( 'Status', 'qartvelo-guard' ) ) . '</th></tr></thead><tbody>';
		foreach ( $ids as $id ) {
			$user = get_userdata( $id );
			if ( ! $user ) {
				continue;
			}
			$trusted = $watch && $watch->is_trusted( $id );
			$html   .= '<tr><td>' . $this->t( $user->user_login . ' (#' . $id . ')' ) . '</td><td>' . $this->t( self::mask_email( $user->user_email ) ) . '</td><td>' . $this->t( (string) $user->user_registered . ' UTC' ) . '</td><td>'
				. ( $trusted ? $this->t( __( 'Trusted', 'qartvelo-guard' ) ) : '<strong class="bad">' . $this->t( __( 'Not reviewed', 'qartvelo-guard' ) ) . '</strong>' ) . '</td></tr>';
		}
		return $html . '</tbody></table></section>';
	}

	/**
	 * Protection settings (no addresses, webhooks or keys).
	 *
	 * @return string
	 */
	private function section_settings() {
		$s     = wpcybersec()->settings->all();
		$yes   = __( 'On', 'qartvelo-guard' );
		$no    = __( 'Off', 'qartvelo-guard' );
		$guard = wpcybersec()->guard_manager ? wpcybersec()->guard_manager->status() : array();
		$until = wpcybersec()->install_gate ? (int) wpcybersec()->install_gate->unlocked_until() : 0;
		$rows  = array(
			__( 'Protection level', 'qartvelo-guard' )            => (string) $s['protection_level'],
			__( 'Uploads', 'qartvelo-guard' )                     => (string) $s['upload_mode'] . ( $s['upload_bypass_roles'] ? ' (' . __( 'clean uploads pass for', 'qartvelo-guard' ) . ' ' . implode( ', ', (array) $s['upload_bypass_roles'] ) . ')' : '' ),
			__( 'Hold files WordPress downloads', 'qartvelo-guard' ) => $s['gate_sideloads'] ? $yes : $no,
			__( 'Plugin and theme installs', 'qartvelo-guard' )   => (string) $s['install_mode'],
			__( 'Hold updates too', 'qartvelo-guard' )            => $s['hold_updates'] ? $yes : $no,
			__( 'Freeze file changes', 'qartvelo-guard' )         => $s['freeze_mods'] ? ( $until > time() ? __( 'On, unlocked for now', 'qartvelo-guard' ) : __( 'On, locked', 'qartvelo-guard' ) ) : $no,
			__( 'Built-in code editor disabled', 'qartvelo-guard' ) => $s['disable_file_editor'] || ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) ? $yes : $no,
			__( 'New unknown files', 'qartvelo-guard' )           => (string) $s['file_mode'],
			__( 'Modified executable files', 'qartvelo-guard' )   => (string) $s['modified_action'],
			__( 'Quarantine critical threats automatically', 'qartvelo-guard' ) => $s['auto_quarantine'] ? $yes : $no,
			__( 'Scan schedule', 'qartvelo-guard' )               => (string) $s['scan_schedule'],
			__( 'Malware signatures in scheduled scans', 'qartvelo-guard' ) => $s['scan_malware'] ? $yes : $no,
			__( 'Official checksums', 'qartvelo-guard' )          => $s['use_checksums'] ? $yes : $no,
			__( 'Copies of file versions', 'qartvelo-guard' )     => $s['snapshots'] ? $yes : $no,
			__( 'Notifications', 'qartvelo-guard' )               => (string) $s['notify_mode'] . ( '' !== (string) $s['webhook_url'] ? ', ' . __( 'webhook set', 'qartvelo-guard' ) : '' ),
			__( 'ClamAV for uploads', 'qartvelo-guard' )          => $s['clamav_enabled'] ? $yes : $no,
			__( 'Early upload guard', 'qartvelo-guard' )          => ! empty( $guard['installed'] ) ? __( 'Installed', 'qartvelo-guard' ) : __( 'Not installed', 'qartvelo-guard' ),
			__( 'Allowlist tamper check (WPCYBERSEC_HMAC_KEY)', 'qartvelo-guard' ) => defined( 'WPCYBERSEC_HMAC_KEY' ) && WPCYBERSEC_HMAC_KEY ? __( 'Set', 'qartvelo-guard' ) : __( 'Not set', 'qartvelo-guard' ),
			__( 'Setup wizard', 'qartvelo-guard' )                => $s['wizard_completed'] ? __( 'Completed', 'qartvelo-guard' ) : __( 'Not completed', 'qartvelo-guard' ),
		);
		return '<section><h2>' . $this->t( __( 'Protection settings', 'qartvelo-guard' ) ) . '</h2>' . $this->kv( $rows ) . '</section>';
	}

	/**
	 * Environment checks.
	 *
	 * @return string
	 */
	private function section_environment() {
		$checks = array();
		try {
			$checks = (array) wpcybersec()->sysadmin->diagnostics();
		} catch ( \Throwable $e ) {
			$checks = array();
		}
		$html = '<section><h2>' . $this->t( __( 'Environment checks', 'qartvelo-guard' ) ) . '</h2>';
		if ( ! $checks ) {
			return $html . '<p>' . $this->t( __( 'The environment checks could not be run.', 'qartvelo-guard' ) ) . '</p></section>';
		}
		$labels = array(
			'pass' => __( 'OK', 'qartvelo-guard' ),
			'warn' => __( 'Warning', 'qartvelo-guard' ),
			'fail' => __( 'Problem', 'qartvelo-guard' ),
			'info' => __( 'Info', 'qartvelo-guard' ),
		);
		$html .= '<table class="list"><thead><tr><th>' . $this->t( __( 'Check', 'qartvelo-guard' ) ) . '</th><th>' . $this->t( __( 'Result', 'qartvelo-guard' ) ) . '</th><th>' . $this->t( __( 'Details', 'qartvelo-guard' ) ) . '</th></tr></thead><tbody>';
		foreach ( $checks as $check ) {
			if ( ! is_array( $check ) ) {
				continue;
			}
			$status = isset( $check['status'] ) ? (string) $check['status'] : 'info';
			$detail = isset( $check['detail'] ) ? wp_strip_all_tags( (string) $check['detail'] ) : '';
			$fix    = isset( $check['fix'] ) && is_string( $check['fix'] ) ? wp_strip_all_tags( $check['fix'] ) : '';
			$html  .= '<tr><td>' . $this->t( isset( $check['label'] ) ? (string) $check['label'] : '' ) . '</td><td><span class="st st-' . esc_attr( $status ) . '">' . $this->t( isset( $labels[ $status ] ) ? $labels[ $status ] : $status ) . '</span></td><td>' . $this->t( $detail );
			if ( '' !== $fix && 'pass' !== $status ) {
				$html .= '<div class="muted">' . $this->t( $fix ) . '</div>';
			}
			$html .= '</td></tr>';
		}
		return $html . '</tbody></table></section>';
	}

	/**
	 * The last activity log entries.
	 *
	 * @return string
	 */
	private function section_log() {
		$result = wpcybersec()->store->log_query(
			array(
				'per_page' => self::LOG_ENTRIES,
				'page'     => 1,
			)
		);
		$rows = (array) $result['rows'];
		$html = '<section><h2>' . $this->t(
			sprintf(
				/* translators: %s: number of entries */
				__( 'Activity (last %s entries)', 'qartvelo-guard' ),
				number_format_i18n( self::LOG_ENTRIES )
			)
		) . '</h2>';
		if ( ! $rows ) {
			return $html . '<p>' . $this->t( __( 'Nothing recorded yet.', 'qartvelo-guard' ) ) . '</p></section>';
		}
		$html .= '<table class="list log"><thead><tr><th>' . $this->t( __( 'When', 'qartvelo-guard' ) ) . '</th><th>' . $this->t( __( 'Event', 'qartvelo-guard' ) ) . '</th><th>' . $this->t( __( 'Message', 'qartvelo-guard' ) ) . '</th><th>' . $this->t( __( 'User', 'qartvelo-guard' ) ) . '</th><th>' . $this->t( __( 'IP address', 'qartvelo-guard' ) ) . '</th></tr></thead><tbody>';
		$names = array();
		foreach ( $rows as $row ) {
			$user_id = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			if ( $user_id && ! isset( $names[ $user_id ] ) ) {
				$user               = get_userdata( $user_id );
				$names[ $user_id ] = $user ? (string) $user->user_login : '#' . $user_id;
			}
			$html .= '<tr><td class="nowrap">' . $this->t( $this->when( (int) strtotime( (string) $row['created_at'] . ' UTC' ) ) ) . '</td><td><code>' . $this->t( (string) $row['event'] ) . '</code></td><td>' . $this->t( (string) $row['message'] ) . '</td><td>' . $this->t( $user_id ? $names[ $user_id ] : ( \WPCyberSecurity\Admin\Reports_Page::logged_by_cli( (array) $row ) ? 'WP-CLI' : __( 'System', 'qartvelo-guard' ) ) ) . '</td><td>' . $this->t( (string) $row['ip'] ) . '</td></tr>';
		}
		return $html . '</tbody></table></section>';
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Escaped text with email addresses masked.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	private function t( $text ) {
		return esc_html( self::mask_emails( (string) $text ) );
	}

	/**
	 * Key/value table.
	 *
	 * @param array $rows label => plain text.
	 * @return string
	 */
	private function kv( array $rows ) {
		$html = '<dl class="kv">';
		foreach ( $rows as $label => $value ) {
			if ( '' === (string) $value ) {
				continue;
			}
			$html .= '<div><dt>' . $this->t( (string) $label ) . '</dt><dd>' . $this->t( (string) $value ) . '</dd></div>';
		}
		return $html . '</dl>';
	}

	/**
	 * Site-local date and time with the time zone.
	 *
	 * @param int $ts Unix time.
	 * @return string
	 */
	private function when( $ts ) {
		$ts = (int) $ts;
		return $ts > 0 ? wp_date( 'Y-m-d H:i T', $ts ) : '';
	}

	/**
	 * Every secret value this report must never contain.
	 */
	private function collect_secrets() {
		$values = array();
		$consts = get_defined_constants( true );
		foreach ( isset( $consts['user'] ) ? $consts['user'] : array() as $name => $value ) {
			if ( ! is_string( $value ) || strlen( $value ) < 8 || in_array( $name, array( 'DB_NAME', 'DB_USER', 'DB_HOST' ), true ) ) {
				continue;
			}
			if ( ! preg_match( '/(PASSWORD|PASS|SECRET|TOKEN|_KEY|_SALT|AUTH|NONCE)/i', (string) $name ) ) {
				continue;
			}
			// Plain lowercase words (option names, cookie prefixes) are not secrets; hiding them would garble the text.
			if ( 'DB_PASSWORD' !== $name && preg_match( '#^[a-z_\-./]+$#', $value ) ) {
				continue;
			}
			$values[] = $value;
		}
		foreach ( array( 'wpcybersec_snapshot_key' ) as $option ) {
			$value = Network::get_option( $option, '' );
			if ( is_string( $value ) && strlen( $value ) >= 8 ) {
				$values[] = $value;
			}
		}
		$webhook = (string) wpcybersec()->settings->get( 'webhook_url', '' );
		if ( strlen( $webhook ) >= 8 ) {
			$values[] = $webhook;
		}
		$values = array_values( array_unique( $values ) );
		usort(
			$values,
			static function ( $a, $b ) {
				return strlen( $b ) - strlen( $a );
			}
		);
		$this->secrets  = $values;
		$this->data_dir = (string) wpcybersec()->storage->data_dir();
	}

	/**
	 * Final pass: hides any known secret value and the data folder path
	 * that slipped into the text (also in their HTML-escaped form).
	 *
	 * @param string $html Report.
	 * @return string
	 */
	private function scrub( $html ) {
		$search  = array();
		$replace = array();
		foreach ( $this->secrets as $value ) {
			$search[]  = $value;
			$replace[] = self::MASK;
			$escaped   = esc_html( $value );
			if ( $escaped !== $value ) {
				$search[]  = $escaped;
				$replace[] = self::MASK;
			}
		}
		if ( strlen( $this->data_dir ) > 3 ) {
			$search[]  = $this->data_dir;
			$replace[] = '[' . __( 'plugin data folder', 'qartvelo-guard' ) . ']';
			$escaped   = esc_html( $this->data_dir );
			if ( $escaped !== $this->data_dir ) {
				$search[]  = $escaped;
				$replace[] = '[' . __( 'plugin data folder', 'qartvelo-guard' ) . ']';
			}
		}
		return $search ? str_replace( $search, $replace, $html ) : $html;
	}

	/**
	 * Prints the style block of the report: assets/css/report.css, through the
	 * WordPress style API (an inline style on a handle without a file), so the
	 * report stays one self-contained file. The handle is removed again: it
	 * must not reach the admin page that offers the download.
	 * Works in a web request and under WP-CLI. Prints nothing when the
	 * stylesheet cannot be read.
	 */
	public function print_style() {
		$file = WPCYBERSEC_DIR . 'assets/css/report.css';
		$css  = is_readable( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a stylesheet of the plugin itself, read from disk.
		if ( '' === trim( $css ) ) {
			return;
		}
		$handle = 'wpcybersec-report';
		wp_register_style( $handle, false, array(), WPCYBERSEC_VERSION );
		wp_add_inline_style( $handle, $css );
		wp_print_styles( $handle );
		wp_deregister_style( $handle );
		// Printed handles are remembered: forget this one, so a second report of the same request gets its styles too.
		$styles       = wp_styles();
		$styles->done = array_values( array_diff( $styles->done, array( $handle ) ) );
	}

	/**
	 * print_style() captured as a string, for build().
	 *
	 * @return string Markup for the document head ('' when the stylesheet cannot be read).
	 */
	private function style_tag() {
		ob_start();
		$this->print_style();
		return (string) ob_get_clean();
	}
}
