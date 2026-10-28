<?php
/**
 * Reports page: pending approvals, threats, quarantine, history, allowlist, activity.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Db_Scanner;
use WPCyberSecurity\Decisions;
use WPCyberSecurity\Diff;
use WPCyberSecurity\Recent_Changes;
use WPCyberSecurity\Store;
use WPCyberSecurity\User_Watch;

defined( 'ABSPATH' ) || exit;

/**
 * The page where administrators allow or reject what the plugin held.
 * Decisions run through AJAX (core.js data-wpcs-action / WPCyberSec.bulk);
 * every button is also a submit button of the bulk form, so the page keeps
 * working without JavaScript (admin-post wpcybersec_reports_bulk).
 */
class Reports_Page {

	const FORM_ID = 'wpcs-bulk-form';

	/** User meta: preferred diff layout (unified | split). */
	const META_LAYOUT = 'wpcybersec_diff_layout';

	/** Matches listed before the rest is folded away on the changes view. */
	const HITS_VISIBLE = 5;

	/** @var string Current tab. */
	private $tab = 'pending';

	/** @var string Search term. */
	private $search = '';

	/** @var int Current page (1-based). */
	private $paged = 1;

	/** @var string Sort column. */
	private $orderby = 'created_at';

	/** @var string ASC | DESC. */
	private $order = 'DESC';

	/** @var array Extra filters (severity, type, kind, event). */
	private $filters = array();

	/**
	 * Tabs: key => { label, icon, count (Store::counts key or '') }.
	 *
	 * @return array
	 */
	private function tabs() {
		return array(
			'pending'    => array( __( 'Pending approvals', 'qartvelo-guard' ), 'clock', 'pending' ),
			'threats'    => array( __( 'Threats', 'qartvelo-guard' ), 'warning', 'threats' ),
			'quarantine' => array( __( 'Quarantine', 'qartvelo-guard' ), 'lock', 'quarantined' ),
			'history'    => array( __( 'History', 'qartvelo-guard' ), 'backup', '' ),
			'recent'     => array( __( 'Recent changes', 'qartvelo-guard' ), 'calendar-alt', '' ),
			'allowlist'  => array( __( 'Allowlist', 'qartvelo-guard' ), 'yes-alt', '' ),
			'activity'   => array( __( 'Activity', 'qartvelo-guard' ), 'list-view', '' ),
		);
	}

	/**
	 * Prints the page.
	 */
	public function render() {
		if ( ! Admin::can() ) {
			wp_die( esc_html__( 'You are not allowed to view this page.', 'qartvelo-guard' ) );
		}
		$this->read_request();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing.
		$view = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : '';
		if ( 'changes' === $view ) {
			$this->render_changes();
			return;
		}
		if ( 'file' === $view ) {
			$this->render_file_view();
			return;
		}

		echo '<div class="wrap wpcs-wrap wpcs-reports" data-wpcs-reports data-tab="' . esc_attr( $this->tab ) . '">';

		$actions  = '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_DASHBOARD ) ) . '"><span class="dashicons dashicons-dashboard" aria-hidden="true"></span> ' . esc_html__( 'Dashboard', 'qartvelo-guard' ) . '</a>';
		$actions .= '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_SETTINGS ) ) . '"><span class="dashicons dashicons-admin-generic" aria-hidden="true"></span> ' . esc_html__( 'Settings', 'qartvelo-guard' ) . '</a>';
		$actions .= Admin::report_button();
		Admin::header(
			__( 'Reports', 'qartvelo-guard' ),
			__( 'Review what was held or found and decide. Anything you allow is remembered permanently.', 'qartvelo-guard' ),
			$actions
		);

		$this->render_result_notice();
		$this->render_tabs();

		switch ( $this->tab ) {
			case 'allowlist':
				$this->render_allowlist_tab();
				break;
			case 'activity':
				$this->render_activity_tab();
				break;
			case 'recent':
				$this->render_recent_tab();
				break;
			default:
				$this->render_items_tab();
		}

		echo '</div>';
	}

	/**
	 * Reads and validates query args.
	 */
	private function read_request() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only filters.
		$tab       = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'pending';
		$this->tab = array_key_exists( $tab, $this->tabs() ) ? $tab : 'pending';

		$this->search = isset( $_GET['s'] ) ? trim( sanitize_text_field( wp_unslash( $_GET['s'] ) ) ) : '';
		$this->search = function_exists( 'mb_substr' ) ? mb_substr( $this->search, 0, 200 ) : substr( $this->search, 0, 200 );
		$this->paged  = isset( $_GET['paged'] ) ? max( 1, absint( wp_unslash( $_GET['paged'] ) ) ) : 1;

		$defaults      = array(
			'threats' => 'severity',
			'history' => 'updated_at',
		);
		$this->orderby = isset( $defaults[ $this->tab ] ) ? $defaults[ $this->tab ] : 'created_at';
		$orderby       = isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( $_GET['orderby'] ) ) : '';
		if ( in_array( $orderby, array( 'created_at', 'severity', 'updated_at' ), true ) ) {
			$this->orderby = $orderby;
		}
		$order       = isset( $_GET['order'] ) ? strtoupper( sanitize_key( wp_unslash( $_GET['order'] ) ) ) : 'DESC';
		$this->order = 'ASC' === $order ? 'ASC' : 'DESC';

		$severity = isset( $_GET['severity'] ) ? absint( wp_unslash( $_GET['severity'] ) ) : 0;
		$type     = isset( $_GET['type'] ) ? sanitize_key( wp_unslash( $_GET['type'] ) ) : '';
		$kind     = isset( $_GET['kind'] ) ? sanitize_key( wp_unslash( $_GET['kind'] ) ) : '';
		$event    = isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '';
		$days     = isset( $_GET['days'] ) ? absint( wp_unslash( $_GET['days'] ) ) : 7;
		$show     = isset( $_GET['show'] ) ? sanitize_key( wp_unslash( $_GET['show'] ) ) : '';
		// phpcs:enable

		$this->filters = array(
			'severity' => in_array( $severity, array( 2, 3 ), true ) ? $severity : 0,
			'type'     => in_array( $type, array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL, Store::TYPE_FILE, Store::TYPE_THREAT, Store::TYPE_USER ), true ) ? $type : '',
			'kind'     => in_array( $kind, array( 'hash', 'install', 'db' ), true ) ? $kind : '',
			'event'    => substr( $event, 0, 50 ),
			'days'     => in_array( $days, Recent_Changes::WINDOWS, true ) ? $days : 7,
			'show'     => 'no_updates' === $show ? 'no_updates' : '',
		);
	}

	/**
	 * URL of the current view with optional overrides.
	 *
	 * @param array $override Args to change (null removes).
	 * @return string
	 */
	private function view_url( array $override = array() ) {
		$args = array(
			'tab'      => $this->tab,
			's'        => $this->search,
			'severity' => $this->filters['severity'] ? $this->filters['severity'] : '',
			'type'     => $this->filters['type'],
			'kind'     => $this->filters['kind'],
			'event'    => $this->filters['event'],
		);
		if ( 'recent' === $this->tab ) {
			$args['days'] = 7 === $this->filters['days'] ? '' : $this->filters['days'];
			$args['show'] = $this->filters['show'];
		}
		if ( isset( $_GET['orderby'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$args['orderby'] = $this->orderby;
			$args['order']   = strtolower( $this->order );
		}
		foreach ( $override as $key => $value ) {
			$args[ $key ] = $value;
		}
		return Admin::page_url( Admin::PAGE_REPORTS, $args );
	}

	/* ------------------------------------------------------------------ */
	/* Notices and tabs                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Result of a non-JS action (admin-post redirect).
	 */
	private function render_result_notice() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- display only.
		$msg    = isset( $_GET['wpcs_msg'] ) ? sanitize_key( wp_unslash( $_GET['wpcs_msg'] ) ) : '';
		$done   = isset( $_GET['wpcs_done'] ) ? absint( wp_unslash( $_GET['wpcs_done'] ) ) : 0;
		$failed = isset( $_GET['wpcs_failed'] ) ? absint( wp_unslash( $_GET['wpcs_failed'] ) ) : 0;
		// phpcs:enable
		if ( '' === $msg ) {
			return;
		}

		switch ( $msg ) {
			case 'allowlist_removed':
				$this->notice( 'ok', 'yes-alt', __( 'Removed from the allowlist. The next time this file or install appears, it is held for your approval again.', 'qartvelo-guard' ) );
				break;
			case 'allowlist_missing':
				$this->notice( 'warn', 'info-outline', __( 'That allowlist entry no longer exists.', 'qartvelo-guard' ) );
				break;
			case 'no_action':
				$this->notice( 'warn', 'info-outline', __( 'Choose a bulk action first.', 'qartvelo-guard' ) );
				break;
			case 'no_items':
				$this->notice( 'warn', 'info-outline', __( 'Select at least one item first.', 'qartvelo-guard' ) );
				break;
			case 'too_many':
				/* translators: %s: number of items */
				$this->notice( 'warn', 'info-outline', sprintf( __( 'Select at most %s items at a time.', 'qartvelo-guard' ), number_format_i18n( Admin::MAX_BULK ) ) );
				break;
			case 'failed':
				$this->notice( 'bad', 'warning', __( 'The action could not be completed. Reload the page and try again.', 'qartvelo-guard' ) );
				break;
			case 'bulk':
				if ( $done > 0 ) {
					$this->notice(
						'ok',
						'yes-alt',
						sprintf(
							/* translators: %s: number of items */
							_n( '%s item updated.', '%s items updated.', $done, 'qartvelo-guard' ),
							number_format_i18n( $done )
						)
					);
				}
				if ( $failed > 0 ) {
					$key    = 'wpcybersec_bulk_errors_' . get_current_user_id();
					$errors = get_transient( $key );
					delete_transient( $key );
					$errors = is_array( $errors ) ? $errors : array();
					$text   = sprintf(
						/* translators: %s: number of items */
						_n( '%s item could not be changed.', '%s items could not be changed.', $failed, 'qartvelo-guard' ),
						number_format_i18n( $failed )
					);
					$this->notice( 'bad', 'warning', $text, $errors );
				}
				break;
		}
	}

	/**
	 * Inline notice.
	 *
	 * @param string   $tone  ok | warn | bad | info.
	 * @param string   $icon  Dashicon name.
	 * @param string   $text  Plain text.
	 * @param string[] $lines Extra plain text lines.
	 */
	private function notice( $tone, $icon, $text, array $lines = array() ) {
		echo '<div class="wpcs-notice' . ( 'info' === $tone ? '' : ' wpcs-notice--' . esc_attr( $tone ) ) . '" role="status">';
		echo '<span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span><div><p>' . esc_html( $text ) . '</p>';
		foreach ( $lines as $line ) {
			echo '<p class="wpcs-mono">' . esc_html( (string) $line ) . '</p>';
		}
		echo '</div></div>';
	}

	/**
	 * Tab bar with live counts.
	 */
	private function render_tabs() {
		$counts = Admin::counts();
		echo '<nav class="nav-tab-wrapper wpcs-tabs" aria-label="' . esc_attr__( 'Report sections', 'qartvelo-guard' ) . '">';
		foreach ( $this->tabs() as $key => $tab ) {
			$active = $key === $this->tab;
			echo '<a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => $key ) ) ) . '" class="nav-tab' . ( $active ? ' nav-tab-active' : '' ) . '"' . ( $active ? ' aria-current="page"' : '' ) . '>';
			echo '<span class="dashicons dashicons-' . esc_attr( $tab[1] ) . '" aria-hidden="true"></span>' . esc_html( $tab[0] );
			if ( $tab[2] ) {
				$n = isset( $counts[ $tab[2] ] ) ? (int) $counts[ $tab[2] ] : 0;
				$c = 'wpcs-count' . ( $n ? '' : ' wpcs-count--zero' ) . ( 'threats' === $tab[2] ? ' wpcs-count--bad' : ' wpcs-count--neutral' );
				echo ' <span class="' . esc_attr( $c ) . '" data-wpcs-count="' . esc_attr( $tab[2] ) . '">' . esc_html( number_format_i18n( $n ) ) . '</span>';
			}
			echo '</a>';
		}
		echo '</nav>';
	}

	/* ------------------------------------------------------------------ */
	/* Item tabs (pending, threats, quarantine, history)                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Query args for the current item tab.
	 *
	 * @return array
	 */
	private function item_args() {
		$per_page = (int) apply_filters( 'wpcybersec_reports_per_page', 20 );
		$args     = array(
			'search'   => $this->search,
			'orderby'  => $this->orderby,
			'order'    => $this->order,
			'per_page' => max( 5, min( 200, $per_page ) ),
			'page'     => $this->paged,
		);
		switch ( $this->tab ) {
			case 'threats':
				$args['type']         = Store::TYPE_THREAT;
				$args['status']       = Store::STATUS_PENDING;
				$args['min_severity'] = $this->filters['severity'];
				break;
			case 'quarantine':
				$args['held']   = true;
				$args['status'] = array( Store::STATUS_PENDING, Store::STATUS_QUARANTINED );
				if ( $this->filters['type'] ) {
					$args['type'] = $this->filters['type'];
				}
				break;
			case 'history':
				$args['status'] = array( Store::STATUS_APPROVED, Store::STATUS_DENIED, Store::STATUS_IGNORED, Store::STATUS_QUARANTINED, Store::STATUS_RESTORED, Store::STATUS_DELETED, Store::STATUS_RESOLVED );
				if ( $this->filters['type'] ) {
					$args['type'] = $this->filters['type'];
				}
				break;
			default:
				$types          = array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL, Store::TYPE_FILE, Store::TYPE_USER );
				$args['type']   = in_array( $this->filters['type'], $types, true ) ? $this->filters['type'] : $types;
				$args['status'] = Store::STATUS_PENDING;
		}
		return $args;
	}

	/**
	 * Bulk actions offered per tab.
	 *
	 * @return array action => label
	 */
	private function bulk_actions() {
		$labels = $this->action_labels();
		$sets   = array(
			'pending'    => array( 'approve', 'deny', 'quarantine', 'delete' ),
			'threats'    => array( 'ignore', 'quarantine', 'restore', 'delete' ),
			'quarantine' => array( 'approve', 'restore', 'deny', 'delete' ),
			'history'    => array( 'approve', 'quarantine', 'restore', 'delete' ),
		);
		$out = array();
		foreach ( isset( $sets[ $this->tab ] ) ? $sets[ $this->tab ] : array() as $action ) {
			$out[ $action ] = $labels[ $action ][0];
		}
		return $out;
	}

	/**
	 * Labels, icons and classes per decision.
	 *
	 * @return array action => array( label, icon, class )
	 */
	private function action_labels() {
		return array(
			'approve'    => array( __( 'Allow', 'qartvelo-guard' ), 'yes', 'wpcs-btn-approve' ),
			'ignore'     => array( __( 'Mark safe', 'qartvelo-guard' ), 'yes-alt', 'wpcs-btn-safe' ),
			'quarantine' => array( __( 'Quarantine', 'qartvelo-guard' ), 'lock', '' ),
			'restore'    => array( __( 'Restore', 'qartvelo-guard' ), 'undo', '' ),
			'deny'       => array( __( 'Deny', 'qartvelo-guard' ), 'no-alt', '' ),
			'delete'     => array( __( 'Delete', 'qartvelo-guard' ), 'trash', 'wpcs-btn-danger' ),
			// Critical core files only (Decisions::official_source()).
			'restore_official' => array( __( 'Restore official file', 'qartvelo-guard' ), 'backup', '' ),
		);
	}

	/**
	 * Pending, threats, quarantine and history tabs.
	 */
	private function render_items_tab() {
		if ( in_array( $this->tab, array( 'pending', 'threats' ), true ) && '' === $this->search && ! $this->filters['type'] && ! $this->filters['severity'] ) {
			Core_Repair_Card::render( 'reports' );
		}
		$this->render_tab_intro();

		$args   = $this->item_args();
		$result = Admin::call( 'store', 'items_query', array( $args ), null );
		if ( ! is_array( $result ) ) {
			$this->notice( 'bad', 'warning', __( 'The report could not be loaded. The plugin database tables may be missing; deactivate and activate the plugin to recreate them.', 'qartvelo-guard' ) );
			return;
		}
		$rows  = isset( $result['rows'] ) ? (array) $result['rows'] : array();
		$total = isset( $result['total'] ) ? (int) $result['total'] : 0;

		$filtered = '' !== $this->search || $this->filters['type'] || $this->filters['severity'];
		if ( $rows || $filtered ) {
			$this->render_toolbar( $total );
		}

		if ( ! $rows ) {
			$this->render_items_empty();
			return;
		}

		echo '<div class="wpcs-card wpcs-card--flush wpcs-table-card">';
		echo '<table class="widefat wpcs-table wpcs-items">';
		echo '<thead><tr>';
		echo '<td class="wpcs-cb-cell"><input type="checkbox" class="wpcs-cb-all" aria-label="' . esc_attr__( 'Select all', 'qartvelo-guard' ) . '"></td>';
		echo '<th scope="col" class="column-type">' . esc_html__( 'Type', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-item">' . esc_html__( 'Item', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-source">' . esc_html__( 'Source', 'qartvelo-guard' ) . '</th>';
		$this->sort_th( 'created_at', __( 'Detected', 'qartvelo-guard' ), 'column-detected' );
		$this->sort_th( 'severity', __( 'Verdict', 'qartvelo-guard' ), 'column-verdict' );
		echo '<th scope="col" class="column-status">' . esc_html__( 'Status', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-actions">' . esc_html__( 'Actions', 'qartvelo-guard' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $item ) {
			if ( is_array( $item ) && isset( $item['id'] ) ) {
				$this->render_item_row( $item );
			}
		}
		echo '</tbody></table></div>';

		$this->render_pagination( $total, $args['per_page'] );
	}

	/**
	 * Explanation at the top of each item tab.
	 */
	private function render_tab_intro() {
		switch ( $this->tab ) {
			case 'pending':
				echo '<div class="wpcs-notice wpcs-promise"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span><div><p><strong>'
					. esc_html__( 'Allowed once, allowed always.', 'qartvelo-guard' ) . '</strong> '
					. esc_html__( 'When you allow a file, its SHA-256 fingerprint is remembered on the allowlist, so the exact same file is never held again, wherever it is uploaded. If the file changes, its fingerprint changes and it is checked again.', 'qartvelo-guard' )
					. '</p></div></div>';
				break;
			case 'threats':
				echo '<div class="wpcs-notice wpcs-notice--warn"><span class="dashicons dashicons-warning" aria-hidden="true"></span><div><p>'
					. esc_html__( 'Quarantine moves a file to a locked folder where it cannot run, and you can restore it later. Use "Mark safe" only for files you recognize: the exact file is then trusted and not flagged again.', 'qartvelo-guard' ) . ' '
					. esc_html__( 'Database findings (options, widgets, posts) are cleaned where they are stored, for example by editing the post; the report closes by itself after the next scan that no longer finds them.', 'qartvelo-guard' )
					. '</p></div></div>';
				break;
			case 'quarantine':
				echo '<div class="wpcs-notice"><span class="dashicons dashicons-lock" aria-hidden="true"></span><div><p>'
					. esc_html__( 'Held copies are stored in a protected folder with a random name and a .bin extension, so they cannot run even if someone finds them. Download a copy to inspect it on your computer.', 'qartvelo-guard' )
					. '</p></div></div>';
				break;
			case 'history':
				echo '<div class="wpcs-notice"><span class="dashicons dashicons-backup" aria-hidden="true"></span><div><p>'
					. esc_html__( 'Every decision is kept here for your records: who decided, when, and what happened to the file.', 'qartvelo-guard' )
					. '</p></div></div>';
				break;
		}
	}

	/**
	 * Bulk form (left) and filters/search (right).
	 *
	 * @param int $total Matching rows.
	 */
	private function render_toolbar( $total ) {
		$bulk = $this->bulk_actions();
		echo '<div class="wpcs-toolbar">';

		echo '<form id="' . esc_attr( self::FORM_ID ) . '" class="wpcs-bulk" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="wpcybersec_reports_bulk">';
		echo '<input type="hidden" name="tab" value="' . esc_attr( $this->tab ) . '">';
		wp_nonce_field( 'wpcybersec_reports_bulk' );
		if ( $bulk && $total > 0 ) {
			echo '<label for="wpcs-bulk-action" class="screen-reader-text">' . esc_html__( 'Bulk action', 'qartvelo-guard' ) . '</label>';
			echo '<select id="wpcs-bulk-action" name="bulk_action"><option value="">' . esc_html__( 'Bulk actions', 'qartvelo-guard' ) . '</option>';
			foreach ( $bulk as $value => $label ) {
				echo '<option value="' . esc_attr( $value ) . '">' . esc_html( $label ) . '</option>';
			}
			echo '</select> <button type="submit" class="button" name="wpcs_bulk_apply" value="1">' . esc_html__( 'Apply', 'qartvelo-guard' ) . '</button>';
		}
		if ( 'pending' === $this->tab && $total > 0 && in_array( $this->filters['type'], array( '', Store::TYPE_UPLOAD ), true ) ) {
			// Busy sites: approve every held photo without findings in one go (admin.js, AJAX clean_images + allow_clean).
			echo ' <button type="button" class="button wpcs-allow-clean" data-wpcs-allow-clean title="' . esc_attr__( 'Allow every waiting upload that is a verified JPEG, PNG, GIF or WebP image with no findings, and add it to the Media Library', 'qartvelo-guard' ) . '"><span class="dashicons dashicons-format-gallery" aria-hidden="true"></span> ' . esc_html__( 'Allow all clean images', 'qartvelo-guard' ) . '</button>';
		}
		echo '</form>';

		echo '<form class="wpcs-filters" method="get" action="' . esc_url( Admin::admin_page_base() ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( Admin::PAGE_REPORTS ) . '">';
		echo '<input type="hidden" name="tab" value="' . esc_attr( $this->tab ) . '">';

		if ( 'threats' === $this->tab ) {
			$this->select(
				'severity',
				(string) $this->filters['severity'],
				array(
					'0' => __( 'All severities', 'qartvelo-guard' ),
					'2' => __( 'High and critical', 'qartvelo-guard' ),
					'3' => __( 'Critical only', 'qartvelo-guard' ),
				),
				__( 'Filter by severity', 'qartvelo-guard' )
			);
		} else {
			$types = array(
				''                   => __( 'All types', 'qartvelo-guard' ),
				Store::TYPE_UPLOAD  => __( 'Uploads', 'qartvelo-guard' ),
				Store::TYPE_INSTALL => __( 'Installs', 'qartvelo-guard' ),
				Store::TYPE_FILE    => __( 'Files', 'qartvelo-guard' ),
			);
			if ( 'quarantine' !== $this->tab ) {
				$types[ Store::TYPE_USER ] = __( 'Administrators', 'qartvelo-guard' );
			}
			if ( 'pending' !== $this->tab ) {
				$types[ Store::TYPE_THREAT ] = __( 'Threats', 'qartvelo-guard' );
			}
			$this->select( 'type', $this->filters['type'], $types, __( 'Filter by type', 'qartvelo-guard' ) );
		}
		$this->search_box( __( 'Search file name, path or hash', 'qartvelo-guard' ) );
		echo '</form>';

		echo '</div>';

		if ( '' !== $this->search ) {
			echo '<p class="wpcs-search-note">' . esc_html(
				sprintf(
					/* translators: 1: number of results, 2: search term */
					_n( '%1$s result for "%2$s".', '%1$s results for "%2$s".', $total, 'qartvelo-guard' ),
					number_format_i18n( $total ),
					$this->search
				)
			) . ' <a href="' . esc_url( $this->view_url( array( 's' => '' ) ) ) . '">' . esc_html__( 'Clear search', 'qartvelo-guard' ) . '</a></p>';
		}
	}

	/**
	 * Select that submits its form on change (admin.js) with a no-JS fallback button.
	 *
	 * @param string $name    Field name.
	 * @param string $current Current value.
	 * @param array  $options value => label.
	 * @param string $label   Accessible label.
	 */
	private function select( $name, $current, array $options, $label ) {
		$id = 'wpcs-filter-' . $name;
		echo '<label for="' . esc_attr( $id ) . '" class="screen-reader-text">' . esc_html( $label ) . '</label>';
		echo '<select id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" data-wpcs-autosubmit>';
		foreach ( $options as $value => $text ) {
			echo '<option value="' . esc_attr( (string) $value ) . '"' . selected( (string) $current, (string) $value, false ) . '>' . esc_html( $text ) . '</option>';
		}
		echo '</select>';
	}

	/**
	 * Search input + submit.
	 *
	 * @param string $placeholder Placeholder.
	 */
	private function search_box( $placeholder ) {
		echo '<label for="wpcs-search" class="screen-reader-text">' . esc_html( $placeholder ) . '</label>';
		echo '<input type="search" id="wpcs-search" name="s" value="' . esc_attr( $this->search ) . '" placeholder="' . esc_attr( $placeholder ) . '">';
		echo '<button type="submit" class="button">' . esc_html__( 'Search', 'qartvelo-guard' ) . '</button>';
	}

	/**
	 * Sortable column header.
	 *
	 * @param string $key   orderby value.
	 * @param string $label Label.
	 * @param string $class Column class.
	 */
	private function sort_th( $key, $label, $class ) {
		$current = $this->orderby === $key;
		$next    = $current && 'DESC' === $this->order ? 'asc' : 'desc';
		$url     = $this->view_url(
			array(
				'orderby' => $key,
				'order'   => $next,
			)
		);
		$aria    = $current ? ( 'ASC' === $this->order ? 'ascending' : 'descending' ) : 'none';
		$icon    = $current && 'ASC' === $this->order ? 'arrow-up-alt2' : 'arrow-down-alt2';
		echo '<th scope="col" class="' . esc_attr( $class . ' wpcs-sortable' . ( $current ? ' is-sorted' : '' ) ) . '" aria-sort="' . esc_attr( $aria ) . '">';
		echo '<a href="' . esc_url( $url ) . '"><span>' . esc_html( $label ) . '</span><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span></a></th>';
	}

	/**
	 * One item row plus its hidden details row.
	 *
	 * @param array $item Item.
	 */
	private function render_item_row( array $item ) {
		$id        = (int) $item['id'];
		$type      = (string) $item['type'];
		$status    = (string) $item['status'];
		$held      = $this->has_held_copy( $item );
		$available = class_exists( '\WPCyberSecurity\Decisions' ) ? Decisions::available( $item ) : array();
		$details   = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$severity  = (int) $item['severity'];

		$classes = array( 'wpcs-item', 'wpcs-item--' . sanitize_html_class( $type ), 'wpcs-sev-' . $severity );
		if ( ! $available ) {
			$classes[] = 'is-done';
		}
		echo '<tr class="' . esc_attr( implode( ' ', $classes ) ) . '" data-item-id="' . esc_attr( (string) $id ) . '" data-type="' . esc_attr( $type ) . '" data-held="' . ( $held ? '1' : '0' ) . '" data-risk="' . esc_attr( (string) ( Admin::needs_risk_confirm( $item ) ? Admin::risk_level( $item ) : 0 ) ) . '">';

		// Checkbox.
		echo '<th scope="row" class="wpcs-cb-cell"><input type="checkbox" class="wpcs-cb-item" name="ids[]" value="' . esc_attr( (string) $id ) . '" form="' . esc_attr( self::FORM_ID ) . '"'
			. ( $available ? '' : ' disabled' )
			/* translators: %s: file name */
			. ' aria-label="' . esc_attr( sprintf( __( 'Select %s', 'qartvelo-guard' ), $this->item_title( $item ) ) ) . '"></th>';

		// Type.
		echo '<td class="column-type">' . $this->type_badge( $type, $item ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Item.
		echo '<td class="column-item">' . $this->item_cell( $item, $details ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Source.
		// data-label: the narrow layout hides the table header and prints these instead.
		echo '<td class="column-source" data-label="' . esc_attr__( 'Source', 'qartvelo-guard' ) . '">' . $this->source_cell( $item, $details ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Detected.
		$ts = Admin::utc_ts( $item['created_at'] );
		echo '<td class="column-detected" data-label="' . esc_attr__( 'Detected', 'qartvelo-guard' ) . '"><span title="' . esc_attr( Admin::datetime( $ts ) ) . '">' . esc_html( Admin::ago( $ts ) ) . '</span><span class="wpcs-sub">' . esc_html( $ts ? wp_date( get_option( 'date_format' ), $ts ) : '' ) . '</span></td>';

		// Verdict.
		echo '<td class="column-verdict" data-label="' . esc_attr__( 'Verdict', 'qartvelo-guard' ) . '">' . $this->verdict_cell( $item, $details ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Status.
		echo '<td class="column-status" data-label="' . esc_attr__( 'Status', 'qartvelo-guard' ) . '" data-wpcs-status>' . $this->status_cell( $item, $held ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Actions.
		echo '<td class="column-actions">' . $this->actions_cell( $item, $available, $held ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		echo '</tr>';

		echo '<tr class="wpcs-details-row" id="wpcs-details-' . esc_attr( (string) $id ) . '" hidden><td colspan="8">';
		$this->render_details( $item, $details );
		echo '</td></tr>';
	}

	/**
	 * Whether a held copy really exists for an open item (approved uploads may
	 * keep a stale quarantine_path after the copy was imported and purged).
	 *
	 * @param array $item Item.
	 * @return bool
	 */
	private function has_held_copy( array $item ) {
		if ( '' === (string) $item['quarantine_path'] ) {
			return false;
		}
		if ( ! in_array( $item['status'], array( Store::STATUS_PENDING, Store::STATUS_QUARANTINED ), true ) ) {
			return false;
		}
		return (bool) Admin::call( 'quarantine', 'exists', array( $item ), false );
	}

	/**
	 * Readable name of an item.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	private function item_title( array $item ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		if ( Store::TYPE_INSTALL === $item['type'] && ! empty( $details['name'] ) ) {
			return (string) $details['name'];
		}
		if ( Store::TYPE_USER === $item['type'] ) {
			return User_Watch::item_login( $item );
		}
		if ( Db_Scanner::is_db_item( $item ) ) {
			return Db_Scanner::location_label( $item );
		}
		return basename( (string) $item['path'] );
	}

	/**
	 * @param string     $type Item type.
	 * @param array|null $item Item (database findings get their own badge).
	 * @return string HTML.
	 */
	private function type_badge( $type, $item = null ) {
		$map = array(
			Store::TYPE_UPLOAD  => array( __( 'Upload', 'qartvelo-guard' ), 'upload' ),
			Store::TYPE_INSTALL => array( __( 'Install', 'qartvelo-guard' ), 'admin-plugins' ),
			Store::TYPE_FILE    => array( __( 'File', 'qartvelo-guard' ), 'media-code' ),
			Store::TYPE_THREAT  => array( __( 'Threat', 'qartvelo-guard' ), 'warning' ),
			Store::TYPE_USER    => array( __( 'New administrator', 'qartvelo-guard' ), 'admin-users' ),
		);
		$entry = isset( $map[ $type ] ) ? $map[ $type ] : array( ucfirst( $type ), 'marker' );
		$class = $type;
		if ( is_array( $item ) && Db_Scanner::is_db_item( $item ) ) {
			$entry = array( __( 'Database', 'qartvelo-guard' ), 'database' );
			$class = 'database';
		}
		return '<span class="wpcs-badge wpcs-type wpcs-type--' . esc_attr( sanitize_html_class( $class ) ) . '"><span class="dashicons dashicons-' . esc_attr( $entry[1] ) . '" aria-hidden="true"></span>' . esc_html( $entry[0] ) . '</span>';
	}

	/**
	 * Place of a database finding, with an edit link for posts.
	 *
	 * @param array $item Item.
	 * @return string HTML.
	 */
	private function db_location_html( array $item ) {
		$label   = Db_Scanner::location_label( $item );
		$post_id = Db_Scanner::post_id( $item );
		$link    = '';
		if ( $post_id ) {
			// Multisite: the edit screen of the site the post belongs to.
			$link = (string) \WPCyberSecurity\Network::on_site(
				Db_Scanner::blog_id( $item ),
				static function () use ( $post_id ) {
					return get_edit_post_link( $post_id, 'raw' );
				}
			);
		}
		if ( $link ) {
			return '<a class="wpcs-item-name" href="' . esc_url( $link ) . '">' . esc_html( $label ) . '</a>';
		}
		return '<strong class="wpcs-item-name">' . esc_html( $label ) . '</strong>';
	}

	/**
	 * How an account became an administrator.
	 *
	 * @param array $details Item details.
	 * @return string
	 */
	private function admin_how( array $details ) {
		$how = isset( $details['how'] ) ? (string) $details['how'] : '';
		switch ( $how ) {
			case 'registered':
				return __( 'New account created as administrator', 'qartvelo-guard' );
			case 'super_admin':
				return __( 'Made a network super admin', 'qartvelo-guard' );
			case 'scan':
				return __( 'Found by the administrator check of a scan', 'qartvelo-guard' );
			default:
				return __( 'Existing account given the administrator role', 'qartvelo-guard' );
		}
	}

	/**
	 * Who gave an account administrator rights.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return string
	 */
	private function admin_granted_by( array $item, array $details ) {
		if ( 'scan' === (string) $item['source'] ) {
			return __( 'Unknown (possibly added straight to the database)', 'qartvelo-guard' );
		}
		$name = Admin::user_name( $item['user_id'] );
		if ( '' !== $name ) {
			return ! empty( $details['granted_by_login'] ) ? $name . ' (' . (string) $details['granted_by_login'] . ')' : $name;
		}
		if ( ! empty( $details['granted_by_login'] ) ) {
			return (string) $details['granted_by_login'];
		}
		$contexts = array(
			'cli'  => __( 'No logged-in user (WP-CLI)', 'qartvelo-guard' ),
			'cron' => __( 'No logged-in user (scheduled task)', 'qartvelo-guard' ),
		);
		$context  = isset( $details['context'] ) ? (string) $details['context'] : '';
		return isset( $contexts[ $context ] ) ? $contexts[ $context ] : __( 'No logged-in user', 'qartvelo-guard' );
	}

	/**
	 * Path display that emphasises the file name.
	 *
	 * @param string $path Path or name.
	 * @return string HTML.
	 */
	private function path_html( $path ) {
		$path = (string) $path;
		$pos  = strrpos( $path, '/' );
		if ( false === $pos ) {
			return '<span class="wpcs-path"><span class="wpcs-path__file">' . esc_html( $path ) . '</span></span>';
		}
		return '<span class="wpcs-path"><span class="wpcs-path__dir">' . esc_html( substr( $path, 0, $pos + 1 ) ) . '</span><span class="wpcs-path__file">' . esc_html( substr( $path, $pos + 1 ) ) . '</span></span>';
	}

	/**
	 * Shortened hash with the full value in the title.
	 *
	 * @param string $hash SHA-256.
	 * @return string HTML.
	 */
	private function short_hash( $hash ) {
		$hash = (string) $hash;
		if ( '' === $hash ) {
			return '';
		}
		$short = strlen( $hash ) > 16 ? substr( $hash, 0, 12 ) . '...' . substr( $hash, -4 ) : $hash;
		return '<span class="wpcs-hash" title="' . esc_attr( 'SHA-256: ' . $hash ) . '">' . esc_html( $short ) . '</span>';
	}

	/**
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return string HTML.
	 */
	private function item_cell( array $item, array $details ) {
		$html = '';
		if ( Store::TYPE_USER === $item['type'] ) {
			$html  = '<strong class="wpcs-item-name">' . esc_html( User_Watch::item_login( $item ) ) . '</strong>';
			$html .= ' <span class="wpcs-muted">' . esc_html( '#' . User_Watch::item_user_id( $item ) ) . '</span>';
			if ( ! empty( $details['user_email'] ) ) {
				$html .= '<span class="wpcs-sub">' . esc_html( (string) $details['user_email'] ) . '</span>';
			}
			$html .= '<span class="wpcs-sub">' . esc_html( $this->admin_how( $details ) ) . '</span>';
			list( $who, $context ) = $this->source_parts( $item, $details );
			$html .= '<span class="wpcs-sub wpcs-narrow-when">' . esc_html( Admin::ago( Admin::utc_ts( $item['created_at'] ) ) ) . '</span>';
			$html .= '<span class="wpcs-sub wpcs-narrow-source">' . esc_html( $who . ', ' . $context ) . '</span>';
			return $html;
		}
		if ( Db_Scanner::is_db_item( $item ) ) {
			$html = $this->db_location_html( $item );
			$meta = array();
			if ( ! empty( $details['post_type'] ) ) {
				$meta[] = esc_html( (string) $details['post_type'] . ( ! empty( $details['post_status'] ) ? ', ' . (string) $details['post_status'] : '' ) );
			}
			if ( (int) $item['size'] > 0 ) {
				$meta[] = esc_html( size_format( (int) $item['size'], (int) $item['size'] >= KB_IN_BYTES ? 1 : 0 ) );
			}
			if ( $meta ) {
				$html .= '<span class="wpcs-sub wpcs-meta">' . self::meta_html( $meta ) . '</span>';
			}
			list( $who, $context ) = $this->source_parts( $item, $details );
			$html .= '<span class="wpcs-sub wpcs-narrow-when">' . esc_html( Admin::ago( Admin::utc_ts( $item['created_at'] ) ) ) . '</span>';
			$html .= '<span class="wpcs-sub wpcs-narrow-source">' . esc_html( $who . ', ' . $context ) . '</span>';
			return $html;
		}
		if ( Store::TYPE_INSTALL === $item['type'] ) {
			$name = ! empty( $details['name'] ) ? (string) $details['name'] : ( ! empty( $details['slug'] ) ? (string) $details['slug'] : (string) $item['path'] );
			$html = '<strong class="wpcs-item-name">' . esc_html( $name ) . '</strong>';
			if ( ! empty( $details['version'] ) ) {
				/* translators: %s: version number */
				$html .= ' <span class="wpcs-muted">' . esc_html( sprintf( __( 'version %s', 'qartvelo-guard' ), $details['version'] ) ) . '</span>';
			}
			$html .= '<span class="wpcs-sub wpcs-mono">' . esc_html( (string) $item['path'] ) . '</span>';
		} else {
			$html = $this->path_html( $item['path'] );
		}

		$meta = array();
		if ( (int) $item['size'] > 0 ) {
			$meta[] = esc_html( size_format( (int) $item['size'], (int) $item['size'] >= KB_IN_BYTES ? 1 : 0 ) );
		}
		if ( '' !== (string) $item['mime'] ) {
			$meta[] = esc_html( (string) $item['mime'] );
		}
		if ( '' !== (string) $item['sha256'] ) {
			$meta[] = $this->short_hash( $item['sha256'] );
		}
		if ( ! empty( $details['change'] ) && Store::TYPE_FILE === $item['type'] ) {
			$meta[] = 'modified' === $details['change']
				? '<span class="wpcs-chip wpcs-chip--warn">' . esc_html__( 'modified', 'qartvelo-guard' ) . '</span>'
				: '<span class="wpcs-chip">' . esc_html__( 'new', 'qartvelo-guard' ) . '</span>';
		}
		if ( $meta ) {
			$html .= '<span class="wpcs-sub wpcs-meta">' . self::meta_html( $meta ) . '</span>';
		}

		// Shown only on narrow screens, where the Source and Detected columns are hidden.
		list( $who, $context ) = $this->source_parts( $item, $details );
		$html .= '<span class="wpcs-sub wpcs-narrow-when">' . esc_html( Admin::ago( Admin::utc_ts( $item['created_at'] ) ) ) . '</span>';
		$html .= '<span class="wpcs-sub wpcs-narrow-source">' . esc_html( $who . ', ' . $context ) . '</span>';

		$thumb = $this->thumb_html( $item );
		if ( '' !== $thumb ) {
			$html = '<div class="wpcs-item-media">' . $thumb . '<div class="wpcs-item-media__body">' . $html . '</div></div>';
		}
		return $html;
	}

	/**
	 * Upload_Gate::image_preview() of an item ({ ok: false } when unavailable).
	 *
	 * @param array $item Item.
	 * @return array
	 */
	private function preview( array $item ) {
		if ( Store::TYPE_UPLOAD !== $item['type'] ) {
			return array(
				'ok'     => false,
				'reason' => 'not_image',
			);
		}
		$preview = Admin::call( 'upload_gate', 'image_preview', array( $item ), null );
		return is_array( $preview ) ? $preview : array(
			'ok'     => false,
			'reason' => 'not_image',
		);
	}

	/**
	 * Small fixed-size thumbnail of a held image upload (lazy loaded from
	 * Admin::handle_preview()), or a placeholder when the upload was flagged
	 * high or critical or its content is not the image its name says.
	 *
	 * @param array $item Item.
	 * @return string HTML ('' for anything that is not an image upload with a held copy).
	 */
	private function thumb_html( array $item ) {
		$preview = $this->preview( $item );
		if ( ! empty( $preview['ok'] ) ) {
			return '<img class="wpcs-thumb" src="' . esc_url( Admin::preview_url( (int) $item['id'] ) ) . '" width="48" height="48" loading="lazy" decoding="async" alt="">';
		}
		$reason = isset( $preview['reason'] ) ? (string) $preview['reason'] : '';
		if ( 'risky' === $reason ) {
			$label = __( 'No preview for risky files', 'qartvelo-guard' );
			$icon  = 'hidden';
		} elseif ( 'mismatch' === $reason ) {
			$label = __( 'No preview: the content is not a valid image of this type', 'qartvelo-guard' );
			$icon  = 'warning';
		} else {
			return '';
		}
		return '<span class="wpcs-thumb wpcs-thumb--none" role="img" aria-label="' . esc_attr( $label ) . '" title="' . esc_attr( $label ) . '"><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span></span>';
	}

	/**
	 * Larger preview in the expanded details of an image upload.
	 *
	 * @param array $item Item.
	 * @return string HTML ('' when there is nothing to show).
	 */
	private function preview_html( array $item ) {
		$preview = $this->preview( $item );
		$reason  = isset( $preview['reason'] ) ? (string) $preview['reason'] : '';
		if ( empty( $preview['ok'] ) ) {
			if ( 'risky' !== $reason && 'mismatch' !== $reason ) {
				return '';
			}
			$text = 'risky' === $reason
				? __( 'No preview for risky files. A file flagged high or critical, or held under a name the server could run, is never shown in the browser. Download it to inspect it in a safe place.', 'qartvelo-guard' )
				: __( 'No preview: the content is not a valid image of the type its name says. Download it to inspect it in a safe place.', 'qartvelo-guard' );
			return '<div class="wpcs-preview wpcs-preview--none"><span class="dashicons dashicons-' . esc_attr( 'risky' === $reason ? 'hidden' : 'warning' ) . '" aria-hidden="true"></span><p>' . esc_html( $text ) . '</p></div>';
		}
		$w     = max( 1, (int) $preview['width'] );
		$h     = max( 1, (int) $preview['height'] );
		$scale = min( 1, 360 / $w, 270 / $h );
		$dw    = max( 1, (int) round( $w * $scale ) );
		$dh    = max( 1, (int) round( $h * $scale ) );
		$url   = Admin::preview_url( (int) $item['id'] );
		$name  = wp_basename( (string) $item['path'] );
		return '<figure class="wpcs-preview">'
			/* translators: %s: file name */
			. '<a href="' . esc_url( $url ) . '" target="_blank" rel="noopener noreferrer" aria-label="' . esc_attr( sprintf( __( 'Open the full preview of %s in a new tab', 'qartvelo-guard' ), $name ) ) . '">'
			/* translators: %s: file name */
			. '<img src="' . esc_url( $url ) . '" width="' . esc_attr( (string) $dw ) . '" height="' . esc_attr( (string) $dh ) . '" loading="lazy" decoding="async" alt="' . esc_attr( sprintf( __( 'Preview of %s', 'qartvelo-guard' ), $name ) ) . '"></a>'
			. '<figcaption>' . esc_html(
				sprintf(
					/* translators: 1: width in pixels, 2: height in pixels, 3: image type such as image/jpeg */
					__( '%1$s x %2$s pixels, %3$s (content verified)', 'qartvelo-guard' ),
					number_format_i18n( $w ),
					number_format_i18n( $h ),
					(string) $preview['mime']
				)
			) . '</figcaption></figure>';
	}

	/**
	 * Who sent it and from where.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return string HTML.
	 */
	private function source_cell( array $item, array $details ) {
		list( $who, $context ) = $this->source_parts( $item, $details );

		$html  = '<span class="wpcs-source__who">' . esc_html( $who ) . '</span>';
		$html .= '<span class="wpcs-sub">' . esc_html( $context ) . '</span>';
		$site  = isset( $details['blog_id'] ) ? \WPCyberSecurity\Network::site_label( (int) $details['blog_id'] ) : '';
		if ( '' !== $site ) {
			/* translators: %s: site name and address */
			$html .= '<span class="wpcs-sub wpcs-source__site">' . esc_html( sprintf( __( 'Site: %s', 'qartvelo-guard' ), $site ) ) . '</span>';
		}
		if ( '' !== (string) $item['ip'] ) {
			$html .= '<span class="wpcs-sub wpcs-mono">' . esc_html( (string) $item['ip'] ) . '</span>';
		}
		return $html;
	}

	/**
	 * Who sent it and the context label.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return array { who, context }
	 */
	private function source_parts( array $item, array $details ) {
		$source = (string) $item['source'];
		if ( '' === $source && ! empty( $details['context'] ) ) {
			$source = (string) $details['context'];
		}
		$user = Admin::user_name( $item['user_id'] );

		if ( Store::TYPE_USER === $item['type'] ) {
			$who      = $this->admin_granted_by( $item, $details );
			$contexts = array(
				'admin'  => __( 'Admin screens', 'qartvelo-guard' ),
				'ajax'   => __( 'Admin AJAX request', 'qartvelo-guard' ),
				'rest'   => __( 'REST API', 'qartvelo-guard' ),
				'xmlrpc' => __( 'XML-RPC', 'qartvelo-guard' ),
				'cli'    => __( 'WP-CLI', 'qartvelo-guard' ),
				'cron'   => __( 'Scheduled task', 'qartvelo-guard' ),
				'front'  => __( 'Front end request', 'qartvelo-guard' ),
				'scan'   => __( 'Administrator check', 'qartvelo-guard' ),
			);
			$context  = isset( $details['context'], $contexts[ (string) $details['context'] ] ) ? $contexts[ (string) $details['context'] ] : __( 'Administrator watch', 'qartvelo-guard' );
			return array( $who, $context );
		}
		if ( Store::SOURCE_DATABASE === $source ) {
			/* translators: %s: user display name */
			$who = '' !== $user ? sprintf( __( 'Scan by %s', 'qartvelo-guard' ), $user ) : __( 'Scheduled scan', 'qartvelo-guard' );
			return array( $who, __( 'Database scan', 'qartvelo-guard' ) );
		}

		if ( 'review' === $source ) {
			/* translators: %s: user display name */
			$who = '' !== $user ? sprintf( __( 'Reported by %s', 'qartvelo-guard' ), $user ) : __( 'Reported by an administrator', 'qartvelo-guard' );
			return array( $who, __( 'Recent changes', 'qartvelo-guard' ) );
		}
		if ( 'scan' === $source || ( '' === $source && in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) ) {
			/* translators: %s: user display name */
			$who     = '' !== $user ? sprintf( __( 'Scan by %s', 'qartvelo-guard' ), $user ) : __( 'Scheduled scan', 'qartvelo-guard' );
			$context = __( 'File scan', 'qartvelo-guard' );
		} elseif ( 'install' === $source || Store::TYPE_INSTALL === $item['type'] ) {
			$who     = '' !== $user ? $user : __( 'Unknown user', 'qartvelo-guard' );
			$context = $this->install_context( $details );
		} else {
			$who      = '' !== $user ? $user : __( 'Visitor', 'qartvelo-guard' );
			$contexts = array(
				'media'      => __( 'Media Library', 'qartvelo-guard' ),
				'sideload'   => __( 'Downloaded by WordPress', 'qartvelo-guard' ),
				'rest'       => __( 'REST API', 'qartvelo-guard' ),
				'plugin_zip' => __( 'Plugin ZIP', 'qartvelo-guard' ),
				'theme_zip'  => __( 'Theme ZIP', 'qartvelo-guard' ),
				'guard'      => __( 'Early guard', 'qartvelo-guard' ),
			);
			$context  = isset( $contexts[ $source ] ) ? $contexts[ $source ] : ( '' !== $source ? ucfirst( str_replace( '_', ' ', $source ) ) : __( 'Upload', 'qartvelo-guard' ) );
			if ( 'guard' === $source ) {
				$script = ! empty( $details['script'] ) ? (string) $details['script'] : ( ! empty( $details['request_uri'] ) ? (string) $details['request_uri'] : '' );
				if ( '' !== $script ) {
					$context .= ': ' . $script;
				}
			}
		}

		return array( $who, $context );
	}

	/**
	 * Whether an activity row was written by a WP-CLI command (Logger adds the actor).
	 *
	 * @param array $row Log row.
	 * @return bool
	 */
	public static function logged_by_cli( array $row ) {
		if ( ! isset( $row['context'] ) ) {
			return false;
		}
		$context = is_array( $row['context'] ) ? $row['context'] : json_decode( (string) $row['context'], true );
		return is_array( $context ) && isset( $context['actor'] ) && 'wp-cli' === $context['actor'];
	}

	/**
	 * @param array $details Install details.
	 * @return string
	 */
	private function install_context( array $details ) {
		$is_theme = isset( $details['install_type'] ) && 'theme' === $details['install_type'];
		$src      = isset( $details['install_source'] ) ? (string) $details['install_source'] : '';
		if ( 'wporg' === $src ) {
			return $is_theme ? __( 'Theme from WordPress.org', 'qartvelo-guard' ) : __( 'Plugin from WordPress.org', 'qartvelo-guard' );
		}
		if ( 'upload' === $src ) {
			return $is_theme ? __( 'Theme ZIP upload', 'qartvelo-guard' ) : __( 'Plugin ZIP upload', 'qartvelo-guard' );
		}
		if ( 'url' === $src ) {
			return $is_theme ? __( 'Theme from a URL', 'qartvelo-guard' ) : __( 'Plugin from a URL', 'qartvelo-guard' );
		}
		if ( 'cli' === $src ) {
			return $is_theme ? __( 'Theme installed with WP-CLI', 'qartvelo-guard' ) : __( 'Plugin installed with WP-CLI', 'qartvelo-guard' );
		}
		return $is_theme ? __( 'Theme install', 'qartvelo-guard' ) : __( 'Plugin install', 'qartvelo-guard' );
	}

	/**
	 * Severity + top hit, or the reason it was held.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return string HTML.
	 */
	private function verdict_cell( array $item, array $details ) {
		if ( Store::TYPE_USER === $item['type'] ) {
			return Admin::severity_badge( (int) $item['severity'] ) . '<span class="wpcs-verdict__title">' . esc_html__( 'New administrator account', 'qartvelo-guard' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Not on your trusted administrator list', 'qartvelo-guard' ) . '</span>';
		}
		$hits = $this->hits( $details );
		if ( $hits ) {
			$top   = $hits[0];
			$sev   = max( (int) $item['severity'], isset( $top['severity'] ) ? (int) $top['severity'] : 0 );
			$title = ! empty( $top['title'] ) ? (string) $top['title'] : ( ! empty( $top['sig'] ) ? (string) $top['sig'] : __( 'Suspicious code', 'qartvelo-guard' ) );
			$html  = Admin::severity_badge( $sev ) . '<span class="wpcs-verdict__title">' . esc_html( $title ) . '</span>';
			if ( count( $hits ) > 1 ) {
				$html .= '<span class="wpcs-sub">' . esc_html(
					sprintf(
						/* translators: %s: number of further matches */
						_n( '+%s more match', '+%s more matches', count( $hits ) - 1, 'qartvelo-guard' ),
						number_format_i18n( count( $hits ) - 1 )
					)
				) . '</span>';
			}
			return $html;
		}

		$checksum = isset( $details['checksum'] ) ? (string) $details['checksum'] : '';
		if ( 'mismatch' === $checksum ) {
			return '<span class="wpcs-badge wpcs-badge--high">' . esc_html__( 'Checksum mismatch', 'qartvelo-guard' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Differs from the official WordPress.org file', 'qartvelo-guard' ) . '</span>';
		}
		if ( 'unknown_file' === $checksum ) {
			return '<span class="wpcs-badge wpcs-badge--medium">' . esc_html__( 'Unknown file', 'qartvelo-guard' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Not part of the official release', 'qartvelo-guard' ) . '</span>';
		}

		switch ( $item['type'] ) {
			case Store::TYPE_UPLOAD:
				return '<span class="wpcs-badge wpcs-badge--ok">' . esc_html__( 'Clean', 'qartvelo-guard' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Held by policy', 'qartvelo-guard' ) . '</span>';
			case Store::TYPE_INSTALL:
				return '<span class="wpcs-badge wpcs-badge--ok">' . esc_html__( 'Clean', 'qartvelo-guard' ) . '</span><span class="wpcs-sub">' . esc_html( ! empty( $details['update'] ) ? __( 'Update held by policy', 'qartvelo-guard' ) : __( 'New install held by policy', 'qartvelo-guard' ) ) . '</span>';
			case Store::TYPE_FILE:
				if ( isset( $details['change'] ) && 'modified' === $details['change'] ) {
					return '<span class="wpcs-badge wpcs-badge--medium">' . esc_html__( 'Modified', 'qartvelo-guard' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Changed since the baseline', 'qartvelo-guard' ) . '</span>';
				}
				return '<span class="wpcs-badge wpcs-badge--info">' . esc_html__( 'New file', 'qartvelo-guard' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Not in your trusted baseline', 'qartvelo-guard' ) . '</span>';
			default:
				return Admin::severity_badge( (int) $item['severity'] ) . '<span class="wpcs-sub">' . esc_html__( 'Flagged by the scanner', 'qartvelo-guard' ) . '</span>';
		}
	}

	/**
	 * Hits sorted by severity, highest first.
	 *
	 * @param array $details Details.
	 * @return array
	 */
	private function hits( array $details ) {
		$hits = isset( $details['hits'] ) && is_array( $details['hits'] ) ? array_values( array_filter( $details['hits'], 'is_array' ) ) : array();
		usort(
			$hits,
			static function ( $a, $b ) {
				$sa = isset( $a['severity'] ) ? (int) $a['severity'] : 0;
				$sb = isset( $b['severity'] ) ? (int) $b['severity'] : 0;
				return $sb - $sa;
			}
		);
		return $hits;
	}

	/**
	 * Status badge plus a short explanation.
	 *
	 * @param array $item Item.
	 * @param bool  $held Whether a held copy exists.
	 * @return string HTML.
	 */
	private function status_cell( array $item, $held ) {
		$html = Admin::status_badge( $item['status'] );
		if ( Store::STATUS_PENDING === $item['status'] ) {
			if ( $held ) {
				$html .= '<span class="wpcs-sub">' . esc_html__( 'Held in quarantine', 'qartvelo-guard' ) . '</span>';
			} elseif ( Store::TYPE_USER === $item['type'] ) {
				$html .= '<span class="wpcs-sub">' . esc_html__( 'Has administrator rights', 'qartvelo-guard' ) . '</span>';
			} elseif ( Db_Scanner::is_db_item( $item ) ) {
				$html .= '<span class="wpcs-sub">' . esc_html__( 'Still in the database', 'qartvelo-guard' ) . '</span>';
			} elseif ( in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) {
				$html .= '<span class="wpcs-sub">' . esc_html__( 'Still in place', 'qartvelo-guard' ) . '</span>';
			}
			return $html;
		}
		$decided = Admin::utc_ts( isset( $item['decided_at'] ) ? $item['decided_at'] : '' );
		$user    = Admin::user_name( isset( $item['decided_by'] ) ? $item['decided_by'] : 0 );
		$parts   = array();
		if ( '' !== $user ) {
			/* translators: %s: user display name */
			$parts[] = sprintf( __( 'by %s', 'qartvelo-guard' ), $user );
		}
		if ( $decided ) {
			$parts[] = Admin::ago( $decided );
		}
		if ( $parts ) {
			$html .= '<span class="wpcs-sub" title="' . esc_attr( Admin::datetime( $decided ) ) . '">' . esc_html( implode( ', ', $parts ) ) . '</span>';
		}
		return $html;
	}

	/**
	 * Decision buttons (all relevant ones rendered, unavailable ones hidden so
	 * core.js can reveal them after a status change), Download and Details.
	 *
	 * @param array    $item      Item.
	 * @param string[] $available Available actions now.
	 * @param bool     $held      Held copy exists.
	 * @param array    $opts      { details: bool (Details toggle), changes: bool (View changes link) }.
	 * @return string HTML.
	 */
	private function actions_cell( array $item, array $available, $held, array $opts = array() ) {
		$opts = array_merge(
			array(
				'details' => true,
				'changes' => true,
			),
			$opts
		);
		$id     = (int) $item['id'];
		$type   = (string) $item['type'];
		$labels = $this->action_labels();
		$name   = $this->item_title( $item );

		$not_file = Store::TYPE_USER === $type || Db_Scanner::is_db_item( $item );
		if ( Store::TYPE_USER === $type ) {
			$set                = array( 'approve', 'deny' );
			// Neither choice is the obvious one for an unknown administrator: both stay neutral and ask first.
			$labels['approve']  = array( __( 'Trust this admin', 'qartvelo-guard' ), 'yes', '' );
			$labels['deny']     = array( __( 'Remove admin role', 'qartvelo-guard' ), 'admin-users', 'wpcs-btn-danger' );
		} elseif ( Db_Scanner::is_db_item( $item ) ) {
			$set = array( 'ignore' );
		} elseif ( in_array( $type, array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL ), true ) ) {
			$set = array( 'approve', 'deny', 'restore', 'delete' );
		} elseif ( Store::TYPE_THREAT === $type ) {
			$set = array( 'approve', 'ignore', 'restore_official', 'quarantine', 'restore', 'delete' );
		} else {
			$set = array( 'approve', 'restore_official', 'quarantine', 'restore', 'delete' );
		}
		$critical = class_exists( '\WPCyberSecurity\Decisions' ) && Decisions::is_critical( $item );
		if ( $critical ) {
			// Never offered for these files, so the buttons are not rendered at all.
			$set = array_values( array_diff( $set, array( 'quarantine', 'delete' ) ) );
		} else {
			$set = array_values( array_diff( $set, array( 'restore_official' ) ) );
		}

		$titles = array(
			'approve'    => Store::TYPE_INSTALL === $type
				? __( 'Allow this plugin or theme and remember it permanently', 'qartvelo-guard' )
				: __( 'Allow and remember this file permanently', 'qartvelo-guard' ),
			'ignore'     => __( 'False positive: trust this exact file from now on', 'qartvelo-guard' ),
			'quarantine' => __( 'Move the file to the locked quarantine folder where it cannot run', 'qartvelo-guard' ),
			'restore'    => __( 'Put the file back where it was, without trusting it', 'qartvelo-guard' ),
			'deny'       => __( 'Reject it and delete the held copy', 'qartvelo-guard' ),
			'delete'     => __( 'Delete permanently', 'qartvelo-guard' ),
			'restore_official' => __( 'Replace the file with the verified official WordPress copy. The current version is kept as a copy.', 'qartvelo-guard' ),
		);
		if ( Store::TYPE_USER === $type ) {
			$titles['approve'] = __( 'This administrator is expected: trust the account from now on', 'qartvelo-guard' );
			$titles['deny']    = __( 'Make the account a subscriber, revoke super admin and sign it out everywhere', 'qartvelo-guard' );
		} elseif ( Db_Scanner::is_db_item( $item ) ) {
			$titles['ignore'] = __( 'False positive: trust this exact content at this place from now on', 'qartvelo-guard' );
		}
		$confirm_delete = $held
			/* translators: %s: file name */
			? sprintf( __( 'Delete the held copy of %s permanently? This cannot be undone.', 'qartvelo-guard' ), $name )
			/* translators: %s: file name */
			: sprintf( __( 'Delete %s from the server permanently? This cannot be undone.', 'qartvelo-guard' ), $name );

		// Flagged high or critical: the safe decision (deny, quarantine, or the
		// official copy of a critical file) comes first as the primary button;
		// Allow and Mark safe become plain buttons that ask before acting.
		$risky   = Admin::needs_risk_confirm( $item );
		$primary = '';
		if ( $risky ) {
			foreach ( array( 'deny', 'quarantine', 'restore_official' ) as $safe ) {
				if ( in_array( $safe, $set, true ) && in_array( $safe, $available, true ) ) {
					$primary = $safe;
					break;
				}
			}
			if ( '' !== $primary ) {
				$set = array_values( array_merge( array( $primary ), array_diff( $set, array( $primary ) ) ) );
			}
			$labels['approve'][2] = '';
			$labels['ignore'][2]  = '';
		}

		$html = '<div class="wpcs-actions' . ( $risky ? ' wpcs-actions--risky' : '' ) . '">';
		foreach ( $set as $action ) {
			$label   = $labels[ $action ];
			$classes = 'button button-small wpcs-act wpcs-act--' . $action . ( $label[2] ? ' ' . $label[2] : '' ) . ( $action === $primary ? ' wpcs-btn-block' : '' ) . ( in_array( $action, $available, true ) ? '' : ' wpcs-hidden' );
			$ask     = $risky && in_array( $action, array( 'approve', 'ignore' ), true );
			$confirm = $ask ? Admin::risk_confirm_text( $item, $action ) : array();
			$html   .= '<button type="submit" form="' . esc_attr( self::FORM_ID ) . '" name="wpcs_single" value="' . esc_attr( $action . ':' . $id ) . '"'
				. ' class="' . esc_attr( $classes ) . '" data-wpcs-action="' . esc_attr( $action ) . '" data-id="' . esc_attr( (string) $id ) . '"'
				. ' title="' . esc_attr( $titles[ $action ] ) . '"'
				. ( $ask
					? ' data-wpcs-risk="' . esc_attr( (string) Admin::risk_level( $item ) ) . '" data-risk-title="' . esc_attr( $confirm['title'] ) . '"'
						. ' data-risk-verdict="' . esc_attr( $confirm['verdict'] ) . '" data-risk-text="' . esc_attr( $confirm['text'] ) . '"'
						. ' data-risk-confirm="' . esc_attr( $confirm['confirm'] ) . '" data-risk-cancel="' . esc_attr__( 'Cancel', 'qartvelo-guard' ) . '"'
					: '' )
				. ( 'delete' === $action ? ' data-confirm="' . esc_attr( $confirm_delete ) . '"' : '' )
				/* translators: %s: file name */
				. ( 'restore_official' === $action ? ' data-confirm="' . esc_attr( sprintf( __( 'Replace %s with the official WordPress file? The current version is kept as a copy, so the changes can still be viewed.', 'qartvelo-guard' ), $name ) ) . '"' : '' )
				. ( Store::TYPE_USER === $type && 'deny' === $action
					/* translators: %s: user login */
					? ' data-confirm="' . esc_attr( sprintf( __( 'Remove the administrator role from %s? The account becomes a subscriber and is signed out everywhere.', 'qartvelo-guard' ), $name ) ) . '"'
					: '' )
				. ( Store::TYPE_USER === $type && 'approve' === $action
					/* translators: %s: user login */
					? ' data-confirm="' . esc_attr( sprintf( __( 'Trust %s as an administrator? The account keeps full control of the site and is not reported again.', 'qartvelo-guard' ), $name ) ) . '"'
					: '' )
				. ( Store::TYPE_USER !== $type && 'deny' === $action
					/* translators: %s: file name */
					? ' data-confirm="' . esc_attr( sprintf( __( 'Deny %s? The held copy is deleted and cannot be recovered; the file would have to be uploaded again.', 'qartvelo-guard' ), $name ) ) . '"'
					: '' )
				. '><span class="dashicons dashicons-' . esc_attr( $label[1] ) . '" aria-hidden="true"></span>' . esc_html( $label[0] ) . '</button>';
		}
		$html .= '</div>';
		if ( $critical && in_array( $item['status'], array( Store::STATUS_PENDING, Store::STATUS_QUARANTINED, Store::STATUS_RESTORED ), true ) ) {
			$note  = in_array( 'restore_official', $available, true )
				? __( 'Critical file: it cannot be quarantined. If you did not make this change, use Restore official file.', 'qartvelo-guard' )
				: __( 'Critical file: it cannot be quarantined and has no official copy to restore here (wp-config.php and version.php are specific to this site). If you did not make this change, restore it from a backup; Changes shows what was edited.', 'qartvelo-guard' );
			$html .= '<p class="wpcs-critical-note"><span class="dashicons dashicons-shield" aria-hidden="true"></span><span>' . esc_html( $note ) . '</span></p>';
		}

		$html  .= '<div class="wpcs-row-links">';
		$button = $opts['changes'] ? Diff::view_button( $item, $held ) : null;
		if ( $button ) {
			$html .= '<a class="wpcs-view-changes" href="' . esc_url( $this->changes_url( $item ) ) . '" title="' . esc_attr( $button['title'] ) . '"><span class="dashicons dashicons-editor-code" aria-hidden="true"></span>' . esc_html( $button['label'] ) . '</a>';
		}
		$download = wp_nonce_url(
			add_query_arg(
				array(
					'action' => 'wpcybersec_download',
					'id'     => $id,
				),
				admin_url( 'admin-post.php' )
			),
			'wpcybersec_download_' . $id
		);
		if ( ! $not_file ) {
			$html .= '<a class="wpcs-download' . ( $held ? '' : ' wpcs-hidden' ) . '" href="' . esc_url( $download ) . '" title="' . esc_attr__( 'Download the held copy to inspect it (saved with a .quarantined extension)', 'qartvelo-guard' ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Download', 'qartvelo-guard' ) . '</a>';
		}
		if ( $opts['details'] ) {
			$html .= '<button type="button" class="button-link wpcs-details-toggle" aria-expanded="false" aria-controls="wpcs-details-' . esc_attr( (string) $id ) . '"><span class="dashicons dashicons-arrow-down-alt2" aria-hidden="true"></span><span class="wpcs-details-toggle__text">' . esc_html__( 'Details', 'qartvelo-guard' ) . '</span></button>';
		}
		$html .= '</div>';
		return $html;
	}

	/**
	 * Facts under an item name, each kept together with its separator dot so
	 * a narrow column never shows a dot alone on a line.
	 *
	 * @param string[] $meta Escaped HTML pieces.
	 * @return string HTML.
	 */
	private static function meta_html( array $meta ) {
		$html = '';
		foreach ( array_values( $meta ) as $i => $piece ) {
			$html .= '<span class="wpcs-meta__item">' . ( $i ? '<span class="wpcs-sep" aria-hidden="true"></span>' : '' ) . $piece . '</span>';
		}
		return $html;
	}

	/**
	 * Address of the changes view of an item.
	 *
	 * @param array  $item Item.
	 * @param string $from Tab to go back to ('' for the current one).
	 * @param array  $args Extra query args.
	 * @return string Unescaped URL.
	 */
	private function changes_url( array $item, $from = '', array $args = array() ) {
		return Admin::page_url(
			Admin::PAGE_REPORTS,
			array_merge(
				array(
					'view' => 'changes',
					'item' => (int) $item['id'],
					'from' => '' !== $from ? $from : $this->tab,
				),
				$args
			)
		);
	}

	/**
	 * Expanded details: hits with snippets, hashes, paths, request, install info.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 */
	private function render_details( array $item, array $details ) {
		$id   = (int) $item['id'];
		$hits = $this->hits( $details );
		$name = basename( (string) $item['path'] );

		echo '<div class="wpcs-details">';

		echo $this->preview_html( $item ); // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		$button = Diff::view_button( $item, $this->has_held_copy( $item ) );
		if ( $button ) {
			$lazy = in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true );
			$text = 'changes' === $button['kind']
				? __( 'Changes: open the comparison to see exactly which lines changed.', 'qartvelo-guard' )
				: __( 'Read the file with the matched lines highlighted.', 'qartvelo-guard' );
			echo '<p class="wpcs-diff-summary"' . ( $lazy ? ' data-wpcs-diff-summary="' . esc_attr( (string) $id ) . '"' : '' ) . '><span class="dashicons dashicons-editor-code" aria-hidden="true"></span>'
				. '<span class="wpcs-diff-summary__text">' . esc_html( $text ) . '</span> '
				. '<a href="' . esc_url( $this->changes_url( $item ) ) . '">' . esc_html( 'changes' === $button['kind'] ? __( 'View changes', 'qartvelo-guard' ) : __( 'View code', 'qartvelo-guard' ) ) . '</a></p>';
		}

		if ( $hits ) {
			echo '<div class="wpcs-hits"><h4>' . esc_html(
				sprintf(
					/* translators: %s: number of matches */
					_n( '%s malware signature match', '%s malware signature matches', count( $hits ), 'qartvelo-guard' ),
					number_format_i18n( count( $hits ) )
				)
			) . '</h4><ol>';
			foreach ( array_slice( $hits, 0, 25 ) as $hit ) {
				$title   = ! empty( $hit['title'] ) ? (string) $hit['title'] : __( 'Suspicious code', 'qartvelo-guard' );
				$snippet = isset( $hit['snippet'] ) ? Diff::redact_snippet( (string) $hit['snippet'], ! empty( $hit['file'] ) ? basename( (string) $hit['file'] ) : $name ) : '';
				if ( strlen( $snippet ) > 600 ) {
					$snippet = ( function_exists( 'mb_substr' ) ? mb_substr( $snippet, 0, 600 ) : substr( $snippet, 0, 600 ) ) . ' ...';
				}
				echo '<li class="wpcs-hit"><div class="wpcs-hit__head">' . Admin::severity_badge( isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 ) // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in severity_badge().
					. ' <strong>' . esc_html( $title ) . '</strong>';
				if ( ! empty( $hit['file'] ) ) {
					// File inside a held plugin or theme package (install items).
					echo ' <code class="wpcs-hit__file" title="' . esc_attr__( 'File inside the package', 'qartvelo-guard' ) . '">' . esc_html( (string) $hit['file'] ) . '</code>';
				}
				if ( ! empty( $hit['line'] ) ) {
					/* translators: %s: line number */
					echo ' <span class="wpcs-muted">' . esc_html( sprintf( __( 'line %s', 'qartvelo-guard' ), number_format_i18n( (int) $hit['line'] ) ) ) . '</span>';
				}
				if ( ! empty( $hit['sig'] ) ) {
					echo ' <code class="wpcs-hit__sig">' . esc_html( (string) $hit['sig'] ) . '</code>';
				}
				echo '</div>';
				if ( '' !== $snippet ) {
					echo '<pre>' . esc_html( $snippet ) . '</pre>';
				}
				echo '</li>';
			}
			echo '</ol></div>';
		}

		$rows = array();
		if ( Store::TYPE_USER === $item['type'] ) {
			$user_id = User_Watch::item_user_id( $item );
			$edit    = $user_id ? get_edit_user_link( $user_id ) : '';
			$account = esc_html( User_Watch::item_login( $item ) . ' (#' . $user_id . ')' );
			$rows[ __( 'Account', 'qartvelo-guard' ) ] = $edit ? '<a href="' . esc_url( $edit ) . '">' . $account . '</a>' : $account;
			foreach (
				array(
					'user_email'   => __( 'Email', 'qartvelo-guard' ),
					'display_name' => __( 'Display name', 'qartvelo-guard' ),
				) as $key => $label
			) {
				if ( ! empty( $details[ $key ] ) ) {
					$rows[ $label ] = esc_html( (string) $details[ $key ] );
				}
			}
			if ( ! empty( $details['user_registered'] ) ) {
				$rows[ __( 'Registered', 'qartvelo-guard' ) ] = esc_html( Admin::datetime( Admin::utc_ts( (string) $details['user_registered'] ) ) );
			}
			$rows[ __( 'How', 'qartvelo-guard' ) ]        = esc_html( $this->admin_how( $details ) );
			$rows[ __( 'Granted by', 'qartvelo-guard' ) ] = esc_html( $this->admin_granted_by( $item, $details ) );
			if ( '' !== (string) $item['ip'] ) {
				$rows[ __( 'IP address', 'qartvelo-guard' ) ] = '<code>' . esc_html( (string) $item['ip'] ) . '</code>';
			}
			if ( ! empty( $details['roles'] ) && is_array( $details['roles'] ) ) {
				$rows[ __( 'Roles when reported', 'qartvelo-guard' ) ] = esc_html( implode( ', ', array_map( 'strval', $details['roles'] ) ) );
			}
		}
		if ( Db_Scanner::is_db_item( $item ) ) {
			$rows[ __( 'Location', 'qartvelo-guard' ) ] = $this->db_location_html( $item );
			if ( ! empty( $details['table'] ) ) {
				$rows[ __( 'Table and key', 'qartvelo-guard' ) ] = '<code>' . esc_html( (string) $details['table'] . ' / ' . ( isset( $details['key'] ) ? (string) $details['key'] : '' ) ) . '</code>';
			}
			$rows[ __( 'Fingerprint', 'qartvelo-guard' ) ] = '<code class="wpcs-hash-full">' . esc_html( (string) $item['sha256'] ) . '</code>';
		} elseif ( '' !== (string) $item['sha256'] ) {
			$rows[ __( 'SHA-256', 'qartvelo-guard' ) ] = '<code id="wpcs-sha-' . esc_attr( (string) $id ) . '" class="wpcs-hash-full">' . esc_html( (string) $item['sha256'] ) . '</code>'
				. ' <button type="button" class="button-link wpcs-copy-link" data-wpcs-copy="#wpcs-sha-' . esc_attr( (string) $id ) . '">' . esc_html__( 'Copy', 'qartvelo-guard' ) . '</button>';
		}
		if ( ! empty( $details['previous_sha256'] ) ) {
			$rows[ __( 'Previous SHA-256', 'qartvelo-guard' ) ] = '<code class="wpcs-hash-full">' . esc_html( (string) $details['previous_sha256'] ) . '</code>';
		}
		if ( '' !== (string) $item['original_path'] ) {
			$rows[ __( 'Location', 'qartvelo-guard' ) ] = '<span class="wpcs-path">' . esc_html( (string) $item['original_path'] ) . '</span>';
		} elseif ( Store::TYPE_UPLOAD === $item['type'] ) {
			$rows[ __( 'Original name', 'qartvelo-guard' ) ] = '<span class="wpcs-path">' . esc_html( (string) $item['path'] ) . '</span>';
		}
		if ( $this->has_held_copy( $item ) ) {
			$rows[ __( 'Held copy', 'qartvelo-guard' ) ] = '<span class="wpcs-path">' . esc_html( (string) $item['quarantine_path'] ) . '</span>';
		}
		if ( Store::TYPE_INSTALL === $item['type'] ) {
			$parts = array();
			foreach ( array( 'name', 'version', 'slug' ) as $key ) {
				if ( ! empty( $details[ $key ] ) ) {
					$parts[] = (string) $details[ $key ];
				}
			}
			$parts[] = $this->install_context( $details );
			$rows[ __( 'Install', 'qartvelo-guard' ) ] = esc_html( implode( ', ', $parts ) );
		}
		if ( ! empty( $details['request_uri'] ) ) {
			$rows[ __( 'Request', 'qartvelo-guard' ) ] = '<span class="wpcs-path">' . esc_html( (string) $details['request_uri'] ) . '</span>';
		}
		if ( ! empty( $details['script'] ) ) {
			$rows[ __( 'Receiving script', 'qartvelo-guard' ) ] = '<span class="wpcs-path">' . esc_html( (string) $details['script'] ) . '</span>';
		}
		if ( ! empty( $details['field'] ) ) {
			$rows[ __( 'Form field', 'qartvelo-guard' ) ] = '<code>' . esc_html( (string) $details['field'] ) . '</code>';
		}
		if ( ! empty( $details['post_id'] ) ) {
			$post_id = (int) $details['post_id'];
			$link    = get_edit_post_link( $post_id );
			$title   = get_the_title( $post_id );
			/* translators: %d: post id */
			$text = '' !== (string) $title ? $title : sprintf( __( 'Post #%d', 'qartvelo-guard' ), $post_id );
			$rows[ __( 'Attach to', 'qartvelo-guard' ) ] = $link ? '<a href="' . esc_url( $link ) . '">' . esc_html( $text ) . '</a>' : esc_html( $text );
		}
		if ( ! empty( $details['attachment_id'] ) ) {
			$link = get_edit_post_link( (int) $details['attachment_id'] );
			if ( $link ) {
				$rows[ __( 'Media Library', 'qartvelo-guard' ) ] = '<a href="' . esc_url( $link ) . '">' . esc_html__( 'View the imported file', 'qartvelo-guard' ) . '</a>';
			}
		}
		if ( ! empty( $details['verified'] ) ) {
			$sources  = array(
				'core'   => __( 'WordPress core', 'qartvelo-guard' ),
				'plugin' => __( 'wordpress.org plugin', 'qartvelo-guard' ),
				'self'   => __( 'This plugin (checksums.json)', 'qartvelo-guard' ),
			);
			$verified = array();
			foreach ( (array) $details['verified'] as $source ) {
				$verified[] = isset( $sources[ (string) $source ] ) ? $sources[ (string) $source ] : (string) $source;
			}
			$verified = implode( ', ', $verified );
			$rows[ __( 'Official checksum', 'qartvelo-guard' ) ] = esc_html( $verified );
		}
		if ( Store::STATUS_PENDING !== $item['status'] ) {
			$decided = Admin::utc_ts( isset( $item['decided_at'] ) ? $item['decided_at'] : '' );
			$user    = Admin::user_name( isset( $item['decided_by'] ) ? $item['decided_by'] : 0 );
			$text    = trim( wp_strip_all_tags( Admin::status_badge( $item['status'] ) ) );
			if ( '' !== $user ) {
				/* translators: %s: user display name */
				$text .= ' ' . sprintf( __( 'by %s', 'qartvelo-guard' ), $user );
			}
			if ( $decided ) {
				$text .= ', ' . Admin::datetime( $decided );
			}
			$rows[ __( 'Decision', 'qartvelo-guard' ) ] = esc_html( $text );
		}
		if ( Store::STATUS_APPROVED === $item['status'] && ! empty( $details['approval_note'] ) ) {
			// What the admin still has to do after approving (for example upload the ZIP again).
			$rows[ __( 'Next step', 'qartvelo-guard' ) ] = esc_html( (string) $details['approval_note'] );
		}
		$rows[ __( 'Item', 'qartvelo-guard' ) ] = esc_html( '#' . $id );

		echo '<dl class="wpcs-details__grid">';
		foreach ( $rows as $label => $value ) {
			echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . wp_kses( $value, $this->details_kses() ) . '</dd></div>';
		}
		echo '</dl></div>';
	}

	/* ------------------------------------------------------------------ */
	/* Changes view (view=changes&item=<id>)                               */
	/* ------------------------------------------------------------------ */

	/**
	 * What changed in a reported file: the item, every malware match, and a
	 * line by line comparison with the last trusted or the official version
	 * (or the full content when there is nothing to compare with).
	 */
	private function render_changes() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only view.
		$id     = isset( $_GET['item'] ) ? absint( wp_unslash( $_GET['item'] ) ) : 0;
		$layout = isset( $_GET['layout'] ) ? sanitize_key( wp_unslash( $_GET['layout'] ) ) : '';
		$from   = isset( $_GET['from'] ) ? sanitize_key( wp_unslash( $_GET['from'] ) ) : '';
		// phpcs:enable

		$user_id = get_current_user_id();
		if ( in_array( $layout, array( 'unified', 'split' ), true ) ) {
			if ( get_user_meta( $user_id, self::META_LAYOUT, true ) !== $layout ) {
				update_user_meta( $user_id, self::META_LAYOUT, $layout );
			}
		} else {
			$layout = 'split' === get_user_meta( $user_id, self::META_LAYOUT, true ) ? 'split' : 'unified';
		}

		$item = $id ? Admin::call( 'store', 'item_get', array( $id ), null ) : null;
		$item = is_array( $item ) && ! empty( $item['id'] ) ? $item : null;

		$tabs = $this->tabs();
		if ( ! isset( $tabs[ $from ] ) || in_array( $from, array( 'allowlist', 'activity' ), true ) ) {
			$from = $item ? $this->tab_for( $item ) : 'pending';
		}
		$back = '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => $from ) ) ) . '"><span class="dashicons dashicons-arrow-left-alt" aria-hidden="true"></span> '
			/* translators: %s: name of a Reports tab, such as Threats */
			. esc_html( sprintf( __( 'Back to %s', 'qartvelo-guard' ), $tabs[ $from ][0] ) ) . '</a>';

		echo '<div class="wrap wpcs-wrap wpcs-reports wpcs-changes" data-wpcs-changes>';
		if ( ! $item ) {
			Admin::header( __( 'Changes', 'qartvelo-guard' ), '', $back );
			$this->empty_state(
				'search',
				__( 'Report not found', 'qartvelo-guard' ),
				__( 'This report no longer exists, so there is nothing to show.', 'qartvelo-guard' ),
				'<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => $from ) ) ) . '">' . esc_html__( 'Back to the reports', 'qartvelo-guard' ) . '</a>'
			);
			echo '</div>';
			return;
		}

		$held   = $this->has_held_copy( $item );
		$button = Diff::view_button( $item, $held );
		try {
			$result = Diff::for_item( $item, array( 'layout' => $layout ) );
		} catch ( \Throwable $e ) {
			Admin::debug_log( $e );
			$result = array(
				'mode'          => 'unavailable',
				'reason'        => 'error',
				'reason_text'   => __( 'The file could not be compared because of an unexpected error. Try again in a moment.', 'qartvelo-guard' ),
				'base_label'    => '',
				'current_label' => '',
				'added'         => 0,
				'removed'       => 0,
				'html'          => '',
				'notes'         => array(),
				'hit_lines'     => array(),
				'layout'        => $layout,
			);
		}

		Admin::header(
			$button && 'changes' === $button['kind'] ? __( 'What changed', 'qartvelo-guard' ) : __( 'File contents', 'qartvelo-guard' ),
			(string) $item['path'],
			$back
		);
		$this->render_result_notice();

		// No-JS fallback target of the decision buttons (core.js sends them through AJAX).
		echo '<form id="' . esc_attr( self::FORM_ID ) . '" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="wpcybersec_reports_bulk"><input type="hidden" name="tab" value="' . esc_attr( $from ) . '">';
		wp_nonce_field( 'wpcybersec_reports_bulk' );
		echo '</form>';

		$this->render_change_item( $item, $held );
		$this->render_change_hits( $item, $result );
		$this->render_change_diff( $item, $result, $from );
		echo '</div>';
	}

	/**
	 * Reports tab an item belongs to.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	private function tab_for( array $item ) {
		if ( Store::STATUS_PENDING === $item['status'] ) {
			return Store::TYPE_THREAT === $item['type'] ? 'threats' : 'pending';
		}
		return Store::STATUS_QUARANTINED === $item['status'] ? 'quarantine' : 'history';
	}

	/**
	 * Summary card: what the file is, its state, and the decision buttons.
	 *
	 * @param array $item Item.
	 * @param bool  $held Held copy exists.
	 */
	private function render_change_item( array $item, $held ) {
		$details   = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$available = Decisions::available( $item );
		$hits      = $this->hits( $details );
		$severity  = (int) $item['severity'];
		$ts        = Admin::utc_ts( $item['created_at'] );

		echo '<section class="wpcs-card wpcs-change-item wpcs-sev-' . esc_attr( (string) $severity ) . '" data-item-id="' . esc_attr( (string) $item['id'] ) . '" data-held="' . ( $held ? '1' : '0' ) . '">';
		echo '<div class="wpcs-change-item__badges">' . $this->type_badge( (string) $item['type'], $item ); // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
		if ( Store::TYPE_THREAT === $item['type'] || $hits ) {
			echo Admin::severity_badge( $severity ); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in severity_badge().
		}
		if ( ! empty( $details['change'] ) ) {
			echo 'modified' === $details['change']
				? '<span class="wpcs-chip wpcs-chip--warn">' . esc_html__( 'modified', 'qartvelo-guard' ) . '</span>'
				: '<span class="wpcs-chip">' . esc_html__( 'new', 'qartvelo-guard' ) . '</span>';
		}
		if ( isset( $details['checksum'] ) && 'mismatch' === $details['checksum'] ) {
			echo '<span class="wpcs-chip wpcs-chip--warn">' . esc_html__( 'differs from the official file', 'qartvelo-guard' ) . '</span>';
		}
		echo '</div>';
		echo '<h2 class="wpcs-change-item__path">' . $this->path_html( (string) $item['path'] ) . '</h2>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		list( $who, $context ) = $this->source_parts( $item, $details );
		$facts = array(
			__( 'Status', 'qartvelo-guard' )   => '<span data-wpcs-status>' . $this->status_cell( $item, $held ) . '</span>',
			__( 'Detected', 'qartvelo-guard' ) => '<span title="' . esc_attr( Admin::datetime( $ts ) ) . '">' . esc_html( Admin::ago( $ts ) ) . '</span><span class="wpcs-sub">' . esc_html( Admin::datetime( $ts ) ) . '</span>',
			__( 'Found by', 'qartvelo-guard' ) => esc_html( $who ) . '<span class="wpcs-sub">' . esc_html( $context ) . '</span>',
		);
		if ( (int) $item['size'] > 0 ) {
			$facts[ __( 'Size', 'qartvelo-guard' ) ] = esc_html( size_format( (int) $item['size'], (int) $item['size'] >= KB_IN_BYTES ? 1 : 0 ) );
		}
		if ( '' !== (string) $item['sha256'] ) {
			$facts[ __( 'SHA-256', 'qartvelo-guard' ) ] = $this->short_hash( (string) $item['sha256'] );
		}
		if ( ! empty( $details['previous_sha256'] ) ) {
			$facts[ __( 'Previous SHA-256', 'qartvelo-guard' ) ] = $this->short_hash( (string) $details['previous_sha256'] );
		}
		echo '<dl class="wpcs-change-item__facts">';
		foreach ( $facts as $label => $value ) {
			echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . $value . '</dd></div>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
		}
		echo '</dl>';

		echo '<div class="wpcs-change-item__actions">' . $this->actions_cell( $item, $available, $held, array( 'details' => false, 'changes' => false ) ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
		echo '</section>';
	}

	/**
	 * Every malware match, each linked to its line below.
	 *
	 * @param array $item   Item.
	 * @param array $result Diff::for_item() result.
	 */
	private function render_change_hits( array $item, array $result ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$hits    = $this->hits( $details );
		if ( ! $hits ) {
			return;
		}
		$name  = basename( (string) $item['path'] );
		$count = count( $hits );
		$html  = isset( $result['html'] ) ? (string) $result['html'] : '';

		echo '<section class="wpcs-card wpcs-change-hits">';
		echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-warning" aria-hidden="true"></span>' . esc_html(
			sprintf(
				/* translators: %s: number of matches */
				_n( '%s malware signature match', '%s malware signature matches', $count, 'qartvelo-guard' ),
				number_format_i18n( $count )
			)
		) . '</h2>';
		echo '<ol class="wpcs-hitlist">';
		foreach ( $hits as $i => $hit ) {
			if ( self::HITS_VISIBLE === $i && $count > self::HITS_VISIBLE + 1 ) {
				echo '</ol><details class="wpcs-more-hits"><summary>' . esc_html(
					sprintf(
						/* translators: %s: number of matches */
						_n( 'Show %s more match', 'Show %s more matches', $count - self::HITS_VISIBLE, 'qartvelo-guard' ),
						number_format_i18n( $count - self::HITS_VISIBLE )
					)
				) . '</summary><ol class="wpcs-hitlist" start="' . esc_attr( (string) ( self::HITS_VISIBLE + 1 ) ) . '">';
			}
			$title = ! empty( $hit['title'] ) ? (string) $hit['title'] : __( 'Suspicious code', 'qartvelo-guard' );
			$line  = isset( $hit['line'] ) ? (int) $hit['line'] : 0;
			$code  = $this->hit_code( $hit, $line, $result, ! empty( $hit['file'] ) ? basename( (string) $hit['file'] ) : $name );

			echo '<li class="wpcs-hit"><div class="wpcs-hit__head">' . Admin::severity_badge( isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 ) // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in severity_badge().
				. ' <strong>' . esc_html( $title ) . '</strong>';
			if ( $line > 0 ) {
				/* translators: %s: line number */
				$text = sprintf( __( 'line %s', 'qartvelo-guard' ), number_format_i18n( $line ) );
				if ( false !== strpos( $html, ' id="L' . $line . '"' ) ) {
					echo ' <a class="wpcs-hit__line" href="#L' . esc_attr( (string) $line ) . '">' . esc_html( $text ) . '</a>';
				} else {
					echo ' <span class="wpcs-muted">' . esc_html( $text ) . '</span>';
				}
			}
			if ( ! empty( $hit['file'] ) ) {
				echo ' <code class="wpcs-hit__file">' . esc_html( (string) $hit['file'] ) . '</code>';
			}
			if ( ! empty( $hit['sig'] ) ) {
				echo ' <code class="wpcs-hit__sig">' . esc_html( (string) $hit['sig'] ) . '</code>';
			}
			echo '</div>';
			if ( '' !== $code ) {
				echo '<pre class="wpcs-hit__code">' . esc_html( $code ) . '</pre>';
			}
			echo '</li>';
		}
		echo '</ol>';
		if ( $count > self::HITS_VISIBLE + 1 ) {
			echo '</details>';
		}
		echo '</section>';
	}

	/**
	 * Code to show for one match: the redacted line from the file when it is
	 * known (a window around the match for very long lines), else the stored
	 * snippet, redacted.
	 *
	 * @param array  $hit    Hit.
	 * @param int    $line   Line number.
	 * @param array  $result Diff::for_item() result.
	 * @param string $name   File name.
	 * @return string Plain text.
	 */
	private function hit_code( array $hit, $line, array $result, $name ) {
		$snippet = isset( $hit['snippet'] ) ? trim( (string) $hit['snippet'] ) : '';
		if ( $line > 0 && isset( $result['hit_lines'][ $line ] ) ) {
			$text = (string) $result['hit_lines'][ $line ];
			if ( strlen( $text ) <= 600 ) {
				return trim( $text );
			}
			$pos   = '' !== $snippet ? strpos( $text, substr( $snippet, 0, 40 ) ) : false;
			$start = false === $pos ? 0 : max( 0, $pos - 120 );
			$part  = function_exists( 'mb_strcut' ) ? mb_strcut( $text, $start, 600, 'UTF-8' ) : substr( $text, $start, 600 );
			return ( $start > 0 ? '... ' : '' ) . $part . ' ...';
		}
		if ( '' === $snippet ) {
			return '';
		}
		$snippet = Diff::redact_snippet( $snippet, $name );
		if ( strlen( $snippet ) > 600 ) {
			$snippet = ( function_exists( 'mb_substr' ) ? mb_substr( $snippet, 0, 600 ) : substr( $snippet, 0, 600 ) ) . ' ...';
		}
		return $snippet;
	}

	/**
	 * The comparison (or the content, or why neither can be shown).
	 *
	 * @param array  $item   Item.
	 * @param array  $result Diff::for_item() result.
	 * @param string $from   Tab to go back to.
	 */
	private function render_change_diff( array $item, array $result, $from ) {
		$mode   = (string) $result['mode'];
		$layout = isset( $result['layout'] ) && 'split' === $result['layout'] ? 'split' : 'unified';

		echo '<section class="wpcs-card wpcs-diff-card" id="wpcs-diff">';
		echo '<div class="wpcs-diff-head"><div class="wpcs-diff-head__text">';
		if ( 'diff' === $mode ) {
			echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-editor-code" aria-hidden="true"></span>' . esc_html__( 'Line by line', 'qartvelo-guard' )
				. ' <span class="wpcs-diffstat" title="' . esc_attr__( 'Lines added and removed', 'qartvelo-guard' ) . '">'
				. '<span class="wpcs-diffstat__add">+' . esc_html( number_format_i18n( (int) $result['added'] ) ) . '</span>'
				. '<span class="wpcs-diffstat__del">-' . esc_html( number_format_i18n( (int) $result['removed'] ) ) . '</span></span></h2>';
			echo '<p class="wpcs-diff-head__compare"><span class="wpcs-diff-head__base">' . esc_html( (string) $result['base_label'] ) . '</span>'
				. '<span class="dashicons dashicons-arrow-right-alt" aria-hidden="true"></span><span class="screen-reader-text">' . esc_html__( 'compared with', 'qartvelo-guard' ) . '</span>'
				. '<span class="wpcs-diff-head__current">' . esc_html( (string) $result['current_label'] ) . '</span></p>';
		} elseif ( 'content' === $mode ) {
			echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-media-code" aria-hidden="true"></span>' . esc_html__( 'Full content', 'qartvelo-guard' ) . '</h2>';
			if ( '' !== (string) $result['current_label'] ) {
				echo '<p class="wpcs-diff-head__compare"><span class="wpcs-diff-head__current">' . esc_html( (string) $result['current_label'] ) . '</span></p>';
			}
		} else {
			echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-media-code" aria-hidden="true"></span>' . esc_html__( 'Nothing to show', 'qartvelo-guard' ) . '</h2>';
		}
		echo '</div>';

		if ( 'diff' === $mode && (int) $result['added'] + (int) $result['removed'] > 0 ) {
			echo '<div class="wpcs-segmented" role="group" aria-label="' . esc_attr__( 'Layout', 'qartvelo-guard' ) . '">';
			foreach ( array(
				'unified' => __( 'Unified', 'qartvelo-guard' ),
				'split'   => __( 'Split', 'qartvelo-guard' ),
			) as $value => $label ) {
				$url = $this->changes_url( $item, $from, array( 'layout' => $value ) ) . '#wpcs-diff';
				echo '<a class="button button-small' . ( $value === $layout ? ' button-primary is-active' : '' ) . '" href="' . esc_url( $url ) . '"' . ( $value === $layout ? ' aria-current="true"' : '' ) . '>' . esc_html( $label ) . '</a>';
			}
			echo '</div>';
		}
		echo '</div>';

		if ( 'content' === $mode && '' !== (string) $result['reason_text'] ) {
			$this->notice( 'info', 'info-outline', (string) $result['reason_text'] );
		}
		foreach ( isset( $result['notes'] ) ? (array) $result['notes'] : array() as $note ) {
			$tone = isset( $note[0] ) ? (string) $note[0] : 'info';
			$icon = 'warn' === $tone ? 'warning' : ( 'ok' === $tone ? 'yes-alt' : 'info-outline' );
			$this->notice( $tone, $icon, isset( $note[1] ) ? (string) $note[1] : '' );
		}

		if ( 'unavailable' === $mode ) {
			echo '<div class="wpcs-empty wpcs-empty--compact"><span class="dashicons dashicons-media-code" aria-hidden="true"></span><p>' . esc_html( (string) $result['reason_text'] ) . '</p></div>';
		} elseif ( '' !== (string) $result['html'] ) {
			// Built by Diff with every line passed through esc_html().
			echo '<div class="wpcs-diff-body">' . $result['html'] . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		echo '</section>';
	}

	/**
	 * @return array
	 */
	private function details_kses() {
		return array(
			'a'      => array( 'href' => true, 'class' => true ),
			'code'   => array( 'id' => true, 'class' => true ),
			'span'   => array( 'class' => true, 'title' => true ),
			'strong' => array( 'class' => true ),
			'button' => array( 'type' => true, 'class' => true, 'data-wpcs-copy' => true ),
		);
	}

	/**
	 * Empty state for item tabs.
	 */
	private function render_items_empty() {
		if ( '' !== $this->search || $this->filters['type'] || $this->filters['severity'] ) {
			$this->empty_state(
				'search',
				__( 'No matching items', 'qartvelo-guard' ),
				__( 'Nothing matches the current search or filter.', 'qartvelo-guard' ),
				'<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => $this->tab ) ) ) . '">' . esc_html__( 'Show everything', 'qartvelo-guard' ) . '</a>'
			);
			return;
		}
		$dashboard = '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_DASHBOARD ) ) . '">' . esc_html__( 'Go to the dashboard', 'qartvelo-guard' ) . '</a>';
		switch ( $this->tab ) {
			case 'threats':
				$this->empty_state( 'shield', __( 'No threats found', 'qartvelo-guard' ), __( 'No file currently matches a malware signature. Run a full malware scan from the dashboard any time.', 'qartvelo-guard' ), $dashboard );
				break;
			case 'quarantine':
				$this->empty_state( 'lock', __( 'Quarantine is empty', 'qartvelo-guard' ), __( 'Held uploads and quarantined files appear here. They are stored where they cannot run.', 'qartvelo-guard' ) );
				break;
			case 'history':
				$this->empty_state( 'backup', __( 'No decisions yet', 'qartvelo-guard' ), __( 'When you allow, deny or quarantine something, the decision is recorded here.', 'qartvelo-guard' ) );
				break;
			default:
				$this->empty_state( 'yes-alt', __( 'Nothing waiting for approval', 'qartvelo-guard' ), __( 'New uploads, plugin or theme installs and unknown files appear here until you allow or deny them.', 'qartvelo-guard' ) );
		}
	}

	/**
	 * Empty state card.
	 *
	 * @param string $icon        Dashicon name.
	 * @param string $title       Title.
	 * @param string $text        Text.
	 * @param string $action_html Escaped button HTML.
	 */
	private function empty_state( $icon, $title, $text, $action_html = '' ) {
		echo '<div class="wpcs-card wpcs-empty-card"><div class="wpcs-empty"><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span>';
		echo '<h3>' . esc_html( $title ) . '</h3><p>' . esc_html( $text ) . '</p>';
		if ( '' !== $action_html ) {
			echo '<p>' . wp_kses( $action_html, array( 'a' => array( 'class' => true, 'href' => true ) ) ) . '</p>';
		}
		echo '</div></div>';
	}

	/**
	 * Count + page links.
	 *
	 * @param int $total    Total rows.
	 * @param int $per_page Rows per page.
	 */
	private function render_pagination( $total, $per_page ) {
		$per_page = max( 1, (int) $per_page );
		$pages    = (int) ceil( $total / $per_page );
		echo '<div class="wpcs-tablenav"><span class="wpcs-muted">' . esc_html(
			sprintf(
				/* translators: %s: number of items */
				_n( '%s item', '%s items', $total, 'qartvelo-guard' ),
				number_format_i18n( $total )
			)
		) . '</span>';
		if ( $pages > 1 ) {
			$links = paginate_links(
				array(
					'base'      => add_query_arg( 'paged', '%#%', $this->view_url() ),
					'format'    => '',
					'current'   => min( $this->paged, $pages ),
					'total'     => $pages,
					'prev_text' => '<span aria-hidden="true">&lsaquo;</span><span class="screen-reader-text">' . esc_html__( 'Previous page', 'qartvelo-guard' ) . '</span>',
					'next_text' => '<span aria-hidden="true">&rsaquo;</span><span class="screen-reader-text">' . esc_html__( 'Next page', 'qartvelo-guard' ) . '</span>',
					'mid_size'  => 1,
				)
			);
			echo '<nav class="wpcs-pagination" aria-label="' . esc_attr__( 'Pages', 'qartvelo-guard' ) . '">' . wp_kses_post( (string) $links ) . '</nav>';
		}
		echo '</div>';
	}

	/* ------------------------------------------------------------------ */
	/* Recent changes tab (incident mode)                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * Executable and config files modified in the last 7, 14 or 30 days,
	 * whatever the baseline says, with what explains each change.
	 */
	private function render_recent_tab() {
		echo '<div class="wpcs-notice"><span class="dashicons dashicons-calendar-alt" aria-hidden="true"></span><div><p>'
			. esc_html__( 'Scans compare files with the baseline, so a file that was already infected when the baseline was recorded looks normal; this list shows every PHP, script and configuration file modified recently, whatever the baseline says, so you can check what nothing explains.', 'qartvelo-guard' )
			. '</p></div></div>';

		$recent   = new Recent_Changes();
		$per_page = 50;
		try {
			$result = $recent->query(
				array(
					'days'         => $this->filters['days'],
					'search'       => $this->search,
					'hide_updates' => 'no_updates' === $this->filters['show'],
					'page'         => $this->paged,
					'per_page'     => $per_page,
				)
			);
		} catch ( \Throwable $e ) {
			Admin::debug_log( $e );
			$this->notice( 'bad', 'warning', __( 'The list could not be loaded. The plugin database tables may be missing; deactivate and activate the plugin to recreate them.', 'qartvelo-guard' ) );
			return;
		}

		$last = Admin::call( 'scan_job', 'last_result', array(), array() );
		$when = is_array( $last ) && ! empty( $last['finished_at'] ) ? (int) $last['finished_at'] : 0;
		echo '<p class="wpcs-muted wpcs-tab-hint">' . esc_html(
			$when
				/* translators: %s: date and time of the last scan */
				? sprintf( __( 'Modification times as the last scan saw them (%s). Run a quick scan first to include changes made since then.', 'qartvelo-guard' ), Admin::datetime( $when ) )
				: __( 'No scan has finished yet, so there is nothing to list. Run a scan from the dashboard first.', 'qartvelo-guard' )
		) . '</p>';

		echo '<div class="wpcs-toolbar"><div></div>';
		echo '<form class="wpcs-filters" method="get" action="' . esc_url( Admin::admin_page_base() ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( Admin::PAGE_REPORTS ) . '"><input type="hidden" name="tab" value="recent">';
		$days = array();
		foreach ( Recent_Changes::WINDOWS as $n ) {
			/* translators: %s: number of days */
			$days[ (string) $n ] = sprintf( _n( 'Last %s day', 'Last %s days', $n, 'qartvelo-guard' ), number_format_i18n( $n ) );
		}
		$this->select( 'days', (string) $this->filters['days'], $days, __( 'Time window', 'qartvelo-guard' ) );
		$this->select(
			'show',
			$this->filters['show'],
			array(
				''           => __( 'All changed files', 'qartvelo-guard' ),
				'no_updates' => __( 'Hide files changed by updates', 'qartvelo-guard' ),
			),
			__( 'Show', 'qartvelo-guard' )
		);
		$this->search_box( __( 'Search path', 'qartvelo-guard' ) );
		echo '</form></div>';

		$rows  = (array) $result['rows'];
		$total = (int) $result['total'];
		if ( $result['capped'] ) {
			$this->notice(
				'warn',
				'info-outline',
				sprintf(
					/* translators: %s: number of files */
					__( 'More than %s files changed in this window; only the newest are listed. Choose a shorter window or search for a folder.', 'qartvelo-guard' ),
					number_format_i18n( Recent_Changes::SCAN_CAP )
				)
			);
		}
		if ( ! $rows ) {
			if ( '' !== $this->search || $this->filters['show'] ) {
				$this->empty_state( 'search', __( 'No matching files', 'qartvelo-guard' ), __( 'No changed file matches the current search or filter.', 'qartvelo-guard' ), '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'recent', 'days' => $this->filters['days'] ) ) ) . '">' . esc_html__( 'Show everything', 'qartvelo-guard' ) . '</a>' );
			} else {
				$this->empty_state( 'yes-alt', __( 'No recent changes', 'qartvelo-guard' ), __( 'No PHP, script or configuration file was modified in this time window.', 'qartvelo-guard' ) );
			}
			return;
		}

		$unexplained = 0;
		$html        = '';
		foreach ( $rows as $row ) {
			$why = $recent->explain( $row );
			if ( 'none' === $why['kind'] ) {
				++$unexplained;
			}
			$html .= $this->recent_row( $row, $why );
		}

		if ( $unexplained ) {
			$this->notice(
				'warn',
				'warning',
				sprintf(
					/* translators: %s: number of files */
					_n( '%s file on this page changed without an update, an official checksum or your approval to explain it. Look at its code; if you do not recognise the change, report it for review.', '%s files on this page changed without an update, an official checksum or your approval to explain them. Look at their code; if you do not recognise a change, report it for review.', $unexplained, 'qartvelo-guard' ),
					number_format_i18n( $unexplained )
				)
			);
		}

		echo '<div class="wpcs-card wpcs-card--flush wpcs-table-card"><table class="widefat wpcs-table wpcs-recent">';
		echo '<thead><tr>';
		echo '<th scope="col" class="column-file">' . esc_html__( 'File', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-modified">' . esc_html__( 'Modified', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-size">' . esc_html__( 'Size', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-explained">' . esc_html__( 'Explained by', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-actions">' . esc_html__( 'Actions', 'qartvelo-guard' ) . '</th>';
		echo '</tr></thead><tbody>';
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built with escaping in recent_row().
		echo '</tbody></table></div>';

		$this->render_pagination( $total, $per_page );
	}

	/**
	 * One row of the Recent changes table.
	 *
	 * @param array $row Recent_Changes::query() row.
	 * @param array $why Recent_Changes::explain() result.
	 * @return string HTML.
	 */
	private function recent_row( array $row, array $why ) {
		$rel   = (string) $row['path'];
		$mtime = (int) $row['mtime'];
		$none  = 'none' === $why['kind'];
		$icons = array(
			'update'   => array( 'update', 'ok' ),
			'checksum' => array( 'yes-alt', 'ok' ),
			'allowed'  => array( 'yes-alt', 'ok' ),
			'reported' => array( 'clock', 'pending' ),
			'plugin'   => array( 'shield', 'info' ),
			'inert'    => array( 'minus', 'muted' ),
			'none'     => array( 'warning', 'high' ),
		);
		$icon  = isset( $icons[ $why['kind'] ] ) ? $icons[ $why['kind'] ] : $icons['none'];

		$html  = '<tr class="wpcs-recent-row' . ( $none ? ' is-unexplained' : '' ) . '">';
		$html .= '<td class="column-file">' . $this->path_html( $rel );
		$meta  = array();
		if ( Store::STATE_THREAT === $row['state'] ) {
			$meta[] = '<span class="wpcs-chip wpcs-chip--warn">' . esc_html__( 'reported as a threat', 'qartvelo-guard' ) . '</span>';
		} elseif ( Store::STATE_PENDING === $row['state'] ) {
			$meta[] = '<span class="wpcs-chip">' . esc_html__( 'waiting for approval', 'qartvelo-guard' ) . '</span>';
		}
		if ( ! $why['exists'] ) {
			$meta[] = '<span class="wpcs-chip">' . esc_html__( 'deleted since the last scan', 'qartvelo-guard' ) . '</span>';
		} elseif ( $why['changed'] ) {
			$meta[] = '<span class="wpcs-chip wpcs-chip--warn">' . esc_html__( 'changed again since the last scan', 'qartvelo-guard' ) . '</span>';
		}
		if ( $meta ) {
			$html .= '<span class="wpcs-sub wpcs-meta">' . implode( ' ', $meta ) . '</span>';
		}
		$html .= '</td>';
		$html .= '<td class="column-modified"><span title="' . esc_attr( Admin::datetime( $mtime ) ) . '">' . esc_html( Admin::ago( $mtime ) ) . '</span><span class="wpcs-sub">' . esc_html( Admin::datetime( $mtime ) ) . '</span></td>';
		$html .= '<td class="column-size">' . esc_html( size_format( (int) $row['size'], (int) $row['size'] >= KB_IN_BYTES ? 1 : 0 ) ) . '</td>';
		$html .= '<td class="column-explained"><span class="wpcs-badge wpcs-badge--' . esc_attr( $icon[1] ) . ' wpcs-explained"><span class="dashicons dashicons-' . esc_attr( $icon[0] ) . '" aria-hidden="true"></span>' . esc_html( $why['label'] ) . '</span></td>';

		$html .= '<td class="column-actions"><div class="wpcs-row-links">';
		if ( is_array( $why['item'] ) ) {
			$html .= '<a href="' . esc_url( $this->changes_url( $why['item'], 'recent' ) ) . '"><span class="dashicons dashicons-visibility" aria-hidden="true"></span>' . esc_html__( 'Open the report', 'qartvelo-guard' ) . '</a>';
		} elseif ( $why['exists'] ) {
			$html .= '<a href="' . esc_url( $this->file_url( $rel ) ) . '"><span class="dashicons dashicons-editor-code" aria-hidden="true"></span>' . esc_html__( 'View code', 'qartvelo-guard' ) . '</a>';
			if ( $none ) {
				$html .= $this->report_form( $rel, 'button-link' );
			}
		}
		$html .= '</div></td></tr>';
		return $html;
	}

	/**
	 * Address of the read-only code view of a monitored file.
	 *
	 * @param string $rel Relative path.
	 * @return string Unescaped URL.
	 */
	private function file_url( $rel ) {
		return Admin::page_url(
			Admin::PAGE_REPORTS,
			array(
				'view' => 'file',
				'path' => $rel,
				'days' => 7 === $this->filters['days'] ? '' : $this->filters['days'],
			)
		);
	}

	/**
	 * "Report for review" button (admin-post with nonce).
	 *
	 * @param string $rel   Relative path.
	 * @param string $class Button class.
	 * @return string HTML.
	 */
	private function report_form( $rel, $class ) {
		return '<form class="wpcs-inline-form" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">'
			. '<input type="hidden" name="action" value="wpcybersec_recent_report">'
			. '<input type="hidden" name="path" value="' . esc_attr( $rel ) . '">'
			. wp_nonce_field( 'wpcybersec_recent_report', '_wpnonce', true, false )
			. '<button type="submit" class="' . esc_attr( $class ) . ' wpcs-report-file" title="' . esc_attr__( 'Add this file to Pending approvals, where you can allow or quarantine it', 'qartvelo-guard' ) . '"><span class="dashicons dashicons-flag" aria-hidden="true"></span>' . esc_html__( 'Report for review', 'qartvelo-guard' ) . '</button>'
			. '</form>';
	}

	/**
	 * Read-only code of a monitored file that has no report
	 * (view=file&path=<relative path>): the matches, and the content (or what
	 * changed since the last trusted copy, or since the official release),
	 * secrets hidden.
	 */
	private function render_file_view() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only view.
		$rel = isset( $_GET['path'] ) && is_string( $_GET['path'] ) ? substr( (string) wp_unslash( $_GET['path'] ), 0, 4096 ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated by Recent_Changes::resolve().
		// phpcs:enable
		$this->tab = 'recent';
		$back      = '<a class="button" href="' . esc_url( $this->view_url() ) . '"><span class="dashicons dashicons-arrow-left-alt" aria-hidden="true"></span> '
			. esc_html__( 'Back to Recent changes', 'qartvelo-guard' ) . '</a>';

		echo '<div class="wrap wpcs-wrap wpcs-reports wpcs-changes">';
		$file = Recent_Changes::resolve( $rel );
		if ( is_wp_error( $file ) ) {
			Admin::header( __( 'File contents', 'qartvelo-guard' ), '', $back );
			$this->empty_state( 'search', __( 'File not available', 'qartvelo-guard' ), $file->get_error_message() );
			echo '</div>';
			return;
		}

		// A file with an open report is shown in its report, with the decision buttons.
		foreach ( array( Store::TYPE_THREAT, Store::TYPE_FILE ) as $type ) {
			$open = Admin::call( 'store', 'item_find_open', array( $type, $file['rel'] ), null );
			if ( is_array( $open ) ) {
				$back .= '<a class="button" href="' . esc_url( $this->changes_url( $open, 'recent' ) ) . '">' . esc_html__( 'Open the report', 'qartvelo-guard' ) . '</a>';
				break;
			}
		}

		$item = Recent_Changes::file_item( $file );
		try {
			$result = Diff::for_item( $item, array( 'layout' => 'split' === get_user_meta( get_current_user_id(), self::META_LAYOUT, true ) ? 'split' : 'unified' ) );
		} catch ( \Throwable $e ) {
			Admin::debug_log( $e );
			$result = array(
				'mode'          => 'unavailable',
				'reason_text'   => __( 'The file could not be read because of an unexpected error. Try again in a moment.', 'qartvelo-guard' ),
				'base_label'    => '',
				'current_label' => '',
				'added'         => 0,
				'removed'       => 0,
				'html'          => '',
				'notes'         => array(),
				'hit_lines'     => array(),
				'layout'        => 'unified',
			);
		}

		Admin::header( 'diff' === $result['mode'] ? __( 'What changed', 'qartvelo-guard' ) : __( 'File contents', 'qartvelo-guard' ), $file['rel'], $back );

		$why   = ( new Recent_Changes() )->explain( $file['row'] );
		$mtime = (int) $file['row']['mtime'];
		echo '<section class="wpcs-card wpcs-change-item wpcs-sev-' . esc_attr( (string) (int) $item['severity'] ) . '">';
		echo '<div class="wpcs-change-item__badges"><span class="wpcs-badge wpcs-type wpcs-type--file"><span class="dashicons dashicons-media-code" aria-hidden="true"></span>' . esc_html__( 'File', 'qartvelo-guard' ) . '</span>';
		$tone = 'none' === $why['kind'] ? 'high' : ( 'reported' === $why['kind'] ? 'pending' : 'ok' );
		echo '<span class="wpcs-badge wpcs-badge--' . esc_attr( $tone ) . '">' . esc_html( $why['label'] ) . '</span></div>';
		echo '<h2 class="wpcs-change-item__path">' . $this->path_html( $file['rel'] ) . '</h2>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
		$facts = array(
			__( 'Modified', 'qartvelo-guard' ) => '<span title="' . esc_attr( Admin::datetime( $mtime ) ) . '">' . esc_html( Admin::ago( $mtime ) ) . '</span><span class="wpcs-sub">' . esc_html( Admin::datetime( $mtime ) ) . '</span>',
			__( 'Size', 'qartvelo-guard' )     => esc_html( size_format( (int) $item['size'], (int) $item['size'] >= KB_IN_BYTES ? 1 : 0 ) ),
		);
		if ( '' !== (string) $item['sha256'] ) {
			$facts[ __( 'SHA-256', 'qartvelo-guard' ) ] = $this->short_hash( (string) $item['sha256'] );
		}
		echo '<dl class="wpcs-change-item__facts">';
		foreach ( $facts as $label => $value ) {
			echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . $value . '</dd></div>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
		}
		echo '</dl>';
		if ( 'none' === $why['kind'] && ! is_array( $why['item'] ) ) {
			echo '<div class="wpcs-change-item__actions"><p class="wpcs-muted">' . esc_html__( 'Nothing explains this change. If you do not recognise it, report the file: it then waits in Pending approvals, where you can allow it or move it to quarantine.', 'qartvelo-guard' ) . '</p>'
				. $this->report_form( $file['rel'], 'button button-primary' ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
		}
		echo '</section>';

		$this->render_change_hits( $item, $result );
		$this->render_file_diff( $result );
		echo '</div>';
	}

	/**
	 * Code card of the read-only file view (no layout links: they belong to items).
	 *
	 * @param array $result Diff::for_item() result.
	 */
	private function render_file_diff( array $result ) {
		$mode = (string) $result['mode'];
		echo '<section class="wpcs-card wpcs-diff-card" id="wpcs-diff"><div class="wpcs-diff-head"><div class="wpcs-diff-head__text">';
		if ( 'diff' === $mode ) {
			echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-editor-code" aria-hidden="true"></span>' . esc_html__( 'Line by line', 'qartvelo-guard' )
				. ' <span class="wpcs-diffstat"><span class="wpcs-diffstat__add">+' . esc_html( number_format_i18n( (int) $result['added'] ) ) . '</span>'
				. '<span class="wpcs-diffstat__del">-' . esc_html( number_format_i18n( (int) $result['removed'] ) ) . '</span></span></h2>';
			echo '<p class="wpcs-diff-head__compare"><span class="wpcs-diff-head__base">' . esc_html( (string) $result['base_label'] ) . '</span>'
				. '<span class="dashicons dashicons-arrow-right-alt" aria-hidden="true"></span><span class="wpcs-diff-head__current">' . esc_html( (string) $result['current_label'] ) . '</span></p>';
		} else {
			echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-media-code" aria-hidden="true"></span>' . esc_html( 'content' === $mode ? __( 'Full content', 'qartvelo-guard' ) : __( 'Nothing to show', 'qartvelo-guard' ) ) . '</h2>';
		}
		echo '</div></div>';
		if ( 'content' === $mode ) {
			// The item reasons speak of reports; for a file without one, say it plainly.
			$this->notice(
				'info',
				'info-outline',
				isset( $result['reason'] ) && 'too_large_to_diff' === $result['reason']
					? (string) $result['reason_text']
					: __( 'No earlier version of this file is stored and it is not an official WordPress.org file that could be compared, so its full content is shown.', 'qartvelo-guard' )
			);
		}
		foreach ( isset( $result['notes'] ) ? (array) $result['notes'] : array() as $note ) {
			$tone = isset( $note[0] ) ? (string) $note[0] : 'info';
			$icon = 'warn' === $tone ? 'warning' : ( 'ok' === $tone ? 'yes-alt' : 'info-outline' );
			$this->notice( $tone, $icon, isset( $note[1] ) ? (string) $note[1] : '' );
		}
		if ( 'unavailable' === $mode ) {
			echo '<div class="wpcs-empty wpcs-empty--compact"><span class="dashicons dashicons-media-code" aria-hidden="true"></span><p>' . esc_html( (string) $result['reason_text'] ) . '</p></div>';
		} elseif ( '' !== (string) $result['html'] ) {
			// Built by Diff with every line passed through esc_html() after redaction.
			echo '<div class="wpcs-diff-body">' . $result['html'] . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		echo '</section>';
	}

	/* ------------------------------------------------------------------ */
	/* Allowlist tab                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Allowlist entries with Remove.
	 */
	private function render_allowlist_tab() {
		echo '<div class="wpcs-notice"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span><div><p><strong>'
			. esc_html__( 'Everything you allowed, remembered permanently.', 'qartvelo-guard' ) . '</strong> '
			. esc_html__( 'File fingerprints (SHA-256) pass wherever the same file shows up again; plugin and theme entries let that install through; database entries stop one exact value at one place (an option or a post) from being reported. Removing an entry does not delete anything: it only means the file, install or value is reported again the next time it is found.', 'qartvelo-guard' )
			. '</p></div></div>';

		$per_page = 50;
		$result   = Admin::call(
			'allowlist',
			'query',
			array(
				array(
					'kind'     => $this->filters['kind'],
					'search'   => $this->search,
					'per_page' => $per_page,
					'page'     => $this->paged,
				),
			),
			null
		);
		if ( ! is_array( $result ) ) {
			$this->notice( 'bad', 'warning', __( 'The allowlist could not be loaded.', 'qartvelo-guard' ) );
			return;
		}
		$rows  = isset( $result['rows'] ) ? (array) $result['rows'] : array();
		$total = isset( $result['total'] ) ? (int) $result['total'] : 0;

		echo '<div class="wpcs-toolbar"><div></div>';
		echo '<form class="wpcs-filters" method="get" action="' . esc_url( Admin::admin_page_base() ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( Admin::PAGE_REPORTS ) . '"><input type="hidden" name="tab" value="allowlist">';
		$this->select(
			'kind',
			$this->filters['kind'],
			array(
				''        => __( 'All entries', 'qartvelo-guard' ),
				'hash'    => __( 'File fingerprints', 'qartvelo-guard' ),
				'install' => __( 'Plugins and themes', 'qartvelo-guard' ),
				'db'      => __( 'Database values', 'qartvelo-guard' ),
			),
			__( 'Filter by kind', 'qartvelo-guard' )
		);
		$this->search_box( __( 'Search name or hash', 'qartvelo-guard' ) );
		echo '</form></div>';

		if ( ! $rows ) {
			if ( '' !== $this->search || $this->filters['kind'] ) {
				$this->empty_state( 'search', __( 'No matching entries', 'qartvelo-guard' ), __( 'Nothing on the allowlist matches the current search or filter.', 'qartvelo-guard' ), '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'allowlist' ) ) ) . '">' . esc_html__( 'Show everything', 'qartvelo-guard' ) . '</a>' );
			} else {
				$this->empty_state( 'yes-alt', __( 'The allowlist is empty', 'qartvelo-guard' ), __( 'When you allow a file, its SHA-256 fingerprint is remembered here so the same file is never held again.', 'qartvelo-guard' ) );
			}
			return;
		}

		echo '<div class="wpcs-card wpcs-card--flush wpcs-table-card"><table class="widefat wpcs-table wpcs-allowlist">';
		echo '<thead><tr>';
		foreach ( array(
			'kind'   => __( 'Kind', 'qartvelo-guard' ),
			'label'  => __( 'Name', 'qartvelo-guard' ),
			'value'  => __( 'Fingerprint or install', 'qartvelo-guard' ),
			'by'     => __( 'Added by', 'qartvelo-guard' ),
			'when'   => __( 'Added', 'qartvelo-guard' ),
			'note'   => __( 'Note', 'qartvelo-guard' ),
			'remove' => '<span class="screen-reader-text">' . esc_html__( 'Actions', 'qartvelo-guard' ) . '</span>',
		) as $key => $label ) {
			echo '<th scope="col" class="column-' . esc_attr( $key ) . '">' . wp_kses( $label, array( 'span' => array( 'class' => true ) ) ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) || empty( $row['id'] ) ) {
				continue;
			}
			$entry_id = (int) $row['id'];
			$kind     = isset( $row['kind'] ) ? (string) $row['kind'] : '';
			$value    = isset( $row['value'] ) ? (string) $row['value'] : '';
			$label    = isset( $row['label'] ) && '' !== (string) $row['label'] ? (string) $row['label'] : $value;
			$ts       = Admin::utc_ts( isset( $row['created_at'] ) ? $row['created_at'] : '' );
			$by       = Admin::user_name( isset( $row['created_by'] ) ? $row['created_by'] : 0 );

			if ( 'db' === $kind ) {
				$badge   = '<span class="wpcs-badge wpcs-type wpcs-type--database"><span class="dashicons dashicons-database" aria-hidden="true"></span>' . esc_html__( 'Database', 'qartvelo-guard' ) . '</span>';
				$value_h = $this->short_hash( $value );
			} elseif ( 'install' === $kind ) {
				$is_theme = 0 === strpos( $value, 'theme:' );
				$badge    = '<span class="wpcs-badge wpcs-type wpcs-type--install"><span class="dashicons dashicons-' . ( $is_theme ? 'admin-appearance' : 'admin-plugins' ) . '" aria-hidden="true"></span>' . esc_html( $is_theme ? __( 'Theme', 'qartvelo-guard' ) : __( 'Plugin', 'qartvelo-guard' ) ) . '</span>';
				$value_h  = '<code class="wpcs-mono">' . esc_html( $value ) . '</code>';
			} else {
				$badge   = '<span class="wpcs-badge wpcs-type wpcs-type--hash"><span class="dashicons dashicons-media-default" aria-hidden="true"></span>' . esc_html__( 'File', 'qartvelo-guard' ) . '</span>';
				$value_h = $this->short_hash( $value );
			}

			$remove = wp_nonce_url(
				add_query_arg(
					array(
						'action' => 'wpcybersec_allowlist_remove',
						'entry'  => $entry_id,
					),
					admin_url( 'admin-post.php' )
				),
				'wpcybersec_allowlist_remove_' . $entry_id
			);
			/* translators: %s: entry name */
			$confirm = sprintf( __( 'Remove "%s" from the allowlist? No file is deleted, but the next time it appears it is held for your approval again.', 'qartvelo-guard' ), $label );

			echo '<tr>';
			echo '<td class="column-kind">' . $badge . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
			echo '<td class="column-label"><span class="wpcs-path">' . esc_html( $label ) . '</span></td>';
			echo '<td class="column-value">' . $value_h . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
			echo '<td class="column-by">' . esc_html( '' !== $by ? $by : __( 'System', 'qartvelo-guard' ) ) . '</td>';
			echo '<td class="column-when"><span title="' . esc_attr( Admin::datetime( $ts ) ) . '">' . esc_html( Admin::ago( $ts ) ) . '</span></td>';
			echo '<td class="column-note"><span class="wpcs-sub">' . esc_html( isset( $row['note'] ) ? (string) $row['note'] : '' ) . '</span></td>';
			echo '<td class="column-remove"><a class="button button-small wpcs-btn-danger" href="' . esc_url( $remove ) . '" data-wpcs-confirm="' . esc_attr( $confirm ) . '"><span class="dashicons dashicons-minus" aria-hidden="true"></span>' . esc_html__( 'Remove', 'qartvelo-guard' ) . '</a></td>';
			echo '</tr>';
		}
		echo '</tbody></table></div>';

		$this->render_pagination( $total, $per_page );
	}

	/* ------------------------------------------------------------------ */
	/* Activity tab                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Activity log with event filter.
	 */
	private function render_activity_tab() {
		$per_page = 50;
		$result   = Admin::call(
			'store',
			'log_query',
			array(
				array(
					'event'    => $this->filters['event'],
					'search'   => $this->search,
					'per_page' => $per_page,
					'page'     => $this->paged,
				),
			),
			null
		);
		if ( ! is_array( $result ) ) {
			$this->notice( 'bad', 'warning', __( 'The activity log could not be loaded.', 'qartvelo-guard' ) );
			return;
		}
		$rows  = isset( $result['rows'] ) ? (array) $result['rows'] : array();
		$total = isset( $result['total'] ) ? (int) $result['total'] : 0;

		$retention = (int) Admin::setting( 'log_retention_days', 90 );
		echo '<p class="wpcs-muted wpcs-tab-hint">' . esc_html(
			$retention > 0
				/* translators: %s: number of days */
				? sprintf( _n( 'Everything the plugin did or was asked to do. Entries are kept for %s day.', 'Everything the plugin did or was asked to do. Entries are kept for %s days.', $retention, 'qartvelo-guard' ), number_format_i18n( $retention ) )
				: __( 'Everything the plugin did or was asked to do. Entries are kept until you delete the plugin data.', 'qartvelo-guard' )
		) . '</p>';

		$options = array( '' => __( 'All events', 'qartvelo-guard' ) );
		foreach ( $this->log_events() as $event ) {
			$meta              = Admin::event_meta( $event );
			$options[ $event ] = $meta['label'];
		}
		if ( $this->filters['event'] && ! isset( $options[ $this->filters['event'] ] ) ) {
			$meta                                = Admin::event_meta( $this->filters['event'] );
			$options[ $this->filters['event'] ] = $meta['label'];
		}

		echo '<div class="wpcs-toolbar"><div></div>';
		echo '<form class="wpcs-filters" method="get" action="' . esc_url( Admin::admin_page_base() ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( Admin::PAGE_REPORTS ) . '"><input type="hidden" name="tab" value="activity">';
		$this->select( 'event', $this->filters['event'], $options, __( 'Filter by event', 'qartvelo-guard' ) );
		$this->search_box( __( 'Search messages', 'qartvelo-guard' ) );
		echo '</form></div>';

		if ( ! $rows ) {
			if ( '' !== $this->search || $this->filters['event'] ) {
				$this->empty_state( 'search', __( 'No matching activity', 'qartvelo-guard' ), __( 'Nothing in the log matches the current search or filter.', 'qartvelo-guard' ), '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'activity' ) ) ) . '">' . esc_html__( 'Show everything', 'qartvelo-guard' ) . '</a>' );
			} else {
				$this->empty_state( 'list-view', __( 'No activity recorded yet', 'qartvelo-guard' ), __( 'Held uploads, decisions, scans and setting changes are recorded here.', 'qartvelo-guard' ) );
			}
			return;
		}

		echo '<div class="wpcs-card wpcs-card--flush wpcs-table-card"><table class="widefat wpcs-table wpcs-activity-table">';
		echo '<thead><tr>';
		echo '<th scope="col" class="column-when">' . esc_html__( 'When', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-event">' . esc_html__( 'Event', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-message">' . esc_html__( 'Message', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-user">' . esc_html__( 'User', 'qartvelo-guard' ) . '</th>';
		echo '<th scope="col" class="column-ip">' . esc_html__( 'IP address', 'qartvelo-guard' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$event = isset( $row['event'] ) ? (string) $row['event'] : '';
			$meta  = Admin::event_meta( $event );
			$ts    = Admin::utc_ts( isset( $row['created_at'] ) ? $row['created_at'] : '' );
			$user  = Admin::user_name( isset( $row['user_id'] ) ? $row['user_id'] : 0 );
			if ( '' === $user && self::logged_by_cli( $row ) ) {
				$user = 'WP-CLI';
			}
			$url   = Admin::page_url(
				Admin::PAGE_REPORTS,
				array(
					'tab'   => 'activity',
					'event' => $event,
				)
			);
			echo '<tr>';
			echo '<td class="column-when"><span title="' . esc_attr( Admin::datetime( $ts ) ) . '">' . esc_html( Admin::ago( $ts ) ) . '</span><span class="wpcs-sub">' . esc_html( Admin::datetime( $ts ) ) . '</span></td>';
			echo '<td class="column-event"><a class="wpcs-event wpcs-event--' . esc_attr( $meta['tone'] ) . '" href="' . esc_url( $url ) . '" title="' . esc_attr__( 'Show only this event', 'qartvelo-guard' ) . '"><span class="dashicons dashicons-' . esc_attr( $meta['icon'] ) . '" aria-hidden="true"></span>' . esc_html( $meta['label'] ) . '</a></td>';
			echo '<td class="column-message">' . esc_html( isset( $row['message'] ) ? (string) $row['message'] : '' ) . '</td>';
			echo '<td class="column-user">' . esc_html( '' !== $user ? $user : __( 'System', 'qartvelo-guard' ) ) . '</td>';
			echo '<td class="column-ip"><span class="wpcs-mono">' . esc_html( isset( $row['ip'] ) ? (string) $row['ip'] : '' ) . '</span></td>';
			echo '</tr>';
		}
		echo '</tbody></table></div>';

		$this->render_pagination( $total, $per_page );
	}

	/**
	 * Distinct event names for the filter.
	 *
	 * @return string[]
	 */
	private function log_events() {
		$events = Admin::call( 'store', 'log_events', array(), null );
		if ( ! is_array( $events ) ) {
			global $wpdb;
			$table  = Store::table( 'log' );
			$events = $wpdb->get_col( "SELECT DISTINCT event FROM {$table} ORDER BY event ASC LIMIT 200" ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is Store::table(): $wpdb->prefix plus a fixed name.
		}
		$events = array_filter( array_map( 'sanitize_key', (array) $events ) );
		sort( $events );
		return array_values( array_unique( $events ) );
	}
}
