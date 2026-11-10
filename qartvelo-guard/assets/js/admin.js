/**
 * Qartvelo Guard - dashboard and reports behaviour.
 *
 * Builds on window.WPCyberSec (core.js), which already handles scan buttons,
 * single item decisions (data-wpcs-action), counts, copy and confirm links.
 * This file adds:
 *   - details rows toggle (.wpcs-details-toggle)
 *   - select all / shift-click range selection (.wpcs-cb-all, .wpcs-cb-item)
 *   - bulk decisions through WPCyberSec.bulk with row updates (#wpcs-bulk-form)
 *   - auto-submitting filter selects ([data-wpcs-autosubmit])
 *   - freeze lock unlock / lock buttons ([data-wpcs-freeze])
 *   - menu and admin bar count updates after decisions
 *   - dashboard refresh after a scan finishes ([data-wpcs-dashboard])
 *   - "+N -M lines" summary loaded when a details row opens ([data-wpcs-diff-summary])
 *   - bulk Allow / Mark safe of rows flagged high or critical asks first (tr[data-risk])
 *   - "Allow all clean images" ([data-wpcs-allow-clean]): AJAX clean_images, a confirmation
 *     with the count, then allow_clean in batches with a progress bar
 *   - changes view refresh after a decision ([data-wpcs-changes])
 */
(function () {
	'use strict';

	var api = window.WPCyberSec;
	if (!api) {
		return;
	}
	var i18n = (window.wpcybersecAdmin && window.wpcybersecAdmin.i18n) || {};
	var coreI18n = (window.wpcybersecData && window.wpcybersecData.i18n) || {};

	function t(key, fallback) {
		return i18n[key] || fallback;
	}

	/* Picks the "One" variant of a string for a count of 1. */
	function tn(key, count, fallback) {
		var text = count === 1 && i18n[key + 'One'] ? i18n[key + 'One'] : t(key, fallback);
		return api.sprintf(text, api.number(count));
	}

	function toArray(list) {
		return Array.prototype.slice.call(list || []);
	}

	/* ---------------- Details rows ---------------- */

	function setDetails(btn, open) {
		var row = document.getElementById(btn.getAttribute('aria-controls'));
		if (!row) {
			return;
		}
		if (open) {
			row.removeAttribute('hidden');
		} else {
			row.setAttribute('hidden', '');
		}
		btn.setAttribute('aria-expanded', open ? 'true' : 'false');
		var text = btn.querySelector('.wpcs-details-toggle__text');
		if (text) {
			text.textContent = open ? t('hideDetails', 'Hide details') : t('details', 'Details');
		}
		if (open) {
			loadDiffSummary(row);
		}
	}

	/* Fills "Changes: +N -M lines vs ..." once, when the details are first opened. */
	function loadDiffSummary(row) {
		var box = row.querySelector('[data-wpcs-diff-summary]');
		if (!box || box.getAttribute('data-loaded')) {
			return;
		}
		box.setAttribute('data-loaded', '1');
		var text = box.querySelector('.wpcs-diff-summary__text');
		if (!text) {
			return;
		}
		var before = text.textContent;
		text.textContent = t('comparing', 'Comparing...');
		api.ajax('diff_summary', { id: box.getAttribute('data-wpcs-diff-summary') })
			.then(function (res) {
				text.textContent = res && res.text ? res.text : before;
			})
			.catch(function () {
				text.textContent = before;
			});
	}

	function bindDetails() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('.wpcs-details-toggle');
			if (!btn) {
				return;
			}
			e.preventDefault();
			setDetails(btn, btn.getAttribute('aria-expanded') !== 'true');
		});
	}

	/* ---------------- Selection ---------------- */

	function itemBoxes(scope) {
		return toArray((scope || document).querySelectorAll('.wpcs-cb-item')).filter(function (box) {
			return !box.disabled;
		});
	}

	function syncSelectAll(table) {
		if (!table) {
			return;
		}
		var all = table.querySelector('.wpcs-cb-all');
		if (!all) {
			return;
		}
		var boxes = itemBoxes(table);
		var checked = boxes.filter(function (b) {
			return b.checked;
		}).length;
		all.checked = boxes.length > 0 && checked === boxes.length;
		all.indeterminate = checked > 0 && checked < boxes.length;
		all.disabled = boxes.length === 0;
	}

	function bindSelection() {
		var last = null;

		document.addEventListener('click', function (e) {
			var box = e.target.closest('.wpcs-cb-item');
			if (!box) {
				return;
			}
			var table = box.closest('table');
			if (e.shiftKey && last && last !== box && table && table.contains(last)) {
				var boxes = itemBoxes(table);
				var a = boxes.indexOf(last);
				var b = boxes.indexOf(box);
				if (a !== -1 && b !== -1) {
					boxes.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(function (x) {
						x.checked = box.checked;
					});
				}
			}
			last = box;
			syncSelectAll(table);
		});

		document.addEventListener('change', function (e) {
			if (!e.target.matches('.wpcs-cb-all')) {
				return;
			}
			var table = e.target.closest('table');
			itemBoxes(table).forEach(function (b) {
				b.checked = e.target.checked;
			});
			syncSelectAll(table);
		});
	}

	/* ---------------- Row updates ---------------- */

	var NEXT_STATUS = {
		approve: 'approved',
		deny: 'denied',
		ignore: 'ignored',
		quarantine: 'quarantined',
		restore: 'restored',
		'delete': 'deleted'
	};

	var STATUS_BADGE = {
		approved: 'ok',
		denied: 'muted',
		ignored: 'ok',
		quarantined: 'medium',
		restored: 'info',
		deleted: 'muted'
	};

	/* Mirrors Decisions::available() for statuses reached through a decision.
	   A file moved out of wp-admin or wp-includes (data-core="1") is not put back
	   by the plugin: only its held copy can be deleted. */
	function availableAfter(status, row) {
		if (status === 'quarantined' && row && row.getAttribute('data-core') === '1') {
			return [ 'delete' ];
		}
		if (status === 'quarantined') {
			return [ 'approve', 'restore', 'delete' ];
		}
		if (status === 'restored') {
			return [ 'approve', 'quarantine' ];
		}
		return [];
	}

	/* Whether a downloadable held copy remains after a decision. */
	function heldAfter(action) {
		return action === 'quarantine';
	}

	function applyRowState(row, status, available, held) {
		row.classList.remove('is-busy');
		row.classList.add('is-done');
		row.setAttribute('data-held', held ? '1' : '0');

		var cell = row.querySelector('[data-wpcs-status]');
		if (cell && status) {
			cell.innerHTML = '';
			var badge = document.createElement('span');
			badge.className = 'wpcs-badge wpcs-badge--' + (STATUS_BADGE[status] || 'muted');
			badge.textContent = coreI18n[status] || status;
			cell.appendChild(badge);
		}

		toArray(row.querySelectorAll('.wpcs-actions [data-wpcs-action]')).forEach(function (b) {
			b.classList.toggle('wpcs-hidden', available.indexOf(b.getAttribute('data-wpcs-action')) === -1);
		});
		// The "Reinstall WordPress core" link of a changed core file: decided now.
		toArray(row.querySelectorAll('.wpcs-actions [data-wpcs-core-link]')).forEach(function (a) {
			a.classList.add('wpcs-hidden');
		});

		var download = row.querySelector('.wpcs-download');
		if (download) {
			download.classList.toggle('wpcs-hidden', !held);
		}
		showCoreNote(row, held);

		var box = row.querySelector('.wpcs-cb-item');
		if (box) {
			box.checked = false;
			box.disabled = available.length === 0;
		}
	}

	/* The note of a file held out of wp-admin or wp-includes: shown while its copy is held. */
	function showCoreNote(row, held) {
		var note = row.querySelector('[data-wpcs-core-note]');
		if (note) {
			note.classList.toggle('wpcs-hidden', !held);
		}
	}

	/* ---------------- Counts in the admin menu and admin bar ---------------- */

	function updateMenuCounts(counts) {
		if (!counts) {
			return;
		}
		var total = (parseInt(counts.pending, 10) || 0) + (parseInt(counts.threats, 10) || 0);
		toArray(document.querySelectorAll('#adminmenu .wpcs-menu-count')).forEach(function (el) {
			el.className = el.className.replace(/\bcount-\d+\b/, 'count-' + total);
			var n = el.querySelector('.pending-count');
			if (n) {
				n.textContent = api.number(total);
			}
			var sr = el.querySelector('.screen-reader-text');
			if (sr) {
				sr.textContent = api.sprintf(t('menuCount', '%s items need your review'), api.number(total));
			}
			el.style.display = total ? '' : 'none';
		});
		toArray(document.querySelectorAll('#wp-admin-bar-wpcybersec .wpcs-ab-count')).forEach(function (el) {
			el.textContent = api.number(total);
		});
		var node = document.getElementById('wp-admin-bar-wpcybersec');
		if (node && !total) {
			node.style.display = 'none';
		}
	}

	function bindItemUpdates() {
		document.addEventListener('wpcybersec:item-updated', function (e) {
			var res = e.detail || {};
			updateMenuCounts(res.counts);
			var item = res.item;
			if (!item) {
				return;
			}
			var row = document.querySelector('[data-item-id="' + parseInt(item.id, 10) + '"]');
			if (!row) {
				return;
			}
			if (document.querySelector('[data-wpcs-changes]')) {
				// The file may have moved or changed: show the view again for its new state.
				setTimeout(function () {
					window.location.reload();
				}, 1200);
			}
			var held = !!item.quarantine_path && (item.status === 'pending' || item.status === 'quarantined');
			var available = res.available || [];
			row.setAttribute('data-held', held ? '1' : '0');
			var download = row.querySelector('.wpcs-download');
			if (download) {
				download.classList.toggle('wpcs-hidden', !held);
			}
			showCoreNote(row, held);
			var box = row.querySelector('.wpcs-cb-item');
			if (box) {
				box.checked = false;
				box.disabled = available.length === 0;
			}
			syncSelectAll(row.closest('table'));
		});
	}

	/* ---------------- Bulk actions ---------------- */

	function bindBulk() {
		var form = document.getElementById('wpcs-bulk-form');
		if (!form) {
			return;
		}
		form.addEventListener('submit', function (e) {
			var submitter = e.submitter || null;
			if (submitter && submitter.name === 'wpcs_single') {
				return; // Plain form post (core.js normally handles these buttons).
			}
			e.preventDefault();

			var select = form.querySelector('select[name="bulk_action"]');
			var action = select ? select.value : '';
			if (!action) {
				api.toast(t('chooseAction', 'Choose a bulk action first.'), true);
				return;
			}
			var boxes = toArray(document.querySelectorAll('.wpcs-cb-item:checked')).filter(function (b) {
				return !b.disabled;
			});
			if (!boxes.length) {
				api.toast(t('chooseItems', 'Select at least one item.'), true);
				return;
			}
			var ids = boxes.map(function (b) {
				return b.value;
			});
			if (action === 'delete' || action === 'deny') {
				api.confirmDialog({
					title: action === 'delete' ? tn('confirmDelete', ids.length, 'Delete %s items permanently?') : tn('confirmDeny', ids.length, 'Deny %s items?'),
					confirm: select.options[select.selectedIndex].text,
					cancel: t('cancel', 'Cancel'),
					tone: 'danger'
				}).then(function (confirmed) {
					if (confirmed) {
						runBulk(form, action, ids, null);
					}
				});
				return;
			}
			var risky = (action === 'approve' || action === 'ignore') ? riskyRows(ids) : [];
			if (risky.length) {
				var first = risky[0].querySelector('[data-wpcs-action="' + action + '"][data-wpcs-risk]');
				api.confirmDialog({
					title: tn(action === 'ignore' ? 'riskBulkSafe' : 'riskBulkAllow', risky.length, 'Allow %s risky items anyway?'),
					verdict: risky.length === 1 && first ? first.getAttribute('data-risk-verdict') : api.sprintf(t('riskBulkVerdict', '%1$s of the %2$s selected items were flagged high or critical.'), api.number(risky.length), api.number(ids.length)),
					text: first ? first.getAttribute('data-risk-text') : '',
					confirm: action === 'ignore' ? t('riskSafeYes', 'Mark safe anyway') : t('riskAllowYes', 'Allow anyway'),
					cancel: t('cancel', 'Cancel'),
					tone: 'danger'
				}).then(function (confirmed) {
					if (confirmed) {
						runBulk(form, action, ids, { risk_ok: 1 });
					}
				});
				return;
			}
			runBulk(form, action, ids, null);
		});
	}

	/* Selected rows flagged high or critical (Reports_Page sets data-risk). */
	function riskyRows(ids) {
		return ids
			.map(function (id) {
				return document.querySelector('tr[data-item-id="' + parseInt(id, 10) + '"]');
			})
			.filter(function (row) {
				return row && (parseInt(row.getAttribute('data-risk'), 10) || 0) >= 2;
			});
	}

	function runBulk(form, action, ids, extra) {
		var select = form.querySelector('select[name="bulk_action"]');
		var apply = form.querySelector('[name="wpcs_bulk_apply"]');
		var rows = ids
			.map(function (id) {
				return document.querySelector('tr[data-item-id="' + parseInt(id, 10) + '"]');
			})
			.filter(Boolean);
		rows.forEach(function (row) {
			row.classList.add('is-busy');
		});
		if (apply) {
			apply.disabled = true;
		}

		api.bulk(action, ids, extra)
			.then(function (res) {
				var failed = {};
				(res.errors || []).forEach(function (msg) {
					var m = /^#(\d+):/.exec(String(msg));
					if (m) {
						failed[m[1]] = true;
					}
				});
				var status = NEXT_STATUS[action];
				rows.forEach(function (row) {
					var id = row.getAttribute('data-item-id');
					if (failed[id]) {
						row.classList.remove('is-busy');
						return;
					}
					var held = heldAfter(action);
					applyRowState(row, status, availableAfter(status, row), held);
				});
				toArray(document.querySelectorAll('.wpcs-items')).forEach(syncSelectAll);
				updateMenuCounts(res.counts);

				var done = parseInt(res.done, 10) || 0;
				var errors = res.errors || [];
				var msg = done ? tn('bulkDone', done, '%s items updated.') : '';
				if (errors.length) {
					msg += (msg ? ' ' : '') + tn('bulkFailed', errors.length, '%s items could not be changed:') + ' ' + errors.slice(0, 3).join(' ');
					api.toast(msg, true);
				} else {
					api.toast(msg);
				}
				if (select) {
					select.value = '';
				}
			})
			.catch(function (err) {
				rows.forEach(function (row) {
					row.classList.remove('is-busy');
				});
				api.toast(err.message, true);
			})
			.then(function () {
				if (apply) {
					apply.disabled = false;
				}
			});
	}

	/* ---------------- Allow all clean images ---------------- */

	function progressBox(anchor) {
		var box = document.createElement('div');
		box.className = 'wpcs-progress wpcs-clean-progress';
		box.innerHTML = '<div class="wpcs-progress__track"><div class="wpcs-progress__bar"></div></div>'
			+ '<div class="wpcs-progress__label"><span class="wpcs-progress__text" role="status" aria-live="polite"></span></div>';
		anchor.parentNode.insertBefore(box, anchor.nextSibling);
		return {
			set: function (doneCount, total) {
				var pct = total ? Math.round((doneCount / total) * 100) : 100;
				box.querySelector('.wpcs-progress__bar').style.width = pct + '%';
				box.querySelector('.wpcs-progress__text').textContent = api.sprintf(t('cleanProgress', '%1$s of %2$s images done'), api.number(doneCount), api.number(total));
			}
		};
	}

	function runClean(ids) {
		var total = ids.length;
		var queue = ids.slice();
		var handled = 0;
		var approved = 0;
		var errors = [];
		var toolbar = document.querySelector('.wpcs-toolbar') || document.querySelector('.wpcs-tabs');
		var progress = progressBox(toolbar);
		progress.set(0, total);

		function next() {
			if (!queue.length) {
				return Promise.resolve();
			}
			var batch = queue.splice(0, 5);
			return api.ajax('allow_clean', { ids: batch }).then(function (res) {
				var left = res.remaining || [];
				queue = left.concat(queue);
				handled += batch.length - left.length;
				approved += parseInt(res.done, 10) || 0;
				errors = errors.concat(res.errors || []);
				(res.approved || []).forEach(function (id) {
					var row = document.querySelector('tr[data-item-id="' + parseInt(id, 10) + '"]');
					if (row) {
						applyRowState(row, 'approved', [], false);
					}
				});
				updateMenuCounts(res.counts);
				progress.set(handled, total);
				return next();
			});
		}

		return next().then(function () {
			var msg = tn('cleanDone', approved, '%s images were allowed and added to the Media Library.');
			if (errors.length) {
				api.toast(msg + ' ' + tn('bulkFailed', errors.length, '%s items could not be changed:') + ' ' + errors.slice(0, 3).join(' '), true);
			} else {
				api.toast(msg);
			}
			// The list shows the rows that are left.
			setTimeout(function () {
				window.location.reload();
			}, errors.length ? 6000 : 1800);
		});
	}

	function bindAllowClean() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-allow-clean]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			if (btn.disabled) {
				return;
			}
			btn.disabled = true;
			btn.setAttribute('aria-busy', 'true');
			var finish = function () {
				btn.disabled = false;
				btn.removeAttribute('aria-busy');
			};
			api.ajax('clean_images')
				.then(function (res) {
					var ids = (res && res.ids) || [];
					if (!ids.length) {
						api.toast(t('cleanNone', 'No clean images are waiting. Images with findings, and files that are not verified JPEG, PNG, GIF or WebP images, are left for you to review one by one.'));
						return null;
					}
					return api.confirmDialog({
						title: tn('cleanTitle', ids.length, 'Allow %s clean images?'),
						verdict: res.more ? t('cleanMore', 'Only the first part of a long list was checked; run it again for the rest.') : '',
						text: t('cleanText', 'Only uploads with no findings whose content was verified as a JPEG, PNG, GIF or WebP image are included. Each one is added to the Media Library and its fingerprint is remembered, like a single Allow.'),
						confirm: tn('cleanYes', ids.length, 'Allow %s images'),
						cancel: t('cancel', 'Cancel'),
						tone: 'ok'
					}).then(function (confirmed) {
						return confirmed ? runClean(ids) : null;
					});
				})
				.catch(function (err) {
					api.toast(err.message, true);
				})
				.then(finish);
		});
	}

	/* ---------------- Filters ---------------- */

	function bindAutosubmit() {
		document.addEventListener('change', function (e) {
			if (e.target.matches('[data-wpcs-autosubmit]') && e.target.form) {
				e.target.form.submit();
			}
		});
	}

	/* ---------------- Dashboard ---------------- */

	function bindFreeze() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-freeze]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			var mode = btn.getAttribute('data-wpcs-freeze');
			var params = {};
			var minutes = parseInt(btn.getAttribute('data-minutes'), 10);
			if (minutes > 0) {
				params.minutes = minutes;
			}
			btn.disabled = true;
			var label = btn.textContent;
			btn.textContent = t('working', 'Working...');
			api.ajax(mode === 'unlock' ? 'unlock' : 'lock', params)
				.then(function () {
					api.toast(mode === 'unlock' ? t('unlocked', 'Unlocked.') : t('locked', 'Locked.'));
					setTimeout(function () {
						window.location.reload();
					}, 900);
				})
				.catch(function (err) {
					btn.disabled = false;
					btn.textContent = label;
					api.toast(err.message, true);
				});
		});
	}

	function bindDashboardRefresh() {
		if (!document.querySelector('[data-wpcs-dashboard]')) {
			return;
		}
		document.addEventListener('wpcybersec:scan-finished', function (e) {
			var status = (e && e.detail) || {};
			var delay = 1400;
			if (status.otherScan && status.notice) {
				// The requested scan never got to run: leave time to read why.
				api.toast(status.notice, true);
				delay = 6000;
			} else {
				api.toast(t('refreshing', 'Scan finished. Refreshing the dashboard...'));
			}
			setTimeout(function () {
				window.location.reload();
			}, delay);
		});
	}

	/* ---------------- Init ---------------- */

	function init() {
		bindDetails();
		bindSelection();
		bindItemUpdates();
		bindBulk();
		bindAllowClean();
		bindAutosubmit();
		bindFreeze();
		bindDashboardRefresh();
		toArray(document.querySelectorAll('.wpcs-items')).forEach(syncSelectAll);
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
