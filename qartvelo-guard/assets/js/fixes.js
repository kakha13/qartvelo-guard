/**
 * Qartvelo Guard - one-click environment fixes.
 *
 * Markup (printed by the wizard environment step and Settings > Advanced):
 *   <button data-wpcs-fix="wp_config_perms">Fix permissions</button>
 *   <button data-wpcs-fix-all="wp_config_perms,file_edit,data_dir">Fix all</button>
 *   <div data-wpcs-manual="wp_config_perms" class="wpcs-hidden">...steps...</div>
 *
 * After fixes the page reloads with &recheck=1 so the checks run again.
 */
(function () {
	'use strict';

	var t = window.wpcybersecFixes || {};

	function api() {
		return window.WPCyberSec;
	}

	/**
	 * Reloads the page with &recheck=1. Assigning a URL that differs from the
	 * current one only in its #fragment would just scroll, so a URL that does
	 * not change is reloaded instead.
	 */
	function reloadFresh() {
		var url = new URL(window.location.href);
		var here = new URL(window.location.href);
		url.hash = '';
		here.hash = '';
		url.searchParams.set('recheck', '1');
		if (url.toString() === here.toString()) {
			window.location.reload();
			return;
		}
		window.location.assign(url.toString() + window.location.hash);
	}

	function showManual(id) {
		document.querySelectorAll('[data-wpcs-manual="' + id + '"]').forEach(function (el) {
			el.classList.remove('wpcs-hidden');
			if (el.tagName === 'DETAILS') {
				el.open = true;
			}
		});
	}

	/**
	 * The button's text, wrapped in a .wpcs-btn-label span on first use (in place of the text
	 * node, so a Dashicon before or after it stays where it is). Only this span is rewritten.
	 */
	function labelOf(btn) {
		var label = btn.querySelector('.wpcs-btn-label');
		if (label) {
			return label;
		}
		label = document.createElement('span');
		label.className = 'wpcs-btn-label';
		var texts = Array.prototype.slice.call(btn.childNodes).filter(function (n) {
			return n.nodeType === 3 && n.nodeValue.trim() !== '';
		});
		if (texts.length) {
			btn.insertBefore(label, texts[0]);
			texts.forEach(function (n) {
				label.appendChild(n);
			});
		} else {
			btn.appendChild(label);
		}
		return label;
	}

	function setLabel(btn, text) {
		labelOf(btn).textContent = text;
	}

	function setBusy(btn, busy) {
		var label = labelOf(btn);
		if (busy) {
			if (!btn.dataset.label) {
				btn.dataset.label = label.textContent;
			}
			label.textContent = t.working || 'Fixing...';
			btn.disabled = true;
		} else {
			label.textContent = btn.dataset.label || label.textContent;
			btn.disabled = false;
		}
	}

	function messages(map, keys) {
		return keys.map(function (k) {
			return map[k] && map[k].message ? map[k].message : map[k];
		}).filter(function (m) {
			return typeof m === 'string' && m !== '';
		});
	}

	document.addEventListener('click', function (e) {
		var one = e.target.closest('[data-wpcs-fix]');
		var all = e.target.closest('[data-wpcs-fix-all]');
		if (!one && !all) {
			return;
		}
		e.preventDefault();
		var WP = api();
		if (!WP) {
			return;
		}

		if (one) {
			var id = one.getAttribute('data-wpcs-fix');
			setBusy(one, true);
			WP.ajax('fix', { fix: id })
				.then(function (res) {
					setLabel(one, t.fixed || 'Fixed');
					var note = res && res.message ? res.message : t.allDone || 'Fixed';
					WP.toast(note);
					setTimeout(reloadFresh, note.length > 40 ? 3500 : 900);
				})
				.catch(function (err) {
					setBusy(one, false);
					showManual(id);
					WP.toast((err && err.message ? err.message + ' ' : '') + (t.failed || ''), true);
				});
			return;
		}

		var ids = (all.getAttribute('data-wpcs-fix-all') || '').split(',').filter(Boolean);
		setBusy(all, true);
		WP.ajax('fix_all', { fixes: ids })
			.then(function (res) {
				var results = (res && res.results) || {};
				var skipped = (res && res.skipped) || {};
				var ran = Object.keys(results);
				var failed = ran.filter(function (k) {
					return !results[k].ok;
				});
				var notes = messages(results, ran.filter(function (k) {
					return results[k].ok && results[k].note;
				}));
				// Fixes that need their own button (the early guard, the cron switch).
				var skippedNotes = messages(skipped, Object.keys(skipped));

				failed.forEach(showManual);
				if (failed.length) {
					setBusy(all, false);
					WP.toast(messages(results, failed).concat(skippedNotes).join(' '), true);
					setTimeout(reloadFresh, 3500);
					return;
				}
				if (!ran.length) {
					setBusy(all, false);
					WP.toast(skippedNotes.join(' ') || t.nothing || 'Nothing to fix.');
					return;
				}
				var done = skippedNotes.length ? t.partDone || t.allDone || 'Done' : t.allDone || 'Done';
				var text = [done].concat(notes, skippedNotes).join(' ');
				WP.toast(text);
				setTimeout(reloadFresh, text.length > 60 ? 4000 : 700);
			})
			.catch(function (err) {
				setBusy(all, false);
				WP.toast(err.message, true);
			});
	});
})();
