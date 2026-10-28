/**
 * Qartvelo Guard - shared admin script.
 *
 * Exposes window.WPCyberSec:
 *   ajax(name, params)            POST to admin-ajax "wpcybersec_<name>", resolves with response.data
 *   toast(message, isError)       Small bottom-right message
 *   sprintf(fmt, a, b)            Replaces %s and %1$s style placeholders
 *   scan.start(opts)              opts: { mode: incremental|full|baseline, malware: bool, trigger }
 *   scan.run(opts, onProgress)    Starts (or attaches to a running scan) and ticks until finished.
 *                                 When a scan of another mode was already running, it toasts the
 *                                 server's notice (unless opts.quiet) and the final status gets
 *                                 otherScan: true and requested: <mode>.
 *   scan.attach(onProgress)       Keeps ticking a scan that is already running
 *   scan.cancel()
 *   renderProgress(el, status)    Fills a .wpcs-progress block
 *   itemAction(action, id, extra) Applies a decision, resolves with { item, available, counts, message }
 *                                 (extra: more fields, e.g. { risk_ok: 1 } after the risk dialog)
 *   bulk(action, ids, extra)      Bulk decision, resolves with { done, errors, counts }
 *   confirmDialog(opts)           Accessible modal confirmation (native <dialog>), resolves true / false.
 *                                 opts: { title, verdict, text, confirm, cancel, tone: 'danger'|'ok' }.
 *                                 Focus starts on Cancel; Escape and the backdrop cancel.
 *
 * Declarative hooks (no extra JS needed):
 *   <button data-wpcs-scan data-mode="full" data-malware="1" data-target="#prog" data-reload="1">
 *   <div id="prog" class="wpcs-progress wpcs-hidden" data-wpcs-progress-auto> ...markup below... </div>
 *   <button data-wpcs-action="approve" data-id="12" [data-confirm="..."]>   inside a <tr data-item-id="12">
 *   <button data-wpcs-action="approve" data-wpcs-risk="3" data-risk-title data-risk-verdict data-risk-text data-risk-confirm data-risk-cancel>
 *                                 items flagged high or critical: confirmDialog() first, then risk_ok=1
 *   <span data-wpcs-count="pending|threats|quarantined">3</span>
 *   <button class="wpcs-copy" data-wpcs-copy>                              inside .wpcs-code (copies its <pre>)
 *   <a data-wpcs-confirm="Message">                                        asks before following a link / submitting
 *   <button data-wpcs-clamav-enable>                                       turns on ClamAV for uploads, then reloads
 *
 * Progress markup:
 *   <div class="wpcs-progress">
 *     <div class="wpcs-progress__track"><div class="wpcs-progress__bar"></div></div>
 *     <div class="wpcs-progress__label"><span class="wpcs-progress__text"></span><span class="wpcs-progress__current"></span></div>
 *   </div>
 */
(function () {
	'use strict';

	var data = window.wpcybersecData || {};
	var i18n = data.i18n || {};
	var RUNNING = [ 'enumerating', 'processing', 'finishing' ];

	function sprintf(fmt) {
		var args = Array.prototype.slice.call(arguments, 1);
		var i = 0;
		return String(fmt).replace(/%(\d+)\$s|%s/g, function (m, n) {
			var v = n ? args[parseInt(n, 10) - 1] : args[i++];
			return v === undefined ? '' : String(v);
		});
	}

	function number(n) {
		n = parseInt(n, 10) || 0;
		try {
			return n.toLocaleString();
		} catch (e) {
			return String(n);
		}
	}

	function ajax(name, params) {
		var body = new FormData();
		body.append('action', 'wpcybersec_' + name);
		body.append('_ajax_nonce', data.nonce || '');
		Object.keys(params || {}).forEach(function (key) {
			var value = params[key];
			if (Array.isArray(value)) {
				value.forEach(function (v) {
					body.append(key + '[]', v);
				});
			} else if (typeof value === 'boolean') {
				body.append(key, value ? '1' : '0');
			} else if (value !== undefined && value !== null) {
				body.append(key, value);
			}
		});
		return fetch(data.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body })
			.then(function (r) {
				return r.json().catch(function () {
					throw new Error(i18n.error || 'Request failed');
				});
			})
			.then(function (res) {
				if (!res || !res.success) {
					throw new Error((res && res.data && res.data.message) || i18n.error || 'Request failed');
				}
				return res.data;
			});
	}

	var toastTimer = null;
	/* The live region is created empty in init(), so screen readers know it before the first message. */
	function toastRegion() {
		var el = document.querySelector('.wpcs-toast');
		if (!el) {
			el = document.createElement('div');
			el.className = 'wpcs-toast';
			el.setAttribute('role', 'status');
			el.setAttribute('aria-live', 'polite');
			document.body.appendChild(el);
		}
		return el;
	}
	function toast(message, isError) {
		var el = toastRegion();
		el.textContent = message;
		el.classList.toggle('wpcs-toast--error', !!isError);
		el.classList.add('is-visible');
		clearTimeout(toastTimer);
		toastTimer = setTimeout(function () {
			el.classList.remove('is-visible');
		}, isError ? 6000 : 3000);
	}

	/* ---------------- Scans ---------------- */

	function isRunning(status) {
		return status && RUNNING.indexOf(status.state) !== -1;
	}

	function wait(ms) {
		return new Promise(function (resolve) {
			setTimeout(resolve, ms);
		});
	}

	/* Ticks until the scan stops running. A tick refused because another runner holds the lock
	   (locked_out) returns at once, and so may one that made no progress: both wait before the
	   next request instead of sending back-to-back admin-ajax requests from a second tab. */
	function loop(onProgress, previous) {
		return ajax('scan_tick').then(function (status) {
			if (onProgress) {
				onProgress(status);
			}
			if (!isRunning(status)) {
				return status;
			}
			var delay = 0;
			if (status.locked_out) {
				delay = 1500;
			} else if (previous && previous.state === status.state && String(previous.files_done) === String(status.files_done) && String(previous.files_total) === String(status.files_total)) {
				delay = 1000;
			}
			if (!delay) {
				return loop(onProgress, status);
			}
			return wait(delay).then(function () {
				return loop(onProgress, status);
			});
		});
	}

	var scan = {
		start: function (opts) {
			opts = opts || {};
			return ajax('scan_start', {
				mode: opts.mode || 'incremental',
				malware: opts.malware === undefined ? true : !!opts.malware,
				trigger: opts.trigger || 'manual'
			});
		},
		run: function (opts, onProgress) {
			opts = opts || {};
			var requested = opts.mode || 'incremental';
			return scan.start(opts).then(function (status) {
				// The server returned a scan that was already running instead of starting ours.
				var other = !!(status && status.attached && status.mode && status.mode !== requested);
				if (other && !opts.quiet && status.notice) {
					toast(status.notice);
				}
				if (onProgress) {
					onProgress(status);
				}
				var done = isRunning(status) ? loop(onProgress) : Promise.resolve(status);
				return done.then(function (final) {
					if (other && final) {
						final.otherScan = true;
						final.requested = requested;
						final.notice = status.notice || '';
					}
					return final;
				});
			});
		},
		attach: function (onProgress) {
			return ajax('scan_status').then(function (status) {
				if (onProgress) {
					onProgress(status);
				}
				return isRunning(status) ? loop(onProgress) : status;
			});
		},
		cancel: function () {
			return ajax('scan_cancel');
		},
		isRunning: isRunning
	};

	function renderProgress(el, status) {
		if (!el || !status) {
			return;
		}
		el.classList.remove('wpcs-hidden');
		var bar = el.querySelector('.wpcs-progress__bar');
		var text = el.querySelector('.wpcs-progress__text');
		var current = el.querySelector('.wpcs-progress__current');
		var state = status.state || 'idle';
		var indeterminate = state === 'enumerating';
		el.classList.toggle('is-indeterminate', indeterminate);

		var pct = Math.max(0, Math.min(100, parseFloat(status.percent) || 0));
		if (state === 'done') {
			pct = 100;
		}
		if (bar) {
			bar.style.width = indeterminate ? '' : pct + '%';
		}
		var label;
		if (state === 'enumerating') {
			// The job saves its count only between steps, so 0 means "not known yet".
			label = (i18n.enumerating || 'Listing files') + (parseInt(status.files_total, 10) > 0 ? ' - ' + sprintf(i18n.filesFound || '%s files found so far', number(status.files_total)) : '...');
		} else if (state === 'processing') {
			label = (i18n.processing || 'Checking files') + ' - ' + sprintf(i18n.filesChecked || '%1$s of %2$s files checked', number(status.files_done), number(status.files_total));
		} else if (state === 'finishing') {
			label = i18n.finishing || 'Finishing';
		} else if (state === 'done') {
			label = (i18n.done || 'Scan complete') + (status.message ? ' - ' + status.message : '');
		} else if (state === 'failed') {
			label = (i18n.failed || 'Scan failed') + (status.message ? ': ' + status.message : '');
		} else if (state === 'cancelled') {
			label = i18n.cancelled || 'Scan cancelled';
		} else {
			label = status.message || '';
		}
		if (text) {
			text.textContent = label;
		}
		if (current) {
			current.textContent = isRunning(status) ? status.current || '' : '';
		}
	}

	function setScanButtons(disabled) {
		document.querySelectorAll('[data-wpcs-scan]').forEach(function (b) {
			b.disabled = disabled;
		});
	}

	function bindScanButtons() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-scan]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			if (btn.disabled) {
				return;
			}
			if (btn.getAttribute('data-confirm')) {
				confirmDialog({ title: btn.getAttribute('data-confirm'), tone: 'ok', confirm: i18n.confirmYes || 'Continue' }).then(function (confirmed) {
					// Started directly rather than through a second click, so nothing is left behind
					// when autoAttach() disabled the button meanwhile (a scan began elsewhere).
					if (confirmed && !btn.disabled) {
						startScan(btn);
					}
				});
				return;
			}
			startScan(btn);
		});
	}

	function startScan(btn) {
		var target = document.querySelector(btn.getAttribute('data-target') || '[data-wpcs-progress-auto]');
		var opts = {
			mode: btn.getAttribute('data-mode') || 'incremental',
			malware: btn.getAttribute('data-malware') !== '0',
			trigger: btn.getAttribute('data-trigger') || 'manual'
		};
		var onProgress = function (status) {
			renderProgress(target, status);
			document.dispatchEvent(new CustomEvent('wpcybersec:scan-progress', { detail: status }));
		};
		// Another scan was running and has finished: start the one that was asked for, once.
		var runRequested = function (attempt) {
			return scan.run(opts, onProgress).then(function (status) {
				if (status && status.otherScan && status.state === 'done' && attempt < 1) {
					return runRequested(attempt + 1);
				}
				if (status && status.otherScan && status.notice) {
					toast(status.notice, true);
				}
				return status;
			});
		};
		setScanButtons(true);
		runRequested(0)
			.then(function (status) {
				document.dispatchEvent(new CustomEvent('wpcybersec:scan-finished', { detail: status }));
				if (btn.getAttribute('data-reload') === '1') {
					setTimeout(function () {
						window.location.reload();
					}, 900);
				} else {
					setScanButtons(false);
				}
			})
			.catch(function (err) {
				toast(err.message, true);
				setScanButtons(false);
			});
	}

	function autoAttach() {
		var target = document.querySelector('[data-wpcs-progress-auto]');
		if (!target) {
			return;
		}
		ajax('scan_status')
			.then(function (status) {
				if (!isRunning(status)) {
					return;
				}
				setScanButtons(true);
				renderProgress(target, status);
				return loop(function (s) {
					renderProgress(target, s);
				}).then(function (s) {
					document.dispatchEvent(new CustomEvent('wpcybersec:scan-finished', { detail: s }));
					setScanButtons(false);
				});
			})
			.catch(function () {});
	}

	/* ---------------- Item decisions ---------------- */

	function updateCounts(counts) {
		if (!counts) {
			return;
		}
		Object.keys(counts).forEach(function (key) {
			document.querySelectorAll('[data-wpcs-count="' + key + '"]').forEach(function (el) {
				el.textContent = number(counts[key]);
				el.classList.toggle('wpcs-count--zero', !counts[key]);
			});
		});
	}

	function merge(base, extra) {
		Object.keys(extra || {}).forEach(function (key) {
			base[key] = extra[key];
		});
		return base;
	}

	function itemAction(action, id, extra) {
		return ajax('item_action', merge({ do: action, id: id }, extra)).then(function (res) {
			updateCounts(res.counts);
			return res;
		});
	}

	function bulk(action, ids, extra) {
		return ajax('bulk_action', merge({ do: action, ids: ids }, extra)).then(function (res) {
			updateCounts(res.counts);
			return res;
		});
	}

	/* ---------------- Confirmation dialog ---------------- */

	var dialogSeq = 0;

	function confirmDialog(opts) {
		opts = opts || {};
		var probe = document.createElement('dialog');
		if (typeof probe.showModal !== 'function') {
			// Browsers without <dialog>: the plain confirm box still says everything.
			return Promise.resolve(window.confirm([opts.title, opts.verdict, opts.text].filter(Boolean).join('\n\n')));
		}
		return new Promise(function (resolve) {
			var id = 'wpcs-dialog-' + ++dialogSeq;
			var previous = document.activeElement;
			var d = document.createElement('dialog');
			d.className = 'wpcs-dialog wpcs-dialog--' + (opts.tone === 'ok' ? 'ok' : 'danger');
			d.setAttribute('aria-labelledby', id + '-title');
			d.setAttribute('aria-describedby', id + '-desc');

			var head = document.createElement('div');
			head.className = 'wpcs-dialog__head';
			var icon = document.createElement('span');
			icon.className = 'dashicons dashicons-' + (opts.tone === 'ok' ? 'format-gallery' : 'warning');
			icon.setAttribute('aria-hidden', 'true');
			var title = document.createElement('h2');
			title.id = id + '-title';
			title.textContent = opts.title || i18n.confirm || 'Are you sure?';
			head.appendChild(icon);
			head.appendChild(title);
			d.appendChild(head);

			var desc = document.createElement('div');
			desc.id = id + '-desc';
			desc.className = 'wpcs-dialog__body';
			if (opts.verdict) {
				var verdict = document.createElement('p');
				verdict.className = 'wpcs-dialog__verdict';
				verdict.textContent = opts.verdict;
				desc.appendChild(verdict);
			}
			if (opts.text) {
				var text = document.createElement('p');
				text.textContent = opts.text;
				desc.appendChild(text);
			}
			d.appendChild(desc);

			var actions = document.createElement('div');
			actions.className = 'wpcs-dialog__actions';
			var cancel = document.createElement('button');
			cancel.type = 'button';
			cancel.className = 'button button-primary';
			cancel.textContent = opts.cancel || i18n.cancel || 'Cancel';
			var ok = document.createElement('button');
			ok.type = 'button';
			ok.className = 'button ' + (opts.tone === 'ok' ? 'wpcs-btn-approve' : 'wpcs-btn-danger');
			ok.textContent = opts.confirm || i18n.confirmYes || 'Continue';
			actions.appendChild(cancel);
			actions.appendChild(ok);
			d.appendChild(actions);

			cancel.addEventListener('click', function () {
				d.close('cancel');
			});
			ok.addEventListener('click', function () {
				d.close('confirm');
			});
			d.addEventListener('click', function (e) {
				if (e.target === d) {
					d.close('cancel'); // Click on the backdrop.
				}
			});
			d.addEventListener('close', function () {
				var confirmed = d.returnValue === 'confirm';
				if (d.parentNode) {
					d.parentNode.removeChild(d);
				}
				if (previous && typeof previous.focus === 'function' && document.contains(previous)) {
					previous.focus();
				}
				resolve(confirmed);
			});
			// Inside the plugin wrapper (its colour tokens); the modal itself sits in the top layer.
			(document.querySelector('.wpcs-wrap') || document.body).appendChild(d);
			d.showModal();
			cancel.focus();
		});
	}

	/* Options of the risk dialog from a button's data-risk-* attributes. */
	function riskOptions(btn) {
		return {
			title: btn.getAttribute('data-risk-title') || '',
			verdict: btn.getAttribute('data-risk-verdict') || '',
			text: btn.getAttribute('data-risk-text') || '',
			confirm: btn.getAttribute('data-risk-confirm') || '',
			cancel: btn.getAttribute('data-risk-cancel') || '',
			tone: 'danger'
		};
	}

	var STATUS_LABEL = {
		approved: { text: i18n.approved || 'Approved', cls: 'ok' },
		denied: { text: i18n.denied || 'Denied', cls: 'muted' },
		ignored: { text: i18n.ignored || 'Marked safe', cls: 'ok' },
		quarantined: { text: i18n.quarantined || 'Quarantined', cls: 'medium' },
		restored: { text: i18n.restored || 'Restored', cls: 'info' },
		deleted: { text: i18n.deleted || 'Deleted', cls: 'muted' },
		resolved: { text: i18n.resolved || 'Resolved', cls: 'muted' }
	};

	function bindItemActions() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-action]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			var action = btn.getAttribute('data-wpcs-action');
			var id = btn.getAttribute('data-id');
			if (btn.hasAttribute('data-wpcs-risk')) {
				// Flagged high or critical: the dialog names the finding before anything is allowed.
				confirmDialog(riskOptions(btn)).then(function (confirmed) {
					if (confirmed) {
						runItemAction(btn, action, id, { risk_ok: 1 });
					}
				});
				return;
			}
			var confirmMsg = btn.getAttribute('data-confirm') || (action === 'delete' ? i18n.confirmDelete : '');
			if (confirmMsg) {
				confirmDialog({ title: confirmMsg, tone: 'danger', confirm: btn.textContent.trim() || i18n.confirmYes || 'Continue' }).then(function (confirmed) {
					if (confirmed) {
						runItemAction(btn, action, id, null);
					}
				});
				return;
			}
			runItemAction(btn, action, id, null);
		});
	}

	function runItemAction(btn, action, id, extra) {
		var row = btn.closest('[data-item-id]');
		// The row's buttons are disabled while the request runs: the CSS pointer-events rule
		// stops the mouse, but not a second Enter on the still focused button.
		var buttons = row ? row.querySelectorAll('[data-wpcs-action]') : [ btn ];
		var setBusy = function (busy) {
			Array.prototype.forEach.call(buttons, function (b) {
				b.disabled = busy;
			});
			if (row) {
				row.classList.toggle('is-busy', busy);
				if (busy) {
					row.setAttribute('aria-busy', 'true');
				} else {
					row.removeAttribute('aria-busy');
				}
			}
		};
		setBusy(true);
		itemAction(action, id, extra)
			.then(function (res) {
				var status = res.item ? res.item.status : action;
				var label = STATUS_LABEL[status] || { text: status, cls: 'muted' };
				setBusy(false);
				if (row) {
					row.classList.add('is-done');
					var statusCell = row.querySelector('[data-wpcs-status]');
					if (statusCell) {
						statusCell.innerHTML = '';
						var badge = document.createElement('span');
						badge.className = 'wpcs-badge wpcs-badge--' + label.cls;
						badge.textContent = label.text;
						statusCell.appendChild(badge);
					}
					var actions = row.querySelector('.wpcs-actions');
					if (actions) {
						actions.querySelectorAll('[data-wpcs-action]').forEach(function (b) {
							var allowed = (res.available || []).indexOf(b.getAttribute('data-wpcs-action')) !== -1;
							b.classList.toggle('wpcs-hidden', !allowed);
						});
					}
				}
				// Extra instructions from the server (for example "upload the ZIP again") win over the generic text.
				toast(res.message ? res.message : label.text + ': ' + (res.item ? res.item.path : '#' + id));
				document.dispatchEvent(new CustomEvent('wpcybersec:item-updated', { detail: res }));
			})
			.catch(function (err) {
				setBusy(false);
				toast(err.message, true);
			});
	}

	/* ---------------- Misc ---------------- */

	function copyText(text) {
		if (navigator.clipboard && window.isSecureContext) {
			return navigator.clipboard.writeText(text);
		}
		var ta = document.createElement('textarea');
		ta.value = text;
		ta.style.position = 'fixed';
		ta.style.opacity = '0';
		document.body.appendChild(ta);
		ta.select();
		try {
			document.execCommand('copy');
		} finally {
			document.body.removeChild(ta);
		}
		return Promise.resolve();
	}

	function bindCopy() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-copy]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			var sel = btn.getAttribute('data-wpcs-copy');
			var src = sel ? document.querySelector(sel) : null;
			if (!src) {
				var box = btn.closest('.wpcs-code');
				src = box ? box.querySelector('pre') : null;
			}
			if (!src) {
				return;
			}
			copyText(src.value !== undefined && src.tagName === 'TEXTAREA' ? src.value : src.textContent).then(function () {
				// Keep an icon inside the button: swap only the text.
				var label = btn.querySelector('.wpcs-btn-label');
				if (!label) {
					label = document.createElement('span');
					label.className = 'wpcs-btn-label';
					Array.prototype.slice.call(btn.childNodes).forEach(function (n) {
						if (n.nodeType === 3) {
							label.appendChild(n);
						}
					});
					btn.appendChild(label);
				}
				clearTimeout(btn._wpcsCopied);
				if (!btn.hasAttribute('data-label')) {
					btn.setAttribute('data-label', label.textContent);
				}
				label.textContent = i18n.copied || 'Copied';
				btn._wpcsCopied = setTimeout(function () {
					label.textContent = btn.getAttribute('data-label');
				}, 1500);
			});
		});
	}

	/* Follows a confirmed link or submits its form directly. A second, synthetic click would need
	   an "already confirmed" flag, and that flag stays behind when the control is disabled by then. */
	function proceed(el) {
		if (el.tagName === 'A') {
			if (el.href) {
				window.location.href = el.href;
			}
			return;
		}
		var form = el.form || el.closest('form');
		if (!form) {
			return;
		}
		if (typeof form.requestSubmit === 'function') {
			form.requestSubmit(el.type === 'submit' ? el : undefined);
		} else {
			form.submit();
		}
	}

	function bindConfirm() {
		document.addEventListener('click', function (e) {
			var el = e.target.closest('[data-wpcs-confirm]');
			if (!el) {
				return;
			}
			e.preventDefault();
			e.stopImmediatePropagation();
			confirmDialog({ title: el.getAttribute('data-wpcs-confirm') || i18n.confirm || 'Are you sure?', tone: 'danger', confirm: (el.textContent || el.value || '').trim() || i18n.confirmYes || 'Continue' }).then(function (confirmed) {
				if (confirmed) {
					proceed(el);
				}
			});
		}, true);
	}

	function bindClamavEnable() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-clamav-enable]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			if (btn.disabled) {
				return;
			}
			btn.disabled = true;
			btn.setAttribute('aria-busy', 'true');
			ajax('clamav_enable')
				.then(function (res) {
					toast(res && res.message ? res.message : '');
					// The settings form must not warn about unsaved changes on this reload.
					window.wpcsSkipUnload = true;
					setTimeout(function () {
						window.location.reload();
					}, 1200);
				})
				.catch(function (err) {
					btn.disabled = false;
					btn.removeAttribute('aria-busy');
					toast(err.message, true);
				});
		});
	}

	function bindOptionCards() {
		document.addEventListener('change', function (e) {
			if (!e.target.matches('.wpcs-option input[type="radio"]')) {
				return;
			}
			var name = e.target.name;
			document.querySelectorAll('.wpcs-option input[name="' + name + '"]').forEach(function (r) {
				r.closest('.wpcs-option').classList.toggle('is-selected', r.checked);
			});
		});
	}

	window.WPCyberSec = {
		ajax: ajax,
		toast: toast,
		sprintf: sprintf,
		number: number,
		scan: scan,
		renderProgress: renderProgress,
		itemAction: itemAction,
		bulk: bulk,
		confirmDialog: confirmDialog,
		updateCounts: updateCounts,
		copyText: copyText
	};

	function init() {
		toastRegion();
		bindConfirm();
		bindScanButtons();
		bindItemActions();
		bindCopy();
		bindClamavEnable();
		bindOptionCards();
		autoAttach();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
