/**
 * Qartvelo Guard - "WordPress core looks damaged" card (Dashboard, Reports).
 *
 * Builds on window.WPCyberSec (core.js):
 *   [data-wpcs-core-start]    confirmDialog() with the texts on the button (data-title,
 *                             data-verdict, data-text, data-confirm-label), then ONE request:
 *                             AJAX core_reinstall do=run. WordPress reinstalls its own core in
 *                             that request (its built-in updater); the button is busy meanwhile.
 *                             The answer is a message, plus the quick scan the server started,
 *                             which is followed in the progress block before the page reloads.
 *   [data-wpcs-core-dismiss]  AJAX core_reinstall do=dismiss (hides the outcome of the last reinstall).
 */
(function () {
	'use strict';

	var api = window.WPCyberSec;
	if (!api) {
		return;
	}
	var i18n = (window.wpcybersecCore && window.wpcybersecCore.i18n) || {};
	var coreI18n = (window.wpcybersecData && window.wpcybersecData.i18n) || {};
	var generic = coreI18n.error || 'Request failed';

	function reloadSoon(ms) {
		window.setTimeout(function () {
			window.location.reload();
		}, ms);
	}

	function setStatus(root, text, isError) {
		var el = root && root.querySelector('[data-wpcs-core-status]');
		if (!el) {
			return;
		}
		el.textContent = text || '';
		el.classList.toggle('wpcs-hidden', !text);
		el.classList.toggle('is-error', !!isError);
	}

	function setBusy(root, btn, busy) {
		btn.disabled = busy;
		btn.classList.toggle('is-busy', busy);
		if (root) {
			if (busy) {
				root.setAttribute('aria-busy', 'true');
			} else {
				root.removeAttribute('aria-busy');
			}
		}
	}

	function run(root, btn) {
		setBusy(root, btn, true);
		setStatus(root, i18n.working || 'WordPress is reinstalling its core. Keep this page open.', false);
		api.ajax('core_reinstall', { do: 'run' }).then(function (res) {
			var message = res.message || coreI18n.done || 'Done';
			setStatus(root, message, false);
			api.toast(message);
			btn.classList.remove('is-busy');
			var prog = root && root.querySelector('[data-wpcs-core-progress]');
			if (res.scan && api.scan && typeof api.scan.attach === 'function' && api.scan.isRunning(res.scan)) {
				return api.scan.attach(function (status) {
					if (prog) {
						api.renderProgress(prog, status);
					}
				}).then(function () {
					window.location.reload();
				}, function () {
					window.location.reload();
				});
			}
			reloadSoon(1500);
			return null;
		}).catch(function (err) {
			var message = (err && err.message) || generic;
			if (message === generic) {
				// No JSON came back (a proxy timeout, the maintenance page): the updater may still be running.
				message = i18n.timeout || message;
			}
			setBusy(root, btn, false);
			setStatus(root, message, true);
			api.toast(message, true);
		});
	}

	document.addEventListener('click', function (e) {
		var btn = e.target.closest('[data-wpcs-core-start]');
		if (btn) {
			e.preventDefault();
			if (btn.disabled) {
				return;
			}
			var root = btn.closest('[data-wpcs-core]');
			api.confirmDialog({
				title: btn.getAttribute('data-title') || btn.textContent.trim(),
				verdict: btn.getAttribute('data-verdict') || '',
				text: btn.getAttribute('data-text') || '',
				confirm: btn.getAttribute('data-confirm-label') || btn.textContent.trim(),
				tone: 'danger'
			}).then(function (ok) {
				if (ok) {
					run(root, btn);
				}
			});
			return;
		}

		btn = e.target.closest('[data-wpcs-core-dismiss]');
		if (btn) {
			e.preventDefault();
			btn.disabled = true;
			api.ajax('core_reinstall', { do: 'dismiss' }).then(function () {
				var box = btn.closest('[data-wpcs-core-result]');
				if (box) {
					box.parentNode.removeChild(box);
				}
			}).catch(function (err) {
				btn.disabled = false;
				api.toast((err && err.message) || generic, true);
			});
		}
	});
})();
