/**
 * Qartvelo Guard - setup wizard and settings page.
 *
 * Uses window.WPCyberSec from core.js. Behaviour:
 *   - protection level cards sync the related fields to the preset values
 *   - "Custom" hint when the fields differ from the selected preset
 *   - wizard baseline scan runner with progress and result (Continue becomes
 *     the main action once a baseline exists)
 *   - wizard upload policy radios follow the chosen protection level
 *   - test email button (AJAX, falls back to the form submit without JS)
 *   - freeze lock Unlock / Lock buttons
 *   - Settings > Advanced section chips work as tabs (one section at a time)
 *   - custom scan folder field toggle
 *   - unsaved changes warning on the settings form
 */
(function () {
	'use strict';

	var data = window.wpcybersecSetup || {};
	var i18n = data.i18n || {};
	var presets = data.presets || {};
	var levels = data.levels || {};

	/** Preset keys that do not decide the level (must match Sysadmin_Tools::LEVEL_IGNORE). */
	var LEVEL_IGNORE = ['notify_mode'];

	function api() {
		return window.WPCyberSec || null;
	}

	function fmt(text) {
		var S = api();
		var args = Array.prototype.slice.call(arguments);
		if (S && S.sprintf) {
			return S.sprintf.apply(null, args);
		}
		var rest = args.slice(1);
		var i = 0;
		return String(text).replace(/%(\d+)\$s|%s/g, function (m, n) {
			var v = n ? rest[parseInt(n, 10) - 1] : rest[i++];
			return v === undefined ? '' : String(v);
		});
	}

	function toast(message, isError) {
		var S = api();
		if (S && S.toast) {
			S.toast(message, isError);
		} else if (message) {
			window.alert(message);
		}
	}

	function each(list, fn) {
		Array.prototype.forEach.call(list || [], fn);
	}

	/* ------------------------------------------------------------------ */
	/* Protection level presets                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Wizard toggles and how they derive from a preset.
	 */
	var WIZARD_SYNC = {
		hold_admin_uploads: function (p) {
			return (p.upload_bypass_roles || []).indexOf('administrator') === -1;
		},
		hold_installs: function (p) {
			return p.install_mode === 'hold';
		},
		quarantine_php: function (p) {
			return p.file_mode === 'quarantine_exec';
		}
	};

	/**
	 * Wizard radio groups and the value a preset gives them.
	 */
	var WIZARD_RADIOS = {
		upload_mode: function (p) {
			return p.upload_mode === 'hold_risky' ? 'hold_risky' : 'hold_all';
		}
	};

	function radioValue(form, name) {
		var checked = form.querySelector('input[type="radio"][name="' + name + '"]:checked');
		return checked ? checked.value : '';
	}

	function selectedLevel(form) {
		var checked = form.querySelector('input[data-wpcs-level]:checked');
		return checked ? checked.value : '';
	}

	/**
	 * Current value of a named field, with PHP "last value wins" semantics
	 * (hidden "0" followed by a checkbox).
	 */
	function fieldValue(form, key) {
		var multi = form.querySelectorAll('input[name="' + key + '[]"]');
		if (multi.length) {
			var values = [];
			each(multi, function (el) {
				if (el.checked) {
					values.push(el.value);
				}
			});
			return values;
		}
		var els = form.querySelectorAll('[name="' + key + '"]');
		if (!els.length) {
			return undefined;
		}
		var value;
		each(els, function (el) {
			if (el.type === 'radio' || el.type === 'checkbox') {
				if (el.checked) {
					value = el.value;
				}
			} else {
				value = el.value;
			}
		});
		return value;
	}

	function sameValue(expected, actual) {
		if (actual === undefined) {
			return true;
		}
		if (Array.isArray(expected)) {
			var a = (actual || []).slice().sort();
			var b = expected.slice().sort();
			return a.length === b.length && a.every(function (v, i) {
				return v === b[i];
			});
		}
		if (typeof expected === 'boolean') {
			return (actual === '1') === expected;
		}
		return String(actual) === String(expected);
	}

	function applyPreset(form, preset) {
		Object.keys(preset).forEach(function (key) {
			var expected = preset[key];
			var multi = form.querySelectorAll('input[name="' + key + '[]"]');
			if (multi.length) {
				each(multi, function (el) {
					el.checked = Array.isArray(expected) && expected.indexOf(el.value) !== -1;
				});
				return;
			}
			each(form.querySelectorAll('[name="' + key + '"]'), function (el) {
				if (el.type === 'radio') {
					el.checked = el.value === String(expected);
				} else if (el.type === 'checkbox') {
					el.checked = typeof expected === 'boolean' ? expected : el.value === String(expected);
				} else if (el.tagName === 'SELECT') {
					el.value = String(expected);
				}
			});
		});
	}

	function differsFromPreset(form, preset, isWizard) {
		if (isWizard) {
			var toggles = Object.keys(WIZARD_SYNC).some(function (key) {
				var el = form.querySelector('[data-wpcs-sync="' + key + '"]');
				return el && el.checked !== WIZARD_SYNC[key](preset);
			});
			return toggles || Object.keys(WIZARD_RADIOS).some(function (name) {
				var value = radioValue(form, name);
				return value !== '' && value !== WIZARD_RADIOS[name](preset);
			});
		}
		return Object.keys(preset).some(function (key) {
			if (LEVEL_IGNORE.indexOf(key) !== -1) {
				return false;
			}
			return !sameValue(preset[key], fieldValue(form, key));
		});
	}

	function updateHint(form, isWizard) {
		var hint = form.querySelector('[data-wpcs-custom-hint]');
		if (!hint) {
			return;
		}
		var level = selectedLevel(form);
		var preset = presets[level];
		var differs = preset ? differsFromPreset(form, preset, isWizard) : false;
		hint.textContent = differs ? fmt(i18n.customHint || '%s', levels[level] || level) : '';
		hint.classList.toggle('wpcs-hidden', !differs);
	}

	function bindLevels() {
		each(document.querySelectorAll('form'), function (form) {
			if (!form.querySelector('input[data-wpcs-level]')) {
				return;
			}
			var isWizard = form.id === 'wpcs-wizard-form';

			form.addEventListener('change', function (e) {
				var target = e.target;
				if (target.matches('input[data-wpcs-level]')) {
					var preset = presets[target.value];
					if (!preset) {
						return;
					}
					if (isWizard) {
						Object.keys(WIZARD_SYNC).forEach(function (key) {
							var el = form.querySelector('[data-wpcs-sync="' + key + '"]');
							if (el) {
								el.checked = WIZARD_SYNC[key](preset);
							}
						});
						Object.keys(WIZARD_RADIOS).forEach(function (name) {
							var wanted = WIZARD_RADIOS[name](preset);
							each(form.querySelectorAll('input[type="radio"][name="' + name + '"]'), function (el) {
								el.checked = el.value === wanted;
							});
						});
					} else {
						applyPreset(form, preset);
						var synced = form.querySelector('[data-wpcs-level-synced]');
						if (synced) {
							synced.value = '1';
						}
					}
					updateHint(form, isWizard);
					return;
				}
				updateHint(form, isWizard);
			});

			// The page may load with fields that already differ from the stored level.
			var synced = form.querySelector('[data-wpcs-level-synced]');
			if (synced) {
				synced.value = '1';
			}
			updateHint(form, isWizard);
		});
	}

	/* ------------------------------------------------------------------ */
	/* Baseline scan (wizard)                                              */
	/* ------------------------------------------------------------------ */

	function notice(type, text, link) {
		var box = document.createElement('div');
		box.className = 'wpcs-notice' + (type ? ' wpcs-notice--' + type : '');
		var icon = document.createElement('span');
		var icons = { ok: 'yes-alt', warn: 'warning', bad: 'dismiss', '': 'info' };
		icon.className = 'dashicons dashicons-' + (icons[type] || 'info');
		icon.setAttribute('aria-hidden', 'true');
		var p = document.createElement('p');
		p.textContent = text;
		if (link) {
			p.appendChild(document.createTextNode(' '));
			var a = document.createElement('a');
			a.href = link.href;
			a.textContent = link.text;
			p.appendChild(a);
		}
		box.appendChild(icon);
		box.appendChild(p);
		return box;
	}

	function bindBaseline() {
		var box = document.querySelector('[data-wpcs-baseline-box]');
		var S = api();
		if (!box || !S) {
			return;
		}
		var button = box.querySelector('[data-wpcs-baseline]');
		var progress = box.querySelector('[data-wpcs-baseline-progress]');
		var result = box.querySelector('[data-wpcs-baseline-result]');
		var hint = box.querySelector('[data-wpcs-baseline-hint]');
		var form = box.closest('form');
		var next = form ? form.querySelector('[data-wpcs-continue]') : null;
		var running = false;

		if (box.getAttribute('data-has-baseline') !== '1' && next) {
			next.disabled = true;
		}

		function show(el) {
			result.innerHTML = '';
			result.appendChild(el);
			result.classList.remove('wpcs-hidden');
		}

		/**
		 * The listing phase: the count only once the job reports one (it is
		 * saved at the end of each step, so it can stay 0 for a while).
		 */
		function listingLabel(status) {
			if (!status || status.state !== 'enumerating') {
				return;
			}
			var text = progress.querySelector('.wpcs-progress__text');
			var found = parseInt(status.files_total, 10) || 0;
			if (text) {
				text.textContent = found > 0 ? fmt(i18n.listingCount || '%s', S.number(found)) : i18n.listing || '';
			}
		}

		/** After a finished scan: Continue is the main action, scanning again is secondary. */
		function demote() {
			button.className = 'button button-large';
			var label = button.querySelector('[data-wpcs-baseline-label]');
			if (label) {
				label.textContent = i18n.scanAgain || label.textContent;
			}
			var icon = button.querySelector('.dashicons');
			if (icon) {
				icon.className = 'dashicons dashicons-update';
			}
		}

		function onProgress(status) {
			S.renderProgress(progress, status);
			listingLabel(status);
			if (status && status.mode && status.mode !== 'baseline' && S.scan.isRunning(status)) {
				show(notice('', i18n.waitOther || ''));
			} else if (status && status.mode === 'baseline' && !result.classList.contains('wpcs-hidden') && S.scan.isRunning(status)) {
				result.classList.add('wpcs-hidden');
			}
		}

		function begin() {
			running = true;
			button.disabled = true;
			box.classList.add('is-running');
			result.classList.add('wpcs-hidden');
			progress.classList.remove('wpcs-hidden');
		}

		function end(status) {
			running = false;
			button.disabled = false;
			box.classList.remove('is-running');
			status = status || {};
			if (status.state === 'done') {
				S.renderProgress(progress, status);
				var files = parseInt(status.files_total, 10) || parseInt(status.files_done, 10) || 0;
				var threats = parseInt(status.threats, 10) || 0;
				var wrap = document.createElement('div');
				wrap.appendChild(notice('ok', fmt(i18n.fingerprinted || '%s', S.number(files)) + ' ' + (threats ? '' : i18n.noThreats || '')));
				if (threats) {
					wrap.appendChild(notice('bad', fmt(i18n.threatsFound || '%s', S.number(threats)), { href: data.threatsUrl, text: i18n.threatsLink || '' }));
				}
				show(wrap);
				box.setAttribute('data-has-baseline', '1');
				demote();
				if (next) {
					next.disabled = false;
					next.focus();
				}
				if (hint) {
					hint.hidden = true;
				}
			} else if (status.state === 'cancelled') {
				show(notice('warn', i18n.scanCancelled || ''));
			} else if (status.state === 'failed') {
				show(notice('bad', fmt(i18n.scanFailed || '%s', status.message || '')));
			}
		}

		function fail(err) {
			running = false;
			button.disabled = false;
			box.classList.remove('is-running');
			show(notice('bad', fmt(i18n.scanFailed || '%s', err && err.message ? err.message : '')));
		}

		function runBaseline(attempt) {
			// quiet: onProgress already shows its own "another scan is running" notice.
			return S.scan.run({ mode: 'baseline', malware: true, trigger: 'wizard', quiet: true }, onProgress).then(function (status) {
				// Another scan was running: it is finished now, so start the baseline.
				if (status && status.mode && status.mode !== 'baseline' && attempt < 2) {
					return runBaseline(attempt + 1);
				}
				return status;
			});
		}

		button.addEventListener('click', function (e) {
			e.preventDefault();
			if (running) {
				return;
			}
			begin();
			S.renderProgress(progress, { state: 'enumerating', files_total: 0, message: i18n.starting || '' });
			listingLabel({ state: 'enumerating', files_total: 0 });
			runBaseline(0).then(end).catch(fail);
		});

		window.addEventListener('beforeunload', function (e) {
			if (running) {
				e.preventDefault();
				e.returnValue = i18n.leaving || '';
				return i18n.leaving || '';
			}
		});

		// Re-attach to a baseline scan that is still running (page reload).
		S.ajax('scan_status')
			.then(function (status) {
				if (!S.scan.isRunning(status) || status.mode !== 'baseline') {
					return;
				}
				begin();
				onProgress(status);
				return S.scan.attach(onProgress).then(end);
			})
			.catch(function () {});
	}

	/* ------------------------------------------------------------------ */
	/* Test email                                                          */
	/* ------------------------------------------------------------------ */

	function bindTestEmail() {
		document.addEventListener('click', function (e) {
			var button = e.target.closest('[data-wpcs-test-email]');
			var S = api();
			if (!button || !S) {
				return;
			}
			e.preventDefault();
			if (button.disabled) {
				return;
			}
			var source = document.querySelector(button.getAttribute('data-source') || '');
			var original = button.innerHTML;
			button.disabled = true;
			button.textContent = i18n.sending || '...';
			S.ajax('test_email', { emails: source ? source.value : '' })
				.then(function (res) {
					toast(res && res.message ? res.message : '');
				})
				.catch(function (err) {
					toast(err.message, true);
				})
				.then(function () {
					button.disabled = false;
					button.innerHTML = original;
				});
		});
	}

	/* ------------------------------------------------------------------ */
	/* Freeze lock                                                         */
	/* ------------------------------------------------------------------ */

	function setLockState(until) {
		var unlocked = !!(until && until * 1000 > Date.now());
		each(document.querySelectorAll('[data-wpcs-lock-state]'), function (el) {
			el.className = 'wpcs-badge wpcs-badge--' + (unlocked ? 'medium' : 'ok');
			el.textContent = unlocked
				? fmt(i18n.unlockedUntil || '%s', new Date(until * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))
				: i18n.locked || '';
		});
		// Only the button that makes sense now.
		each(document.querySelectorAll('[data-wpcs-unlock]'), function (b) {
			b.hidden = unlocked;
		});
		each(document.querySelectorAll('[data-wpcs-lock]'), function (b) {
			b.hidden = !unlocked;
		});
	}

	function bindUnlockMinutes() {
		document.addEventListener('input', function (e) {
			if (!e.target.matches('#wpcs-unlock-minutes')) {
				return;
			}
			var minutes = parseInt(e.target.value, 10);
			if (!minutes || minutes < 1) {
				return;
			}
			each(document.querySelectorAll('[data-wpcs-unlock-label]'), function (el) {
				el.textContent = fmt(minutes === 1 ? i18n.unlockFor1 || '%s' : i18n.unlockFor || '%s', minutes);
			});
		});
	}

	function bindLock() {
		document.addEventListener('click', function (e) {
			var S = api();
			var unlock = e.target.closest('[data-wpcs-unlock]');
			var lock = e.target.closest('[data-wpcs-lock]');
			if ((!unlock && !lock) || !S) {
				return;
			}
			e.preventDefault();
			var button = unlock || lock;
			button.disabled = true;
			var request;
			if (unlock) {
				var input = document.querySelector(unlock.getAttribute('data-minutes-input') || '');
				request = S.ajax('unlock', { minutes: input ? input.value : '' });
			} else {
				request = S.ajax('lock');
			}
			request
				.then(function (res) {
					button.disabled = false;
					setLockState(res && res.unlocked_until ? parseInt(res.unlocked_until, 10) : 0);
					toast(unlock ? i18n.unlockedToast : i18n.lockedToast);
					// Keep the keyboard focus on the button that replaced this one.
					var other = document.querySelector(unlock ? '[data-wpcs-lock]' : '[data-wpcs-unlock]');
					if (other && !other.hidden) {
						other.focus();
					}
				})
				.catch(function (err) {
					button.disabled = false;
					toast(err.message, true);
				});
		});
	}

	/* ------------------------------------------------------------------ */
	/* Misc                                                                */
	/* ------------------------------------------------------------------ */

	function bindScanRoot() {
		document.addEventListener('change', function (e) {
			if (!e.target.matches('input[name="scan_root"]')) {
				return;
			}
			var custom = document.querySelector('[data-wpcs-scan-root-custom]');
			if (!custom) {
				return;
			}
			var isCustom = e.target.value === 'custom' && e.target.checked;
			custom.classList.toggle('wpcs-hidden', !isCustom);
			if (isCustom) {
				var input = custom.querySelector('input');
				if (input) {
					input.focus();
				}
			}
		});
	}

	function bindDirtyForms() {
		var dirty = false;
		var forms = document.querySelectorAll('form.wpcs-settings-form');
		if (!forms.length) {
			return;
		}
		each(forms, function (form) {
			form.addEventListener('change', function () {
				dirty = true;
			});
			form.addEventListener('input', function () {
				dirty = true;
			});
			form.addEventListener('submit', function () {
				dirty = false;
			});
		});
		window.addEventListener('beforeunload', function (e) {
			if (dirty && !window.wpcsSkipUnload) {
				e.preventDefault();
				e.returnValue = '';
				return '';
			}
		});
	}

	function bindBusyForms() {
		document.addEventListener('submit', function (e) {
			var form = e.target;
			if (form.id === 'wpcs-wizard-form' || form.classList.contains('wpcs-settings-form')) {
				form.classList.add('is-submitting');
				form.setAttribute('aria-busy', 'true');
			}
		});
	}

	/* ------------------------------------------------------------------ */
	/* Advanced sections as tabs                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * The chips above Settings > Advanced become a tablist: one section shows
	 * at a time. Hidden sections stay inside the settings form (only hidden),
	 * so Save still sends every field. The open section is kept in the URL
	 * (?section=) and in the form, so a reload and the redirect after saving
	 * come back to it. Without scripts every section stays visible.
	 */
	function bindSections() {
		var nav = document.querySelector('[data-wpcs-sections]');
		if (!nav) {
			return;
		}
		var tabs = Array.prototype.slice.call(nav.querySelectorAll('[data-wpcs-section]'));
		var panels = {};
		each(document.querySelectorAll('[data-wpcs-panel]'), function (p) {
			panels[p.getAttribute('data-wpcs-panel')] = p;
		});
		var input = document.querySelector('[data-wpcs-section-input]');
		var savebar = document.querySelector('[data-wpcs-savebar]');
		var aliases = { clamav: 'antivirus' };

		nav.setAttribute('role', 'tablist');
		document.body.classList.add('wpcs-has-tabs');

		function keyFor(name) {
			name = String(name || '').replace(/^#/, '').replace(/^wpcs-(panel-|tab-)?/, '');
			name = aliases[name] || name;
			return panels[name] ? name : '';
		}

		/** Section that contains an element with this id (for links to inner anchors). */
		function keyForId(id) {
			var direct = keyFor(id);
			if (direct) {
				return direct;
			}
			var el = id ? document.getElementById(id) : null;
			var panel = el ? el.closest('[data-wpcs-panel]') : null;
			return panel ? panel.getAttribute('data-wpcs-panel') : '';
		}

		function select(key, opts) {
			opts = opts || {};
			if (!panels[key]) {
				return;
			}
			tabs.forEach(function (tab) {
				var on = tab.getAttribute('data-wpcs-section') === key;
				tab.setAttribute('aria-selected', on ? 'true' : 'false');
				tab.setAttribute('tabindex', on ? '0' : '-1');
				tab.classList.toggle('is-active', on);
				if (on && opts.focus) {
					tab.focus();
				}
				if (on && tab.scrollIntoView && nav.scrollWidth > nav.clientWidth) {
					// Narrow screens: keep the chosen chip in view inside the scrolling row.
					var left = tab.offsetLeft - nav.offsetLeft;
					if (left < nav.scrollLeft || left + tab.offsetWidth > nav.scrollLeft + nav.clientWidth) {
						nav.scrollLeft = Math.max(0, left - 24);
					}
				}
			});
			Object.keys(panels).forEach(function (k) {
				var on = k === key;
				panels[k].hidden = !on;
				panels[k].classList.toggle('is-active', on);
			});
			if (input) {
				input.value = key;
			}
			if (savebar) {
				savebar.classList.toggle('is-idle', panels[key].getAttribute('data-has-fields') !== '1');
			}
			if (opts.url !== false && window.history && window.history.replaceState) {
				var url = new URL(window.location.href);
				url.searchParams.set('section', key);
				url.searchParams.delete('recheck');
				url.searchParams.delete('settings-updated');
				url.hash = '';
				window.history.replaceState(null, '', url.toString());
			}
		}

		// One form holds every section. A constrained field (a number outside min/max) in a hidden
		// panel would cancel Save without any visible message: the invalid event does not bubble,
		// so it is caught here while capturing, and the panel of the first invalid field is opened
		// before the browser focuses that field and shows its message.
		var form = input ? input.form : document.querySelector('form.wpcs-settings-form');
		if (form) {
			var opening = false;
			form.addEventListener('invalid', function (e) {
				if (opening || !e.target || !e.target.closest) {
					return;
				}
				var panel = e.target.closest('[data-wpcs-panel]');
				if (panel && panel.hidden) {
					select(panel.getAttribute('data-wpcs-panel'));
				}
				// Later invalid fields of the same check keep the panel of the first (focused) one.
				opening = true;
				setTimeout(function () {
					opening = false;
				}, 0);
			}, true);
		}

		tabs.forEach(function (tab) {
			var key = tab.getAttribute('data-wpcs-section');
			tab.setAttribute('role', 'tab');
			if (panels[key]) {
				panels[key].setAttribute('role', 'tabpanel');
				panels[key].setAttribute('aria-labelledby', tab.id);
				panels[key].setAttribute('tabindex', '-1');
			}
			tab.addEventListener('click', function (e) {
				e.preventDefault();
				select(key);
			});
		});

		nav.addEventListener('keydown', function (e) {
			var current = tabs.indexOf(document.activeElement);
			if (current === -1) {
				return;
			}
			var next = -1;
			if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
				next = (current + 1) % tabs.length;
			} else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
				next = (current - 1 + tabs.length) % tabs.length;
			} else if (e.key === 'Home') {
				next = 0;
			} else if (e.key === 'End') {
				next = tabs.length - 1;
			} else if (e.key === ' ' || e.key === 'Spacebar') {
				e.preventDefault();
				select(tabs[current].getAttribute('data-wpcs-section'));
				return;
			}
			if (next !== -1) {
				e.preventDefault();
				select(tabs[next].getAttribute('data-wpcs-section'), { focus: true });
			}
		});

		// Links inside the page to another section ("Developer instructions", "Antivirus engines"):
		// data-wpcs-goto="<key>", or a plain "#wpcs-..." fragment. Links that change the query
		// (such as "Check again" with recheck=1) load the page as usual.
		document.addEventListener('click', function (e) {
			var link = e.target.closest('[data-wpcs-goto], a[href^="#wpcs-"]');
			if (!link || link.closest('[data-wpcs-sections]')) {
				return;
			}
			var key = link.getAttribute('data-wpcs-goto') ? keyFor(link.getAttribute('data-wpcs-goto')) : keyForId(link.getAttribute('href').slice(1));
			if (!key) {
				return;
			}
			e.preventDefault();
			select(key);
			window.scrollTo({ top: Math.max(0, nav.getBoundingClientRect().top + window.pageYOffset - 48), behavior: 'smooth' });
		});

		// Start: a fragment (#wpcs-guard, an old #wpcs-clamav link) wins over ?section=.
		var fromHash = keyForId(window.location.hash.slice(1));
		var fromQuery = keyFor(new URL(window.location.href).searchParams.get('section'));
		var active = nav.querySelector('.is-active');
		var start = fromHash || fromQuery || (active ? active.getAttribute('data-wpcs-section') : '') || tabs[0].getAttribute('data-wpcs-section');
		select(start, { url: !!fromHash });

		window.addEventListener('hashchange', function () {
			var key = keyForId(window.location.hash.slice(1));
			if (key) {
				select(key, { url: false });
			}
		});
	}

	function init() {
		bindSections();
		bindUnlockMinutes();
		bindLevels();
		bindBaseline();
		bindTestEmail();
		bindLock();
		bindScanRoot();
		bindDirtyForms();
		bindBusyForms();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
