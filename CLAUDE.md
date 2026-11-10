# Qartvelo Guard

WordPress security plugin: full-site malware scan, holds every new upload/install/unknown file until an admin approves it, approvals remembered by SHA-256. Plugin lives in `qartvelo-guard/`; module contracts in `docs/ARCHITECTURE.md` (read it before changing cross-module APIs).

## Commands
- `scripts/build.sh` - lint, stage without dev files, rebuild checksums, zip to `dist/` and verify
- `scripts/build.sh --wporg` - same plus WordPress.org checks (needs real `Contributors:` in readme.txt)
- `scripts/build.sh --svn PATH` - sync trunk/tags/assets into a wp.org SVN checkout (prints svn commands, does not commit)
- `php qartvelo-guard/bin/build-checksums.php` - regenerate `checksums.json`; run after ANY plugin file change, or the plugin flags its own edited files as tampered
- `wp wpcybersec scan [--full|--baseline] [--database] [--url=URL]` - run a scan to completion from the CLI; `--url` is the network address on multisite. There is no standalone runner any more (bin/cron.php was removed in 1.2.0 for the WordPress.org review): real cron is WP-CLI or a request for wp-cron.php
- `wp wpcybersec report --file=report.html` - the downloadable security report (also Reports > Download report)
- Lint: `for f in $(find qartvelo-guard -name '*.php'); do php -l $f; done` and `node --check` on `assets/js/*.js`

## Code rules
- PHP 7.4 compatible syntax (no match, `?->`, named args, union types, `str_contains`); WordPress 6.2+ (SQL identifiers go through `$wpdb->prepare()` with `%i`)
- Namespace `WPCyberSecurity\` (admin: `WPCyberSecurity\Admin\`), file `class-foo-bar.php` for `Foo_Bar`, autoloaded
- Services via `wpcybersec()->name`; module constructors stay cheap, hooks go in `register()`
- Capability checks via `Admin\Admin::can()` (network admin on multisite), plus nonce on every handler
- No em/en dashes anywhere (code, comments, UI strings); icons are Dashicons, no emojis
- Never show secrets: diff/snippet output goes through `Diff::redact()` / `Diff::redact_snippet()`
- Allowlist approvals are bound to executability: `is_allowed_hash( $sha, $executable )`
- WordPress.org review rules (third review, 1.2.0), keep them or the plugin is rejected again:
  - Escape late: helper HTML is printed as `echo wp_kses( $html, Admin\Kses::allowed() );` at the echo, never with a `phpcs:ignore` for EscapeOutput (only `guard/guard.php` has two). A new tag or attribute must be added to `Kses::allowed()` or it disappears silently
  - SQL: no variable inside a query string except core `$wpdb->` table properties; everything through `$wpdb->prepare()`, table and column names as `%i`
  - Paths: `ABSPATH` only in the direct access guards, in `Paths::wp_root()` and in core includes; other folders from `WP_CONTENT_DIR`, `WP_PLUGIN_DIR`, `WPMU_PLUGIN_DIR`, `WP_LANG_DIR`, `get_theme_root()`, `wp_upload_dir()`, never built from a name and never with a `defined()` fallback
  - Core includes: `require_once ABSPATH . 'wp-admin/includes/x.php';` inside a `function_exists`/`class_exists` test, with the use on the next line; never load wp-load.php or wp-config.php
  - No `set_time_limit()`, `error_reporting()`, `ini_set()`; no literal `<style>` or `<script>` output (use the enqueue API); no file that bootstraps WordPress
  - Never create or overwrite a file in wp-admin, wp-includes or the plugin's own folder (`Paths::in_core_dir()`; quarantine restore refuses those targets). Core repair is WordPress's `Core_Upgrader` only. Stored copies live in the uploads data folder under names that cannot run (.bin, .gz, .bak)

## Gotchas
- Renamed from CyberGate Security (slug cybergate-security) to Qartvelo Guard (slug qartvelo-guard) in 1.1.0 for the WordPress.org review: "wp" is a restricted term in plugin names and slugs. Internal identifiers stay `wpcybersec`/`WPCYBERSEC_`/`WPCyberSecurity\` (options, tables, hooks, WP-CLI). Files written by older versions carry legacy markers that must stay recognised: `Guard_Manager::LEGACY_MARKER`, `Sysadmin_Tools::LEGACY_MARKER`, the wp-config "Added by CyberGate Security" comment, settings exports with `plugin: cybergate-security`
- The data folder defaults to uploads/qartvelo-guard (`Storage::default_dir()`); the pre-1.1.0 wp-content/wpcybersec is only read and moved once by `Hardening::move_legacy_data_dir()`
- `class-signatures.php` contains malware patterns as data; it only passes scans because `checksums.json` matches it
- Activation runs after `plugins_loaded`, so `Installer` must not rely on booted services
- A whole-site scan without a baseline (`wpcybersec_baseline_at`) is converted to a baseline; never run an incremental scan on an empty manifest
- Files written by the plugin itself (`.htaccess`, `.user.ini`, `wp-config.php` edits) must be passed to `file_monitor->trust_file()` or the next scan reports them
- Guard (`guard/guard.php`) runs before WordPress via `auto_prepend_file`: no WP functions, PHP 5.6 syntax, must never fatal
- Real-site false positives to keep quiet: server `error_log` files (no extension) inside core folders, `wordfence-waf.php` in the root, bundled `wp-content/plugins/hello.php` (verify against core checksums, not the hello-dolly listing), thousands of changed files right after plugin updates
- Script injection hides in header/footer plugins (`{prefix}hfcm_scripts`, `ihaf_insert_*`, Code Snippets): the database scan must cover them
- ClamAV/maldet find more known infections but do not block attacks; say it that way in UI text
- Multisite is one network-wide install (`Network: true`): plugin options only through `Network::get_option()`/`update_option()` (never plain `get_option()`), tables through `Store::table()` (base prefix), cron through `Network::schedule_event()` and friends (main site only), page links through `Admin::page_url()` (Network Admin); anything tied to one site (media import, post links, site URLs) records `details.blog_id` and runs in `Network::on_site()`
- Host compatibility: files may live outside the scan root (absolute manifest keys), so guard live-file access with `Paths::in_scope()`, not "inside scan_root"; check `Storage::path_allowed()` before touching a path (open_basedir); a storage failure must never block a clean upload; budgets go through `Scan_Job::clamp_budget()`
- Never build test sandboxes with `wp core download`: its tar.gz extraction truncates long wp-includes/php-ai-client paths and the plugin (correctly) reports them; use the .zip from wordpress.org
- Admin pages must stay at 0 plugin queries: write small state options only through `Network::update_option()` (autoloaded `STATE_OPTIONS`), and read badge counts via `Store::counts()`; never run ClamAV or loopback tests inside an upload request (use the cached self-test / last ping)
