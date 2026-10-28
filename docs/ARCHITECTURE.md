# Qartvelo Guard - architecture and module contracts

Plugin folder: `qartvelo-guard/` (slug `qartvelo-guard`, text domain `qartvelo-guard`).
Namespace `WPCyberSecurity\`, admin classes in `WPCyberSecurity\Admin\`. Prefix for options,
hooks, cron, AJAX, CSS classes: `wpcybersec_` / `wpcs-`. PHP 7.4+, WordPress 6.0+. No build step.

## What the plugin does

1. **Scans the whole site** (core, plugins, themes, uploads, web root, optionally the parent
   folder) for malware, webshells and backdoors, and verifies core and wordpress.org plugin
   files against official checksums.
2. **Holds every new upload** (media library, REST, sideloads, plugin/theme ZIPs) in quarantine
   until an administrator approves it on the Reports page. Optional early guard
   (`auto_prepend_file`) also holds uploads sent to ANY PHP script, not just WordPress.
3. **Holds new plugin/theme installs** until approved.
4. **Detects new and modified files** by comparing every file with a manifest (path -> sha256);
   unknown executable files can be quarantined automatically.
5. **Allow once, allowed always**: approving stores the file's SHA-256 (or the install slug) in
   a permanent allowlist. The same content is never held again.
6. **Setup wizard** for site owners and an **Advanced** settings tab for system administrators
   (data dir outside web root, early guard, real cron, exclusions, fapolicyd/inotify/nginx
   snippets, ClamAV, tamper checksum, freeze lock).

## Rules for every module

- Every class has a **no-argument constructor that does nothing heavy** and, if it needs hooks,
  a public `register()` method. `Plugin::boot()` creates and registers everything.
- Reach other services through `wpcybersec()->name` (see the list below). Never construct
  core services yourself except `new Storage()` in code that may run before boot.
- Escape all output (`esc_html`, `esc_attr`, `esc_url`, `wp_kses_post`), check the capability with
  `Admin\Admin::can()` (`manage_options` on a single site, `manage_network_options` on multisite)
  and a nonce on every form/AJAX/admin-post handler.
- Plugin options go through `Network::get_option()` / `update_option()` / `add_option()` /
  `delete_option()` (network options on multisite), plugin cron events through
  `Network::schedule_event()` and friends (main site only), plugin page links through
  `Admin\Admin::page_url()` (Network Admin on multisite). See "Multisite network mode".
- Translatable strings use text domain `qartvelo-guard`. **Never use em dashes or en dashes**
  in any string or comment; use a plain hyphen.
- Icons: Dashicons only (`<span class="dashicons dashicons-shield"></span>`). No emojis.
- Datetimes in the DB are UTC; display with `get_date_from_gmt( $utc, get_option('date_format') . ' ' . get_option('time_format') )`.
- PHP 7.4 compatible syntax: no `match`, no nullsafe `?->`, no named arguments, no union types,
  no `str_contains` (use `false !== strpos`).
- File operations go through `Fs` (WordPress filesystem API): `delete`, `rmdir`, `mkdir`, `chmod`,
  `is_writable`, `touch`, `move` (never overwrites, never leaves two copies), `replace`
  (atomic temp file + rename), `rename` (one-step rename on the same filesystem, folders too,
  never onto an existing path), `copy`, `delete_tree` (recursive, never follows symlinks:
  WP_Filesystem_Direct::delete() would) and `same_device`. Raw PHP file functions stay only where WordPress is not loaded
  (`guard/guard.php`, `bin/cron.php`) or for streams (`fopen`/`flock`), each with a
  `phpcs:ignore ... -- reason` comment. The release must pass Plugin Check with no errors.

## Services (`wpcybersec()->...`)

| Property | Class | Owner |
|---|---|---|
| settings | `Settings` | core |
| storage | `Storage` | core |
| store | `Store` | core |
| logger | `Logger` | core |
| allowlist | `Allowlist` | core |
| quarantine | `Quarantine` | core |
| decisions | `Decisions` | core |
| snapshots | `Snapshots` | core (changes view) |
| ajax | `Ajax` | core |
| scanner | `Scanner` | engine |
| file_monitor | `File_Monitor` | engine |
| scan_job | `Scan_Job` | engine |
| db_scanner | `Db_Scanner` | engine (database scan) |
| user_watch | `User_Watch` | engine (administrator watch) |
| notifier | `Notifier` | gates |
| upload_gate | `Upload_Gate` | gates |
| install_gate | `Install_Gate` | gates |
| guard_manager | `Guard_Manager` | gates |
| sysadmin | `Sysadmin_Tools` | setup |
| hardening | `Hardening` | setup (one-click fixes) |
| developer | `Developer_Instructions` | setup (steps that need server access) |
| hosting | `Hosting` | setup (hosting panel detection and panel steps) |
| core_repair | `Core_Repair` | engine (core damage check, clean core reinstall) |
| stats | `Stats` | core (opt-in install statistics, off by default) |
| admin | `Admin\Admin` | admin UI |

Static helpers: `Paths` (core), `Fs` (core), `Guard_Config` (core), `Installer` (core), `Network`
(core, multisite mode), `Config_Editor` (core, wp-config.php edits), `Cli` (setup),
`Signatures` (engine), `Admin\Assets` (core), `Diff` (changes view). `Originals`,
`Recent_Changes` and `Site_Report` are created on demand (`new Originals()`, ...).

## Core API (already written - read the source in `includes/`)

- `Settings`: `defaults()`, `enums()`, `presets()`, `all()`, `get($key, $default)`,
  `update(array $values)`, `apply_level($level)`, `recipients()` (empty `notify_emails` means
  `Network::default_recipients()`: the site admin email, on multisite the network admin email
  plus every super admin). Action `wpcybersec_settings_updated($new, $old)`. One option
  `wpcybersec_settings` (a network option on multisite).
- `Storage`: `data_dir()`, `path($sub)`, `quarantine_dir()`, `jobs_dir()`, `spool_dir()`,
  `guard_dir()`, `ensure()`, `protect($dir)`, `is_in_webroot($path)`, static `is_within($path, $dir)`.
  Folder resolution (`resolve()`, once per request, `Storage::reset()` forgets it), first writable
  one wins: `WPCYBERSEC_DATA_DIR`, a fallback folder already in use (option
  `wpcybersec_data_fallback`; it keeps being used until its data is moved, so held items stay
  reachable), the folder of the one-click move (option `wpcybersec_data_dir`, single sites
  only), the pre-1.1.0 `wp-content/wpcybersec` while it still exists (`legacy_dir()`, only read;
  `Hardening::move_legacy_data_dir()` moves it away), else the default
  `<main site uploads>/qartvelo-guard/<random 32 chars>` (`default_dir()`, the folder name is kept
  in option `wpcybersec_data_token`), with a new fallback `<main site uploads>/qartvelo-guard-<random 16>`
  when the default cannot be used.
  `status()` / `available()`: `{ state ok|fallback|unavailable, dir, primary, source
  constant|moved|default|fallback, primary_ok }`. `check()` (activation, settings and plugin
  pages) re-resolves, stores option `wpcybersec_storage_status` and logs a change;
  `problem($status)` gives the admin notice text `{ level, title, text, fix, code }`. Uploads are
  never blocked because this storage failed (Upload_Gate lets a clean upload through and logs
  `upload_not_held` once an hour; only malicious ones are refused). `configured_dir()`,
  `default_dir()`, static `site_id()` (md5 of ABSPATH plus `$wpdb->base_prefix`, so every site of a
  network shares it; written into `.wpcybersec-site`, `marker_matches()`, `write_marker()`),
  `suggested_outside_dir()` (next to the WordPress folder; when open_basedir hides that, a
  writable folder inside an allowed one that is not served and not a temp folder; callers check
  `path_allowed()`), static `basedir_hint()` (the open_basedir sentence `problem()` puts in front
  of its fix text instead of suggesting a folder PHP may not use), static `path_allowed($path)`
  (open_basedir: paths outside it are never touched or suggested), `dir_usable()`, `relocate($target, $after_switch)` (copy, verify,
  switch, remove; resumable with `resume_move()` / `move_pending()`, option
  `wpcybersec_data_move`; refused on multisite and with the constant).
- `Paths` (static): `scan_root()`, `rel($abs)`, `abs($rel)`, `hash($rel)`, `ext($name)`,
  `is_executable($name)`, `is_excluded($rel)`. Scan set: `scan_set()` is the scan root plus the
  WordPress folders outside it (ABSPATH, WP_CONTENT_DIR, WP_PLUGIN_DIR, WPMU_PLUGIN_DIR, the
  uploads folder: walked in full; the home folder of WordPress in a subfolder or Bedrock's `web/`:
  its own files only; a wp-config.php one folder above ABSPATH; Bedrock's `<project>/config/`
  folder, walked in full, only when the home folder is `<project>/web/`, `config/application.php`
  exists and that wp-config.php names it (kind `config-dir`); every other file wp-config.php loads
  before wp-settings.php, each on its own, at most 300 (kind `loaded`, `config_includes()`)), each
  realpath'd and dropped when another entry covers it (entries `{ path, depth all|top|file, kind,
  alias }`, filter `wpcybersec_scan_set`). `config_includes($config)`: from
  `get_included_files()` (after wp-config.php, before wp-settings.php) when the request included
  wp-config.php itself, remembered in network option `wpcybersec_config_includes`; WP-CLI evaluates
  wp-config.php instead of including it and uses that option, else the plain `require`/`include`
  lines of wp-config.php (`__DIR__`, `dirname( __FILE__ )`, `dirname( __DIR__ )` plus a string).
  Unrelated parent folders are never walked. `extra_roots()` (all but the root), `outside_root()` (for the UI),
  `in_scope($abs)` (a whole-site scan covers it: use this, not "inside the scan root", before
  reading or touching a live file), `in_full_scope($dir)`, `scope_entry($abs)`, `alias($abs)`
  (`wp-content/...` name of a file outside the root, for exclusions), `home_dir()`, `reset()`.
  Files outside the scan root keep their absolute path as the manifest key. On multisite the
  uploads and home folders are the main site's (`Network::on_main()`).
- `Config_Editor` (static): `path()`, `can_check()` (tokenizer), `can_edit()`, `has_constant()`,
  `set_constant($name, $value)` (replaces a define in place, else adds it above "That's all, stop
  editing!" under a `// Added by Qartvelo Guard on <date>.` line; refuses when the constant is
  defined in another file wp-config.php loads, never adds a duplicate), `remove_constant($name)`,
  `remove_marked_constant($name)` (only defines below that marker comment; uninstall),
  `parses($code)`. Every write is parse-checked, atomic (`Fs::replace()`), backed up into the data
  folder only when that folder cannot be downloaded, and trusted in the manifest.
- `Store`: constants `TYPE_*` (upload, install, file, threat), `STATUS_*` (pending, approved,
  denied, ignored, quarantined, restored, deleted, resolved), `SEV_*` (0 info, 1 medium, 2 high,
  3 critical), `STATE_*` (trusted, pending, threat). Items: `item_insert`, `item_get`,
  `item_update`, `items_query`, `items_count`, `counts()`, `item_find_open($type, $path, $sha256)`,
  `items_delete`. Manifest: `manifest_get_many`, `manifest_get`, `manifest_upsert_many`,
  `manifest_touch`, `manifest_unseen`, `manifest_delete`, `manifest_delete_prefix`,
  `manifest_count`, `manifest_set_state`, `manifest_truncate`, `manifest_page`. Log:
  `log_insert`, `log_query`, `log_prune`. Static `table` (`$wpdb->base_prefix . 'wpcybersec_' .
  $name`: one set of tables for a whole multisite network), `now`, `severity_label`, `client_ip`.
- `Allowlist`: `is_allowed_hash`, `allow_hash($sha256, $label, $note)`, `is_allowed_install($type, $slug)`,
  `allow_install($type, $slug, $label, $note)`, static `install_key`, `remove($id)`, `get($id)`,
  `query($args)` (kind `hash` matches `hash` and `hash_exec`: the "File fingerprints" filter), `count()`, `hashes()`, `export_guard_file()`, `verify_integrity()` (true/false/null).
- `Quarantine`: `hold($src, $move = true)` -> `{quarantine_path, sha256, size}`|WP_Error,
  `restore($item)`, `to_temp($item)`, `purge($item)`, `exists($item)`, `stream($item)`.
- `Logger`: `log($event, $message, $context = array())`.
- `Decisions`: `ACTIONS`, static `available($item)`, `apply($action, $id)`, `bulk($action, $ids)`.
  Critical files (static `is_critical_path($abs)` / `is_critical($item)`: wp-config.php, the root
  `CRITICAL_ROOT` files, and wp-admin/ or wp-includes/ files listed in the core checksums) are never
  offered or allowed `quarantine` or `delete`, and Scan_Job never auto-quarantines them. A changed
  critical core file still in place gets `restore_official` (verified `Originals` copy, current
  version kept as a snapshot first, atomic `Fs::replace()`, item becomes `resolved`).
- `Guard_Config` (static): `file()`, `allow_file()`, `read()`, `write($config)`,
  `set_enabled($bool)`, `atomic_write($file, $content)`.
- `Ajax`: endpoints listed in `class-ajax.php` (scan_start/tick/status/cancel, item_action,
  bulk_action, counts, unlock, lock, diff_summary, clamav_enable). Nonce action `Ajax::NONCE` = `wpcybersec_ajax`.
- `Admin\Assets`: `register()`, `enqueue()`. Handles `wpcybersec-base` (css) and
  `wpcybersec-core` (js, exposes `window.WPCyberSec`, see header comment in `assets/js/core.js`).
- `Installer`: `CRON_HOOKS`, `REDIRECT_OPTION` (`wpcybersec_activation_redirect`, set on activation),
  `activate($network_wide)`, `install()` (on multisite first `Network::migrate_main_options()`,
  then tables and defaults, then a bounded `Network::migrate_sites()` pass), `maybe_upgrade()`
  (DB version `WPCYBERSEC_DB_VERSION`, 5 since network mode), `deactivate($network_wide)`
  (`Network::clear_cron_everywhere()`, guard config disabled), `tables()`.

### Item row shape

```
id, type (upload|install|file|threat|user), status, severity (0-3),
path            relative path (file/threat), original file name (upload), "plugin:<slug>" (install),
                "db:option:<name>" / "db:post:<ID>" / "db:hfcm:<id>" / "db:snippets:<id>" (threat with source database),
                "user:<ID>" (user)
original_path   absolute path where the file lives / must be restored to ('' for uploads)
quarantine_path absolute path of the held copy ('' when nothing is held)
sha256, size, mime, source, user_id, ip,
details         array (decoded JSON), see below
created_at, updated_at, decided_by, decided_at
```

`details` keys used across modules (all optional):
- `hits`: list of `{ sig, title, severity, line, snippet }` (malware signature hits)
- `change`: `new` | `modified`; `previous_sha256`
- `verified`: `core` | `plugin` checksum verdicts, `checksum`: `mismatch` | `unknown_file`
- `post_id` (attach approved upload to this post), `context`: `media` | `sideload` | `plugin_zip` | `theme_zip` | `guard`
- `request_uri`, `script` (guard), `field` (guard form field name)
- `install_type` (`plugin`|`theme`), `slug`, `name`, `version`, `install_source` (`wporg`|`upload`|`url`)
- `checksum_verified` (install items: files whose signature hits the wordpress.org checksums cleared)
- `blog_id` (multisite: the site an upload, guard upload, database finding or administrator
  belongs to), `sites` (user items: every site where the account is administrator),
  `migrated_from` (copied from a site's own tables by the network migration)

Sources (`source` column): `media`, `sideload`, `rest`, `plugin_zip`, `theme_zip`, `guard`,
`scan`, `install`, `database` (Db_Scanner finding; `sha256` is the place-bound fingerprint, only
"ignore" applies, which stores it in the allowlist as kind `db`), `user` (User_Watch real time),
`review` (a file an administrator reported from Reports > Recent changes; type `file`,
`user_id` = who reported it, `details.context` = `recent_changes`).

Database findings (`Db_Scanner`): options (decoder + eval payloads, document.write(unescape,
fromCharCode + eval; scripts from other sites and hidden iframes only in widget_*, theme_mods_*,
*custom_html*), posts of every type except revisions/oembed_cache/customize_changeset (publish,
draft, private, pending, future), and code plugin storage reported as medium "review" findings
(ihaf_insert_* options, hefo, wpcode posts, {prefix}hfcm_scripts, {prefix}snippets). Chunked by
primary key range; `Scan_Job` runs it in the finishing phase of full and baseline scans, with
opts `database => true`, and once a day for cron scans. Details: table, key, label, hits
(redacted snippets), fingerprint, seen_run. A complete run resolves open findings it no longer
sees. Last run summary: option `wpcybersec_db_scan`.

Administrator watch (`User_Watch`): option `wpcybersec_trusted_admins` (user ids, seeded from the
current administrators on install/upgrade or first use). Untrusted administrators (role or
super admin) become `user` items in real time (user_register, set_user_role, add_user_role,
grant_super_admin) and during whole-site scans. approve = trust; deny = role subscriber,
super admin revoked, sessions destroyed (refused for the current user and the last
administrator). Deleted or demoted accounts resolve their item.

Core integrity (`Scanner::integrity_issue()`, every scan mode including baseline): executable
or PHP-content files in wp-admin/ or wp-includes/ that core does not ship are high threats
(only when core checksums loaded; logs ignored); .htaccess-like files there and non-core PHP
files in the WordPress root (except wp-config.php, the guard bootstrap and a plain Wordfence
loader) are medium file items. The guard bootstrap counts when it is exactly the current one, or
`Guard_Manager::is_leftover_bootstrap()` (one an earlier install wrote for another data folder). Checksum mismatches of core, wordpress.org plugin and
own files are threats in every mode, for executable names and .js/.mjs. Whole-site runs count
missing core files (`missing_core` in status/last_result, "Missing core files: N" in the
summary).

## Multisite network mode

Files: `includes/class-network.php` plus small parts of most modules. The plugin header says
`Network: true`: on multisite it is network activated and works ONCE for the whole network,
because every site shares the file system. Single sites behave exactly as before (every
`Network` method falls back to the plain WordPress function).

- Shared state: tables on `$wpdb->base_prefix` (manifest, items, allowlist, log), every plugin
  option as a network option (`Network::get_option()` and friends; `flush_option_cache()`
  drops it from the request cache), caches of shared data as site transients
  (`Network::get_transient()` and friends: snapshot stats, original-file hits, the quarantine web
  probe, the developer instruction count), one data folder, one quarantine, one snapshot store, one
  guard config. Raw lock rows of the scan job (`wpcybersec_job_lock`, `wpcybersec_job_cancel`)
  live in the main site's options table (`Network::lock_table()`).
- Cron: every plugin event is scheduled on the main site (`Network::schedule_event()`,
  `schedule_single()`, `next_scheduled()`, `get_schedule()`, `unschedule_event()`,
  `clear_hook()` switch there). Code that only keeps a schedule in shape runs on the main site
  (`Network::is_main()`); other sites never check it. `clear_site_cron()` (init of admin and cron
  requests on other sites, and a stray `wpcybersec_scheduled_scan` handler there) removes events
  older versions left on other sites. Scans therefore run once for the network.
- Screens: menu on `network_admin_menu` (Dashboard, Reports, Settings, Wizard in Network Admin);
  site admins see no plugin menu and get 403 on the pages; `Admin::page_url()` and
  `Admin::admin_page_base()` point at Network Admin; admin-post and AJAX go to the main site's
  `admin-post.php` / `admin-ajax.php` with `Admin::can()` (`manage_network_options`). The
  activation redirect waits for a Network Admin page. Admin bar node and notices: super admins
  only. Uploads on every site are still gated.
- Sites: `main_site_id()`, `on_main($fn)`, `on_site($blog_id, $fn)`, `site_ids_after($after,
  $limit)` (batched, id order), `site_label($blog_id)` ("Name (host/path/)"), `home_paths()`,
  `home_url()` / `admin_url()` / `name()` (network address and name).
- Items remember the site: held uploads (`Upload_Gate`) and guard uploads (spool `host` + `uri`
  mapped with `get_site_by_path()`) store `details.blog_id`; approving a media/REST/sideload
  upload imports it into that site's Media Library inside `Network::on_site()`. Like core, only
  `:80` / `:443` are dropped from the host (a network on another port stores `host:port` as the
  domain); the host without the port is tried second (a deleted site:
  the hash is allowed only). The same file held on two sites is two items. Database findings and
  administrator items record `blog_id` too. Reports (source column "Site: ..."), alert emails
  ("Site" row) and the downloadable report show it; the report also counts the network's sites.
- Database scan: one run walks every site in id order (cursor `blog`, `sites`; resumable like
  the chunks, each site in `switch_to_blog()`). Places on a site other than the main one are
  `db:site:<id>:option:<name>` / `db:site:<id>:post:<ID>` (own fingerprints);
  `Db_Scanner::blog_id($item)`, `location_label()` and `post_id()` understand both forms.
- Administrator watch: one trusted list for the network. Administrators of every site come from
  one query on the shared usermeta table (`User_Watch::network_admin_sites()`: the
  `<prefix>capabilities` rows that hold "administrator", mapped to site ids), plus super admins,
  so a scan needs no `switch_to_blog()` per site on any network size. Items carry
  `details.sites`; deny removes the role on every site and revokes super admin.
- Guard: one config for the network. `home_path` is the main site's, `home_paths` lists every
  site's URL path (`Network::home_paths()`), so REST exemptions such as `/wp-json/wp/v2/media`
  match `/sub1/wp-json/...` too; `front_root()` is worked out on the main site. Creating or
  deleting a site (`wp_initialize_site`, `wp_delete_site`) rewrites the config.
- Alerts default to the network admin email plus every super admin; emails say the network
  name and address and link to Network Admin.
- Migration (`Network::migrate_main_options()` + `migrate_sites()`, network option
  `wpcybersec_ms_migration` = last site id done, then `done`): the main site's plugin options
  become network options (existing network options win); then, per site in batches of 50 under a
  MySQL `GET_LOCK` and a 10 second budget (continued on later admin, cron and CLI requests from
  `Plugin::boot()`), a site with its own tables (`<site prefix>wpcybersec_*`, created by older
  versions) has them merged and dropped: allowlist `INSERT IGNORE`, log copied, items copied with
  `details.blog_id` and `migrated_from` (rows the network table already has with the same type,
  status, hash and path are skipped; database findings get the `db:site:<id>:` place, so their
  old "Mark safe" fingerprints no longer match and they are reported once more), the manifest
  dropped (each site had built a copy of the whole network) unless it is the main site's and
  the network manifest is empty (main site with another prefix). Every site's trusted
  administrators are merged, its other plugin options and transients deleted, its plugin cron
  events cleared and its `snapshots/site-<id>/` folder removed. On a standard network the main
  site's prefix IS the base prefix, so its tables are used as they are. A summary is logged per
  site (`network_site_merged`) and at the end (`network_migrated`).
- Data folder: shared; the one-click move stays single-site only (`WPCYBERSEC_DATA_DIR` moves it
  for a network). Several networks in one database share the base tables.

## Changes view (what changed in a file)

Files: `includes/class-snapshots.php`, `includes/class-originals.php`, `includes/class-diff.php`,
`Admin\Reports_Page::render_changes()` (`admin.php?page=wpcybersec-reports&view=changes&item=<id>&from=<tab>&layout=unified|split`).

- `Snapshots`: gzip copies of file versions at `<data_dir>/snapshots/<k[0:2]>/<k[2:4]>/<k>.gz`
  (0600), `k = hmac_sha256(sha256, option wpcybersec_snapshot_key)` so a leaked fingerprint is
  never a download address. Only when setting `snapshots` is on, the name is executable, a config
  file or .js/.html/.svg, size <= `snapshot_max_kb`, and the content is not binary. Store limits:
  at most `snapshot_max_files` copies (1000 - 1000000, default 20000; inode quotas) and
  `snapshot_max_mb` (10 - 10240, default 200), both on Settings > General. Running totals in option
  `wpcybersec_snapshot_usage`; a new copy is refused while the store is full, `enforce_cap()`
  (after every scan and from `prune()`) deletes the least recently used copies down to 90 % of
  both limits; `usage()` reports files, bytes, limits, refused copies and write failures. Raising
  a limit (or `snapshot_max_kb`) resets the backfill. API: `store($abs,
  $sha)`, `store_trusted($abs, $sha, $verify)` (skips official core/plugin checksum matches),
  `put_content($content)`, `has`, `get` (sha256 checked), `stored_at`, `stats`, `clear`, `prune`
  (daily from `wpcybersec_maintenance`, keeps versions referenced by the manifest or by a file/threat
  item's `sha256`, `details.previous_sha256`, `details.base_sha256`; resumable via a cursor option).
  `needs_backfill()`: the next whole-site scan also copies unchanged trusted files once (after the
  feature is switched on, the limit is raised, or copies are deleted).
- Capture points: `Scan_Job` (every file a run trusts, the current version of every reported file
  before it may be quarantined, the backfill), `File_Monitor::trust_file()` and
  `rebaseline_paths()`, `Decisions` quarantine/delete of a live file.
- `Originals::fetch($rel)`: official core file from core.svn (md5 must match core checksums) or
  wordpress.org plugin file from plugins.svn tag/trunk (sha256 must be in the plugin checksums JSON).
  Cached in Snapshots; misses cached 6 h. Remembered on the item as `details.base_sha256`.
- `Diff::for_item($item, $args)`: `{ mode diff|content|unavailable, reason, base_label, current_label,
  base, current, added, removed, html, notes, secrets, hit_lines }`. Base: previous copy, else official
  original, else content mode. Current: live file, held copy (`Quarantine::read()`), saved copy.
  Secrets are redacted (`Diff::redact()`) before comparing or showing. Rendering uses core's
  `Text_Diff` engine with its own escaped renderer (wp_text_diff() collapses whitespace).
- AJAX `diff_summary` (id) feeds the "Changes: +N -M lines vs ..." line in the expandable details.
- `Diff::excerpt($item, $max = 200, $network = false)`: plain rows `{ kind ' '|'+'|'-'|'@'|'!', old, new,
  text }` of the redacted diff (changes with 3 context lines) or of the content (lines around the
  matches, else the start), for output that cannot use the screen HTML (the downloadable report).
  `for_item()` takes `texts => true` so a render-less call still returns the redacted `current`.

## Recent changes (incident mode)

Files: `includes/class-recent-changes.php`, `Admin\Reports_Page::render_recent_tab()` /
`render_file_view()` (`admin.php?page=wpcybersec-reports&tab=recent&days=7|14|30&show=no_updates`,
`...&view=file&path=<relative path>`), admin-post `wpcybersec_recent_report` (nonce
`wpcybersec_recent_report`, POST `path`).

- Why: changes are judged against the baseline; files infected before the baseline look normal.
- `query({days, search, hide_updates, page, per_page})`: manifest rows with `mtime >= now - days`
  (index `mtime`, DB version 4), newest first, at most `SCAN_CAP` rows read, filtered to
  `Paths::is_executable()` and not excluded. Times are what the last scan saw.
- `explain($row)`: `update` (an update mark covers the path and the mtime is within 1 h before or
  15 min after it: "WordPress update", "<Plugin> update", "<Theme> install"), `checksum`
  (`Scanner::verify()` match of the live file), `allowed` (allowlisted hash), `reported` (open
  file/threat item), else `none` ("Unexplained", highlighted).
- Update marks: option `wpcybersec_update_marks` (list of `{ p: relative prefix, t: unix, a:
  update|install }`, 45 days, at most 600) written by `Install_Gate::process_complete()` through
  `Recent_Changes::remember_update()`, plus the `rebaselined` activity log events (older updates).
- `resolve($rel)`: accepts only an exact manifest key (relative, or absolute for a file outside
  the scan root) whose real path `Paths::in_scope()` covers and that is outside the data folder;
  `..` segments are refused. `file_item()` describes it like an item (id 0) for
  `Diff::for_item()` (live file, matches from `scan_file()`, last trusted copy as the base when the
  file changed after the scan, else the official original, else the content).
- `report($rel)`: "Report for review" creates a pending `file` item (source `review`, hits,
  checksum verdict, snapshot of the current version) and sets the manifest row to pending, so the
  normal Allow / Quarantine / Delete decisions apply. An open report of the file is reused.

## Downloadable report

Files: `includes/class-site-report.php`; admin-post `wpcybersec_report` (GET, nonce
`wpcybersec_report`, `Admin::report_url()` / `Admin::report_button()` on the Reports and Dashboard
headers) sends `<host>-security-report-<Y-m-d>.html` as an attachment; `wp wpcybersec report
[--file=path]`.

- One HTML document, inline CSS, no scripts or external assets: overview (site, versions),
  last scan (`last_result` incl. missing core, database findings, new administrators, last
  database scan), open items (pending, most severe first, up to 300; hits with
  `Diff::redact_snippet()` snippets; `Diff::excerpt()` of the first 40 file/threat items, 200
  lines each), administrator accounts, protection settings, `Sysadmin_Tools::diagnostics()`,
  allowlist size, last 100 log entries.
- Never included: secret values, wp-config.php beyond redacted excerpts, nonces, webhook URLs,
  the data folder path or held copy paths, full email addresses (masked `j***@example.com`).
  A final pass replaces every value of a defined constant whose name looks secret (DB_PASSWORD,
  keys, salts, WPCYBERSEC_HMAC_KEY), the snapshot key and the webhook URL with `********`, and the
  data folder path with `[plugin data folder]`.

## Engine module (owner: engine builder)

Files: `includes/class-scanner.php`, `includes/class-signatures.php`,
`includes/class-file-monitor.php`, `includes/class-scan-job.php`, `bin/cron.php`.

### `Scanner`
- `register()`: nothing required (may add cache cleanup).
- `scan_file($abs, $rel = '')`: array of hits `{ sig, title, severity, line, snippet }`. Reads
  at most `read_cap()` bytes: `max_file_mb` (`max_bytes()`), lowered when the memory left under
  memory_limit (`memory_room()`) could not hold about four copies plus 8 MB (after trying
  `wp_raise_memory_limit()`), never below 64 KB. Skips binary media except the "PHP hidden in
  image" checks (head and tail 8 KB). Applies `min_severity`.
- `scan_upload($tmp_path, $original_name)`: hits for an incoming upload (name-based checks such
  as double extensions + content checks + optional ClamAV). Severity >= 2 means "malicious".
- `max_severity(array $hits)`: int.
- `verify($rel, $sha256, $md5 = '')`: `'match' | 'mismatch' | 'unknown'` using core checksums
  (`get_core_checksums()`, md5) and wordpress.org plugin checksums
  (`https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json`, sha256),
  cached in site transients. Only when setting `use_checksums` is on. Core checksums are fetched
  for `package_locale()`: `$wp_local_package` in wp-includes/version.php (what the core files
  were built for), en_US when unset, not the site language; when only another locale's list is
  available, version.php is compared without its `$wp_local_package` line.
- `checksum_map($slug, $version)`: the wordpress.org checksum list of one plugin version (same
  fetch and site transient as `verify()`, without the "does it fit the installed copy" sample that
  `plugin_map()` adds); `matches_map($map, $inner, $abs)`: the file has a listed sha256 (other line
  endings count).
- `is_core_path($rel)`, `plugin_slug_for($rel)` helpers.
- `clamav_available()`: bool, `clamav_scan($path)`: null (not available) or hits.

### `Signatures`
- static `all()`: list of `{ id, title, severity, pattern (PCRE), targets ('php'|'js'|'html'|'any'|'image'|'htaccess') }`
  plus optional keys documented in the class header (`needle`, `requires`, `unless`, ...).
  `unless` was called `exclude`; the old key is still read for signatures added through the
  `wpcybersec_signatures` filter.
  Low false positives are critical (must stay quiet on WooCommerce, Elementor, Yoast, Polylang).

### `File_Monitor`
- `register()`: schedules `wpcybersec_scheduled_scan` according to `scan_schedule` on `init`
  (scheduling runs `cron_schedules`, where other plugins translate; core's `weekly` interval is
  used, no own interval), on the main site only (reschedules on `wpcybersec_settings_updated`),
  hooks `wpcybersec_scheduled_scan` (starts an incremental job, ticks once; on another site of a
  network it clears that stray event instead) and `wpcybersec_scan_tick` (continues a running job,
  re-schedules itself in 60s while running). A cron tick asks for `CRON_BUDGET` (20 s).
- `trust_file($abs, $sha256 = '')`: manifest row -> trusted (hash computed if empty).
- `forget_file($abs)`: delete the manifest row.
- `rebaseline_paths(array $abs_dirs)`: synchronously re-trust files under these folders (used
  after plugin/theme/core updates), BUT files with malware hits >= 2 or checksum mismatches
  become threat items instead of trusted. Never rebaselines the whole site.
- `evaluate($abs, $rel, $stat, $manifest_row, $job)`: decision logic shared with Scan_Job
  (may be private; Scan_Job is in the same module).

### `Scan_Job`
Only one job at a time. State in option `wpcybersec_job` (not autoloaded); file list in
`<jobs_dir>/<id>.list`. Read the class header for the full contract; the essentials:
- Whole-site runs walk `Paths::scan_set()`. Folders are read as a stream: a folder with more than
  `DIR_CAP` (20000) entries is listed across ticks from an entry count (state `cursor`), and its
  rows are never treated as deleted meanwhile. Folders outside the scan root that older versions
  never scanned (option `wpcybersec_manifest_extra`) are adopted like a baseline the first time.
- Symlinks: a symlinked folder is not walked through the link; when its target is in the scan set
  it is scanned there once, otherwise it is counted (`symlinks`, `symlink_list`, "symlinked
  folders not scanned").
- Budgets: `tick($budget)` uses at most about half of what max_execution_time leaves
  (`exec_seconds_left()`, `clamp_budget()`), so the batch running over the deadline, the state
  save and a database step still fit.
- Crash guard: before real work on a file its name goes into `<jobs_dir>/<id>.cur` (crash
  marker, emptied when done; a shutdown function records the fatal error and releases the
  lock). A file that stopped the scan `CRASH_LIMIT` (2) times is skipped, reported as a pending
  file item "could not be scanned" and remembered in option `wpcybersec_unscannable` (path hash
  => size:mtime, at most 200) so later runs skip it until it changes (`unscannable` count).
- `generated_kind($abs)`: `dropin` (a drop-in name at the top of WP_CONTENT_DIR) or `generated`
  (wp-content/cache/, litespeed/, wp-rocket-config/, w3tc-config/, wp-cache-config.php). Such
  files and critical files are reported but never quarantined automatically.
- `start(array $opts)`: opts `mode` (`incremental`|`full`|`baseline`), `malware` (bool),
  `paths` (optional absolute folders), `trigger` (`manual`|`cron`|`cli`|`wizard`|`update`),
  `force` (bool). Returns job id string or WP_Error. If a job is running and not `force`,
  returns the running id.
- `tick($budget_seconds)`: does work for up to the budget, returns `status()`.
- `status()`: `{ id, state (idle|enumerating|processing|finishing|done|failed|cancelled), mode,
  malware, trigger, files_total, files_done, new, modified, deleted, threats, quarantined,
  skipped, started_at (unix), finished_at (unix), current (rel path), message, percent }`.
- `cancel()`, `last_result()` (status of the last finished job, option `wpcybersec_last_scan`),
  `run_to_completion(callable $progress = null)` for CLI and bin/cron.php.
- Decisions per file:
  - `baseline`: everything trusted, except malware hits (when `malware`) -> threat item.
  - `incremental`: unchanged files (same size+mtime) are skipped; new/changed files are hashed,
    checksum-verified (match -> trusted), allowlisted hash -> trusted, else: malware hits ->
    threat item (auto-quarantine critical if `auto_quarantine`); new executable files with
    `file_mode=quarantine_exec` -> quarantined + pending file item; else `file_mode=report` ->
    pending file item (file stays). Modified executable files: `modified_action`.
  - `full`: like incremental but also re-scans unchanged files for malware.
  - Duplicates: never create a second open item for the same path+hash.
  - Deleted files: manifest rows not seen this run are removed and counted (logged, no item).
- Calls `wpcybersec()->notifier->item_created($id)` for each new item, and
  `wpcybersec()->notifier->scan_finished($status)` at the end.

### `bin/cron.php`
CLI runner for real cron without WP-CLI: `php bin/cron.php [--full|--baseline] [--no-malware] [--isolated] [--quiet] [--wp=/abs/path] [--url=https://example.com/]`.
Refuses to run from the web (CLI, or php-cgi started from a shell or cron without request
variables; use `php-cgi -q`). Without `--wp` it walks up from its own folder, then from the
current one, and looks for `wp-load.php` in each folder and in its `wp/` and `web/wp/` subfolders
(Bedrock). Loads `wp-load.php`, runs a scan to completion, prints a one-line
summary, exits 1 when the scan failed. `--url` sets HTTP_HOST / REQUEST_URI; without it a
multisite host comes from `DOMAIN_CURRENT_SITE` / `PATH_CURRENT_SITE` in wp-config.php. When
WordPress exits while loading (no site for the address) a shutdown function says so, with the
multisite hint (pass the network address; with a wrong `--url` it names the value that matched no
site), and exits 1.
Records network option `wpcybersec_cli_cron_at` (proof that real cron runs). WP-CLI records it too
(`Cli::record_cron_run()`): after `wp wpcybersec scan` and after `wp cron event run` (hook
`after_invoke:cron event run`), only when run with `--quiet` or without a terminal, so a command typed
once by hand does not count.
`Sysadmin_Tools::cron_snippets()` builds the crontab lines (`cron_url_arg()` adds `--url` on
multisite). The plain `php wp-cron.php` line has no host either, so on multisite it becomes
`curl` of the main site's `wp-cron.php?doing_wp_cron` (where every plugin event lives), and the
WP-CLI variant runs `wp cron event run --due-now --url=<site>` for every site of `wp site list`.

`--isolated` (clean-room scan): before `wp-load.php`, filters are pre-registered in the
`$wp_filter` global (turned into WP_Hook objects by `WP_Hook::build_preinitialized_hooks()`):
`option_active_plugins` / `site_option_active_sitewide_plugins` keep only this plugin (matched by
real path), `template_directory` / `stylesheet_directory` return a folder without functions.php
(wp-settings.php includes a theme's functions.php only when it exists there), and
`pre_update_option_active_plugins`, `pre_update_site_option_active_sitewide_plugins`,
`pre_update_option_template`, `pre_update_option_stylesheet` keep the old value, so nothing is
deactivated persistently. After boot it checks `get_included_files()` for code of any other plugin
or theme (symlinked folders resolved) and exits 2 without scanning when it finds some. mu-plugins
and drop-ins cannot be isolated: they are listed ("mu-plugins still load: N found").
`wp wpcybersec scan --isolated` only explains this (WP-CLI has loaded plugins already).

## Gates module (owner: gates builder)

Files: `includes/class-upload-gate.php`, `includes/class-install-gate.php`,
`includes/class-guard-manager.php`, `includes/class-notifier.php`, `guard/guard.php`.

### `Upload_Gate`
- `register()`: `wp_handle_upload_prefilter` and `wp_handle_sideload_prefilter` (priority 1000).
- Also `wp_upload_bits` and the REST media route: `rest_request_after_callbacks` turns the
  error of a held REST upload into `wpcybersec_upload_held` with status 403 (instead of WordPress's
  500).
- Policy (`upload_mode`): `hold_all` holds everything not allowlisted; `hold_risky` holds
  executable/script/archive/svg/html types, files whose real type does not match the extension,
  and anything with hits; `scan_only` holds only uploads with hits >= 2; `off` does nothing.
  Users with a role in `upload_bypass_roles` pass when clean. Malicious uploads (hits >= 2)
  are always held unless the hash is allowlisted. `gate_sideloads` controls sideloads.
- Holding = `quarantine->hold($tmp, false)` + item (type upload, status pending, path = original
  file name, source media|sideload|rest|plugin_zip|theme_zip, details.post_id/context/hits,
  `upload_subdir`, `blog_id` on multisite) + log + notifier, then `$file['error'] = <message>`
  so WordPress shows it in the uploader. When the copy cannot be stored (data folder problem) a
  clean upload is let through and a malicious one refused without a copy (`not_held`).
- `with_bypass(callable $fn)`: runs $fn with the gate disabled (used when importing).
- `on_approve(array $item)`: allowlist the hash; for media/sideload/rest uploads import the held
  file into the Media Library (`media_handle_sideload`, attach to `details.post_id`) and store
  `details.attachment_id`; for plugin/theme ZIPs also allowlist the install slug found in the
  ZIP (top folder, read with ZipArchive or the bundled PclZip) so the install gate lets it
  through. Purge the held copy after import. Multisite: the import runs on the item's site.
- `on_deny(array $item)`: optional hook (logging).

### `Install_Gate`
- `register()`: `upgrader_source_selection` (hold new installs unless
  `Allowlist::is_allowed_install`; return WP_Error with a clear message and create an item of
  type install), optional update holding (`hold_updates`), `upgrader_process_complete`
  (call `file_monitor->rebaseline_paths()` for just the updated plugin/theme folders, or core
  folders after a core update; the same folders are remembered as update marks with
  `Recent_Changes::remember_update()`), `file_mod_allowed` (when `freeze_mods` is on, return false
  unless unlocked).
- Package check (`scan_package()`): signature hits of an unpacked plugin are dropped for files that
  match the wordpress.org checksums of that slug and version (`Scanner::checksum_map()`, only with
  `use_checksums`; fetched once, only when something was found), so official test fixtures in
  vendor/ do not make a wordpress.org plugin Critical. A changed or unlisted file keeps its hits.
  The item gets `details.checksum_verified` (number of such files).
- `on_approve(array $item)`: allowlist install key (and package hash if known).
- `unlock($minutes)`, `lock()`, `is_unlocked()`, `unlocked_until()` (unix, 0 when locked).
- static `local_path($path)`: the local path of a path the filesystem API handed over (with
  FS_METHOD ftpext/ftpsockets/ssh2 the upgrader works with FTP paths), '' when it cannot be
  mapped; static `mods_disallowed()`: `DISALLOW_FILE_MODS` is on, so the freeze lock has nothing
  to unlock (the UI and CLI say so instead of offering it).

### `Guard_Manager`
- `register()`: imports the guard spool into items (`import_spool()`) on `admin_init` (cheap
  check: file size > 0) and on cron hook `wpcybersec_guard_import`; keeps the guard config in
  sync on `wpcybersec_settings_updated` and `wpcybersec_allowlist_changed`; re-enables the
  config on boot if the guard was installed (option `wpcybersec_guard_installed`).
- `bootstrap_path()`: `ABSPATH . 'wpcybersec-guard.php'`.
- `front_root()`: real folder of the front controller index.php when it is not ABSPATH
  (WordPress in its own subfolder, Bedrock's `web/`), '' otherwise; from the home/site URLs (of
  the main site on multisite) and DOCUMENT_ROOT, confirmed by an index.php that loads
  `<sub>/wp-blog-header.php`, remembered in option `wpcybersec_front_root` for cron and CLI.
  `wiring_dirs()`: ABSPATH plus that folder; `write_user_ini()`, `write_htaccess()` and their
  `remove_*()` act on both (a failure in one undoes the other). static `litespeed_edition()`:
  `openlitespeed` | `enterprise` | `unknown` | ''.
- `config_array()`: `home_path` (main site) and on multisite `home_paths` (every site's URL path);
  rewritten on `wp_initialize_site` / `wp_delete_site`; kept in sync from the main site only.
- Leftover bootstrap: static `bootstrap_parts($code)` returns `{ guard, config, chain }` only when
  the code is exactly `build_bootstrap()`'s template (rebuilt with those paths it must be the same
  text). `is_leftover_bootstrap($code)` additionally requires this plugin's `guard_file()`, no
  chained file other than the saved `wpcybersec_guard_chain`, and the current config file or a
  `guard/config.php` inside a `wpcybersec*` data folder that is missing or holds only data
  (static `config_is_data()`: tokens of `return array( ... );` with plain values). The marker
  `WPCYBERSEC_GUARD_BOOTSTRAPPED` alone never counts. `refresh_leftover_bootstrap()` rewrites such
  a file for the current data folder: from `Installer::activate()` when the guard is not installed,
  and on admin pages for administrators.
- `install()`: writes the bootstrap (checks `file_exists` before including the plugin's
  `guard/guard.php`, so deleting the plugin never fatals), `Guard_Config::write()`,
  `allowlist->export_guard_file()`, sets option `wpcybersec_guard_installed`.
- `uninstall()`: disables config; removes bootstrap only if `auto_prepend_file` no longer points to it.
- `status()`: `{ installed, active (constant WPCYBERSEC_GUARD_ACTIVE defined in this request),
  bootstrap_path, bootstrap_exists, prepend (ini value), conflict (other prepend file or null),
  sapi, pending_spool }`.
- static `ols_activation_step()`: on OpenLiteSpeed / CyberPanel `{ inline, text, code, next }` for a
  .user.ini line lsphp has not read yet (`touch <PHP user's home>/.lsphp_restart.txt` or `killall lsphp`,
  then Test again; else the vHost phpIniOverride); used by Hardening's guard fix, "Only write .user.ini",
  Test again and the Early guard card, null elsewhere. `foreign_prepend_hint()`: `{ text, code, note }`
  for a prepend file of another site (`other_site_root()`): the `grep -rn auto_prepend_file` command over
  the loaded php.ini folder, lsphp's php.ini and vhost.conf files, panel folders, /etc/php* and this site's
  .user.ini/.htaccess, and the note that a shared php.ini serves the other site too (read only on the
  Early guard card and the Environment check, never from `status()`).
- `snippets()`: list of `{ id, label, file, code, help, recommended }` for .user.ini, .htaccess
  (mod_php, LiteSpeed Enterprise, mod_lsapi; every line in IfModule), OpenLiteSpeed (WebAdmin
  php.ini Override or CyberPanel vhost.conf; it ignores php_value in .htaccess), php-fpm pool,
  nginx fastcgi_param, php.ini; `recommended_snippet()` by SAPI and LiteSpeed edition.
- `write_user_ini()`: appends/updates `auto_prepend_file` in `ABSPATH/.user.ini`.
- `import_spool()`: int imported.

### `guard/guard.php`
Standalone (no WordPress). Exits when it is itself the requested script (direct access);
included or prepended it runs normally. Defines `WPCYBERSEC_GUARD_ACTIVE`. Reads `WPCYBERSEC_GUARD_CONFIG`
(set by the bootstrap). Returns immediately if disabled or `$_FILES` empty or the request path
matches `exempt` (`.php` patterns match the script file; route patterns match `home_path`, or
any entry of `home_paths` on multisite, plus the route; core endpoints need login credentials).
For each uploaded file (nested `$_FILES` arrays too) with no error:
sha256 the tmp file; allowlisted -> pass; else copy into `quarantine_dir`, append a JSON line
to `spool_file` (`time, script, uri, host, method, ip, ua, field, name, size, sha256,
quarantine_path, type, exec, held, dropped, note, action`; `host` lets the import find the site),
unlink the tmp file, and either answer `403` with the message (`block`) or strip it from
`$_FILES` (`strip`). Must never fatal: wrap in try/catch, fail open on internal errors.

### `Notifier`
- Recipients: `Settings::recipients()` (multisite default: network admin email and super admins).
  Subjects and bodies use `Network::name()` / `Network::home_url()`, review links go to
  Network Admin on multisite, items with `details.blog_id` get a "Site" row.
- `register()`: cron `wpcybersec_digest` (daily) when `notify_mode=digest`.
- `item_created($id)`: instant mode emails recipients (throttle: one email per 10 minutes,
  queued items are summarized in the next email) and posts to `webhook_url` if set.
- `scan_finished(array $status)`: email only when threats/new pending items were found.
- `send_test()`: bool.
- `send_digest()`.

## Admin UI module (owner: admin builder)

Files: `includes/admin/class-admin.php`, `includes/admin/class-dashboard-page.php`,
`includes/admin/class-reports-page.php`, `assets/css/admin.css`, `assets/js/admin.js`.

- `Admin\Admin::register()`: menu `Guard` (page title Qartvelo Guard) (dashicons-shield, position 80, capability
  `Admin::cap()`, count bubble = pending + threats; on `network_admin_menu` on multisite), submenus Dashboard (`wpcybersec`),
  Reports (`wpcybersec-reports`), Settings (`wpcybersec-settings`, rendered by
  `Admin\Settings_Page`), Setup Wizard (`wpcybersec-wizard`, rendered by `Admin\Wizard`).
  Registers `Admin\Assets` on `admin_enqueue_scripts` and enqueues base + page assets only on
  plugin pages. Activation redirect: if option `Installer::REDIRECT_OPTION` is set and the wizard
  is not completed, delete it and redirect to the wizard (skip on bulk activation, network
  admin, AJAX). Admin bar node "Qartvelo Guard (N)" for admins when N pending. Admin notice on
  other screens when the wizard is not completed. "Settings" and "Setup" action links on the
  plugins screen. admin-post handlers: `wpcybersec_download` (stream held file),
  `wpcybersec_allowlist_remove`, `wpcybersec_report` (download report), `wpcybersec_recent_report`.
- Header partial used by every page: `Admin\Admin::header($title, $subtitle, $actions_html)`
  renders `.wpcs-header` with the shield icon. **The setup builder uses this too.**
- Dashboard: status cards (protection level, pending approvals, threats, quarantine, files
  monitored, last scan), scan buttons (Quick scan = incremental, Full malware scan, Rebuild
  baseline) with a progress block, recent activity, guard and freeze status, link to wizard.
- Reports: tabs Pending approvals / Threats / Quarantine / History / Recent changes / Allowlist / Activity. Tables with
  type badge, file, size, hash, who/where, when, verdict/hits, status cell
  (`data-wpcs-status`), action buttons (`data-wpcs-action`) from `Decisions::available()`,
  expandable details (hits with snippet and line), bulk actions, search, pagination.
  Allowlist tab: remove entry. Activity tab: log with filters.

## Setup module (owner: setup builder)

Files: `includes/admin/class-wizard.php`, `includes/admin/class-settings-page.php`,
`includes/class-sysadmin-tools.php`, `includes/class-cli.php`, `assets/css/setup.css`,
`assets/js/setup.js`.

- Wizard steps: Welcome, Environment check, Protection level, Baseline scan, Notifications,
  Server hardening (sysadmin, optional), Done. Saves via admin-post `wpcybersec_wizard`.
  Baseline step runs `WPCyberSec.scan.run({mode:'baseline', malware:true, trigger:'wizard'})`.
  Completing sets `wizard_completed`.
- Settings page tabs: General (protection level presets + fine-grained upload/install/file
  monitor/schedule/notification settings) and Advanced for system administrators (server health,
  antivirus engines (ClamAV + maldet), developer instructions, data dir, scan root, exclusions,
  limits, early guard install + snippets, real cron, freeze lock, hardening snippets,
  fapolicyd/inotify, tamper checksum, import/export, uninstall behavior). Saves via admin-post
  `wpcybersec_save_settings`. Advanced is one form split into sections
  (`Settings_Page::advanced_sections()`, card id `wpcs-<key>`) that setup.js shows one at a time as
  tabs; hidden sections stay in the form. The open section travels as `?section=<key>` (also the
  hidden `section` field, kept through the save redirect); `Sysadmin_Tools::settings_url('advanced',
  [], 'wpcs-<key>')` adds it from the fragment.
- `Hardening`: one-click fixes (`run($id)`; fix `world_writable`, part of "Fix all", removes only the
  o+w bit (`chmod o-w`) from the paths of `world_writable_scan()` that PHP owns (lstat uid equals
  `posix_geteuid()`, never a symlink), then scans again; paths of another owner get `manual_steps()` with
  Hosting task `permissions` first), `move_data_dir($target, $outside_only)` moves the
  data folder through `Storage::relocate()` (refused while a scan runs, on multisite, or when the
  guard bootstrap cannot be rewritten; a target outside open_basedir is refused with that reason
  before anything else; the guard spool is imported first, the allowlist mirror and
  guard config are rewritten in the new folder, the guard is reinstalled there). The uploads PHP
  block is only reported fixed after a live test (a probe PHP file must not run, a probe text file
  must still load; otherwise rolled back); on nginx the rule is shown instead of writing a
  .htaccess. `DISABLE_WP_CRON` and `WPCYBERSEC_HMAC_KEY` are written with `Config_Editor`.
- `Developer_Instructions`: `items($checks = null)` (each `{ id, title, why, steps, error, at,
  optional }`), `count()` (cached), static `record_failure($id, $message)` / `clear_failure($id)`
  (option `wpcybersec_fix_failures`; Hardening::run(), the guard and uploads/.htaccess handlers call
  them), `as_text($items)`, admin-post `wpcybersec_dev_instructions` (.txt download). No secrets.
- `Sysadmin_Tools`: `diagnostics()` (list of `{ id, label, status pass|warn|fail|info, detail, fix }`),
  `cron_snippets()`, `apache_uploads_rules()`, static `nginx_uploads_rule()` (the one nginx rule that
  blocks PHP in uploads, `UPLOADS_EXEC_PATTERN`; Hardening's manual steps use it and
  `apache_uploads_rules()` too), `nginx_rules()`, `permission_commands()`,
  `fapolicyd_trust_export()`, `fapolicyd_rules()`, `inotify_script()`, `maldet_steps()`,
  `antivirus_status()` (ClamAV shows "Unknown (hosting hides it)" instead of "Not installed" when
  `clamav_hidden()` says the host may hide the binary; maldet likewise with `maldet_hidden()`, key
  `maldet.hidden`), static `maldet_detect()`, `inotifywait_installed()`,
  `write_uploads_htaccess()`, `hmac_snippet()`. `antivirus_live()` (cached per request): rows `{ id
  clamd|maldet|maldet_monitor|maldet_watch|maldet_quarantine, label, state ok|bad|unknown|na, text, hint,
  code }`; hint/code say why a row is unknown or not set up and give the root command (Antivirus card and
  Developer instructions entries `maldet_monitor`, `maldet_watch`). static `processes_hidden()`: /proc
  mounted with hidepid (`/proc/self` visible, `/proc/1` not), so process checks (pgrep, pid files) are
  unknown, never "not running"; socket checks (clamd) are unaffected; `processes_hidden_text()`,
  `monitor_check_hint()` (`pgrep -af inotifywait` / `cgav monitor status`), `cgav_installed()`,
  `monitor_watches($lines, $site)` (exact line or a watched parent folder: maldet watches recursively),
  `monitor_add_site_step()` (`cgav add-site <site>`, else the monitor_paths line plus `systemctl restart
  maldet`: maldet's reload_monitor re-reads only its settings, not the folder list). ClamAV and maldet are
  per server and shared by every site; `cgav_install_block()` ends with `cgav add-site <site>`.
  World-writable code: `world_writable_roots()` (plugin folder, wp-content, plugins and themes with one
  level of entries, mu-plugins, ABSPATH, wp-admin, wp-includes; wp-config.php has its own check),
  `world_writable_scan($cap = 500)` (lstat, never follows symlinks, open_basedir respected, null on
  Windows; `{ paths, roots, checked, truncated }`), `world_writable_command($roots)` (`find <root> -perm
  -o+w -not -type l -exec chmod o-w {} +`), check id `world_writable`, `display_path()`. WP-CLI:
  `wp_cli($bin)` is `wp`, or this site's PHP plus the wp program (`/usr/local/lsws/lsphp83/bin/php
  /usr/local/bin/wp`, `"$(command -v wp)"` when wp is not found) when `is_default_php()` says the default
  php of a shell is another binary; used by the WP-CLI cron variant, managed-host cron steps and the core
  reinstall lines. `php_binary()` returns lsphpXX/bin/php for lsphp even when open_basedir hides it.
  `site_slug()` names per-site server files (fapolicyd `35-wordpress-<slug>.rules` and
  `wordpress-<slug>.trust`, `inotify_script_path()` `/usr/local/bin/wpcybersec-watch-<slug>.sh`). `server-tools/cgav.sh` (also offered as a
  download, `includes/admin/cgav-script.txt`) installs and checks ClamAV and Linux Malware Detect
  on the server (status, install-clamav, install-maldet, monitor, test, update, scan, logs; safe to
  re-run, never deletes site files).
- `Cli`: static `register()` -> `WP_CLI::add_command('wpcybersec', ...)` with `status`, `scan`,
  `pending`, `approve`, `deny`, `allowlist`, `guard`, `unlock`, `lock`, `report`,
  `core-reinstall [--yes]` (Core_Repair start/tick/swap, asks before the swap without --yes, then
  runs the quick scan to completion).

## Hosting panel detection

Files: `includes/class-hosting.php`; used by `Sysadmin_Tools` (check `hosting`), `Hardening::manual_steps()`,
`Developer_Instructions`, `Guard_Manager::snippets()`, `Admin\Settings_Page`, `Admin\Wizard`, `Site_Report`.

- `detect()`: `{ id, name, kind panel|managed|local|unknown, confidence high|likely|'', signals[], web_server,
  web_server_name, php_handler fpm|lsapi|mod_php|cgi|cli|other, php_handler_name, sapi }`. Only folders, files,
  constants and environment variables, never a program; every file check goes through the probe, whose default
  (`default_probe()`) checks `Storage::path_allowed()` before `@is_dir()` / `@is_file()`. `new Hosting( $probe )`
  takes a callable `( $what dir|file|func|const|env|server|value, $arg )` so tests fake all of it. A marker that
  belongs to the panel (install folder, host constant) gives `high` and beats any layout; site paths alone give
  `likely`; CloudLinux only decides (cPanel, likely) when nothing else matched. DDEV and Lando win over managed
  hosts' mu-plugins copied with a site; `PANTHEON_ENVIRONMENT=lando` is Lando.
- `current( $fresh )`: the cached detection (non-autoloaded option `wpcybersec_hosting` `{ v, at, result }`, 12 h,
  `RULES_VERSION`) with setting `hosting_panel` applied (`''` detect, a panel id, or `other` for the generic
  steps); adds `detected_*`, `overridden`. Read it only on pages that show instructions (Advanced sections,
  wizard Environment and Server steps, developer instructions, the report): normal admin pages stay at 0 queries.
- `steps( $task )` for `cron`, `prepend`, `php_restart`, `clamav`, `maldet`, `web_rules`, `data_dir`, `permissions`: the usual
  `{ text, code }` steps, empty when the panel has none (generic steps apply). Cron steps come from
  `Sysadmin_Tools::cron_jobs()` (which also gives `script`, `args`, `url` for panels that ask for them apart),
  nginx rules from `Sysadmin_Tools::nginx_uploads_block()` (the `UPLOADS_EXEC_PATTERN` rule as a prefix location
  with the PHP block nested, so it works wherever a panel includes it) and `nginx_data_rule()`, Apache rules
  from `apache_uploads_rules()`. Filter `wpcybersec_hosting_steps`.
- `file_manager()`: `{ name, open, upload, extract, move }` of the panel's own file manager (null when it has
  none); `manages_core()`: the name of a host that manages WordPress core itself ('' otherwise). Both for
  `Core_Repair::manual_steps()`.
- `merge( $task, $generic )`: panel steps, then the marker step `Hosting::other_ways()` (`{ text, other: true }`),
  then the generic ones; `Settings_Page::render_steps()` folds what follows the marker under "Other ways",
  `Developer_Instructions::as_text()` prints "Other ways:". `prepend` adds the `php_restart` steps; `data_dir`
  notes go in front without a fold. `prepend_snippet()` is the recommended `Guard_Manager::snippets()` entry
  (id `panel`) when the panel has one. `Settings_Page::render_panel_steps()` / `other_ways_open()` /
  `other_ways_close()` do the same for cards.
- `server-tools/cgav.sh` `detect_panel()` checks the same install folders (then the site path) as root, prints the
  panel in `cgav status`, and `install-clamav` follows it (cPanel's own package, DirectAdmin CustomBuild hint
  unless `CGAV_OS_PACKAGES=1`, Plesk note, system packages elsewhere).

## Core reinstall

Files: `includes/class-core-repair.php` (`Core_Repair`, service `core_repair`),
`includes/admin/class-core-repair-card.php` (`Admin\Core_Repair_Card::render( 'dashboard'|'reports' )`),
`assets/js/core-repair.js` (enqueued on the Dashboard and Reports pages, strings in `wpcybersecCore`).

- Detection, `damage()`: open (pending, not held) file/threat items whose `original_path` is under
  ABSPATH `wp-admin/`, `wp-includes/` or the WordPress root (one query on the items table, skipped
  when `Store::counts()` has nothing pending), classified by `classify()` from what the scan stored:
  `modified` (`details.verified = core`, `checksum = mismatch`; a localized version.php never),
  `unknown` (sig `core_unknown_file` / `core_unknown_config`, or `checksum = unknown_file`; `exec`
  when it can run code), `threat` (other open threats in core folders or root core file names,
  `ROOT_FALLBACK`), plus `missing_core` of the last scan. One count per path. `show` = total >=
  `THRESHOLD` (5, filter `wpcybersec_core_damage_threshold`) or any unknown executable file. Root
  PHP files that are not core (backdoor.php) are not counted: they stay in Reports. With 1 to 4
  changed files the per-file "Restore official file" stays the way. Called only on the Dashboard,
  the Reports Pending/Threats tabs (no search or filter), the downloadable report
  (`Site_Report::section_core()`) and Developer instructions (entry `core_reinstall`); normal admin
  pages never load it.
- Card: counts, why replacing core beats reviewing files, option B (when `auto_status()` is ok) and
  option A ("Do it by hand", open when B is not available) with "Download the package", "Turn on
  maintenance mode" (AJAX `core_maintenance`, standard `.maintenance`, 10 minutes) and the .txt of
  Developer instructions. A running job (resumed by the script on page load), the finished or
  failed job (Dismiss) and every kept backup ("Restore the previous core", Dashboard only).
- `layout()`: `standard`, `composer` (composer.json one or two folders up naming roots/wordpress,
  johnpbloch/wordpress, wordpress/core-implementation or roots/bedrock, ABSPATH under vendor/, or
  Bedrock's `web/wp/`), `symlink` (wp-admin or wp-includes is a link), `custom` (WPINC renamed).
  `Hosting::manages_core()`: WP Engine, Kinsta, Pantheon, WordPress.com, Pressable, Flywheel.
- By hand, `manual_steps()` (`{ text, code }`, `Hosting::other_ways()` marker before the SSH block):
  backup, the no-content zip of this exact version (`package_url()`: the `update_core` offer's
  `packages->no_content` when it is for this version and en_US, else
  `https://downloads.wordpress.org/release/wordpress-<v>-no-content.zip`), the English-package note
  for localized sites, the panel's file manager (`Hosting::file_manager()`: cPanel, Plesk,
  DirectAdmin, CyberPanel, aaPanel, HestiaCP, VestaCP, CloudPanel, CWP, Virtualmin, FASTPANEL,
  ISPmanager, Hostinger, SiteGround; SFTP otherwise), upload first, maintenance, delete wp-admin,
  wp-includes and exactly the root files of the checksum list (`root_files()`), keep everything
  else (what is in the folder is listed), extract, move up, clean up, full scan, then
  `after_steps()` (passwords, salts, plugins/themes/uploads). Other ways: `ssh_block()` (subshell
  with `set -e`, refuses without wp-config.php / wp-content, curl, `.sha1` check, unzip or PHP
  ZipArchive, `.maintenance`, delete exactly the core paths, copy, chown to the owner of
  wp-content when run as root, clean up) and `wp core verify-checksums` (with the warning against
  `wp core download --force` on 7.x). Composer: `composer reinstall <package>` instead, no delete
  steps. Managed hosts: ask the host or use its restore tools.
- One click, `auto_status( $live )`: refused with the reason for DISALLOW_FILE_MODS, the freeze lock,
  a non-standard layout, a managed host, no ZipArchive, `get_filesystem_method()` other than
  `direct`, ABSPATH/wp-admin/wp-includes not writable, or no place (`places()`): the work folder
  `<data>/core-stage/<id>` (data folder on the same filesystem as ABSPATH) else
  `<parent of ABSPATH>/.wpcybersec-core-stage`; the backup `<data>/core-backup/<id>` when the data
  folder is outside the web root, or inside it on Apache/LiteSpeed with its deny-all .htaccess, or
  when the web probe says blocked, else `<parent>/.wpcybersec-core-backup-<id>` (same filesystem,
  writable, not served, not in the scan set). Never a backup that the web can reach.
- Job (option `wpcybersec_core_reinstall`, not autoloaded; AJAX `core_reinstall`
  do=start|tick|swap|cancel|status|dismiss): `start()` (checks incl. the live ones, no running scan,
  `checksums( $version )` = `get_core_checksums( $version, 'en_US' )` without wp-content, saved as
  `checksums.json` in the work folder) -> `download` (`download_url()`, compared with the release
  `.sha1`) -> `extract` (every entry name checked first: under `wordpress/`, no `..`, no wp-content;
  then ZipArchive batches within `BUDGET`) -> `verify` (md5 of every listed file, then no extra file;
  any difference fails with nothing changed) -> `ready` (`confirm_text()` for `confirmDialog()`) ->
  `swap()`: backup folder with marker `.wpcybersec-core-backup` (JSON id, abspath, version, added
  root files, disabled configs), `exchange()`: wp-admin/includes/file.php and update.php loaded
  first, a loopback of the home page, `.maintenance` (`maintenance_on()`, an existing foreign one is
  kept), wp-includes then wp-admin renamed into the backup and the verified ones renamed in, root
  files copied to `<backup>/root/` and replaced atomically (`put_file()`), every step journaled in
  the state, `opcache_reset()`, maintenance off, `post_check()` (version.php included in a closure
  must report the version; home page not 5xx, and answering when it answered before; filter
  `wpcybersec_core_reinstall_check`), on failure maintenance on, `rollback()` of the journal,
  maintenance off. A shutdown function rolls back when PHP dies mid-swap; `recover()` (every
  request that looks at the job) rolls back a swap whose state is older than `STALE`. When a step
  cannot be undone, the backup and work folder are kept. Then the backup's .htaccess/.user.ini/
  php.ini/web.config files get `.wpcs-off` (an attacker's .htaccess must not open the backup) ->
  `finish()`: core items resolved (`details.resolution` `core_reinstalled`, or `removed_with_core`
  for extra files in wp-admin/wp-includes, plus `core_backup`), the extra files logged
  (`core_unknown_moved`), manifest rows under wp-admin/ and wp-includes/ dropped and every new core
  file upserted trusted (`run_id` core), `missing_core` of the last scan recounted, work folder
  deleted, a quick scan started (trigger `update`).
- Backups (option `wpcybersec_core_backups`): `restore( $id )` (AJAX `core_restore`) swaps the old
  core back with the same exchange, check and rollback, forgets the manifest rows of core paths so
  the next scan judges the old files again, deletes the backup and the replaced clean core, starts a
  quick scan. `prune()` on `wpcybersec_maintenance`: backups older than `KEEP_DAYS` (7, only folders
  with their marker) and jobs left for a day. Uninstall with "Delete all data" removes marked
  backups next to the WordPress folder too.
- Multisite: network admin only (`Admin::can()`), one core for every site, the loopback goes to the
  network home. Log events `core_reinstall_started`, `core_package_verified`, `core_reinstalled`,
  `core_items_resolved`, `core_items_removed`, `core_unknown_moved`, `core_reinstall_failed`,
  `core_reinstall_rolled_back`, `core_reinstall_cancelled`, `core_restored_previous`,
  `core_backup_deleted`, `core_maintenance_on`.

## Speed and usability contracts

- **Admin query budget.** A normal admin page or heartbeat costs the plugin 0 queries on a single site (1 on multisite); the front end costs 0. Keep it that way:
  - Small state options are in `Network::STATE_OPTIONS` and always autoloaded. Write them only through `Network::update_option()` / `add_option()` / `delete_option()`; a direct core `update_option( ..., false )` hides the value once `Network::prime()` marks missing ones in `notoptions`. `Installer::autoload_state_options()` flips existing rows once (flag option `Network::AUTOLOAD_FLAG`).
  - Badge counts come from `Store::counts( $fresh = false )`: one combined query cached in `wpcybersec_counts`, cleared by `Store::flush_counts()` on every item insert, status/type/quarantine change and delete. `Store::newest_open_id()` feeds the pending notice.
  - The guard spool is imported at `init` priority 1 on admin pages (`Guard_Manager::early_import()`, two stats when empty), before the menu counts are built.
- **ClamAV self-test.** `Scanner::clamav_selftest( $fresh )` scans the EICAR string (built at run time by `Scanner::eicar()`, never stored in a plugin file) with every binary, with a time limit, and stores `{ at, key, error, bins: { path: { ok, error, kind, ms, daemon, flags } } }` in `Scanner::SELFTEST_OPTION` (6 h; refreshed in the background, by Check again and when a ClamAV setting changes). Scans and uploads only read the cached result (`clamav_selftest_cached()`), never wait for a new test. `clamav_plan( $context )` skips failed binaries, uses only clamdscan for whole-site scans, and skips a plain clamscan slower than `SLOW_MS` for uploads someone waits for unless `wpcybersec_clamav_slow_uploads` is on. Turning ClamAV on runs the test first and refuses with the reason.
- **Guard status.** `Guard_Manager::record_ping()` stores the last live test (`PING_OPTION`); `live_state()` uses it where the current request cannot tell (WP-CLI, cron, built-in server): "Active (confirmed by a live test N minutes ago)". Re-tested at most every 6 hours (`maybe_reping()`). Hardening fix `guard` installs, picks .user.ini or .htaccess, tests and rolls back; fix `guard_files` only writes the guard files. "Write .user.ini" is refused while the bootstrap file is missing (a prepend line to a missing file breaks every request).
- **Cron advice.** One source: `Sysadmin_Tools` cron recommendation (hourly quick scan, nightly full scan, WordPress cron every 5 minutes; `--quiet --wp`, plus `--url` on multisite). The Environment check, wizard Server step, Settings > Real cron, Hardening steps and Developer instructions all print it.
- **Upload volume hint.** `Sysadmin_Tools::upload_activity()` (one grouped query, cached 1 h) counts the last 30 days of attachments and the share from non-administrators; above 15 a day the wizard recommends Balanced with `upload_mode = hold_risky`.
- **Reports.** Items flagged high or critical show the safe action (Deny, Quarantine or Restore) as primary; Allow / Mark safe open `WPCyberSec.confirmDialog()` and the server refuses them without `risk_ok=1` (AJAX `item_action`, `bulk_action`; the no-JS form shows a confirmation page). All confirmations use `confirmDialog()` (native `confirm()` only where `<dialog>` is missing).
  - Image previews: admin-post `wpcybersec_preview` (capability + per-item nonce) streams a held jpeg/png/gif/webp only after `Upload_Gate::image_preview()` verified it (getimagesize and finfo agree, inside the quarantine folder, severity below high, never svg), with nosniff, inline, private cache and a sandbox CSP.
  - "Allow all clean images": AJAX `clean_images` (count) and `allow_clean` (batches of 5, each id re-checked with `Upload_Gate::is_clean_image()`, approved through `decisions->bulk( 'approve' )` so each is imported like a single Allow).
- **Activity log.** Guard imports are logged with no user and the visitor IP, never as the administrator whose page load ran the import.

## Opt-in install statistics

Files: `includes/class-stats.php` (`Stats`, service `stats`), `Admin\Settings_Page::share_stats_box()` (wizard
Alerts step and the "Usage statistics" card of Settings > General), endpoint and admin on qartvelo.com.

- WordPress.org guideline 7: setting `share_stats` (default false) is the only switch, no notice ever asks for it.
  The Alerts step saves it with "Save and continue" ("Skip" saves nothing); a settings import never copies it.
  `WPCYBERSEC_DISABLE_STATS` (true) stops every message whatever the setting says.
- Endpoint `Stats::endpoint()`: `WPCYBERSEC_STATS_URL`, else `https://qartvelo.com/api/qartvelo-guard/stats`,
  filter `wpcybersec_stats_url`. `wp_remote_post`, JSON, timeout 5 s, no redirects.
- Events: `opt_in` (on the switch from off to on, `wpcybersec_settings_updated`), `heartbeat` (cron
  `wpcybersec_stats_heartbeat`, weekly, main site only, kept in shape on `init` (autoloaded cron option, no query); first run 10 minutes after
  a reactivation, else a week after the last check-in), `deactivate` (`Installer::deactivate()`, non-blocking),
  `uninstall` (`uninstall.php` before options are deleted, non-blocking, only when opted in), `opt_out` (on the
  switch from on to off, one last message). Never from a page view.
- Identity: network option `wpcybersec_stats_identity` `{ id (UUID), secret (64 hex), site (home URL without
  scheme), registered }`, created at the first message and again when the site address changes (clones are new
  installs). The secret goes once in `opt_in` (`signing_secret`); every body is signed, header `X-CGS-Signature`
  = `hash_hmac( 'sha256', body, secret )`. A heartbeat answered 404 (unknown install) registers again with
  `opt_in`. Last result: network option `wpcybersec_stats_last` (not autoloaded) for the "Last sent" line.
- Payload (`payload()`): `install_id, event, sent_at, plugin, plugin_version`; plus (not for `opt_out`)
  `site_url, site_name, wp_version, php_version, db_version, locale, multisite, sites_count`; plus (opt_in and
  heartbeat) `server_software, hosting_panel, hosting_panel_name, settings { protection_level, upload_mode,
  install_mode, file_mode, clamav_enabled, maldet_installed, guard_active }, stats { files_monitored,
  pending_items, threats_last_scan (two significant digits, `round_count()`), last_scan_at }`. Never emails,
  user names, file names or paths, visitor IPs, keys or content. `Stats::fields()` is the list the UI shows;
  keep it, readme.txt and the docs page in step with `payload()`.

## Uninstall and deactivation

- Deactivation (`Installer::deactivate()`): plugin cron events cleared on every site of a network
  (`Network::clear_cron_everywhere()`, time-boxed), guard config disabled, redirect flag removed.
- `uninstall.php` always removes the wp-config.php backups (they hold the database password).
  With "Delete all data on uninstall" (read from the network option on multisite, the main
  site's option before migration) it also: loads the plugin and removes only the define lines it
  marked (`Config_Editor::remove_marked_constant()` for `WPCYBERSEC_HMAC_KEY` and
  `DISABLE_WP_CRON`, never a hand-written one, never when wp-config.php does not parse); removes
  the guard lines (`; BEGIN/END Qartvelo Guard early guard` block and the `auto_prepend_file` line)
  from .user.ini and the `# BEGIN/END Qartvelo Guard early guard` block from .htaccess, in ABSPATH
  and the front controller folder; removes the `# BEGIN/END Qartvelo Guard` block from the
  (main site's) uploads .htaccess (deleting the file when nothing else was in it); drops the
  tables, deletes options, transients and site transients (`_site_transient_wpcybersec_*` and
  their timeouts, in the options table on single sites) and cron events of every site (multisite:
  `get_sites()` over every network, old per-site tables too), deletes the network options and user
  meta, removes the data folders that carry this install's marker, and deletes
  `wpcybersec-guard.php` only when nothing points auto_prepend_file at it (never from WP-CLI).
