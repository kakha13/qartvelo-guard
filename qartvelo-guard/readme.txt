=== Qartvelo Guard ===
Contributors: kakha13
Tags: security, malware scanner, file integrity, upload, quarantine
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Scans your site for malware and holds every new upload, install and unknown file until you approve it. Approve once, allowed always.

== Description ==

Qartvelo Guard works like a door that only opens for files you know. Every new upload, plugin, theme and unknown PHP file waits in a private quarantine until an administrator approves it, and the whole site is scanned for malware, web shells and backdoors.

= Approve once, allowed always =

* **Holds new files until you allow them.** Media uploads, files WordPress downloads, plugin and theme ZIPs and new installs wait on the Reports page. Approving a file remembers its SHA-256 fingerprint, so the same file is never held again. A file approved as an image is never accepted as a PHP file.
* **Image previews and bulk approval.** Held images show a thumbnail that is only served after the plugin verified the file really is that image. "Allow all clean images" approves every verified image without findings in one go. Risky files such as a GIF with PHP code inside get Deny as the main button.
* **Setup wizard.** Checks your server, fixes most findings with one click and picks a protection level. On busy sites it shows how many uploads a day you would have to approve and suggests holding only risky uploads instead.

= Find what is already there =

* **Full site malware scan.** WordPress core, plugins, themes, uploads and the web root. Core files and plugins from WordPress.org are compared with their official checksums, so original files are never reported.
* **What changed.** A line by line diff of a modified file against the last approved version or the official original, with every malware match linked to its line. Passwords, keys and salts are masked.
* **Database scan.** Options, posts and the storage of header and footer script plugins (WPCode, Header Footer Code Manager, Code Snippets) are checked for injected scripts.
* **Administrator watch.** Every new administrator account is reported and waits for your review: at once when it is created through WordPress, and at the next scan when it was inserted straight into the database. Deny removes the role and signs the account out.
* **Recent changes.** A site that was already infected when the baseline was recorded looks normal to a scan. Reports > Recent changes lists every PHP, script and configuration file modified in the last 7, 14 or 30 days and says what explains each change: an update, an official checksum, or nothing.
* **Clean core reinstall.** When WordPress core looks damaged, one button downloads the official package of your version from WordPress.org, checks every file against the official checksums, swaps wp-admin, wp-includes and the root core files in a few seconds with maintenance mode on, and puts the old core back by itself if the site stops answering. Step by step instructions are offered for doing it by hand.

= For administrators and hosts =

* **Hosting panel detection.** The plugin recognises cPanel, Plesk, DirectAdmin, CyberPanel, aaPanel, HestiaCP, CloudPanel, CWP, ISPConfig, RunCloud, GridPane, Cloudways, Hostinger and many managed hosts and local tools, and shows the steps for your panel first.
* **Early upload guard (optional).** Holds files uploaded to any PHP script on the site, not only to WordPress, through auto_prepend_file. One click installs it, makes a live test request and undoes everything automatically if the site stops answering.
* **ClamAV and Linux Malware Detect (optional).** When ClamAV is installed on the server the plugin runs a real self-test with the EICAR test file and, once you turn it on, also scans uploads with it. maldet signatures are used through ClamAV. They know many more existing infections; they do not block attacks.
* **Security report.** "Download report" creates one HTML file with the scan results, everything waiting for a decision, settings, server checks and recent activity. Passwords, keys and email addresses are hidden, so it is safe to send to a developer.
* **Multisite network mode.** Network activated, it protects the whole network once: one Reports page in Network Admin, uploads of every site are held, scans run once for the network.
* **Light on your site.** Normal front end pages cost zero database queries, and admin pages zero on a single site. Scans run in the background in small steps.
* **WP-CLI.** `wp wpcybersec status`, `scan`, `pending`, `approve`, `deny`, `allowlist`, `guard`, `core-reinstall`, `unlock`, `lock`, `report`.

== Installation ==

1. Install the plugin through Plugins > Add New Plugin, or upload the ZIP there.
2. Activate it. On multisite, network activate it. The setup wizard opens.
3. Follow the steps: environment check, protection level, baseline scan, alerts and optional server hardening.

== Frequently Asked Questions ==

= Does it slow my site down? =

No. Visitors' pages cost the plugin zero database queries. Uploads take a moment longer because each file is scanned. Whole site scans run in the background in short steps, through WP-Cron or a real cron job if you set one up.

= Does it work with Wordfence? =

Yes. Wordfence's firewall loader (wordfence-waf.php) is recognised and not reported. If Wordfence already uses auto_prepend_file, the early upload guard loads Wordfence's file as well instead of replacing it.

= I am on shared hosting without SSH. Can I use it? =

Yes. Everything except the optional server tools works from the WordPress admin. Settings that need the server (a data folder outside the web root, a real cron job, ClamAV) come with steps for your hosting panel, and Settings > Advanced > Developer instructions collects them in one file you can send to your host.

= Will it block my own uploads? =

With the Balanced or Strict level every upload waits for approval, including yours. To let clean uploads through, choose Relaxed, or in Settings > General set "When a file is uploaded" to "Hold risky uploads", or tick Administrator under "Clean uploads pass for" (the setup wizard calls these "Hold only risky uploads" and the "Hold administrators' own uploads too" switch).

= What happens when I update a plugin or WordPress? =

Updates of installed plugins, themes and core are checked again right away against their official checksums and trusted. New installs wait for approval.

= What if WordPress core itself is infected? =

Modified or extra files in wp-admin and wp-includes are reported as threats. When several core files are damaged, or an extra PHP file sits in wp-admin or wp-includes, the plugin offers to reinstall a clean copy of your WordPress version, verified against the official checksums, with an automatic rollback. wp-config.php, wp-content and your own files are not touched.

= What about false positives? =

Original WordPress and WordPress.org plugin files are never reported because they match the official checksums. For anything else, "Mark safe" (or Allow) remembers the file's fingerprint, so that exact file is not reported again. If the file changes later, it is checked again.

= Does it work on multisite? =

Yes. Network activate it. It works once for the whole network from Network Admin, holds uploads on every site and reports administrator accounts of every site.

= What happens when I deactivate or delete the plugin? =

Deactivating stops the scans and switches the early guard off. Deleting the plugin keeps your data unless "Delete all plugin data when the plugin is deleted" is on in Settings; with it on, the plugin's tables, options and data folder are removed, and so are the lines it added to wp-config.php, .htaccess and .user.ini. Backups of wp-config.php are always removed.

= Does it change wp-config.php or .htaccess? =

Only when you press a fix or install button. Every change to wp-config.php is checked for errors first, and the plugin's own lines are marked so you can find them.

= Does it send any data to the developer? =

Only if you opt in. The setup wizard (Alerts step) and Settings > General offer an optional "Help improve Qartvelo Guard" switch, off by default. When you turn it on, the site address and setup details listed under External services are sent once a week. No email addresses, user names, file names or site content are ever sent, and you can turn it off at any time.

= Where are held files kept? =

In a private folder inside the uploads folder: wp-content/uploads/qartvelo-guard/ followed by a random 32 character folder name, so no file in it has a guessable address. Apache, LiteSpeed and IIS also refuse web access through the deny files the plugin writes; nginx ignores those files, so there the random folder name keeps the data private, both folders contain an index.php against folder listings, and Settings > Advanced shows an nginx rule plus a one-click move of the folder outside the web root. Held files inside have random or content-hash names ending in .bin and cannot run as code. Sites upgraded from a version before 1.1.0 keep their old folder until the plugin moves it on its own admin pages.

== External services ==

The plugin connects to the services below. It sends no personal data, no site content and no tracking data. Nothing is sent to the plugin author unless you turn on the optional usage statistics described last.

* **WordPress.org core checksums** (api.wordpress.org): during scans and before a core reinstall, to get the official checksums of the WordPress core files of your version. Sent: WordPress version and locale. [Privacy policy](https://wordpress.org/about/privacy/)
* **WordPress.org plugin checksums** (downloads.wordpress.org): during scans, the official checksums of installed plugins that are hosted on WordPress.org. Sent: plugin slug and version. [Privacy policy](https://wordpress.org/about/privacy/)
* **WordPress.org core package** (downloads.wordpress.org): only when an administrator starts "Reinstall clean core", the official package of the installed version without wp-content (wordpress-VERSION-no-content.zip) and its .sha1 checksum file. Sent: the WordPress version in the address. [Privacy policy](https://wordpress.org/about/privacy/)
* **WordPress.org Subversion** (core.svn.wordpress.org, plugins.svn.wordpress.org): when you open the "What changed" view of a core file or a WordPress.org plugin file, or press "Restore official file", the original file is downloaded and checked against the official checksum. Sent: the file path, the plugin slug and the version. [Privacy policy](https://wordpress.org/about/privacy/)
* **Your webhook URL** (optional, Slack, Discord, Microsoft Teams or any service you choose): when you enter one, alerts are posted there. Sent: the site name, the number of held files and threats, the names and paths of the files concerned and a link to the Reports page. Nothing is sent unless you enter a URL; the terms and privacy policy of the service you choose apply.
* **Your own site** (loopback requests): the early guard live test, the uploads folder test, the data folder test and the check after a core reinstall request pages and test files of this same site. They do not leave your server's own address.
* **Qartvelo Company statistics** (qartvelo.com), only if you opt in: off by default and nothing is sent before you turn on "Help improve Qartvelo Guard" in the setup wizard (Alerts step) or in Settings > General. Sent to https://qartvelo.com/api/qartvelo-guard/stats when you turn it on, then once a week, when the plugin is deactivated or deleted, and one last time when you turn it off. Sent: a random install ID, the event, the site address and name, the versions of the plugin, WordPress and PHP, the plugin database version, the site language, whether it is a multisite network and how many sites it has, the web server type and detected hosting panel, the protection level and upload, install and new-file settings, whether ClamAV is on, Linux Malware Detect is installed and the early guard is active, rounded counts of files monitored, items waiting and threats from the last scan, the time of the last scan, and once a signing key that proves later messages come from the same site. Never sent: email addresses, user names, file names or paths, visitor IP addresses, keys or passwords, or site content. Turn it off in Settings > General at any time; the constant `WPCYBERSEC_DISABLE_STATS` switches it off for good. [Privacy policy](https://qartvelo.com/qartvelo-guard/docs/privacy-and-external-services), [Terms of use](https://qartvelo.com/qartvelo-guard/docs/terms)

Host names that are not connections: the database scan contains a list of well-known script and image hosts (for example www.googletagmanager.com, connect.facebook.net, js.stripe.com, www.gstatic.com, s.imgur.com). It only compares the addresses of scripts it finds in your database with this list, to tell common embeds from injected code. The plugin never connects to these hosts and never loads anything from them.

The server script offered in Settings > Advanced (Antivirus engines and Developer instructions), cgav, is text for an administrator to read and run on the server. When it is run, it installs ClamAV from the operating system's package repositories and Linux Malware Detect from rfxn.com, and its test command fetches the harmless EICAR test file from secure.eicar.org. The same commands appear in the step by step instructions. The plugin never runs them and never installs software. The only code it ever writes into your site comes from WordPress.org: the official core package for a reinstall you start, or an official original file when you press "Restore official file".

Data kept on your site: for every held file the plugin records the uploading user, their IP address and the time, so you can decide whether to allow it. This stays in your database and is removed with the plugin's data.

== Screenshots ==

1. Setup wizard: choose a protection level, with a hint for sites that receive many uploads.
2. Dashboard: protection level, what waits for you, the last scan and the protection overview.
3. Reports: held uploads with image previews. A GIF with hidden PHP code gets Deny as the main action.
4. What changed: an injected line in a WordPress core file, with the malware match on its line.
5. Settings > Advanced > Server health, with the detected hosting panel and one-click fixes.
6. The early upload guard after the one-click setup and its live test.
7. Damaged WordPress core: reinstall a clean copy, verified against the official checksums.
8. Recent changes: every recently modified code file and what explains the change.

== Changelog ==

= 1.1.2 =
* Reinstalling an installed plugin or theme from a ZIP (including a new version of Qartvelo Guard itself) counts as an update, so it is no longer held as a new install.
* The scanner recognises callback web shells and request input read through $GLOBALS, and no longer skips code that follows a string containing /*.
* Files in a folder that was unreadable during one scan are no longer reported as new on the next scan.
* Scan alerts repeat only for new threats.
* Clearer Reports actions: Deny asks before deleting a held copy, trusting a new administrator asks first, critical files explain when no official copy exists.
* Accessibility: labelled radio groups, visible keyboard focus on protection cards, column labels in the narrow layout, reduced motion and high contrast support.
* Many smaller fixes to WP-CLI, the dashboard, the setup wizard and the server checks.

= 1.1.1 =
* The data folder inside uploads gets a random name (wp-content/uploads/qartvelo-guard/<random>/), so its files have no guessable address on nginx, which ignores .htaccess and web.config.
* No hard-coded uploads path: when WordPress cannot report the uploads folder, the plugin says so instead of guessing.

= 1.1.0 =
* New name: Qartvelo Guard. Settings, held files and approvals are kept when you update from an earlier version.
* New installs keep their data in wp-content/uploads/qartvelo-guard. The folder of earlier versions (wp-content/wpcybersec) is moved there automatically the next time an administrator opens the plugin.
* The early upload guard sanitizes every server value it reads, escapes its JSON replies and no longer uses lcg_value() (deprecated in PHP 8.4).
* Imported settings files are sanitized value by value.

= 1.0.3 =
* The Antivirus engines "On the server now" rows always use the newest ClamAV self-test: "Check again" now tests before any part of the page reads the state, so the clamd row no longer shows an old "Not running".
* A failed ClamAV self-test (for example while clamd restarts or the server is short of memory) is tested again within 15 minutes instead of being kept for 6 hours, and real cron (bin/cron.php) retests it when needed.

= 1.0.2 =
* "Code folders other users can write to" now also looks one level inside the WordPress folder and wp-content: a second WordPress install in a subfolder, translation files (PHP since WordPress 6.5), upgrade, uploads and backup folders. The one-click fix covers them too.

= 1.0.1 =
* The maldet real-time monitor no longer shows "Not running" on servers that hide other users' processes from PHP (/proc mounted with hidepid). It is detected from maldet's own log, or shown as unknown with the reason and the command that checks it as root.
* A site inside a folder the maldet monitor already watches now counts as watched. When the site is not watched, the Antivirus card shows the command that adds it (cgav add-site).
* ClamAV and maldet are installed once per server: the Antivirus card, the cgav script block and Developer instructions now say so, and the one-paste block adds this site to the monitor instead of assuming it is the only site.
* New check "Code folders other users can write to": finds world-writable plugin, theme and core folders, with a one-click fix that removes only the write permission for other users from files PHP owns, and safe commands for the rest.
* WP-CLI commands shown by the plugin (real cron lines, core reinstall checks) now use this site's PHP when the server's default php is another version, as on CyberPanel and OpenLiteSpeed.
* OpenLiteSpeed and CyberPanel: after the early guard is written to .user.ini, the guard page says exactly how to restart lsphp and what to do if it still is not loaded, instead of "within 5 minutes".
* A prepend file of another site now comes with the command that finds where it is set (often the server-wide php.ini) and what removing it means for the other site.
* Real cron run with WP-CLI (wp wpcybersec scan or wp cron event run from a crontab) now counts as real cron, so the "Switch off visitor-triggered cron" button appears.
* The Allowlist filter "File fingerprints" now also lists files approved under executable names.
* GridPane and SpinupWP cron steps now list only the two scan jobs they ask for.
* The help text of the guard's "Not checked by the guard" list now describes exactly how lines are matched.
* The cgav server script now handles many sites per server: cgav sites lists every WordPress site and whether it is watched, cgav add-site, remove-site and add-all change the list, and the monitor is restarted so a new site is really watched (maldet's own reload does not pick up new folders).
* fapolicyd files, the inotify watcher and the HestiaCP template are now named per site, so several sites on one server do not overwrite each other's.

= 1.0.0 =
* First release.
* Full site malware scan with official checksums for WordPress core and WordPress.org plugins.
* Holds new uploads, installs and unknown PHP files until an administrator approves them; approvals are remembered by SHA-256.
* Image previews of held uploads and "Allow all clean images".
* Setup wizard with environment fixes, protection levels and an upload volume hint.
* Hosting panel detection with panel specific steps.
* "What changed" line by line diff, Recent changes and the downloadable security report.
* Database scan for injected scripts and administrator account watch.
* Clean WordPress core reinstall with checksum verification and automatic rollback.
* Optional early upload guard, ClamAV with a self-test, freeze lock, real cron and tamper check.
* Multisite network mode and WP-CLI commands.
* Optional, opt-in usage statistics for the developer, off by default.
