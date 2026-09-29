=== RH Login ===
Contributors: robinherbeck
Tags: login, security, brute force, lockout, limit login attempts
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 0.3.5
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Application-level login attempt limit: locks out an IP after too many failed logins to slow down brute-force attacks.

== Description ==

RH Login counts failed login attempts per IP and blocks further attempts for a while once the limit is reached. It complements server-side protection (CrowdSec, fail2ban). The client IP can be overridden via the rh-blueprint/login/client_ip filter when running behind a proxy.

It can also hide the login URL behind a secret path (wp-login.php is then redirected away, login lives at your chosen path). Default off. After enabling, test login and logout in the browser; deactivating the plugin restores the normal login if needed.

Part of the rh-blueprint collection. Settings live under RH Blueprint > Login.

== Changelog ==

= 0.3.5 =
* Security: on Apache with PATH_INFO, /index.php/wp-login.php and /wp-register.php revealed the hidden login path through WordPress' canonical redirect. Canonical redirects never send guests to the login anymore, raw wp-login.php redirects are only rewritten for logged-in users or on the login itself, and paths ending in wp-register.php return 404.
* Deliberate login redirects via wp_login_url() (for example from a members area plugin) keep working.

= 0.3.4 =
* Security: the hidden login could be bypassed with other spellings of wp-login.php (//wp-login.php, /%77p-login.php, /./wp-login.php and more). Whether wp-login.php runs is now decided by the executed script, not by the URL. Path comparisons are case-insensitive, URL-decoded and slash-normalized.
* Security: /login.php and other core aliases no longer redirect to the secret path. Guests sent to the login by core scripts (Customizer, wp-signup.php) land on the home page instead.
* Security: only the exact action=postpass passes wp-login.php. POSTPASS or postpass with key/checkemail showed the login form.
* Security: the attempt limit now also counts and blocks REST requests with application passwords, which bypassed it completely.

= 0.3.3 =
* Update checks: use a GitHub token from RH_GITHUB_TOKEN (environment variable or wp-config constant) when one is set, which lifts the API limit from 60 to 5,000 requests per hour. Without a token nothing changes.
* Update checks: after a GitHub rate-limit response all rh modules on the site pause their checks until GitHub resets the limit, and the last known update is kept. Bundles core 2.7.1.

= 0.3.2 =
* Fix: bundle core 2.6.1. The 2.6.0 release bundled an incomplete core.

= 0.3.1 =
* Internal: shared building blocks from core 2.6.0. The update check no longer loads on regular front-end requests.

= 0.3.1 =
* Internal: shared building blocks from core 2.6.0. The update check no longer loads on regular front-end requests.

= 0.2.0 =
* Added: hide the login URL behind a custom secret path (opt-in).

= 0.1.0 =
* Initial release: per-IP login attempt limit with configurable threshold and lockout duration.
