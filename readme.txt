=== RH Login ===
Contributors: robinherbeck
Tags: login, security, brute force, lockout, limit login attempts
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 0.3.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Application-level login attempt limit: locks out an IP after too many failed logins to slow down brute-force attacks.

== Description ==

RH Login counts failed login attempts per IP and blocks further attempts for a while once the limit is reached. It complements server-side protection (CrowdSec, fail2ban). The client IP can be overridden via the rh-blueprint/login/client_ip filter when running behind a proxy.

It can also hide the login URL behind a secret path (wp-login.php is then redirected away, login lives at your chosen path). Default off. After enabling, test login and logout in the browser; deactivating the plugin restores the normal login if needed.

Part of the rh-blueprint collection. Settings live under RH Blueprint > Login.

== Changelog ==

= 0.3.1 =
* Internal: shared building blocks from core 2.6.0. The update check no longer loads on regular front-end requests.

= 0.3.1 =
* Internal: shared building blocks from core 2.6.0. The update check no longer loads on regular front-end requests.

= 0.2.0 =
* Added: hide the login URL behind a custom secret path (opt-in).

= 0.1.0 =
* Initial release: per-IP login attempt limit with configurable threshold and lockout duration.
