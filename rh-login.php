<?php

/**
 * Plugin Name:       RH Login
 * Plugin URI:        https://github.com/herbeckrobin/rh-login
 * Update URI:        https://github.com/herbeckrobin/rh-login
 * Description:       Login-Schutz: Versuch-Limit mit IP-Sperre und optionales Verstecken der Login-URL. Teil der rh-blueprint Kollektion.
 * Version:           0.2.1
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Robin Herbeck
 * Author URI:        https://robinherbeck.de
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       rh-login
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
    exit;
}

define('RHLOGIN_VERSION', '0.2.1');
define('RHLOGIN_PLUGIN_FILE', __FILE__);
define('RHLOGIN_PLUGIN_DIR', plugin_dir_path(__FILE__));

$rhlogin_autoload = RHLOGIN_PLUGIN_DIR . 'vendor/autoload.php';

if (! is_readable($rhlogin_autoload)) {
    add_action('admin_notices', static function (): void {
        echo '<div class="notice notice-error"><p><strong>RH Login:</strong> Composer-Dependencies fehlen. Bitte <code>composer install</code> im Plugin-Verzeichnis ausführen.</p></div>';
    });
    return;
}

require_once $rhlogin_autoload;

RhLogin\Plugin::boot();
