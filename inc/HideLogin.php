<?php

declare(strict_types=1);

namespace RhLogin;

use RhLogin\Admin\LoginGroup;

/**
 * Versteckt die Login-URL hinter einem eigenen Pfad (wps-hide-login-Muster).
 *
 * Mechanik:
 * - Auf `plugins_loaded` (früh) den Request abfangen: der geheime Pfad lädt
 *   wp-login.php, ein direkter Zugriff auf /wp-login.php wird auf die Startseite
 *   umgeleitet (außer action=postpass für passwortgeschützte Beiträge).
 * - Alle wp-login.php-URLs (Formular-Action, Logout, Passwort-Reset, Redirects)
 *   werden auf den geheimen Pfad umgeschrieben, damit die normalen Login-Flows
 *   weiterlaufen.
 *
 * Escape-Hatch: bei Aussperrung das Plugin deaktivieren, dann ist /wp-login.php
 * wieder erreichbar (alles läuft nur über Laufzeit-Hooks, nichts wird umgeschrieben).
 *
 * Hooks werden in Plugin::boot() (vor plugins_loaded) registriert; die Settings
 * werden erst im plugins_loaded-Callback gelesen, wo der Core schon geladen ist.
 */
final class HideLogin
{
    public function boot(): void
    {
        add_action('plugins_loaded', [$this, 'run'], 1);
    }

    public function run(): void
    {
        if (! function_exists('rhbp_setting')) {
            return;
        }
        if (! (bool) rhbp_setting(LoginGroup::GROUP_ID, LoginGroup::FIELD_HIDE_ENABLED, false)) {
            return;
        }
        if ($this->slug() === '') {
            return;
        }

        add_filter('site_url', [$this, 'filterUrl'], 10, 1);
        add_filter('network_site_url', [$this, 'filterUrl'], 10, 1);
        add_filter('wp_redirect', [$this, 'filterUrl'], 10, 1);

        // /wp-admin für Gäste verstecken: auf die Startseite, NICHT zum Login leiten.
        // Sonst würde der geheime Login-Pfad im Redirect (Location) geleakt und über
        // die bekannte /wp-admin-Adresse auffindbar. Läuft auf `init` (is_user_logged_in
        // verfügbar) und vor dem auth_redirect von wp-admin/admin.php.
        add_action('init', [$this, 'protectAdmin']);

        $this->intercept();
    }

    /**
     * wp-login.php-URLs auf den geheimen Pfad umschreiben (Query erhalten).
     */
    public function filterUrl(string $url): string
    {
        if (strpos($url, 'wp-login.php') === false) {
            return $url;
        }

        $query = (string) (wp_parse_url($url, PHP_URL_QUERY) ?? '');
        $target = $this->loginUrl();

        return $query !== '' ? $target . '?' . $query : $target;
    }

    private function intercept(): void
    {
        $rel = $this->currentRelPath();
        $slug = $this->slug();

        // Geheimer Pfad -> wp-login.php laden. Das Laden auf `init` verschieben,
        // weil wp-login.php WP-Konstanten (AUTOSAVE_INTERVAL etc.) braucht, die auf
        // plugins_loaded noch nicht definiert sind.
        if ($rel === $slug) {
            add_action('init', [$this, 'serveLogin'], 1);
            return;
        }

        // Direkter Zugriff auf wp-login.php -> verstecken (außer postpass).
        if ($rel === 'wp-login.php') {
            $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
            if ($action === 'postpass') {
                return; // Passwortgeschützte Beiträge brauchen wp-login.php?action=postpass.
            }
            wp_safe_redirect(home_url('/'));
            exit;
        }
    }

    public function protectAdmin(): void
    {
        if (! is_admin() || is_user_logged_in() || wp_doing_ajax()) {
            return;
        }

        // admin-post.php und admin-ajax.php sind legitime Endpoints auch für Gäste.
        $script = isset($GLOBALS['pagenow']) ? (string) $GLOBALS['pagenow'] : '';
        if ($script === 'admin-post.php' || $script === 'admin-ajax.php') {
            return;
        }

        wp_safe_redirect(home_url('/'));
        exit;
    }

    public function serveLogin(): void
    {
        // wp-login.php läuft normal im globalen Scope, seine Funktionen (login_header
        // etc.) erwarten $error/$action/$user_login... als Globals. Da wir die Datei
        // aus einer Methode laden, die Top-Level-Variablen explizit global binden,
        // sonst gibt es "Undefined variable"-Warnings und das Formular zeigt sie an.
        global $error, $interim_login, $action, $user_login, $user, $redirect_to,
            $errors, $reauth, $auth_secure_cookie, $rememberme, $secure_cookie,
            $customize_login, $http_post, $messages, $pagenow;

        $pagenow = 'wp-login.php';
        require_once ABSPATH . 'wp-login.php';
        exit;
    }

    private function currentRelPath(): string
    {
        $path = trim((string) (wp_parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) ?? ''), '/');
        $homePath = trim((string) (wp_parse_url(home_url('/'), PHP_URL_PATH) ?? ''), '/');

        if ($homePath !== '' && strpos($path, $homePath) === 0) {
            $path = trim(substr($path, strlen($homePath)), '/');
        }

        return $path;
    }

    public function slug(): string
    {
        return sanitize_title((string) rhbp_setting(LoginGroup::GROUP_ID, LoginGroup::FIELD_LOGIN_SLUG, ''));
    }

    private function loginUrl(): string
    {
        return home_url('/' . $this->slug());
    }
}
