<?php

declare(strict_types=1);

namespace RhLogin;

use RhLogin\Admin\LoginGroup;

/**
 * Versteckt die Login-URL hinter einem eigenen Pfad (wps-hide-login-Muster).
 *
 * Mechanik:
 * - Auf `plugins_loaded` (früh) den Request abfangen: der geheime Pfad lädt
 *   wp-login.php, ein direkter Zugriff auf wp-login.php wird auf die Startseite
 *   umgeleitet (außer action=postpass für passwortgeschützte Beiträge). Ob
 *   wp-login.php läuft, entscheidet das ausgeführte Skript, nicht die URL. So
 *   kommt keine Schreibweise (//wp-login.php, %77p-login.php, /./) mehr vorbei.
 * - Alle wp-login.php-URLs (Formular-Action, Logout, Passwort-Reset, Redirects)
 *   werden auf den geheimen Pfad umgeschrieben, damit die normalen Login-Flows
 *   weiterlaufen.
 * - Die bekannten Bequem-Aliase (/login, /admin, /dashboard ...), die ein Angreifer
 *   als Erstes rät, liefern ein echtes 404. Eine echte Seite an dem Pfad (z.B. ein
 *   Kundenportal unter /login) bleibt unangetastet.
 *
 * Escape-Hatch: bei Aussperrung das Plugin deaktivieren, dann ist /wp-login.php
 * wieder erreichbar (alles läuft nur über Laufzeit-Hooks, nichts wird umgeschrieben).
 *
 * Hooks werden in Plugin::boot() (vor plugins_loaded) registriert; die Settings
 * werden erst im plugins_loaded-Callback gelesen, wo der Core schon geladen ist.
 */
final class HideLogin
{
    /**
     * Bekannte Standard-Login-Pfade, die wie wp-login.php abgefangen werden.
     *
     * @var string[]
     */
    private const KNOWN_ALIASES = ['login', 'login.php', 'wp-login', 'admin', 'dashboard', 'signin', 'sign-in', 'backend'];

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
        add_filter('wp_redirect', [$this, 'filterRedirect'], 10, 1);

        // Core leitet /login, /login.php, /admin und /dashboard selbst weiter, /login.php
        // direkt auf wp_login_url() und damit auf den geheimen Pfad. So hat ein Scanner
        // den Pfad am 29.09.2026 gefunden.
        remove_action('template_redirect', 'wp_redirect_admin_locations', 1000);

        // Leitet irgendein Core-Skript einen Gast zum Login (auth_redirect im Customizer,
        // wp-signup.php), den Pfad nicht verraten.
        add_filter('wp_redirect', [$this, 'guardRedirect'], 9, 1);

        // redirect_canonical baut Login-Ziele selbst aus der angefragten URL:
        // /wp-register.php -> wp_registration_url(), /index.php/wp-login.php -> /wp-login.php
        // (Apache mit PATH_INFO). Canonical soll einen Gast nie zum Login leiten.
        add_filter('redirect_canonical', [$this, 'guardCanonical'], 99, 1);

        // /wp-admin für Gäste verstecken: auf die Startseite, NICHT zum Login leiten.
        // Sonst würde der geheime Login-Pfad im Redirect (Location) geleakt und über
        // die bekannte /wp-admin-Adresse auffindbar. Läuft auf `init` (is_user_logged_in
        // verfügbar) und vor dem auth_redirect von wp-admin/admin.php.
        add_action('init', [$this, 'protectAdmin']);

        // Bekannte Bequem-Aliase (/login, /admin ...) früh auf 404 setzen, bevor ein
        // Canonical-Redirect oder ein anderes Plugin sie irgendwohin leiten kann.
        add_action('parse_request', [$this, 'blockKnownAliases'], 1);

        $this->intercept();
    }

    /**
     * Die geratenen Standard-Login-Pfade liefern ein echtes 404, außer dort liegt
     * eine echte Seite (Kundenportal) oder es ist der gewählte geheime Pfad.
     */
    public function blockKnownAliases(): void
    {
        $variants = $this->currentRelPaths();
        if (in_array('', $variants, true) || in_array($this->slug(), $variants, true)) {
            return;
        }

        // Core schreibt jeden Pfad auf .*wp-register.php zu index.php?register=true um,
        // redirect_canonical leitet das dann ohne Filter auf wp_registration_url()
        // weiter, also auf den geheimen Pfad. Das gibt es auf Apache, nginx liefert 404.
        foreach ($variants as $variant) {
            if (basename($variant) === 'wp-register.php') {
                $this->notFound();
            }
        }

        /** @var string[] $aliases */
        $aliases = array_map('strtolower', (array) apply_filters('rh-login/blocked_aliases', self::KNOWN_ALIASES));
        $hit = array_values(array_intersect($variants, $aliases));
        if ($hit === []) {
            return;
        }

        // Eine echte Seite an dem Pfad (z.B. /login oder /dashboard als Kundenportal)
        // nicht abwürgen.
        if (get_page_by_path($hit[0]) instanceof \WP_Post) {
            return;
        }

        $this->notFound();
    }

    private function notFound(): never
    {
        status_header(404);
        nocache_headers();
        wp_die(esc_html__('Nicht gefunden.', 'rh-login'), '', ['response' => 404]);
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

    /**
     * Ein Gast, der von einem Core-Skript zum Login geschickt wird, landet auf der
     * Startseite. Ausgenommen ist das Frontend (index.php): dort leiten Plugins wie
     * Mitgliederbereiche bewusst zum Login, das bleibt wie bisher.
     */
    public function guardRedirect(string $location): string
    {
        if (! $this->pointsToLogin($location) || is_user_logged_in()) {
            return $location;
        }
        if ($this->isLoginScript() || in_array($this->slug(), $this->currentRelPaths(), true)) {
            return $location;
        }

        $script = strtolower(basename((string) ($_SERVER['SCRIPT_FILENAME'] ?? '')));

        return $script === 'index.php' ? $location : home_url('/');
    }

    /**
     * Zeigt die Weiterleitung auf den Login? wp_login_url() ist zu diesem Zeitpunkt
     * meist schon über site_url auf den geheimen Pfad umgeschrieben, darum beide
     * Formen erkennen.
     */
    private function pointsToLogin(string $location): bool
    {
        $path = (string) preg_replace('#^[a-z][a-z0-9+.-]*://[^/]*#i', '', $location);
        $homePath = (string) (wp_parse_url(home_url('/'), PHP_URL_PATH) ?? '');
        $targets = LoginPath::variants($path, $homePath);

        return in_array('wp-login.php', $targets, true) || in_array($this->slug(), $targets, true);
    }

    /**
     * @param string|false $url
     * @return string|false
     */
    public function guardCanonical($url)
    {
        if (! is_string($url) || $url === '' || is_user_logged_in()) {
            return $url;
        }

        return $this->pointsToLogin($url) ? false : $url;
    }

    /**
     * Weiterleitungen auf ein rohes wp-login.php nur umschreiben, wenn der Request
     * selbst der Login ist oder jemand eingeloggt ist.
     *
     * Wer bewusst zum Login leitet, nimmt wp_login_url(). Das ist über site_url
     * schon auf den geheimen Pfad umgeschrieben und kommt hier gar nicht an. Ein
     * rohes wp-login.php im Ziel baut dagegen WordPress selbst aus der angefragten
     * URL, etwa redirect_canonical aus /index.php/wp-login.php (Apache mit
     * PATH_INFO). Das umzuschreiben hat am 29.09.2026 auf kraus-hampp.de den Pfad
     * verraten. Bleibt das Ziel wp-login.php, landet der Gast dort auf der Startseite.
     */
    public function filterRedirect(string $location): string
    {
        if (strpos($location, 'wp-login.php') === false) {
            return $location;
        }
        if (! is_user_logged_in() && ! $this->isLoginScript() && ! in_array($this->slug(), $this->currentRelPaths(), true)) {
            return $location;
        }

        return $this->filterUrl($location);
    }

    private function intercept(): void
    {
        // Direkter Zugriff auf wp-login.php -> verstecken (außer postpass). Zuerst
        // prüfen: läuft wp-login.php, ist es nie der geheime Pfad.
        if ($this->isLoginScript()) {
            if (LoginPath::isPostpass($_REQUEST, $_GET)) {
                return; // Passwortgeschützte Beiträge brauchen wp-login.php?action=postpass.
            }
            wp_safe_redirect(home_url('/'));
            exit;
        }

        // Geheimer Pfad -> wp-login.php laden. Das Laden auf `init` verschieben,
        // weil wp-login.php WP-Konstanten (AUTOSAVE_INTERVAL etc.) braucht, die auf
        // plugins_loaded noch nicht definiert sind.
        if (in_array($this->slug(), $this->currentRelPaths(), true)) {
            add_action('init', [$this, 'serveLogin'], 1);
        }
    }

    /**
     * Läuft gerade wp-login.php? Maßgeblich ist die Datei, die der Server ausführt,
     * denn die hat er schon nach Dekodieren und Slash-Glätten gewählt.
     */
    private function isLoginScript(): bool
    {
        $login = realpath(ABSPATH . 'wp-login.php');
        $file = (string) ($_SERVER['SCRIPT_FILENAME'] ?? '');
        $script = $file !== '' ? realpath($file) : false;

        if ($login !== false && $script !== false) {
            // Klein vergleichen: auf einem Dateisystem ohne Groß/Klein-Unterscheidung
            // führt /WP-LOGIN.PHP dieselbe Datei aus.
            return strtolower($script) === strtolower($login);
        }

        return strtolower(basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''))) === 'wp-login.php';
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

    /**
     * @return array<int, string>
     */
    private function currentRelPaths(): array
    {
        $homePath = (string) (wp_parse_url(home_url('/'), PHP_URL_PATH) ?? '');

        return LoginPath::variants((string) ($_SERVER['REQUEST_URI'] ?? ''), $homePath);
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
