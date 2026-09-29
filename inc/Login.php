<?php

declare(strict_types=1);

namespace RhLogin;

use RhLogin\Admin\LoginGroup;
use WP_Error;
use WP_User;

/**
 * Login-Versuch-Limit per IP.
 *
 * Fehlversuche werden in einem Transient pro IP gezählt (TTL = Sperrdauer). Ab dem
 * Limit blockt der authenticate-Filter weitere Versuche, bis der Transient abläuft.
 * Erfolgreicher Login löscht den Zähler. IP über REMOTE_ADDR (per Filter überschreibbar).
 */
final class Login
{
    /**
     * Ein Request zählt höchstens einmal. Bei XML-RPC mit Anwendungspasswort feuern
     * sonst wp_login_failed und application_password_failed_authentication beide.
     */
    private bool $counted = false;

    public function boot(): void
    {
        // Anwendungspasswörter abschalten ist eine eigene Härtung, unabhängig vom Limit.
        if ((bool) rhbp_setting(LoginGroup::GROUP_ID, LoginGroup::FIELD_DISABLE_APP_PASSWORDS, false)) {
            add_filter('wp_is_application_passwords_available', '__return_false');
        }

        if (! (bool) rhbp_setting(LoginGroup::GROUP_ID, LoginGroup::FIELD_ENABLED, true)) {
            return;
        }

        add_filter('authenticate', [$this, 'enforceLockout'], 30, 3);
        add_filter('authenticate', [$this, 'genericError'], 40, 1);
        add_filter('shake_error_codes', [$this, 'shakeCodes']);
        add_action('wp_login_failed', [$this, 'recordFailure']);

        // REST mit Anwendungspasswort (Basic Auth) läuft NICHT über wp_authenticate:
        // weder der authenticate-Filter noch wp_login_failed feuern. Ohne diese zwei
        // Hooks wird dort weder gezählt noch gesperrt.
        add_action('application_password_failed_authentication', [$this, 'recordFailure']);
        add_filter('application_password_is_api_request', [$this, 'blockApiWhenLocked'], 99);
        add_action('wp_login', [$this, 'clearOnSuccess'], 10, 2);
    }

    /**
     * Sperrt weitere Versuche ab dem Limit. Greift für jeden Credential-Login
     * (Formular, XML-RPC, REST/Anwendungspasswort), nicht nur Formular-Submits.
     *
     * @param WP_User|WP_Error|null $user
     * @param string $username
     * @param string $password
     * @return WP_User|WP_Error|null
     */
    public function enforceLockout($user, $username = '', $password = '')
    {
        // Nur echte Zugangsdaten-Versuche zählen. Interne authenticate-Durchläufe
        // ohne Credentials (z.B. leeres Formular) übergehen. Wichtig: NICHT auf
        // $_POST prüfen, sonst entkommen XML-RPC- und REST-Logins dem Limit komplett.
        if ('' === (string) $username && '' === (string) $password) {
            return $user;
        }

        if ($this->attempts() < $this->maxAttempts()) {
            return $user;
        }

        return new WP_Error(
            'rh_login_locked',
            sprintf(
                /* translators: %d: minutes */
                __('Zu viele fehlgeschlagene Login-Versuche. Bitte in %d Minuten erneut versuchen.', 'rh-login'),
                $this->lockoutMinutes()
            )
        );
    }

    /**
     * Macht die verräterischen Login-Fehler generisch, damit sie nicht zwischen
     * "Benutzer existiert nicht" und "falsches Passwort" unterscheiden (User-Enum).
     * Den eigenen Sperr-Hinweis lässt es unberührt.
     *
     * @param WP_User|WP_Error|null $user
     * @return WP_User|WP_Error|null
     */
    public function genericError($user)
    {
        if (! is_wp_error($user)) {
            return $user;
        }

        $reveal = ['invalid_username', 'incorrect_password', 'invalid_email', 'invalidcombo', 'authentication_failed'];
        if (array_intersect($user->get_error_codes(), $reveal)) {
            return new WP_Error('rh_login_failed', __('Benutzername oder Passwort ist falsch.', 'rh-login'));
        }

        return $user;
    }

    /**
     * Eigene Fehler-Codes auch das Login-Formular schütteln lassen (UX-Parität).
     *
     * @param string[] $codes
     * @return string[]
     */
    public function shakeCodes(array $codes): array
    {
        $codes[] = 'rh_login_failed';
        $codes[] = 'rh_login_locked';

        return $codes;
    }

    /**
     * Gesperrte IP: Anwendungspasswörter gar nicht erst prüfen. Der Request läuft
     * dann als Gast weiter und bekommt auf geschützten Routen 401.
     */
    public function blockApiWhenLocked(bool $isApiRequest): bool
    {
        if ($isApiRequest && $this->attempts() >= $this->maxAttempts()) {
            return false;
        }

        return $isApiRequest;
    }

    public function recordFailure(): void
    {
        if ($this->counted) {
            return;
        }
        $this->counted = true;

        $current = (int) get_transient($this->key());
        set_transient($this->key(), $current + 1, $this->lockoutMinutes() * MINUTE_IN_SECONDS);
    }

    public function clearOnSuccess(string $userLogin, WP_User $user): void
    {
        delete_transient($this->key());
    }

    private function attempts(): int
    {
        return (int) get_transient($this->key());
    }

    private function maxAttempts(): int
    {
        $value = (int) rhbp_setting(LoginGroup::GROUP_ID, LoginGroup::FIELD_MAX_ATTEMPTS, '5');

        return $value > 0 ? $value : 5;
    }

    private function lockoutMinutes(): int
    {
        $value = (int) rhbp_setting(LoginGroup::GROUP_ID, LoginGroup::FIELD_LOCKOUT_MINUTES, '15');

        return $value > 0 ? $value : 15;
    }

    private function key(): string
    {
        return 'rhlogin_' . md5($this->clientIp());
    }

    private function clientIp(): string
    {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

        // Hinter einem Reverse-Proxy ist REMOTE_ADDR die Proxy-IP, dann zählt das
        // Limit alle Besucher auf einen Topf (ein Bot sperrt alle aus). Echte IP
        // aus dem Proxy-Header holen, wenn das Setting es erlaubt.
        if ((bool) rhbp_setting(LoginGroup::GROUP_ID, LoginGroup::FIELD_TRUST_PROXY, false)) {
            $ip = $this->proxyIp() ?: $ip;
        }

        $ip = (string) apply_filters('rh-blueprint/login/client_ip', $ip);

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    /**
     * Echte Besucher-IP aus dem Proxy-Header. Nur verlässlich, wenn der Origin
     * NICHT direkt am Proxy vorbei erreichbar ist, sonst ist der Header fälschbar
     * (deshalb opt-in). Für exakte Trusted-Proxy-Logik den Filter
     * `rh-blueprint/login/client_ip` nutzen.
     */
    private function proxyIp(): string
    {
        // Cloudflare setzt diesen Header selbst, am verlässlichsten.
        $cf = isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? trim((string) $_SERVER['HTTP_CF_CONNECTING_IP']) : '';
        if (filter_var($cf, FILTER_VALIDATE_IP)) {
            return $cf;
        }

        // X-Forwarded-For: "client, proxy1, ...", der erste Eintrag ist der Client.
        $xff = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? (string) $_SERVER['HTTP_X_FORWARDED_FOR'] : '';
        if ($xff !== '') {
            $first = trim((string) (explode(',', $xff)[0] ?? ''));
            if (filter_var($first, FILTER_VALIDATE_IP)) {
                return $first;
            }
        }

        return '';
    }
}
