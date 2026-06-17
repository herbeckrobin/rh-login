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
    public function boot(): void
    {
        if (! (bool) rhbp_setting(LoginGroup::GROUP_ID, LoginGroup::FIELD_ENABLED, true)) {
            return;
        }

        add_filter('authenticate', [$this, 'enforceLockout'], 30, 1);
        add_action('wp_login_failed', [$this, 'recordFailure']);
        add_action('wp_login', [$this, 'clearOnSuccess'], 10, 2);
    }

    /**
     * @param WP_User|WP_Error|null $user
     * @return WP_User|WP_Error|null
     */
    public function enforceLockout($user)
    {
        if (empty($_POST)) {
            return $user; // Nur echte Login-Submits prüfen, nicht Cookie-Auth.
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

    public function recordFailure(): void
    {
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
        $ip = (string) apply_filters('rh-blueprint/login/client_ip', $ip);

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }
}
