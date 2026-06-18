<?php

declare(strict_types=1);

namespace RhLogin\Admin;

use RhBlueprint\Core\Settings\GroupInterface;
use RhBlueprint\Core\Settings\SettingField;

/**
 * Settings-Gruppe für das Login-Limit.
 *
 * App-seitige Ergänzung zu server-seitigem Schutz (CrowdSec/fail2ban): sperrt
 * eine IP nach zu vielen Fehlversuchen für eine Weile aus.
 */
final class LoginGroup implements GroupInterface
{
    public const GROUP_ID = 'login';

    public const FIELD_ENABLED = 'limit_enabled';
    public const FIELD_MAX_ATTEMPTS = 'max_attempts';
    public const FIELD_LOCKOUT_MINUTES = 'lockout_minutes';
    public const FIELD_HIDE_ENABLED = 'hide_enabled';
    public const FIELD_LOGIN_SLUG = 'login_slug';

    public function id(): string
    {
        return self::GROUP_ID;
    }

    public function tab(): string
    {
        return 'login';
    }

    public function title(): string
    {
        return __('Login', 'rh-login');
    }

    public function description(): string
    {
        return __('Schützt das Login vor Brute-Force, indem eine IP nach zu vielen Fehlversuchen vorübergehend gesperrt wird.', 'rh-login');
    }

    public function fields(): array
    {
        return [
            new SettingField(
                id: self::FIELD_ENABLED,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Login-Limit aktivieren', 'rh-login'),
                description: __('Sperrt eine IP-Adresse nach zu vielen fehlgeschlagenen Login-Versuchen.', 'rh-login'),
                default: true,
                keywords: ['login', 'limit', 'brute force', 'sperre'],
            ),
            new SettingField(
                id: self::FIELD_MAX_ATTEMPTS,
                type: SettingField::TYPE_TEXT,
                label: __('Maximale Fehlversuche', 'rh-login'),
                description: __('Nach so vielen Fehlversuchen wird die IP gesperrt. Standard 5.', 'rh-login'),
                default: '5',
                keywords: ['versuche', 'attempts', 'max'],
            ),
            new SettingField(
                id: self::FIELD_LOCKOUT_MINUTES,
                type: SettingField::TYPE_TEXT,
                label: __('Sperrdauer (Minuten)', 'rh-login'),
                description: __('Wie lange die IP nach Erreichen des Limits gesperrt bleibt. Standard 15.', 'rh-login'),
                default: '15',
                keywords: ['sperre', 'lockout', 'dauer', 'minuten'],
            ),
            new SettingField(
                id: self::FIELD_HIDE_ENABLED,
                type: SettingField::TYPE_BOOLEAN,
                label: __('Login-URL verstecken', 'rh-login'),
                description: __('Versteckt wp-login.php hinter einem eigenen Pfad. Die geratenen Standard-Pfade (/login, /admin, /dashboard ...) liefern dann ein 404. WICHTIG: nach dem Speichern Login UND Logout testen. Falls ausgesperrt, das Plugin deaktivieren (dann ist /wp-login.php wieder normal erreichbar).', 'rh-login'),
                default: false,
                keywords: ['login', 'url', 'verstecken', 'hide', 'wp-login'],
            ),
            new SettingField(
                id: self::FIELD_LOGIN_SLUG,
                type: SettingField::TYPE_TEXT,
                label: __('Login-Pfad', 'rh-login'),
                description: __('Der geheime Pfad, z.B. mein-zugang, team-eingang, backstage, kontrolle. Am sichersten etwas Eigenes mit Zufallsteil wie zugang-7f3a9. Nur Buchstaben, Zahlen, Bindestrich. Login dann unter deine-domain.de/<pfad>.', 'rh-login'),
                default: '',
                keywords: ['slug', 'pfad', 'login', 'url'],
            ),
        ];
    }
}
