<?php

declare(strict_types=1);

namespace RhLogin;

use RhBlueprint\Core\Core;
use RhBlueprint\Core\UpdateChecker;
use RhBlueprint\Core\Settings\SettingsPage;
use RhLogin\Admin\LoginGroup;

/**
 * Bootstrap von rh-login. Hängt am Core-Hook `rh-blueprint/core/booted`. Braucht nur den Core.
 */
final class Plugin
{
    public static function boot(): void
    {
        add_action('plugins_loaded', static function (): void {
            (new UpdateChecker('rh-login', RHLOGIN_PLUGIN_FILE))->boot();
        }, 0);

        // Früh registrieren: das Verstecken muss den Request auf plugins_loaded abfangen.
        (new HideLogin())->boot();

        add_action('rh-blueprint/core/booted', [self::class, 'onCoreBooted']);
    }

    public static function onCoreBooted(Core $core): void
    {
        $core->settings()->registerTab('login', __('Login', 'rh-login'), 65);
        $core->settings()->registerGroup(new LoginGroup());

        (new Login())->boot();

        add_filter('rh-blueprint/dashboard/quick_links', static function (array $links): array {
            $links[] = [
                'label' => __('Login', 'rh-login'),
                'url' => admin_url('admin.php?page=' . SettingsPage::MENU_SLUG . '&tab=login'),
                'icon' => 'lock',
            ];
            return $links;
        });
    }
}
