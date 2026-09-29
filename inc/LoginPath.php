<?php

declare(strict_types=1);

namespace RhLogin;

/**
 * Bringt den angefragten Pfad in die Form, in der der Webserver ihn auflöst.
 *
 * nginx und Apache dekodieren den Pfad, fassen doppelte Slashes zusammen und
 * lösen /./ und /../ auf, bevor sie entscheiden, welches Skript läuft. PHP sieht
 * in REQUEST_URI aber die rohe Fassung. Ein Vergleich gegen die rohe Fassung
 * lässt deshalb //wp-login.php oder /%77p-login.php durch, während der Server
 * trotzdem wp-login.php ausführt. Genau so kamen am 28.09.2026 1775
 * Anmeldeversuche am versteckten Login vorbei. Dazu kommt: parse_url() liest
 * //wp-login.php als Hostnamen und liefert gar keinen Pfad.
 *
 * Deshalb zwei Fassungen, wie in rh-hardening (RouteMatch):
 *
 *   roh        klein geschrieben, Slashes zusammengefasst, Punkt-Segmente aufgelöst
 *   dekodiert  dasselbe, zusätzlich URL-dekodiert (auch mehrfach kodiert)
 *
 * Framework-frei, damit es ohne WordPress testbar ist.
 */
final class LoginPath
{
    /** Mehr Kodier-Schichten nimmt kein Server auseinander. */
    private const MAX_DECODE_ROUNDS = 3;

    /**
     * Relative Pfade (ohne Slash am Rand, ohne Unterverzeichnis der Installation).
     *
     * @return array<int, string>
     */
    public static function variants(string $requestUri, string $homePath = ''): array
    {
        // Query und Fragment von Hand abschneiden. parse_url() hält //x für einen Host.
        $path = (string) preg_replace('/[?#].*$/s', '', $requestUri);
        $home = self::normalize($homePath, true);

        $variants = [];
        foreach ([false, true] as $decode) {
            $variants[] = self::stripHome(self::normalize($path, $decode), $home);
        }

        return array_values(array_unique($variants));
    }

    public static function normalize(string $path, bool $decode): string
    {
        if ($decode) {
            for ($round = 0; $round < self::MAX_DECODE_ROUNDS; $round++) {
                $decoded = rawurldecode($path);

                if ($decoded === $path) {
                    break;
                }

                $path = $decoded;
            }
        }

        $segments = [];
        foreach (explode('/', strtolower($path)) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
                continue;
            }
            $segments[] = $segment;
        }

        return implode('/', $segments);
    }

    /**
     * Nur die exakte Aktion "postpass" darf an wp-login.php vorbei. wp-login.php
     * nimmt die Aktion roh, eine gesäuberte Fassung (POSTPASS, post pass) wäre dort
     * eine unbekannte Aktion und würde das Login-Formular zeigen. key und
     * checkemail überschreiben die Aktion in wp-login.php, darum schließen sie aus.
     *
     * @param array<string, mixed> $request $_REQUEST
     * @param array<string, mixed> $query   $_GET
     */
    public static function isPostpass(array $request, array $query): bool
    {
        if (isset($query['key']) || isset($query['checkemail'])) {
            return false;
        }

        return isset($request['action']) && $request['action'] === 'postpass';
    }

    private static function stripHome(string $path, string $home): string
    {
        if ($home === '') {
            return $path;
        }
        if ($path === $home) {
            return '';
        }
        if (str_starts_with($path, $home . '/')) {
            return substr($path, strlen($home) + 1);
        }

        return $path;
    }
}
