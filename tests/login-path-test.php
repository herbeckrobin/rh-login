<?php

/**
 * Prüfungen, die ohne laufendes WordPress möglich sind.
 *
 *   php tests/login-path-test.php
 *
 * Deckt die Pfad-Normalisierung ab, an der die Umgehung vom 28.09.2026 hing
 * (//wp-login.php). Den echten Weg durch nginx misst tests/login-http-check.php.
 */

declare(strict_types=1);

require dirname(__DIR__) . '/inc/LoginPath.php';

use RhLogin\LoginPath;

/** Zählt Fehler. Statisch statt global, damit die Analyse den Stand nicht als 0 festschreibt. */
function failures(bool $add = false): int
{
    static $count = 0;

    if ($add) {
        $count++;
    }

    return $count;
}

function pathCheck(string $name, mixed $got, mixed $want): void
{
    $ok = $got === $want;

    if (! $ok) {
        failures(true);
    }

    printf(
        "%-52s %s%s\n",
        $name,
        $ok ? 'OK' : 'FEHLER',
        $ok ? '' : sprintf('  ist=%s soll=%s', var_export($got, true), var_export($want, true))
    );
}

function hits(string $uri, string $target, string $home = ''): bool
{
    return in_array($target, LoginPath::variants($uri, $home), true);
}

echo "Schreibweisen von wp-login.php\n";
foreach ([
    '/wp-login.php', '//wp-login.php', '///wp-login.php', '/WP-LOGIN.PHP', '/%77p-login.php',
    '/wp-login%2Ephp', '//%77p-login.php', '/%2Fwp-login.php', '/%252Fwp-login.php', '/%25252Fwp-login.php',
    '/./wp-login.php', '/wp-admin/../wp-login.php', '/wp-login.php/', '/wp-login.php?action=lostpassword',
    '//wp-login.php#x',
] as $uri) {
    pathCheck($uri, hits($uri, 'wp-login.php'), true);
}

echo "\nGeheimer Pfad und Unterverzeichnis\n";
pathCheck('/zugang-7f3a9', hits('/zugang-7f3a9', 'zugang-7f3a9'), true);
pathCheck('//zugang-7f3a9/', hits('//zugang-7f3a9/', 'zugang-7f3a9'), true);
pathCheck('/Zugang-7F3A9?x=1', hits('/Zugang-7F3A9?x=1', 'zugang-7f3a9'), true);
pathCheck('/wp/zugang-7f3a9 bei Installation in /wp', hits('/wp/zugang-7f3a9', 'zugang-7f3a9', '/wp/'), true);
pathCheck('//wp//zugang-7f3a9 bei Installation in /wp', hits('//wp//zugang-7f3a9', 'zugang-7f3a9', '/wp/'), true);
pathCheck('/wpx/zugang-7f3a9 ist nicht /wp', hits('/wpx/zugang-7f3a9', 'zugang-7f3a9', '/wp/'), false);
pathCheck('/zugang-7f3a9x trifft nicht', hits('/zugang-7f3a9x', 'zugang-7f3a9'), false);
pathCheck('/zugang-7f3a9/unterseite trifft nicht', hits('/zugang-7f3a9/unterseite', 'zugang-7f3a9'), false);
pathCheck('Startseite ist leer', LoginPath::variants('/', ''), ['']);

echo "\nAliase\n";
pathCheck('/login.php', hits('/login.php', 'login.php'), true);
pathCheck('/LOGIN/', hits('/LOGIN/', 'login'), true);
pathCheck('/%6Cogin', hits('/%6Cogin', 'login'), true);

echo "\nPATH_INFO über index.php (redirect_canonical)\n";
// Der Pfad ist nicht wp-login.php, das Skript ist index.php. Abgefangen wird das über
// redirect_canonical und den Redirect-Filter, nicht über den Pfadvergleich.
pathCheck('/index.php/wp-login.php ist nicht wp-login.php', hits('/index.php/wp-login.php', 'wp-login.php'), false);
pathCheck('/index.php//wp-login.php normalisiert', LoginPath::variants('/index.php//wp-login.php'), ['index.php/wp-login.php']);
foreach (['/wp-register.php', '/foo/wp-register.php', '/WP-REGISTER.PHP', '/index.php/wp-register.php', '/wp-%72egister.php'] as $uri) {
    $hit = false;
    foreach (LoginPath::variants($uri) as $variant) {
        $hit = $hit || basename($variant) === 'wp-register.php';
    }
    pathCheck($uri . ' endet auf wp-register.php', $hit, true);
}

echo "\npostpass\n";
pathCheck('postpass exakt', LoginPath::isPostpass(['action' => 'postpass'], []), true);
pathCheck('POSTPASS', LoginPath::isPostpass(['action' => 'POSTPASS'], []), false);
pathCheck('post pass', LoginPath::isPostpass(['action' => 'post pass'], []), false);
pathCheck('postpass mit Nullbyte', LoginPath::isPostpass(['action' => "postpass\0"], []), false);
pathCheck('action als Array', LoginPath::isPostpass(['action' => ['postpass']], []), false);
pathCheck('postpass mit key (wird resetpass)', LoginPath::isPostpass(['action' => 'postpass'], ['key' => 'x']), false);
pathCheck('postpass mit checkemail', LoginPath::isPostpass(['action' => 'postpass'], ['checkemail' => 'confirm']), false);
pathCheck('ohne action', LoginPath::isPostpass([], []), false);

echo "\n" . (failures() === 0 ? 'Alles grün.' : failures() . ' Fehler.') . "\n";
exit(failures() === 0 ? 0 : 1);
