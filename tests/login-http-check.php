<?php

/**
 * Misst den versteckten Login und die Brute-Force-Sperre gegen echtes HTTP.
 *
 * Läuft im DDEV-Webcontainer und spricht nginx direkt an, am Router vorbei. Der
 * Router (Traefik) glättet doppelte Slashes und Kodierungen, genau wie manche
 * Hoster davor. Ein Test durch ihn hindurch hätte die Umgehung vom 28.09.2026
 * (//wp-login.php) nie gezeigt.
 *
 *   ddev exec env RH_SLUG=geheim-zugang RH_USER=... RH_PASS=... RH_APPPASS=... \
 *     php /var/www/html/rh-login/tests/login-http-check.php
 *
 * Voraussetzung: Login-URL verstecken ist an, Login-Limit an, pretty Permalinks.
 * Zwischen den Gruppen wird der Sperrzähler der eigenen IP per WP-CLI gelöscht.
 */

declare(strict_types=1);

$base = getenv('RH_BASE') ?: 'http://127.0.0.1';
$host = getenv('RH_HOST') ?: 'rh-blueprint.ddev.site';
$slug = getenv('RH_SLUG') ?: '';
$user = getenv('RH_USER') ?: '';
$pass = getenv('RH_PASS') ?: '';
$appPass = getenv('RH_APPPASS') ?: '';
$wpPath = getenv('RH_WP') ?: '/var/www/html/wordpress';
// XML-RPC-Gruppe mit eingeschaltetem XML-RPC fahren. Braucht ein Test-mu-plugin, das
// xmlrpc_enabled bei Header X-RH-Test-Xmlrpc: 1 auf true setzt.
$xmlrpcOn = getenv('RH_XMLRPC') === '1';
$max = (int) (getenv('RH_MAX') ?: 5);

if ($slug === '' || $user === '' || $pass === '') {
    fwrite(STDERR, "RH_SLUG, RH_USER und RH_PASS setzen.\n");
    exit(2);
}

/** Zählt Fehler. Statisch statt global, damit die Analyse den Stand nicht als 0 festschreibt. */
function failures(bool $add = false): int
{
    static $count = 0;

    if ($add) {
        $count++;
    }

    return $count;
}

/**
 * @return array{status:int, location:string, headers:string, body:string}
 */
function request(string $method, string $path, array $extra = []): array
{
    global $base, $host;

    $ch = curl_init($base . $path);
    $headers = array_merge(['Host: ' . $host, 'X-Forwarded-Proto: https'], $extra['headers'] ?? []);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER => $headers,
        // Den Pfad exakt so senden wie angegeben, ohne dass curl // oder /./ glättet.
        CURLOPT_PATH_AS_IS => true,
        CURLOPT_TIMEOUT => 20,
    ]);
    if (isset($extra['body'])) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $extra['body']);
    }
    if (isset($extra['basic'])) {
        curl_setopt($ch, CURLOPT_USERPWD, $extra['basic']);
    }

    $raw = (string) curl_exec($ch);
    $size = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    $head = substr($raw, 0, $size);
    $location = preg_match('/^location:\s*(.+)$/im', $head, $m) ? trim($m[1]) : '';

    return ['status' => $status, 'location' => $location, 'headers' => $head, 'body' => substr($raw, $size)];
}

function expect(string $name, bool $ok, string $detail): void
{
    if (! $ok) {
        failures(true);
    }

    printf("%-52s %-7s %s\n", $name, $ok ? 'OK' : 'FEHLER', $detail);
}

function describe(array $r): string
{
    $form = str_contains($r['body'], 'id="loginform"') ? ' Formular' : '';

    return $r['status'] . ($r['location'] !== '' ? ' -> ' . $r['location'] : '') . $form;
}

function leaks(array $r): bool
{
    global $slug;

    return stripos($r['headers'], $slug) !== false || stripos($r['body'], $slug) !== false;
}

function resetLockout(): void
{
    global $wpPath;

    shell_exec('wp --path=' . escapeshellarg($wpPath) . ' transient delete rhlogin_' . md5('127.0.0.1') . ' >/dev/null 2>&1');
}

function counter(): int
{
    global $wpPath;

    return (int) trim((string) shell_exec('wp --path=' . escapeshellarg($wpPath) . ' transient get rhlogin_' . md5('127.0.0.1') . ' 2>/dev/null'));
}

function xmlrpcCall(string $u, string $p): string
{
    return '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params>'
        . '<param><value><string>' . htmlspecialchars($u) . '</string></value></param>'
        . '<param><value><string>' . htmlspecialchars($p) . '</string></value></param>'
        . '</params></methodCall>';
}

// 1) Der geheime Pfad selbst muss funktionieren, sonst ist jede Sperre unten wertlos.
echo "Geheimer Pfad\n";
$r = request('GET', '/' . $slug);
expect('/' . $slug, $r['status'] === 200 && str_contains($r['body'], 'id="loginform"'), describe($r));

resetLockout();
$r = request('POST', '/' . $slug, ['body' => http_build_query(['log' => $user, 'pwd' => $pass, 'testcookie' => '1']), 'headers' => ['Cookie: wordpress_test_cookie=WP%20Cookie%20check']]);
expect('Anmelden über den geheimen Pfad', (bool) preg_match('/set-cookie:\s*wordpress_logged_in/i', $r['headers']), describe($r));
$r = request('GET', '/' . $slug . '?action=lostpassword');
expect('Passwort vergessen über den geheimen Pfad', str_contains($r['body'], 'id="lostpasswordform"'), $r['status'] . '');
$r = request('GET', '/%2F' . $slug);
// nginx lädt den Login, Apache weist %2F im Pfad standardmäßig mit 404 ab. Beides ok.
expect('Kodierter geheimer Pfad: Login oder 404', ($r['status'] === 200 && str_contains($r['body'], 'id="loginform"')) || $r['status'] === 404, describe($r));

// 2) Kein anderer Weg darf das Formular zeigen oder den Pfad verraten.
echo "\nVerstecken\n";
$hidden = [
    '/wp-login.php', '//wp-login.php', '///wp-login.php', '//wp-login.php?action=login',
    '/WP-LOGIN.PHP', '/Wp-Login.php', '/%77p-login.php', '/wp-login%2Ephp', '//%77p-login.php',
    '/%2Fwp-login.php', '/%252Fwp-login.php', '/./wp-login.php', '/wp-admin/../wp-login.php',
    '/wp-login.php/', '/wp-login.php/x', '/wp-login.php;x',
    '/wp-login.php?action=lostpassword', '/wp-login.php?action=register', '/wp-login.php?action=rp',
    '/wp-login.php?action=resetpass', '/wp-login.php?action=confirm_admin_email',
    '/wp-login.php?action=POSTPASS', '/wp-login.php?action=PostPass', '/wp-login.php?action=post%20pass',
    '/wp-login.php?action=postpass%00', '/wp-login.php?action[]=postpass',
    '/login', '/login/', '/Login', '/LOGIN.PHP', '/login.php', '/wp-login', '/admin', '/admin/', '/dashboard',
    '/signin', '/sign-in', '/backend',
    '/wp-admin', '/wp-admin/', '/wp-admin/index.php', '/wp-admin/profile.php', '/wp-admin/customize.php',
    '/wp-admin/options.php', '//wp-admin/', '/WP-ADMIN/',
    '/wp-signup.php', '/wp-activate.php', '/wp-register.php',
    // PATH_INFO über index.php: redirect_canonical streicht /index.php/ und leitet
    // auf das rohe Ziel weiter. Auf Apache aktiv, nginx liefert hier 404.
    '/index.php/wp-login.php', '/index.php//wp-login.php', '/index.php/%77p-login.php',
    '/index.php/WP-LOGIN.PHP', '/index.php/wp-login.php?action=lostpassword',
    '/index.php/wp-login.php?action=register', '/index.php/wp-login.php/x',
    '/index.php/wp-admin/', '/index.php/wp-admin/profile.php', '/index.php/wp-admin/customize.php',
    '/index.php/login.php', '/index.php/login', '/index.php/wp-signup.php',
    '/foo/wp-register.php', '/WP-REGISTER.PHP', '/index.php/wp-register.php',
    '/?pagename=wp-login.php', '/?pagename=wp-login', '/index.php?pagename=wp-login.php',
];
foreach ($hidden as $path) {
    $r = request('GET', $path);
    $form = str_contains($r['body'], 'id="loginform"') || str_contains($r['body'], 'id="lostpasswordform"')
        || str_contains($r['body'], 'id="registerform"') || str_contains($r['body'], 'id="resetpassform"');
    expect('GET ' . $path, ! $form && ! leaks($r), describe($r));
}

// postpass muss für passwortgeschützte Beiträge weiter durchkommen, darf aber nur
// weiterleiten, nie ein Formular zeigen.
$r = request('POST', '/wp-login.php?action=postpass', ['body' => 'post_password=x']);
expect('POST /wp-login.php?action=postpass (Beitragspasswort)', in_array($r['status'], [200, 302], true) && ! leaks($r) && ! str_contains($r['body'], 'loginform'), describe($r));
foreach (['/wp-login.php?action=postpass&key=x&login=admin', '/wp-login.php?action=postpass&checkemail=confirm'] as $path) {
    $r = request('GET', $path);
    expect('GET ' . $path, ! str_contains($r['body'], 'id="loginform"') && ! str_contains($r['body'], 'resetpassform') && ! leaks($r), describe($r));
}

// Ein Frontend-Plugin (Mitgliederbereich), das Gäste bewusst per wp_login_url()
// zum Login schickt, muss weiter auf den geheimen Pfad kommen.
$r = request('GET', '/', ['headers' => ['X-RH-Test-Member: 1']]);
expect('Frontend-Plugin leitet per wp_login_url() auf den Pfad', $r['status'] === 302 && stripos($r['location'], '/' . $slug) !== false, describe($r));

// admin-ajax und admin-post bleiben für Gäste erreichbar, ohne den Pfad zu verraten.
foreach (['/wp-admin/admin-ajax.php', '/wp-admin/admin-post.php'] as $path) {
    $r = request('GET', $path);
    expect('GET ' . $path, $r['status'] !== 302 && ! leaks($r), describe($r));
}

// 3) Ein Anmeldeversuch am Formular vorbei darf gar nicht erst ankommen.
echo "\nAnmelden am Pfad vorbei\n";
resetLockout();
foreach (['//wp-login.php', '/%77p-login.php', '/WP-LOGIN.PHP', '/wp-login.php?action=PostPass'] as $path) {
    $r = request('POST', $path, ['body' => http_build_query(['log' => $user, 'pwd' => $pass, 'wp-submit' => 'Anmelden'])]);
    $in = (bool) preg_match('/set-cookie:\s*wordpress_logged_in/i', $r['headers']);
    expect('POST ' . $path . ' mit richtigem Passwort', ! $in && ! leaks($r), describe($r) . ($in ? ' EINGELOGGT' : ''));
}
resetLockout();

// 4) Sperre am Formular: nach $max Fehlversuchen hilft auch das richtige Passwort nicht.
echo "\nSperre Formular\n";
resetLockout();
for ($i = 0; $i < $max; $i++) {
    request('POST', '/' . $slug, ['body' => http_build_query(['log' => $user, 'pwd' => 'falsch-' . $i])]);
}
$r = request('POST', '/' . $slug, ['body' => http_build_query(['log' => $user, 'pwd' => $pass])]);
$in = (bool) preg_match('/set-cookie:\s*wordpress_logged_in/i', $r['headers']);
expect("Formular: richtiges Passwort nach $max Fehlversuchen", ! $in && str_contains($r['body'], 'Zu viele'), 'Zähler ' . counter() . ($in ? ' EINGELOGGT' : ''));

// 5) XML-RPC, einzeln und als system.multicall.
echo "\nSperre XML-RPC\n";
resetLockout();
$xh = ['Content-Type: text/xml'];
if ($xmlrpcOn) {
    $xh[] = 'X-RH-Test-Xmlrpc: 1';
}
$probe = request('POST', '/xmlrpc.php', ['body' => xmlrpcCall($user, 'falsch'), 'headers' => $xh]);
if (str_contains($probe['body'], '<int>405</int>')) {
    expect('XML-RPC Anmeldung abgeschaltet', ! $xmlrpcOn, 'Status ' . $probe['status'] . ($xmlrpcOn ? ' (sollte an sein)' : ''));
} else {
    for ($i = 1; $i < $max; $i++) {
        request('POST', '/xmlrpc.php', ['body' => xmlrpcCall($user, 'falsch-' . $i), 'headers' => $xh]);
    }
    $r = request('POST', '/xmlrpc.php', ['body' => xmlrpcCall($user, $pass), 'headers' => $xh]);
    expect("XML-RPC: richtiges Passwort nach $max Fehlversuchen", str_contains($r['body'], 'faultCode'), 'Zähler ' . counter());

    resetLockout();
    $calls = '';
    for ($i = 0; $i < 20; $i++) {
        $calls .= '<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
            . '<member><name>params</name><value><array><data><value><string>' . htmlspecialchars($user) . '</string></value>'
            . '<value><string>falsch-' . $i . '</string></value></data></array></value></member></struct></value>';
    }
    $multi = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
        . $calls . '</data></array></value></param></params></methodCall>';
    request('POST', '/xmlrpc.php', ['body' => $multi, 'headers' => $xh]);
    expect('system.multicall mit 20 Versuchen zählt höchstens 1', counter() <= 1, 'Zähler ' . counter());
}

// 6) REST mit Anwendungspasswort (Basic Auth).
echo "\nSperre REST / Anwendungspasswort\n";
if ($appPass === '') {
    expect('REST übersprungen (RH_APPPASS fehlt)', true, '');
} else {
    resetLockout();
    $ok = request('GET', '/wp-json/wp/v2/settings', ['basic' => $user . ':' . $appPass]);
    expect('REST: Anwendungspasswort funktioniert', $ok['status'] === 200, 'Status ' . $ok['status']);

    for ($i = 0; $i < $max; $i++) {
        request('GET', '/wp-json/wp/v2/settings', ['basic' => $user . ':falsch falsch falsch ' . $i]);
    }
    $count = counter();
    expect("REST: $max Fehlversuche werden gezählt", $count >= $max, 'Zähler ' . $count);

    $r = request('GET', '/wp-json/wp/v2/settings', ['basic' => $user . ':' . $appPass]);
    expect('REST: richtiges Anwendungspasswort nach Sperre', $r['status'] === 401, 'Status ' . $r['status']);
}

resetLockout();

echo "\n" . (failures() === 0 ? 'Alles grün.' : failures() . ' Fehler.') . "\n";
exit(failures() === 0 ? 0 : 1);
