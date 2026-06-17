# RH Login

Login-Schutz: Versuch-Limit und optionales Verstecken der Login-URL. Teil der rh-blueprint Kollektion.

App-seitiger Schutz, der server-seitiges CrowdSec/fail2ban ergänzt (das sieht den POST, aber nicht Erfolg/Fehlschlag).

## Was es macht

- **Login-Versuch-Limit**: zählt Fehlversuche pro IP und sperrt die IP nach dem Limit für eine Weile. Erfolgreicher Login setzt den Zähler zurück.
- **Login-URL verstecken** (opt-in): `wp-login.php` und `/wp-admin` führen für nicht eingeloggte Besucher ins Leere (Startseite), der Login liegt unter einem geheimen Pfad. Der geheime Pfad wird dabei nicht im Redirect verraten. Passwortgeschützte Beiträge (`postpass`) bleiben funktionsfähig.

## Einstellungen

Im Backend unter **RH Blueprint → Login**:

- Login-Limit an/aus, maximale Fehlversuche (Standard 5), Sperrdauer in Minuten (Standard 15).
- Login-URL verstecken an/aus, Login-Pfad (z.B. `mein-zugang`, `team-eingang`, oder etwas Eigenes mit Zufallsteil wie `zugang-7f3a9`).

## Sicherheitshinweis

Nach dem Aktivieren des Versteckens unbedingt **Login UND Logout im Browser testen**. Falls du dich aussperrst: das Plugin deaktivieren, dann ist `/wp-login.php` wieder normal erreichbar (alles läuft nur über Laufzeit-Hooks).

## Für Entwickler

Filter `rh-blueprint/login/client_ip` ($ip): die erkannte Client-IP überschreiben, wenn die Site hinter einem Proxy läuft (z.B. Coolify).

## Installation

ZIP hochladen und aktivieren. Der geteilte Core ist gebündelt.

## Voraussetzungen

WordPress 6.5+, PHP 8.1+.
