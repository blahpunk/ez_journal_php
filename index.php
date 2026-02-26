<?php
declare(strict_types=1);

// Configuration
$databaseUrl = getenv('DATABASE_URL') ?: 'sqlite:////var/lib/ez_journal/journal.db';
$secretKey = getenv('SECRET_KEY') ?: 'change-me';
$pinUserPin = getenv('PIN_USER_PIN') ?: '09111984';
$logPath = getenv('LOG_PATH') ?: '/var/www/log/journal.log';
$appTimeZone = new DateTimeZone('America/Chicago');
$storageTimeZone = new DateTimeZone('UTC');
$oauthLoginEndpoint = getenv('OAUTH_LOGIN_URL') ?: 'https://secure.blahpunk.com/oauth_login';
$oauthLogoutEndpoint = getenv('OAUTH_LOGOUT_URL') ?: 'https://secure.blahpunk.com/logout';
$secureAuthSecret = trim((string) (getenv('SECURE_AUTH_SECRET') ?: getenv('FLASK_SECRET_KEY') ?: ''));
$adminEmail = strtolower(trim((string) (getenv('JOURNAL_ADMIN_EMAIL') ?: 'eric.zeigenbein@gmail.com')));
$damianEmail = strtolower(trim((string) (getenv('JOURNAL_DAMIAN_EMAIL') ?: 'ionru404@gmail.com')));
$pinUserLabel = trim((string) (getenv('JOURNAL_PIN_LABEL') ?: 'J.'));
$adminSessionTtlSeconds = max(86400, (int) (getenv('ADMIN_SESSION_TTL_SECONDS') ?: (60 * 60 * 24 * 365 * 10)));

// Secure session cookie settings
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
ini_set('session.gc_maxlifetime', (string) $adminSessionTtlSeconds);
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $https,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

function db_connect(string $databaseUrl): PDO
{
    if (!str_starts_with($databaseUrl, 'sqlite:///')) {
        throw new RuntimeException('Only sqlite DATABASE_URL is supported.');
    }

    $path = substr($databaseUrl, strlen('sqlite:///'));
    if ($path === false || $path === '') {
        throw new RuntimeException('Invalid sqlite DATABASE_URL path.');
    }

    if ($path[0] !== '/') {
        $path = __DIR__ . '/' . $path;
    }

    $dir = dirname($path);
    if (!is_dir($dir)) {
        throw new RuntimeException('DB directory does not exist: ' . $dir);
    }

    $pdo = new PDO('sqlite:' . $path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA foreign_keys = ON');
    return $pdo;
}

function normalize_email(string $email): string
{
    return strtolower(trim($email));
}

function table_has_column(PDO $db, string $table, string $column): bool
{
    $stmt = $db->query('PRAGMA table_info(' . $table . ')');
    $cols = $stmt ? $stmt->fetchAll() : [];
    foreach ($cols as $col) {
        if (strcasecmp((string) ($col['name'] ?? ''), $column) === 0) {
            return true;
        }
    }
    return false;
}

function ensure_user_columns(PDO $db): void
{
    if (!table_has_column($db, 'user', 'email')) {
        $db->exec('ALTER TABLE user ADD COLUMN email TEXT');
    }
    if (!table_has_column($db, 'user', 'name')) {
        $db->exec('ALTER TABLE user ADD COLUMN name TEXT');
    }
    if (!table_has_column($db, 'user', 'auth_type')) {
        $db->exec("ALTER TABLE user ADD COLUMN auth_type TEXT");
    }
}

function find_user_id_by_label(PDO $db, string $label): ?int
{
    $labelNorm = normalize_email($label);
    if ($labelNorm === '') {
        return null;
    }
    $stmt = $db->prepare(
        "SELECT id FROM user
         WHERE lower(trim(coalesce(label, ''))) = :label
         ORDER BY id
         LIMIT 1"
    );
    $stmt->execute([':label' => $labelNorm]);
    $row = $stmt->fetch();
    return $row ? (int) $row['id'] : null;
}

function find_user_id_by_email(PDO $db, string $email): ?int
{
    $emailNorm = normalize_email($email);
    if ($emailNorm === '') {
        return null;
    }
    $stmt = $db->prepare(
        "SELECT id FROM user
         WHERE lower(trim(coalesce(email, ''))) = :email
         ORDER BY id
         LIMIT 1"
    );
    $stmt->execute([':email' => $emailNorm]);
    $row = $stmt->fetch();
    return $row ? (int) $row['id'] : null;
}

function move_viewer_links(PDO $db, int $fromId, int $toId): void
{
    if ($fromId === $toId) {
        return;
    }
    $copy = $db->prepare(
        'INSERT OR IGNORE INTO entry_viewers (entry_id, user_id)
         SELECT entry_id, :to_id
         FROM entry_viewers
         WHERE user_id = :from_id'
    );
    $copy->execute([':to_id' => $toId, ':from_id' => $fromId]);

    $delete = $db->prepare('DELETE FROM entry_viewers WHERE user_id = :from_id');
    $delete->execute([':from_id' => $fromId]);
}

function upsert_identity_user(PDO $db, string $label, string $email, string $name, int $isEditor): int
{
    $desiredEmail = normalize_email($email);
    $id = find_user_id_by_email($db, $email);
    if ($id === null) {
        $id = find_user_id_by_label($db, $label);
    }

    if ($id === null) {
        $insert = $db->prepare(
            'INSERT INTO user (label, pin_hash, is_editor, email, name, auth_type)
             VALUES (:label, NULL, :is_editor, :email, :name, :auth_type)'
        );
        $insert->execute([
            ':label' => $label,
            ':is_editor' => $isEditor,
            ':email' => $desiredEmail,
            ':name' => $name,
            ':auth_type' => 'oauth',
        ]);
        return (int) $db->lastInsertId();
    }

    $currentStmt = $db->prepare(
        'SELECT label, pin_hash, is_editor, email, name, auth_type
         FROM user
         WHERE id = :id
         LIMIT 1'
    );
    $currentStmt->execute([':id' => $id]);
    $current = $currentStmt->fetch() ?: [];

    $needsUpdate =
        (string) ($current['label'] ?? '') !== $label
        || (int) ($current['is_editor'] ?? 0) !== $isEditor
        || normalize_email((string) ($current['email'] ?? '')) !== $desiredEmail
        || trim((string) ($current['name'] ?? '')) !== $name
        || normalize_email((string) ($current['auth_type'] ?? '')) !== 'oauth'
        || (($current['pin_hash'] ?? null) !== null);

    if ($needsUpdate) {
        $update = $db->prepare(
            'UPDATE user
             SET label = :label,
                 pin_hash = NULL,
                 is_editor = :is_editor,
                 email = :email,
                 name = :name,
                 auth_type = :auth_type
             WHERE id = :id'
        );
        $update->execute([
            ':label' => $label,
            ':is_editor' => $isEditor,
            ':email' => $desiredEmail,
            ':name' => $name,
            ':auth_type' => 'oauth',
            ':id' => $id,
        ]);
    }

    return $id;
}

function init_schema(PDO $db, string $pinUserLabel, string $pinUserPin, string $adminEmail, string $damianEmail): void
{
    $db->exec(
        'CREATE TABLE IF NOT EXISTS login_lockout (
            ip TEXT PRIMARY KEY,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lockout_until TEXT,
            updated_at TEXT NOT NULL
        )'
    );
    $db->exec(
        'CREATE TABLE IF NOT EXISTS entry_draft (
            user_id INTEGER NOT NULL,
            draft_key TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT \'\',
            content TEXT NOT NULL DEFAULT \'\',
            draft_date TEXT NOT NULL DEFAULT \'\',
            draft_time TEXT NOT NULL DEFAULT \'\',
            viewer_ids TEXT NOT NULL DEFAULT \'0\',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, draft_key),
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
        )'
    );
    ensure_user_columns($db);

    $guest = $db->query('SELECT id FROM user WHERE id = 0')->fetch();
    if (!$guest) {
        $stmt = $db->prepare(
            'INSERT INTO user (id, label, pin_hash, is_editor, email, name, auth_type)
             VALUES (0, :label, NULL, 0, NULL, :name, :auth_type)'
        );
        $stmt->execute([':label' => 'Guest', ':name' => 'Guest', ':auth_type' => 'guest']);
    } else {
        $guestStateStmt = $db->prepare('SELECT label, pin_hash, is_editor, email, name, auth_type FROM user WHERE id = 0 LIMIT 1');
        $guestStateStmt->execute();
        $guestState = $guestStateStmt->fetch() ?: [];

        $needsGuestUpdate =
            (string) ($guestState['label'] ?? '') !== 'Guest'
            || (($guestState['pin_hash'] ?? null) !== null)
            || (int) ($guestState['is_editor'] ?? 0) !== 0
            || trim((string) ($guestState['email'] ?? '')) !== ''
            || trim((string) ($guestState['name'] ?? '')) !== 'Guest'
            || normalize_email((string) ($guestState['auth_type'] ?? '')) !== 'guest';

        if ($needsGuestUpdate) {
            $stmt = $db->prepare(
                "UPDATE user
                 SET label = 'Guest',
                     pin_hash = NULL,
                     is_editor = 0,
                     email = NULL,
                     name = 'Guest',
                     auth_type = 'guest'
                 WHERE id = 0"
            );
            $stmt->execute();
        }
    }

    $adminId = upsert_identity_user($db, 'Admin', $adminEmail, 'Eric Zeigenbein', 1);
    $damianId = upsert_identity_user($db, 'Damian', $damianEmail, 'Damian', 0);

    $jId = find_user_id_by_label($db, $pinUserLabel);
    if ($jId === null) {
        $insertPinUser = $db->prepare(
            'INSERT INTO user (label, pin_hash, is_editor, email, name, auth_type)
             VALUES (:label, :pin_hash, 0, NULL, :name, :auth_type)'
        );
        $insertPinUser->execute([
            ':label' => $pinUserLabel,
            ':pin_hash' => hash_pin($pinUserPin),
            ':name' => $pinUserLabel,
            ':auth_type' => 'pin',
        ]);
        $jId = (int) $db->lastInsertId();
    }

    $existingPinHashStmt = $db->prepare('SELECT pin_hash FROM user WHERE id = :id LIMIT 1');
    $existingPinHashStmt->execute([':id' => $jId]);
    $existingPinHash = (string) (($existingPinHashStmt->fetch()['pin_hash'] ?? '') ?: '');
    $needsPinReset = $existingPinHash === '' || !verify_pin($pinUserPin, $existingPinHash);
    $pinUserStateStmt = $db->prepare('SELECT label, is_editor, email, name, auth_type FROM user WHERE id = :id LIMIT 1');
    $pinUserStateStmt->execute([':id' => $jId]);
    $pinUserState = $pinUserStateStmt->fetch() ?: [];
    $needsPinUserUpdate =
        (string) ($pinUserState['label'] ?? '') !== $pinUserLabel
        || (int) ($pinUserState['is_editor'] ?? 0) !== 0
        || trim((string) ($pinUserState['email'] ?? '')) !== ''
        || trim((string) ($pinUserState['name'] ?? '')) !== $pinUserLabel
        || normalize_email((string) ($pinUserState['auth_type'] ?? '')) !== 'pin';

    if ($needsPinReset || $needsPinUserUpdate) {
        $updatePinUser = $db->prepare(
            'UPDATE user
             SET label = :label,
                 pin_hash = :pin_hash,
                 is_editor = 0,
                 email = NULL,
                 name = :name,
                 auth_type = :auth_type
             WHERE id = :id'
        );
        $updatePinUser->execute([
            ':label' => $pinUserLabel,
            ':pin_hash' => $needsPinReset ? hash_pin($pinUserPin) : $existingPinHash,
            ':name' => $pinUserLabel,
            ':auth_type' => 'pin',
            ':id' => $jId,
        ]);
    }

    // If duplicate legacy identities exist, merge their entry permissions into canonical users.
    $mergeCandidatesStmt = $db->query('SELECT id, label, email FROM user WHERE id != 0');
    $mergeCandidates = $mergeCandidatesStmt ? $mergeCandidatesStmt->fetchAll() : [];
    foreach ($mergeCandidates as $candidate) {
        $candidateId = (int) $candidate['id'];
        if ($candidateId === $adminId || $candidateId === $damianId || $candidateId === $jId) {
            continue;
        }
        $labelNorm = normalize_email((string) ($candidate['label'] ?? ''));
        $emailNorm = normalize_email((string) ($candidate['email'] ?? ''));

        if ($labelNorm === 'admin' || $emailNorm === normalize_email($adminEmail)) {
            move_viewer_links($db, $candidateId, $adminId);
        } elseif ($labelNorm === 'damian' || $emailNorm === normalize_email($damianEmail)) {
            move_viewer_links($db, $candidateId, $damianId);
        } elseif ($labelNorm === normalize_email($pinUserLabel)) {
            move_viewer_links($db, $candidateId, $jId);
        }
    }
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function current_path(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $path = parse_url($uri, PHP_URL_PATH);
    return is_string($path) && $path !== '' ? $path : '/';
}

function full_path_with_query(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    return $uri !== '' ? $uri : '/';
}

function current_request_url(): ?string
{
    $host = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
    if ($host === '') {
        return null;
    }

    $scheme = 'http';
    $forwardedProto = trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
    if ($forwardedProto !== '') {
        $scheme = trim(explode(',', $forwardedProto)[0]);
    } elseif (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        $scheme = 'https';
    }

    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    return sprintf('%s://%s%s', $scheme, $host, $uri);
}

function absolute_url_for_path(string $path): string
{
    if (str_starts_with($path, 'http://') || str_starts_with($path, 'https://')) {
        return $path;
    }

    $host = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
    if ($host === '') {
        return $path;
    }

    $scheme = 'http';
    $forwardedProto = trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
    if ($forwardedProto !== '') {
        $scheme = trim(explode(',', $forwardedProto)[0]);
    } elseif (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        $scheme = 'https';
    }

    $normalized = $path === '' ? '/' : $path;
    if ($normalized[0] !== '/') {
        $normalized = '/' . $normalized;
    }
    return sprintf('%s://%s%s', $scheme, $host, $normalized);
}

function sanitize_next_path(?string $next): string
{
    $value = trim((string) $next);
    if ($value === '' || $value[0] !== '/' || str_starts_with($value, '//')) {
        return '/';
    }
    return $value;
}

function build_external_auth_url(string $endpoint, string $nextPath): string
{
    $separator = str_contains($endpoint, '?') ? '&' : '?';
    return $endpoint . $separator . 'next=' . rawurlencode(absolute_url_for_path($nextPath));
}

function base64url_decode_str(string $value): ?string
{
    $base64 = strtr($value, '-_', '+/');
    $padding = strlen($base64) % 4;
    if ($padding > 0) {
        $base64 .= str_repeat('=', 4 - $padding);
    }
    $decoded = base64_decode($base64, true);
    return is_string($decoded) ? $decoded : null;
}

/**
 * @return array{name: string, email: string}|null
 */
function oauth_identity_from_cookie(string $secret): ?array
{
    $cookieValue = trim((string) ($_COOKIE['user'] ?? ''));
    if ($cookieValue === '') {
        return null;
    }

    if ($secret !== '') {
        $providedSig = trim((string) ($_COOKIE['user_sig'] ?? ''));
        $expectedSig = hash_hmac('sha256', $cookieValue, $secret);
        if ($providedSig === '' || !hash_equals($expectedSig, $providedSig)) {
            return null;
        }
    }

    $decoded = base64url_decode_str($cookieValue);
    if ($decoded === null) {
        return null;
    }

    $payload = json_decode($decoded, true);
    if (!is_array($payload)) {
        return null;
    }

    $email = normalize_email((string) ($payload['email'] ?? ''));
    if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        return null;
    }

    $name = trim((string) ($payload['name'] ?? ''));
    if ($name === '') {
        $name = $email;
    }

    return [
        'name' => $name,
        'email' => $email,
    ];
}

function get_client_ip(): string
{
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if ($xff !== '') {
        $parts = explode(',', $xff);
        return trim($parts[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function flash(string $message): void
{
    $_SESSION['flash_messages'][] = $message;
}

function pop_flashes(): array
{
    $messages = $_SESSION['flash_messages'] ?? [];
    unset($_SESSION['flash_messages']);
    return is_array($messages) ? $messages : [];
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function require_csrf(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }
    $token = $_POST['csrf_token'] ?? '';
    $sessionToken = $_SESSION['csrf_token'] ?? '';
    if (!is_string($token) || !is_string($sessionToken) || !hash_equals($sessionToken, $token)) {
        http_response_code(400);
        echo 'Invalid CSRF token';
        exit;
    }
}

function redirect_to(string $path): never
{
    header('Location: ' . $path);
    exit;
}

function scrypt_hash_hex(string $pin, string $salt, int $n = 32768, int $r = 8, int $p = 1, int $dkLen = 64): ?string
{
    // Preferred path: libsodium low-level scrypt via FFI (exact Werkzeug compatibility).
    if (class_exists('FFI')) {
        static $ffi = null;
        if ($ffi === null) {
            $libs = [
                '/usr/lib/x86_64-linux-gnu/libsodium.so',
                'libsodium.so.23',
                'libsodium.so',
            ];

            foreach ($libs as $lib) {
                try {
                    $ffi = FFI::cdef(
                        'int crypto_pwhash_scryptsalsa208sha256_ll('
                        . 'const unsigned char *passwd, size_t passwdlen, '
                        . 'const unsigned char *salt, size_t saltlen, '
                        . 'unsigned long long N, unsigned int r, unsigned int p, '
                        . 'unsigned char *buf, size_t buflen);',
                        $lib
                    );
                    break;
                } catch (Throwable) {
                    $ffi = null;
                }
            }
        }

        if ($ffi !== null) {
            $passLen = strlen($pin);
            $saltLen = strlen($salt);
            $pass = FFI::new("unsigned char[$passLen]");
            $saltBuf = FFI::new("unsigned char[$saltLen]");
            FFI::memcpy($pass, $pin, $passLen);
            FFI::memcpy($saltBuf, $salt, $saltLen);

            $out = FFI::new("unsigned char[$dkLen]");
            $rc = $ffi->crypto_pwhash_scryptsalsa208sha256_ll($pass, $passLen, $saltBuf, $saltLen, $n, $r, $p, $out, $dkLen);
            if ($rc === 0) {
                $hex = '';
                for ($i = 0; $i < $dkLen; $i++) {
                    $hex .= str_pad(dechex(((int) $out[$i]) & 0xff), 2, '0', STR_PAD_LEFT);
                }
                return $hex;
            }
        }
    }

    // Fallback path: OpenSSL CLI SCRYPT KDF.
    $cmd = sprintf(
        "openssl kdf -keylen %d -kdfopt pass:%s -kdfopt hexsalt:%s -kdfopt n:%d -kdfopt r:%d -kdfopt p:%d SCRYPT 2>/dev/null",
        $dkLen,
        escapeshellarg($pin),
        bin2hex($salt),
        $n,
        $r,
        $p
    );
    $output = shell_exec($cmd);
    if (!is_string($output)) {
        return null;
    }
    $hex = strtolower(preg_replace('/[^a-fA-F0-9]/', '', $output) ?? '');
    return strlen($hex) === ($dkLen * 2) ? $hex : null;
}

function hash_pin(string $pin): string
{
    $salt = rtrim(strtr(base64_encode(random_bytes(12)), '+/', '._'), '=');
    $hex = scrypt_hash_hex($pin, $salt);
    if ($hex !== null) {
        return 'scrypt:32768:8:1$' . $salt . '$' . $hex;
    }

    return password_hash($pin, PASSWORD_DEFAULT);
}

function verify_pin(string $pin, ?string $hash): bool
{
    if (!$hash) {
        return false;
    }

    if (str_starts_with($hash, 'scrypt:')) {
        $parts = explode('$', $hash);
        if (count($parts) !== 3) {
            return false;
        }
        [$method, $salt, $expectedHex] = $parts;
        $methodParts = explode(':', $method);
        if (count($methodParts) !== 4 || $methodParts[0] !== 'scrypt') {
            return false;
        }

        $n = (int) $methodParts[1];
        $r = (int) $methodParts[2];
        $p = (int) $methodParts[3];
        $computedHex = scrypt_hash_hex($pin, $salt, $n, $r, $p, 64);
        if ($computedHex === null) {
            return false;
        }
        return hash_equals($expectedHex, $computedHex);
    }

    return password_verify($pin, $hash);
}

function pin_fingerprint(string $pin): string
{
    return substr(hash('sha256', $pin), 0, 12);
}

function log_attempt(string $logPath, DateTimeZone $tz, string $ip, string $pin, string $result): void
{
    $timestamp = (new DateTimeImmutable('now', $tz))->format('Y-m-d H:i:s T');
    $line = sprintf(
        "[%s] IP: %s | PIN_FPR: %s | Result: %s\n",
        $timestamp,
        $ip,
        pin_fingerprint($pin),
        $result
    );

    $dir = dirname($logPath);
    if (!is_dir($dir)) {
        @mkdir($dir, 0770, true);
    }
    @file_put_contents($logPath, $line, FILE_APPEND | LOCK_EX);
}

function sanitize_html(string $html): string
{
    // Drop script/style blocks entirely (including their inner text).
    $html = preg_replace('#<script\b[^>]*>.*?</script>#is', '', $html) ?? '';
    $html = preg_replace('#<style\b[^>]*>.*?</style>#is', '', $html) ?? '';

    $allowedTags = [
        'p', 'br', 'strong', 'em', 'u', 's',
        'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
        'h1', 'h2', 'h3', 'a', 'img', 'span', 'div'
    ];

    $allowedAttrs = [
        'a' => ['href', 'target', 'rel'],
        'img' => ['src', 'alt'],
        'span' => ['class'],
        'div' => ['class'],
        'p' => ['class'],
        'h1' => ['class'],
        'h2' => ['class'],
        'h3' => ['class'],
    ];

    $doc = new DOMDocument();
    libxml_use_internal_errors(true);
    $doc->loadHTML('<?xml encoding="utf-8" ?><body>' . $html . '</body>', LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
    libxml_clear_errors();

    $body = $doc->getElementsByTagName('body')->item(0);
    if (!$body) {
        return '';
    }

    $walker = function (DOMNode $node) use (&$walker, $allowedTags, $allowedAttrs): void {
        if ($node instanceof DOMElement) {
            $tag = strtolower($node->tagName);
            if (!in_array($tag, $allowedTags, true)) {
                $parent = $node->parentNode;
                if ($parent) {
                    while ($node->firstChild) {
                        $parent->insertBefore($node->firstChild, $node);
                    }
                    $parent->removeChild($node);
                }
                return;
            }

            // Remove dangerous attributes and javascript/data URLs.
            $attrs = [];
            foreach ($node->attributes as $attr) {
                $attrs[] = $attr;
            }
            foreach ($attrs as $attr) {
                $name = strtolower($attr->name);
                $value = trim($attr->value);
                $allowedForTag = $allowedAttrs[$tag] ?? [];

                if (str_starts_with($name, 'on')) {
                    $node->removeAttributeNode($attr);
                    continue;
                }
                if (!in_array($name, $allowedForTag, true)) {
                    $node->removeAttributeNode($attr);
                    continue;
                }

                if (($name === 'href' || $name === 'src') && $value !== '') {
                    $lower = strtolower($value);
                    $safe = str_starts_with($lower, 'http://')
                        || str_starts_with($lower, 'https://')
                        || str_starts_with($lower, '/')
                        || str_starts_with($lower, 'data:image/');
                    if (!$safe) {
                        $node->removeAttributeNode($attr);
                    }
                }
            }
        }

        $children = [];
        foreach ($node->childNodes as $child) {
            $children[] = $child;
        }
        foreach ($children as $child) {
            $walker($child);
        }
    };

    foreach (iterator_to_array($body->childNodes) as $child) {
        $walker($child);
    }

    $output = '';
    foreach ($body->childNodes as $child) {
        $output .= $doc->saveHTML($child);
    }
    return $output;
}

/**
 * @return array{id: int, label: string, pin_hash: ?string, is_editor: int, email: ?string, name: ?string, auth_type: string}|null
 */
function fetch_user_by_id(PDO $db, int $id): ?array
{
    $stmt = $db->prepare(
        "SELECT id, label, pin_hash, is_editor, email, name,
                coalesce(nullif(auth_type, ''),
                    CASE
                        WHEN id = 0 THEN 'guest'
                        WHEN pin_hash IS NOT NULL THEN 'pin'
                        ELSE 'oauth'
                    END
                ) AS auth_type
         FROM user
         WHERE id = :id
         LIMIT 1"
    );
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch();
    return $row ?: null;
}

/**
 * @return array{id: int, label: string, pin_hash: ?string, is_editor: int, email: ?string, name: ?string, auth_type: string}|null
 */
function fetch_oauth_user_by_email(PDO $db, string $email): ?array
{
    $emailNorm = normalize_email($email);
    if ($emailNorm === '') {
        return null;
    }

    $stmt = $db->prepare(
        "SELECT id, label, pin_hash, is_editor, email, name,
                coalesce(nullif(auth_type, ''),
                    CASE
                        WHEN id = 0 THEN 'guest'
                        WHEN pin_hash IS NOT NULL THEN 'pin'
                        ELSE 'oauth'
                    END
                ) AS auth_type
         FROM user
         WHERE lower(trim(coalesce(email, ''))) = :email
           AND coalesce(nullif(auth_type, ''), CASE WHEN pin_hash IS NOT NULL THEN 'pin' ELSE 'oauth' END) = 'oauth'
         ORDER BY id
         LIMIT 1"
    );
    $stmt->execute([':email' => $emailNorm]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function require_login(): void
{
    if (empty($_SESSION['user_id'])) {
        $next = urlencode(full_path_with_query());
        redirect_to('/login?next=' . $next);
    }
}

function require_editor(?array $user): void
{
    if (!$user || empty($user['is_editor'])) {
        flash('Permission denied');
        redirect_to('/');
    }
}

function is_admin_user(?array $user, string $adminEmail): bool
{
    if (!$user) {
        return false;
    }
    $email = normalize_email((string) ($user['email'] ?? ''));
    return $email !== '' && $email === normalize_email($adminEmail);
}

function persist_session_cookie(int $ttlSeconds): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return;
    }

    $params = session_get_cookie_params();
    setcookie(session_name(), session_id(), [
        'expires' => time() + $ttlSeconds,
        'path' => $params['path'] ?? '/',
        'domain' => $params['domain'] ?? '',
        'secure' => (bool) ($params['secure'] ?? false),
        'httponly' => (bool) ($params['httponly'] ?? true),
        'samesite' => $params['samesite'] ?? 'Lax',
    ]);
}

function enable_admin_persistent_session(array $user, string $adminEmail, int $ttlSeconds): void
{
    if (!is_admin_user($user, $adminEmail)) {
        return;
    }
    $_SESSION['admin_persistent'] = 1;
    $_SESSION['admin_last_seen'] = time();
    persist_session_cookie($ttlSeconds);
}

function fetch_entry_draft(PDO $db, int $userId, string $draftKey): ?array
{
    $stmt = $db->prepare(
        'SELECT title, content, draft_date, draft_time, viewer_ids, updated_at
         FROM entry_draft
         WHERE user_id = :user_id AND draft_key = :draft_key
         LIMIT 1'
    );
    $stmt->execute([':user_id' => $userId, ':draft_key' => $draftKey]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function upsert_entry_draft(
    PDO $db,
    int $userId,
    string $draftKey,
    string $title,
    string $content,
    string $draftDate,
    string $draftTime,
    string $viewerIds,
    DateTimeZone $storageTimeZone
): string {
    $updatedAt = (new DateTimeImmutable('now', $storageTimeZone))->format(DateTimeInterface::ATOM);
    $stmt = $db->prepare(
        'INSERT INTO entry_draft (user_id, draft_key, title, content, draft_date, draft_time, viewer_ids, updated_at)
         VALUES (:user_id, :draft_key, :title, :content, :draft_date, :draft_time, :viewer_ids, :updated_at)
         ON CONFLICT(user_id, draft_key) DO UPDATE SET
            title = excluded.title,
            content = excluded.content,
            draft_date = excluded.draft_date,
            draft_time = excluded.draft_time,
            viewer_ids = excluded.viewer_ids,
            updated_at = excluded.updated_at'
    );
    $stmt->execute([
        ':user_id' => $userId,
        ':draft_key' => $draftKey,
        ':title' => $title,
        ':content' => $content,
        ':draft_date' => $draftDate,
        ':draft_time' => $draftTime,
        ':viewer_ids' => $viewerIds,
        ':updated_at' => $updatedAt,
    ]);
    return $updatedAt;
}

function delete_entry_draft(PDO $db, int $userId, string $draftKey): void
{
    $stmt = $db->prepare('DELETE FROM entry_draft WHERE user_id = :user_id AND draft_key = :draft_key');
    $stmt->execute([':user_id' => $userId, ':draft_key' => $draftKey]);
}

function normalize_draft_key(string $rawKey): ?string
{
    $key = trim($rawKey);
    if ($key === 'new') {
        return $key;
    }
    if (preg_match('/^edit:\d+$/', $key)) {
        return $key;
    }
    return null;
}

function parse_storage_datetime(string $raw, DateTimeZone $storageTimeZone): DateTimeImmutable
{
    $value = trim($raw);
    if ($value === '') {
        return new DateTimeImmutable('now', $storageTimeZone);
    }

    $dt = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $value, $storageTimeZone);
    if ($dt !== false) {
        return $dt;
    }

    try {
        return new DateTimeImmutable($value, $storageTimeZone);
    } catch (Throwable) {
        return new DateTimeImmutable('now', $storageTimeZone);
    }
}

function auth_current_user(PDO $db, ?array $oauthIdentity, string $adminEmail, int $adminSessionTtlSeconds): ?array
{
    $sessionId = isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
    $sessionMode = (string) ($_SESSION['auth_mode'] ?? '');

    if ($sessionId !== null) {
        $sessionUser = fetch_user_by_id($db, $sessionId);
        if ($sessionUser) {
            $authType = (string) ($sessionUser['auth_type'] ?? '');
            if ($authType === 'pin' && $sessionMode === 'pin') {
                return $sessionUser;
            }

            if ($authType === 'oauth') {
                if ($oauthIdentity !== null) {
                    $sessionEmail = normalize_email((string) ($sessionUser['email'] ?? ''));
                    if ($sessionEmail !== '' && strcasecmp($sessionEmail, $oauthIdentity['email']) === 0) {
                        $_SESSION['auth_mode'] = 'oauth';
                        if ($oauthIdentity['name'] !== '' && trim((string) ($sessionUser['name'] ?? '')) !== $oauthIdentity['name']) {
                            $updateName = $db->prepare('UPDATE user SET name = :name WHERE id = :id');
                            $updateName->execute([':name' => $oauthIdentity['name'], ':id' => (int) $sessionUser['id']]);
                            $sessionUser['name'] = $oauthIdentity['name'];
                        }
                        enable_admin_persistent_session($sessionUser, $adminEmail, $adminSessionTtlSeconds);
                        return $sessionUser;
                    }
                } elseif ($sessionMode === 'oauth' && is_admin_user($sessionUser, $adminEmail)) {
                    enable_admin_persistent_session($sessionUser, $adminEmail, $adminSessionTtlSeconds);
                    return $sessionUser;
                }
            }
        }

        unset($_SESSION['user_id'], $_SESSION['auth_mode'], $_SESSION['admin_persistent'], $_SESSION['admin_last_seen']);
    }

    if ($oauthIdentity === null) {
        return null;
    }

    $oauthUser = fetch_oauth_user_by_email($db, (string) $oauthIdentity['email']);
    if (!$oauthUser) {
        return null;
    }

    $_SESSION['user_id'] = (int) $oauthUser['id'];
    $_SESSION['auth_mode'] = 'oauth';

    if ($oauthIdentity['name'] !== '' && trim((string) ($oauthUser['name'] ?? '')) !== $oauthIdentity['name']) {
        $updateName = $db->prepare('UPDATE user SET name = :name WHERE id = :id');
        $updateName->execute([':name' => $oauthIdentity['name'], ':id' => (int) $oauthUser['id']]);
    }

    $resolvedUser = fetch_user_by_id($db, (int) $oauthUser['id']) ?: $oauthUser;
    enable_admin_persistent_session($resolvedUser, $adminEmail, $adminSessionTtlSeconds);
    return $resolvedUser;
}

function fetch_recent_entries_for_sidebar(PDO $db, ?array $user, int $limit = 10): array
{
    if ($user && (int) $user['is_editor'] === 1) {
        $stmt = $db->prepare('SELECT id, title FROM entry ORDER BY datetime(created_at) DESC LIMIT :lim');
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    $viewerId = $user ? (int) $user['id'] : null;
    if ($viewerId !== null) {
        $stmt = $db->prepare(
            'SELECT DISTINCT e.id, e.title
             FROM entry e
             JOIN entry_viewers ev ON ev.entry_id = e.id
             WHERE ev.user_id = :uid OR ev.user_id = 0
             ORDER BY datetime(e.created_at) DESC
             LIMIT :lim'
        );
        $stmt->bindValue(':uid', $viewerId, PDO::PARAM_INT);
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    $stmt = $db->prepare(
        'SELECT e.id, e.title
         FROM entry e
         JOIN entry_viewers ev ON ev.entry_id = e.id
         WHERE ev.user_id = 0
         ORDER BY datetime(e.created_at) DESC
         LIMIT :lim'
    );
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

function layout(string $content, ?array $currentUser, array $recentEntries, string $title = 'BlahPunk Blog'): void
{
    $flashes = pop_flashes();
    $csrf = csrf_token();
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title><?= h($title) ?></title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self';
                   script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com;
                   style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://unpkg.com;
                   img-src 'self' data: https://*;
                   font-src 'self' https://fonts.gstatic.com;
                   connect-src 'self'">
    <script src="https://cdn.jsdelivr.net/npm/quill@2.0.3/dist/quill.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/quill@2.0.3/dist/quill.snow.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700&family=Source+Sans+Pro:wght@400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/styles.css">
    <script>
      var _paq = window._paq = window._paq || [];
      _paq.push(['trackPageView']);
      _paq.push(['enableLinkTracking']);
      (function() {
        var u="//anal.blahpunk.com/";
        _paq.push(['setTrackerUrl', u+'matomo.php']);
        _paq.push(['setSiteId', '15']);
        var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
        g.async=true; g.src=u+'matomo.js'; s.parentNode.insertBefore(g,s);
      })();
    </script>
</head>
<body>
<nav class="navbar">
    <div class="logo">BlahPunk Blog</div>
    <div class="nav-links">
        <a href="https://blahpunk.com">Home</a>
        <a href="/">Entries</a>
        <?php if ($currentUser): ?>
            <a href="/logout">Logout (<?= h((string) $currentUser['label']) ?>)</a>
            <?php if ((int) $currentUser['is_editor'] === 1): ?>
                <a href="/add">New Entry</a>
                <a href="/manage_users">Manage Users</a>
                <a href="/logs">Logs</a>
            <?php endif; ?>
        <?php else: ?>
            <a href="/login?next=<?= urlencode(full_path_with_query()) ?>">Login</a>
        <?php endif; ?>
    </div>
</nav>

<div class="main-container">
    <div class="main-content">
        <?php foreach ($flashes as $msg): ?>
            <div class="flash"><?= h((string) $msg) ?></div>
        <?php endforeach; ?>
        <?= $content ?>
    </div>

    <div class="sidebar">
        <h3>Recent Entries</h3>
        <ul>
            <?php foreach ($recentEntries as $entry): ?>
                <?php $entryTitle = trim((string) ($entry['title'] ?? '')) !== '' ? (string) $entry['title'] : '(No Title)'; ?>
                <li><a href="#entry-<?= (int) $entry['id'] ?>"><?= h($entryTitle) ?></a></li>
            <?php endforeach; ?>
        </ul>
    </div>
</div>
<input type="hidden" id="global_csrf_token" value="<?= h($csrf) ?>">
</body>
</html>
<?php
}

function render_login_page(
    ?array $user,
    array $recentEntries,
    string $oauthLoginUrl,
    string $pinLoginUrl,
    ?string $unauthorizedEmail
): void {
    ob_start();
    ?>
<h2>Login</h2>
<p class="hint">Use Google sign-in for authorized accounts.</p>
<?php if ($unauthorizedEmail): ?>
    <div class="flash">
        Google account <strong><?= h($unauthorizedEmail) ?></strong> is not authorized for this journal.
    </div>
<?php endif; ?>
<p><a class="button" href="<?= h($oauthLoginUrl) ?>">Continue with Google</a></p>
<p class="hint">
    Private fallback account:
    <a href="<?= h($pinLoginUrl) ?>">Login with PIN</a>
</p>
<?php
    $content = ob_get_clean();
    layout($content, $user, $recentEntries, 'Login');
}

function render_pin_login(int $attemptsRemaining, ?string $suggestion, ?array $user, array $recentEntries, string $next): void
{
    ob_start();
    ?>
<h2>PIN Login</h2>
<p class="hint">(Try date of birth in MMDDYYYY format)</p>
<?php if ($suggestion): ?>
    <p class="hint"><?= h($suggestion) ?></p>
<?php endif; ?>
<p class="hint">Attempts remaining: <?= $attemptsRemaining ?></p>
<form method="post" action="/pin-login?next=<?= urlencode($next) ?>">
    <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
    <input type="password" name="pin" placeholder="Enter PIN" required>
    <button type="submit" class="button">Login</button>
</form>
<p class="hint"><a href="/login?next=<?= urlencode($next) ?>">Back to Google login</a></p>
<?php
    $content = ob_get_clean();
    layout($content, $user, $recentEntries, 'PIN Login');
}

function parse_datetime_or_now(?string $date, ?string $time, DateTimeZone $appTimeZone, DateTimeZone $storageTimeZone): string
{
    if (!$date || !$time) {
        return (new DateTimeImmutable('now', $storageTimeZone))->format('Y-m-d H:i:s');
    }
    $dt = DateTimeImmutable::createFromFormat('Y-m-d H:i', $date . ' ' . $time, $appTimeZone);
    if (!$dt) {
        return (new DateTimeImmutable('now', $storageTimeZone))->format('Y-m-d H:i:s');
    }
    return $dt->setTimezone($storageTimeZone)->format('Y-m-d H:i:s');
}

$db = db_connect($databaseUrl);
init_schema($db, $pinUserLabel, $pinUserPin, $adminEmail, $damianEmail);
$oauthIdentity = oauth_identity_from_cookie($secureAuthSecret);
$currentUser = auth_current_user($db, $oauthIdentity, $adminEmail, $adminSessionTtlSeconds);
$path = rtrim(current_path(), '/');
$path = $path === '' ? '/' : $path;
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Route: /entry/{id}
if (preg_match('#^/entry/(\d+)$#', $path, $m)) {
    $entryId = (int) $m[1];
    $perPage = 10;

    if ($currentUser && (int) $currentUser['is_editor'] === 1) {
        $stmt = $db->query('SELECT id FROM entry ORDER BY datetime(created_at) DESC');
    } elseif ($currentUser) {
        $stmt = $db->prepare(
            'SELECT DISTINCT e.id
             FROM entry e
             JOIN entry_viewers ev ON ev.entry_id = e.id
             WHERE ev.user_id = :uid OR ev.user_id = 0
             ORDER BY datetime(e.created_at) DESC'
        );
        $stmt->execute([':uid' => (int) $currentUser['id']]);
    } else {
        $publicCheck = $db->prepare(
            'SELECT 1
             FROM entry e
             JOIN entry_viewers ev ON ev.entry_id = e.id
             WHERE e.id = :entry_id AND ev.user_id = 0
             LIMIT 1'
        );
        $publicCheck->execute([':entry_id' => $entryId]);
        if (!$publicCheck->fetch()) {
            redirect_to('/login?next=' . urlencode('/entry/' . $entryId));
        }

        $stmt = $db->query(
            'SELECT e.id
             FROM entry e
             JOIN entry_viewers ev ON ev.entry_id = e.id
             WHERE ev.user_id = 0
             ORDER BY datetime(e.created_at) DESC'
        );
    }

    $ids = array_map(fn($row) => (int) $row['id'], $stmt->fetchAll());
    $index = array_search($entryId, $ids, true);
    if ($index === false) {
        flash('Entry not found or access denied');
        redirect_to('/');
    }

    $page = (int) floor($index / $perPage) + 1;
    redirect_to('/?page=' . $page . '#entry-' . $entryId);
}

// Route: /login
if ($path === '/login') {
    $next = sanitize_next_path((string) ($_GET['next'] ?? '/'));
    if ($currentUser) {
        redirect_to($next);
    }

    $oauthLoginUrl = build_external_auth_url($oauthLoginEndpoint, $next);
    $pinLoginUrl = '/pin-login?next=' . rawurlencode($next);

    $unauthorizedEmail = null;
    if ($oauthIdentity !== null) {
        $oauthUser = fetch_oauth_user_by_email($db, (string) $oauthIdentity['email']);
        if (!$oauthUser) {
            $unauthorizedEmail = (string) $oauthIdentity['email'];
        }
    }

    render_login_page(
        $currentUser,
        fetch_recent_entries_for_sidebar($db, $currentUser),
        $oauthLoginUrl,
        $pinLoginUrl,
        $unauthorizedEmail
    );
    exit;
}

// Route: /pin-login
if ($path === '/pin-login') {
    $ip = get_client_ip();
    $next = sanitize_next_path((string) ($_GET['next'] ?? '/'));

    $lockStmt = $db->prepare('SELECT failed_attempts, lockout_until FROM login_lockout WHERE ip = :ip LIMIT 1');
    $lockStmt->execute([':ip' => $ip]);
    $lock = $lockStmt->fetch();

    $attemptsRemaining = 3;
    $suggestion = null;

    if ($lock) {
        $failed = (int) $lock['failed_attempts'];
        $attemptsRemaining = max(0, 3 - $failed);
        if (!empty($lock['lockout_until'])) {
            $now = new DateTimeImmutable('now', $storageTimeZone);
            $until = parse_storage_datetime((string) $lock['lockout_until'], $storageTimeZone);
            if ($now < $until) {
                if ($method === 'POST') {
                    require_csrf();
                }
                flash('Too many failed attempts. You are locked out until ' . $until->setTimezone($appTimeZone)->format('Y-m-d H:i:s T') . '.');
                log_attempt($logPath, $appTimeZone, $ip, '(none)', 'lockout (active)');
                render_pin_login(0, null, $currentUser, fetch_recent_entries_for_sidebar($db, $currentUser), $next);
                exit;
            }

            $clearStmt = $db->prepare('DELETE FROM login_lockout WHERE ip = :ip');
            $clearStmt->execute([':ip' => $ip]);
            $lock = null;
            $attemptsRemaining = 3;
        }
    }

    if ($method === 'POST') {
        require_csrf();
        $pin = (string) ($_POST['pin'] ?? '');

        $users = $db->query(
            "SELECT id, label, pin_hash, is_editor
             FROM user
             WHERE pin_hash IS NOT NULL
               AND coalesce(nullif(auth_type, ''), 'pin') = 'pin'"
        )->fetchAll();
        $matchUser = null;
        foreach ($users as $user) {
            if (verify_pin($pin, $user['pin_hash'])) {
                $matchUser = $user;
                break;
            }
        }

        if ($matchUser) {
            $_SESSION['user_id'] = (int) $matchUser['id'];
            $_SESSION['auth_mode'] = 'pin';
            unset($_SESSION['admin_persistent'], $_SESSION['admin_last_seen']);
            $delStmt = $db->prepare('DELETE FROM login_lockout WHERE ip = :ip');
            $delStmt->execute([':ip' => $ip]);
            log_attempt($logPath, $appTimeZone, $ip, $pin, 'pass');
            redirect_to($next);
        }

        $failedAttempts = ($lock ? (int) $lock['failed_attempts'] : 0) + 1;
        $attemptsRemaining = max(0, 3 - $failedAttempts);

        if ($failedAttempts >= 3) {
            $lockoutUntil = (new DateTimeImmutable('now', $storageTimeZone))->modify('+1 hour')->format(DateTimeInterface::ATOM);
            $upsert = $db->prepare(
                'INSERT INTO login_lockout (ip, failed_attempts, lockout_until, updated_at)
                 VALUES (:ip, :failed_attempts, :lockout_until, :updated_at)
                 ON CONFLICT(ip) DO UPDATE SET
                    failed_attempts = excluded.failed_attempts,
                    lockout_until = excluded.lockout_until,
                    updated_at = excluded.updated_at'
            );
            $upsert->execute([
                ':ip' => $ip,
                ':failed_attempts' => $failedAttempts,
                ':lockout_until' => $lockoutUntil,
                ':updated_at' => (new DateTimeImmutable('now', $storageTimeZone))->format(DateTimeInterface::ATOM),
            ]);
            flash('Too many failed attempts. You are locked out for 1 hour.');
            log_attempt($logPath, $appTimeZone, $ip, $pin, 'lockout');
            $attemptsRemaining = 0;
        } else {
            $upsert = $db->prepare(
                'INSERT INTO login_lockout (ip, failed_attempts, lockout_until, updated_at)
                 VALUES (:ip, :failed_attempts, NULL, :updated_at)
                 ON CONFLICT(ip) DO UPDATE SET
                    failed_attempts = excluded.failed_attempts,
                    lockout_until = NULL,
                    updated_at = excluded.updated_at'
            );
            $upsert->execute([
                ':ip' => $ip,
                ':failed_attempts' => $failedAttempts,
                ':updated_at' => (new DateTimeImmutable('now', $storageTimeZone))->format(DateTimeInterface::ATOM),
            ]);
            flash('Invalid PIN. ' . $attemptsRemaining . ' attempt(s) remaining. (Try your date of birth)');
            $suggestion = 'Try your birthdate in MMDDYYYY format';
            log_attempt($logPath, $appTimeZone, $ip, $pin, 'fail');
        }
    }

    render_pin_login($attemptsRemaining, $suggestion, $currentUser, fetch_recent_entries_for_sidebar($db, $currentUser), $next);
    exit;
}

// Route: /logout
if ($path === '/logout') {
    require_login();
    $next = sanitize_next_path((string) ($_GET['next'] ?? '/'));
    $loggedOutUser = $currentUser;

    unset($_SESSION['user_id'], $_SESSION['auth_mode'], $_SESSION['admin_persistent'], $_SESSION['admin_last_seen']);

    if ($loggedOutUser && (string) ($loggedOutUser['auth_type'] ?? '') === 'oauth') {
        redirect_to(build_external_auth_url($oauthLogoutEndpoint, $next));
    }
    redirect_to($next);
}

// Route: /logs
if ($path === '/logs') {
    require_login();
    $currentUser = auth_current_user($db, $oauthIdentity, $adminEmail, $adminSessionTtlSeconds);
    require_editor($currentUser);

    $lines = [];
    if (is_file($logPath) && is_readable($logPath)) {
        $all = file($logPath, FILE_IGNORE_NEW_LINES);
        $lines = array_slice($all ?: [], -200);
    } else {
        $lines = ['Error reading log file'];
    }

    ob_start();
    ?>
<h2>PIN Attempt Log</h2>
<pre class="log-pre"><?php foreach ($lines as $line): ?>
<?= h((string) $line) ?>
<?php endforeach; ?></pre>
<?php
    $content = ob_get_clean();
    layout($content, $currentUser, fetch_recent_entries_for_sidebar($db, $currentUser), 'Logs');
    exit;
}

// Legacy route: /manage_pins
if ($path === '/manage_pins') {
    redirect_to('/manage_users');
}

// Route: /manage_users
if ($path === '/manage_users') {
    require_login();
    $currentUser = auth_current_user($db, $oauthIdentity, $adminEmail, $adminSessionTtlSeconds);
    require_editor($currentUser);

    if ($method === 'POST') {
        require_csrf();
        $action = (string) ($_POST['action'] ?? '');
        if ($action !== 'edit') {
            flash('Unknown action');
            redirect_to('/manage_users');
        }

        $userId = (int) ($_POST['user_id'] ?? 0);
        if ($userId === 0) {
            flash('Cannot edit guest user');
            redirect_to('/manage_users');
        }

        $targetUser = fetch_user_by_id($db, $userId);
        if (!$targetUser) {
            flash('User not found');
            redirect_to('/manage_users');
        }

        $label = trim((string) ($_POST['label'] ?? ''));
        if ($label === '') {
            flash('Label is required');
            redirect_to('/manage_users');
        }

        $authType = (string) ($targetUser['auth_type'] ?? '');
        if ($authType === 'pin') {
            $newPin = trim((string) ($_POST['pin'] ?? ''));
            if ($newPin !== '' && !ctype_digit($newPin)) {
                flash('PIN must be numeric');
                redirect_to('/manage_users');
            }

            if ($newPin === '') {
                $update = $db->prepare(
                    "UPDATE user
                     SET label = :label,
                         email = NULL,
                         auth_type = 'pin',
                         is_editor = 0
                     WHERE id = :id"
                );
                $update->execute([
                    ':label' => $label,
                    ':id' => $userId,
                ]);
            } else {
                $update = $db->prepare(
                    "UPDATE user
                     SET label = :label,
                         pin_hash = :pin_hash,
                         email = NULL,
                         auth_type = 'pin',
                         is_editor = 0
                     WHERE id = :id"
                );
                $update->execute([
                    ':label' => $label,
                    ':pin_hash' => hash_pin($newPin),
                    ':id' => $userId,
                ]);
            }
            flash('PIN user updated');
            redirect_to('/manage_users');
        }

        $email = normalize_email((string) ($_POST['email'] ?? ''));
        $name = trim((string) ($_POST['name'] ?? ''));
        $isEditor = !empty($_POST['is_editor']) ? 1 : 0;

        if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            flash('A valid email is required for OAuth users');
            redirect_to('/manage_users');
        }

        $dupeStmt = $db->prepare(
            "SELECT id FROM user
             WHERE id != :id AND lower(trim(coalesce(email, ''))) = :email
             LIMIT 1"
        );
        $dupeStmt->execute([
            ':id' => $userId,
            ':email' => $email,
        ]);
        if ($dupeStmt->fetch()) {
            flash('Email is already assigned to another user');
            redirect_to('/manage_users');
        }

        $update = $db->prepare(
            "UPDATE user
             SET label = :label,
                 email = :email,
                 name = :name,
                 is_editor = :is_editor,
                 pin_hash = NULL,
                 auth_type = 'oauth'
             WHERE id = :id"
        );
        $update->execute([
            ':label' => $label,
            ':email' => $email,
            ':name' => $name !== '' ? $name : $label,
            ':is_editor' => $isEditor,
            ':id' => $userId,
        ]);
        flash('OAuth user updated');
        redirect_to('/manage_users');
    }

    $users = $db->query(
        "SELECT id, label, email, name, is_editor,
                coalesce(nullif(auth_type, ''),
                    CASE
                        WHEN id = 0 THEN 'guest'
                        WHEN pin_hash IS NOT NULL THEN 'pin'
                        ELSE 'oauth'
                    END
                ) AS auth_type
         FROM user
         WHERE id != 0
         ORDER BY id"
    )->fetchAll();

    ob_start();
    ?>
<h2>Manage Users</h2>
<p class="hint">Google accounts use email-based login. Only one PIN account should remain.</p>

<?php foreach ($users as $managedUser): ?>
    <?php $isPinUser = ((string) $managedUser['auth_type']) === 'pin'; ?>
    <form method="post" class="stack-form" action="/manage_users">
        <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="action" value="edit">
        <input type="hidden" name="user_id" value="<?= (int) $managedUser['id'] ?>">
        <input type="text" name="label" value="<?= h((string) $managedUser['label']) ?>" required>

        <?php if ($isPinUser): ?>
            <input type="text" value="PIN account (no Google email)" readonly>
            <input type="password" name="pin" placeholder="Set new PIN (optional)">
        <?php else: ?>
            <input type="email" name="email" value="<?= h((string) ($managedUser['email'] ?? '')) ?>" required>
            <input type="text" name="name" value="<?= h((string) ($managedUser['name'] ?? '')) ?>" placeholder="Display name">
            <label>
                <input type="checkbox" name="is_editor" value="1" <?= (int) $managedUser['is_editor'] === 1 ? 'checked' : '' ?>>
                Editor
            </label>
        <?php endif; ?>

        <button type="submit" class="button">Update</button>
    </form>
<?php endforeach; ?>
<?php
    $content = ob_get_clean();
    layout($content, $currentUser, fetch_recent_entries_for_sidebar($db, $currentUser), 'Manage Users');
    exit;
}

// Route: /draft-save
if ($path === '/draft-save') {
    require_login();
    $currentUser = auth_current_user($db, $oauthIdentity, $adminEmail, $adminSessionTtlSeconds);
    require_editor($currentUser);
    if ($method !== 'POST') {
        http_response_code(405);
        echo 'Method not allowed';
        exit;
    }
    require_csrf();

    $draftKey = normalize_draft_key((string) ($_POST['draft_key'] ?? ''));
    if ($draftKey === null) {
        http_response_code(400);
        echo 'Invalid draft key';
        exit;
    }

    $title = trim((string) ($_POST['title'] ?? ''));
    $content = (string) ($_POST['content'] ?? '');
    $draftDate = trim((string) ($_POST['date'] ?? ''));
    $draftTime = trim((string) ($_POST['time'] ?? ''));
    $viewerIds = trim((string) ($_POST['viewer_ids'] ?? '0'));
    if ($viewerIds === '') {
        $viewerIds = '0';
    }

    $updatedAt = upsert_entry_draft(
        $db,
        (int) $currentUser['id'],
        $draftKey,
        $title,
        $content,
        $draftDate,
        $draftTime,
        $viewerIds,
        $storageTimeZone
    );
    header('Content-Type: application/json');
    echo json_encode(['ok' => true, 'updated_at' => $updatedAt]);
    exit;
}

// Route: /draft-discard
if ($path === '/draft-discard') {
    require_login();
    $currentUser = auth_current_user($db, $oauthIdentity, $adminEmail, $adminSessionTtlSeconds);
    require_editor($currentUser);
    if ($method !== 'POST') {
        http_response_code(405);
        echo 'Method not allowed';
        exit;
    }
    require_csrf();

    $draftKey = normalize_draft_key((string) ($_POST['draft_key'] ?? ''));
    if ($draftKey === null) {
        http_response_code(400);
        echo 'Invalid draft key';
        exit;
    }

    delete_entry_draft($db, (int) $currentUser['id'], $draftKey);
    header('Content-Type: application/json');
    echo json_encode(['ok' => true]);
    exit;
}

// Route: /add and /edit/{id}
if ($path === '/add' || preg_match('#^/edit/(\d+)$#', $path, $m)) {
    require_login();
    $currentUser = auth_current_user($db, $oauthIdentity, $adminEmail, $adminSessionTtlSeconds);
    require_editor($currentUser);

    $editing = $path !== '/add';
    $entryId = $editing ? (int) $m[1] : null;
    $draftKey = $editing ? ('edit:' . $entryId) : 'new';

    $entry = null;
    $currentViewerIds = [0];

    if ($editing) {
        $entryStmt = $db->prepare('SELECT id, title, content, created_at FROM entry WHERE id = :id LIMIT 1');
        $entryStmt->execute([':id' => $entryId]);
        $entry = $entryStmt->fetch();
        if (!$entry) {
            http_response_code(404);
            echo 'Entry not found';
            exit;
        }

        $viewerStmt = $db->prepare('SELECT user_id FROM entry_viewers WHERE entry_id = :entry_id ORDER BY user_id');
        $viewerStmt->execute([':entry_id' => $entryId]);
        $rows = $viewerStmt->fetchAll();
        $currentViewerIds = array_map(fn($row) => (int) $row['user_id'], $rows);
        if (!$currentViewerIds) {
            $currentViewerIds = [0];
        }
    }

    if ($method === 'POST') {
        require_csrf();
        $title = trim((string) ($_POST['title'] ?? ''));
        $rawContent = (string) ($_POST['content'] ?? '');
        $content = sanitize_html($rawContent);
        $createdAt = parse_datetime_or_now($_POST['date'] ?? null, $_POST['time'] ?? null, $appTimeZone, $storageTimeZone);
        $viewerIdsCsv = (string) ($_POST['viewer_ids'] ?? '0');
        $viewerIds = array_values(array_unique(array_map('intval', array_filter(explode(',', $viewerIdsCsv), 'strlen'))));
        if (!$viewerIds) {
            $viewerIds = [0];
        }

        $db->beginTransaction();
        try {
            if ($editing) {
                $update = $db->prepare('UPDATE entry SET title = :title, content = :content, created_at = :created_at WHERE id = :id');
                $update->execute([
                    ':title' => $title,
                    ':content' => $content,
                    ':created_at' => $createdAt,
                    ':id' => $entryId,
                ]);

                $clear = $db->prepare('DELETE FROM entry_viewers WHERE entry_id = :entry_id');
                $clear->execute([':entry_id' => $entryId]);
                $targetEntryId = $entryId;
            } else {
                $insert = $db->prepare('INSERT INTO entry (title, content, created_at) VALUES (:title, :content, :created_at)');
                $insert->execute([
                    ':title' => $title,
                    ':content' => $content,
                    ':created_at' => $createdAt,
                ]);
                $targetEntryId = (int) $db->lastInsertId();
            }

            $link = $db->prepare('INSERT OR IGNORE INTO entry_viewers (entry_id, user_id) VALUES (:entry_id, :user_id)');
            foreach ($viewerIds as $userId) {
                $userExistsStmt = $db->prepare('SELECT 1 FROM user WHERE id = :id LIMIT 1');
                $userExistsStmt->execute([':id' => $userId]);
                if ($userExistsStmt->fetch()) {
                    $link->execute([':entry_id' => $targetEntryId, ':user_id' => $userId]);
                }
            }

            $db->commit();
            delete_entry_draft($db, (int) $currentUser['id'], $draftKey);
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            flash('Failed to save entry');
            $redir = $editing ? '/edit/' . $entryId : '/add';
            redirect_to($redir);
        }

        redirect_to('/');
    }

    $users = $db->query('SELECT id, label FROM user WHERE id != 0 ORDER BY label')->fetchAll();
    $allUsers = $db->query('SELECT id, label FROM user ORDER BY id')->fetchAll();
    $userMap = [];
    foreach ($allUsers as $u) {
        $userMap[(int) $u['id']] = (string) $u['label'];
    }

    $entryDateTime = $editing
        ? parse_storage_datetime((string) $entry['created_at'], $storageTimeZone)->setTimezone($appTimeZone)
        : new DateTimeImmutable('now', $appTimeZone);
    $date = $entryDateTime->format('Y-m-d');
    $time = $entryDateTime->format('H:i');
    $entryContent = $editing ? (string) $entry['content'] : '';
    $entryTitle = $editing ? (string) $entry['title'] : '';
    $draft = fetch_entry_draft($db, (int) $currentUser['id'], $draftKey);
    $draftUpdatedAt = null;
    if ($draft) {
        $entryTitle = (string) ($draft['title'] ?? $entryTitle);
        $entryContent = (string) ($draft['content'] ?? $entryContent);

        $draftDate = trim((string) ($draft['draft_date'] ?? ''));
        if ($draftDate !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $draftDate)) {
            $date = $draftDate;
        }

        $draftTime = trim((string) ($draft['draft_time'] ?? ''));
        if ($draftTime !== '' && preg_match('/^\d{2}:\d{2}$/', $draftTime)) {
            $time = $draftTime;
        }

        $draftViewerIds = array_values(array_unique(array_map('intval', array_filter(explode(',', (string) ($draft['viewer_ids'] ?? '0')), 'strlen'))));
        if ($draftViewerIds) {
            $currentViewerIds = $draftViewerIds;
        }
        $rawDraftUpdatedAt = trim((string) ($draft['updated_at'] ?? ''));
        if ($rawDraftUpdatedAt !== '') {
            $draftUpdatedAt = parse_storage_datetime($rawDraftUpdatedAt, $storageTimeZone)
                ->setTimezone($appTimeZone)
                ->format('Y-m-d H:i:s T');
        }
    }

    ob_start();
    ?>
<h2><?= $editing ? 'Edit Entry' : 'New Entry' ?></h2>
<form method="post" action="<?= $editing ? '/edit/' . $entryId : '/add' ?>">
    <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
    <input type="hidden" name="draft_key" id="draft_key" value="<?= h($draftKey) ?>">
    <p class="hint" id="draft-status">
        <?php if ($draftUpdatedAt !== null): ?>
            Loaded saved draft from <?= h($draftUpdatedAt) ?>. Drafts auto-save every 15 seconds.
        <?php else: ?>
            Drafts auto-save every 15 seconds.
        <?php endif; ?>
    </p>
    <input type="text" name="title" id="title" placeholder="Entry Title" value="<?= h($entryTitle) ?>" required>

    <label for="date">Date:</label>
    <input type="date" name="date" id="date" value="<?= h($date) ?>" required>

    <label for="time">Time:</label>
    <input type="time" name="time" id="time" value="<?= h($time) ?>" required>

    <label for="editor-container">Content:</label>
    <div id="editor-container"></div>
    <input type="hidden" name="content" id="content">

    <label>Visibility:</label>
    <select id="viewerSelect">
        <option value="0">Guest</option>
        <?php foreach ($users as $user): ?>
            <option value="<?= (int) $user['id'] ?>"><?= h((string) $user['label']) ?></option>
        <?php endforeach; ?>
    </select>
    <button type="button" class="button" onclick="addViewer()">Add Viewer</button>

    <div id="viewersList">
        <?php foreach ($currentViewerIds as $uid): ?>
            <?php $label = $userMap[$uid] ?? ('User ' . $uid); ?>
            <span class="viewer" data-id="<?= (int) $uid ?>">
                <?= h($label) ?>
                <button type="button" class="button" onclick="removeViewer(this)">x</button>
            </span>
        <?php endforeach; ?>
    </div>
    <input type="hidden" name="viewer_ids" id="viewer_ids" value="<?= h(implode(',', $currentViewerIds)) ?>">

    <button type="button" class="button" id="discard-draft-btn">Discard Draft</button>
    <button type="submit" class="button">Save</button>
</form>

<script>
function addViewer() {
    const select = document.getElementById('viewerSelect');
    const selectedOption = select.options[select.selectedIndex];
    const viewerId = selectedOption.value;
    const viewerLabel = selectedOption.text;
    const viewersList = document.getElementById('viewersList');
    const existingRaw = document.getElementById('viewer_ids').value;
    const existingIds = existingRaw ? existingRaw.split(',').filter(Boolean) : [];

    if (!existingIds.includes(viewerId)) {
        const viewerSpan = document.createElement('span');
        viewerSpan.className = 'viewer';
        viewerSpan.setAttribute('data-id', viewerId);
        viewerSpan.innerHTML = `${viewerLabel} <button type="button" class="button" onclick="removeViewer(this)">x</button>`;
        viewersList.appendChild(viewerSpan);
        existingIds.push(viewerId);
        document.getElementById('viewer_ids').value = existingIds.join(',');
    }
}

function removeViewer(button) {
    const viewerSpan = button.parentElement;
    const viewerId = viewerSpan.getAttribute('data-id');
    const viewersList = document.getElementById('viewersList');
    const existingRaw = document.getElementById('viewer_ids').value;
    const existingIds = existingRaw ? existingRaw.split(',').filter(Boolean) : [];

    viewersList.removeChild(viewerSpan);
    const newIds = existingIds.filter((id) => id !== viewerId);
    document.getElementById('viewer_ids').value = newIds.join(',');
}

document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const draftStatus = document.getElementById('draft-status');
    const csrfToken = form.querySelector('input[name="csrf_token"]').value;
    const draftKey = document.getElementById('draft_key').value;
    let lastDraftPayload = '';

    const quill = new Quill('#editor-container', {
        theme: 'snow',
        placeholder: 'Write something...',
        modules: {
            toolbar: [
                [{ 'header': [1, 2, false] }],
                ['bold', 'italic', 'underline', 'strike'],
                [{ 'list': 'ordered' }, { 'list': 'bullet' }],
                ['blockquote', 'code-block'],
                ['link', 'image'],
                [{ 'align': [] }]
            ]
        }
    });
    quill.root.innerHTML = <?= json_encode($entryContent, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    function serializeDraft() {
        const params = new URLSearchParams();
        params.set('csrf_token', csrfToken);
        params.set('draft_key', draftKey);
        params.set('title', document.getElementById('title').value);
        params.set('content', quill.root.innerHTML);
        params.set('date', document.getElementById('date').value);
        params.set('time', document.getElementById('time').value);
        params.set('viewer_ids', document.getElementById('viewer_ids').value || '0');
        return params.toString();
    }

    async function saveDraft(force) {
        const payload = serializeDraft();
        if (!force && payload === lastDraftPayload) {
            return;
        }
        try {
            const res = await fetch('/draft-save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
                body: payload
            });
            if (!res.ok) {
                throw new Error('save failed');
            }
            lastDraftPayload = payload;
            draftStatus.textContent = 'Draft saved at ' + new Date().toLocaleTimeString();
        } catch (err) {
            draftStatus.textContent = 'Draft save failed. Your current text is still on this page.';
        }
    }

    form.addEventListener('submit', function() {
        document.querySelector('#content').value = quill.root.innerHTML;
        lastDraftPayload = '';
    });

    setInterval(function() {
        saveDraft(false);
    }, 15000);

    quill.on('text-change', function() {
        draftStatus.textContent = 'Saving draft...';
    });
    ['title', 'date', 'time', 'viewer_ids'].forEach(function(id) {
        document.getElementById(id).addEventListener('input', function() {
            draftStatus.textContent = 'Saving draft...';
        });
        document.getElementById(id).addEventListener('change', function() {
            draftStatus.textContent = 'Saving draft...';
        });
    });

    document.getElementById('discard-draft-btn').addEventListener('click', async function() {
        const body = new URLSearchParams();
        body.set('csrf_token', csrfToken);
        body.set('draft_key', draftKey);
        const res = await fetch('/draft-discard', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
            body: body.toString()
        });
        if (res.ok) {
            draftStatus.textContent = 'Draft discarded.';
            lastDraftPayload = '';
        } else {
            draftStatus.textContent = 'Could not discard draft.';
        }
    });
});
</script>
<?php
    $content = ob_get_clean();
    layout($content, $currentUser, fetch_recent_entries_for_sidebar($db, $currentUser), $editing ? 'Edit Entry' : 'New Entry');
    exit;
}

// Route: /delete/{id}
if (preg_match('#^/delete/(\d+)$#', $path, $m)) {
    require_login();
    $currentUser = auth_current_user($db, $oauthIdentity, $adminEmail, $adminSessionTtlSeconds);
    require_editor($currentUser);

    if ($method !== 'POST') {
        http_response_code(405);
        echo 'Method not allowed';
        exit;
    }

    require_csrf();
    $entryId = (int) $m[1];

    $db->beginTransaction();
    try {
        $delLinks = $db->prepare('DELETE FROM entry_viewers WHERE entry_id = :entry_id');
        $delLinks->execute([':entry_id' => $entryId]);
        $delEntry = $db->prepare('DELETE FROM entry WHERE id = :id');
        $delEntry->execute([':id' => $entryId]);
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        flash('Failed to delete entry');
    }
    redirect_to('/');
}

// Route: /
if ($path === '/') {
    $page = isset($_GET['page']) ? max(1, (int) $_GET['page']) : 1;
    $perPage = 10;
    $offset = ($page - 1) * $perPage;

    if ($currentUser && (int) $currentUser['is_editor'] === 1) {
        $countRow = $db->query('SELECT COUNT(*) AS c FROM entry')->fetch();
        $total = (int) $countRow['c'];

        $stmt = $db->prepare('SELECT id, title, content, created_at FROM entry ORDER BY datetime(created_at) DESC LIMIT :lim OFFSET :off');
        $stmt->bindValue(':lim', $perPage, PDO::PARAM_INT);
        $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $entries = $stmt->fetchAll();
    } elseif ($currentUser) {
        $countStmt = $db->prepare(
            'SELECT COUNT(DISTINCT e.id) AS c
             FROM entry e
             JOIN entry_viewers ev ON ev.entry_id = e.id
             WHERE ev.user_id = :uid OR ev.user_id = 0'
        );
        $countStmt->execute([':uid' => (int) $currentUser['id']]);
        $total = (int) $countStmt->fetch()['c'];

        $stmt = $db->prepare(
            'SELECT DISTINCT e.id, e.title, e.content, e.created_at
             FROM entry e
             JOIN entry_viewers ev ON ev.entry_id = e.id
             WHERE ev.user_id = :uid OR ev.user_id = 0
             ORDER BY datetime(e.created_at) DESC
             LIMIT :lim OFFSET :off'
        );
        $stmt->bindValue(':uid', (int) $currentUser['id'], PDO::PARAM_INT);
        $stmt->bindValue(':lim', $perPage, PDO::PARAM_INT);
        $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $entries = $stmt->fetchAll();
    } else {
        $countRow = $db->query(
            'SELECT COUNT(DISTINCT e.id) AS c
             FROM entry e
             JOIN entry_viewers ev ON ev.entry_id = e.id
             WHERE ev.user_id = 0'
        )->fetch();
        $total = (int) $countRow['c'];

        $stmt = $db->prepare(
            'SELECT DISTINCT e.id, e.title, e.content, e.created_at
             FROM entry e
             JOIN entry_viewers ev ON ev.entry_id = e.id
             WHERE ev.user_id = 0
             ORDER BY datetime(e.created_at) DESC
             LIMIT :lim OFFSET :off'
        );
        $stmt->bindValue(':lim', $perPage, PDO::PARAM_INT);
        $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $entries = $stmt->fetchAll();

        if (!$entries) {
            $next = urlencode(full_path_with_query());
            redirect_to('/login?next=' . $next);
        }
    }

    $entryIds = array_map(fn($e) => (int) $e['id'], $entries);
    $viewerMap = [];
    if ($entryIds) {
        $placeholders = implode(',', array_fill(0, count($entryIds), '?'));
        $viewerStmt = $db->prepare(
            "SELECT ev.entry_id, u.label
             FROM entry_viewers ev
             JOIN user u ON u.id = ev.user_id
             WHERE ev.entry_id IN ($placeholders)
             ORDER BY ev.entry_id, u.label"
        );
        foreach ($entryIds as $idx => $id) {
            $viewerStmt->bindValue($idx + 1, $id, PDO::PARAM_INT);
        }
        $viewerStmt->execute();
        foreach ($viewerStmt->fetchAll() as $row) {
            $eid = (int) $row['entry_id'];
            $viewerMap[$eid][] = (string) $row['label'];
        }
    }

    $hasPrev = $page > 1;
    $hasNext = ($offset + $perPage) < $total;

    ob_start();
    foreach ($entries as $entry):
        $eid = (int) $entry['id'];
        $title = (string) $entry['title'];
        $dt = parse_storage_datetime((string) $entry['created_at'], $storageTimeZone)->setTimezone($appTimeZone);
        $viewerLabels = $viewerMap[$eid] ?? [];
        ?>
    <div class="entry-card" id="entry-<?= $eid ?>">
        <h2 class="entry-title"><?= h($title) ?></h2>
        <div class="entry-meta">
            <?= h($dt->format('F d, Y \a\t H:i')) ?>
            <?php if ($currentUser && (int) $currentUser['is_editor'] === 1): ?>
                <a href="/edit/<?= $eid ?>" class="button">Edit</a>
                <form action="/delete/<?= $eid ?>" method="post" class="inline-form">
                    <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
                    <button type="submit" class="button">Delete</button>
                </form>
            <?php endif; ?>
        </div>
        <div class="entry-content"><?= $entry['content'] ?></div>
        <div class="entry-viewers">
            <strong>Viewers:</strong>
            <?= h(implode(', ', $viewerLabels)) ?>
        </div>
    </div>
    <?php endforeach; ?>

    <div class="pagination">
        <?php if ($hasPrev): ?>
            <a href="/?page=<?= $page - 1 ?>" class="button">Previous</a>
        <?php endif; ?>
        <?php if ($hasNext): ?>
            <a href="/?page=<?= $page + 1 ?>" class="button">Next</a>
        <?php endif; ?>
    </div>
<?php
    $content = ob_get_clean();
    layout($content, $currentUser, fetch_recent_entries_for_sidebar($db, $currentUser), 'Entries');
    exit;
}

http_response_code(404);
echo 'Not found';
