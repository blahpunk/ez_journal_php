<?php
declare(strict_types=1);

// Configuration
$databaseUrl = getenv('DATABASE_URL') ?: 'sqlite:////var/lib/ez_journal/journal.db';
$secretKey = getenv('SECRET_KEY') ?: 'change-me';
$adminPin = getenv('ADMIN_PIN') ?: '0000';
$logPath = getenv('LOG_PATH') ?: '/var/www/log/journal.log';
$tz = new DateTimeZone('America/Chicago');

// Secure session cookie settings
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
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

function init_schema(PDO $db, string $adminPin): void
{
    $db->exec(
        'CREATE TABLE IF NOT EXISTS login_lockout (
            ip TEXT PRIMARY KEY,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lockout_until TEXT,
            updated_at TEXT NOT NULL
        )'
    );

    $guest = $db->query('SELECT id FROM user WHERE id = 0')->fetch();
    if (!$guest) {
        $stmt = $db->prepare('INSERT INTO user (id, label, pin_hash, is_editor) VALUES (0, :label, NULL, 0)');
        $stmt->execute([':label' => 'Guest']);
    }

    $countStmt = $db->query('SELECT COUNT(*) AS c FROM user WHERE id != 0');
    $count = (int) $countStmt->fetch()['c'];
    if ($count === 0) {
        $hash = hash_pin($adminPin);
        $stmt = $db->prepare('INSERT INTO user (label, pin_hash, is_editor) VALUES (:label, :pin_hash, 1)');
        $stmt->execute([':label' => 'Admin', ':pin_hash' => $hash]);
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

function require_login(): void
{
    if (empty($_SESSION['user_id'])) {
        $next = urlencode(full_path_with_query());
        redirect_to('/login?next=' . $next);
    }
}

function require_editor(array $user): void
{
    if (empty($user['is_editor'])) {
        flash('Permission denied');
        redirect_to('/');
    }
}

function auth_current_user(PDO $db): ?array
{
    if (!isset($_SESSION['user_id'])) {
        return null;
    }

    $stmt = $db->prepare('SELECT id, label, pin_hash, is_editor FROM user WHERE id = :id LIMIT 1');
    $stmt->execute([':id' => (int) $_SESSION['user_id']]);
    $user = $stmt->fetch();
    return $user ?: null;
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
                <a href="/manage_pins">Manage Users</a>
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

function render_login(int $attemptsRemaining, ?string $suggestion, ?array $user, array $recentEntries): void
{
    ob_start();
    ?>
<h2>Login</h2>
<p class="hint">(Try date of birth in MMDDYYYY format)</p>
<?php if ($suggestion): ?>
    <p class="hint"><?= h($suggestion) ?></p>
<?php endif; ?>
<p class="hint">Attempts remaining: <?= $attemptsRemaining ?></p>
<form method="post" action="/login">
    <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
    <input type="password" name="pin" placeholder="Enter PIN" required>
    <button type="submit" class="button">Login</button>
</form>
<?php
    $content = ob_get_clean();
    layout($content, $user, $recentEntries, 'Login');
}

function parse_datetime_or_now(?string $date, ?string $time): string
{
    if (!$date || !$time) {
        return (new DateTimeImmutable())->format('Y-m-d H:i:s');
    }
    $dt = DateTimeImmutable::createFromFormat('Y-m-d H:i', $date . ' ' . $time);
    if (!$dt) {
        return (new DateTimeImmutable())->format('Y-m-d H:i:s');
    }
    return $dt->format('Y-m-d H:i:s');
}

$db = db_connect($databaseUrl);
init_schema($db, $adminPin);
$currentUser = auth_current_user($db);
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
    $ip = get_client_ip();

    $lockStmt = $db->prepare('SELECT failed_attempts, lockout_until FROM login_lockout WHERE ip = :ip LIMIT 1');
    $lockStmt->execute([':ip' => $ip]);
    $lock = $lockStmt->fetch();

    $attemptsRemaining = 3;
    $suggestion = null;

    if ($lock) {
        $failed = (int) $lock['failed_attempts'];
        $attemptsRemaining = max(0, 3 - $failed);
        if (!empty($lock['lockout_until'])) {
            $now = new DateTimeImmutable('now');
            $until = new DateTimeImmutable((string) $lock['lockout_until']);
            if ($now < $until) {
                if ($method === 'POST') {
                    require_csrf();
                }
                flash('Too many failed attempts. You are locked out until ' . $until->format('Y-m-d H:i:s') . '.');
                log_attempt($logPath, $tz, $ip, '(none)', 'lockout (active)');
                render_login(0, null, $currentUser, fetch_recent_entries_for_sidebar($db, $currentUser));
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

        $users = $db->query('SELECT id, label, pin_hash, is_editor FROM user WHERE pin_hash IS NOT NULL')->fetchAll();
        $matchUser = null;
        foreach ($users as $user) {
            if (verify_pin($pin, $user['pin_hash'])) {
                $matchUser = $user;
                break;
            }
        }

        if ($matchUser) {
            $_SESSION['user_id'] = (int) $matchUser['id'];
            $delStmt = $db->prepare('DELETE FROM login_lockout WHERE ip = :ip');
            $delStmt->execute([':ip' => $ip]);
            log_attempt($logPath, $tz, $ip, $pin, 'pass');

            $target = (string) ($_GET['next'] ?? '/');
            if ($target === '' || $target[0] !== '/') {
                $target = '/';
            }
            redirect_to($target);
        }

        $failedAttempts = ($lock ? (int) $lock['failed_attempts'] : 0) + 1;
        $attemptsRemaining = max(0, 3 - $failedAttempts);

        if ($failedAttempts >= 3) {
            $lockoutUntil = (new DateTimeImmutable('now'))->modify('+1 hour')->format(DateTimeInterface::ATOM);
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
                ':updated_at' => (new DateTimeImmutable('now'))->format(DateTimeInterface::ATOM),
            ]);
            flash('Too many failed attempts. You are locked out for 1 hour.');
            log_attempt($logPath, $tz, $ip, $pin, 'lockout');
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
                ':updated_at' => (new DateTimeImmutable('now'))->format(DateTimeInterface::ATOM),
            ]);
            flash('Invalid PIN. ' . $attemptsRemaining . ' attempt(s) remaining. (Try your date of birth)');
            $suggestion = 'Try your birthdate in MMDDYYYY format';
            log_attempt($logPath, $tz, $ip, $pin, 'fail');
        }
    }

    render_login($attemptsRemaining, $suggestion, $currentUser, fetch_recent_entries_for_sidebar($db, $currentUser));
    exit;
}

// Route: /logout
if ($path === '/logout') {
    require_login();
    unset($_SESSION['user_id']);
    redirect_to('/');
}

// Route: /logs
if ($path === '/logs') {
    require_login();
    $currentUser = auth_current_user($db);
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

// Route: /manage_pins
if ($path === '/manage_pins') {
    require_login();
    $currentUser = auth_current_user($db);
    require_editor($currentUser);

    if ($method === 'POST') {
        require_csrf();
        $action = (string) ($_POST['action'] ?? '');

        if ($action === 'add') {
            $label = trim((string) ($_POST['label'] ?? ''));
            $pin = trim((string) ($_POST['pin'] ?? ''));
            if ($label === '') {
                flash('Label is required');
            } elseif ($pin === '' || !ctype_digit($pin)) {
                flash('PIN must be numeric');
            } else {
                $stmt = $db->prepare('INSERT INTO user (label, pin_hash, is_editor) VALUES (:label, :pin_hash, 0)');
                $stmt->execute([
                    ':label' => $label,
                    ':pin_hash' => hash_pin($pin),
                ]);
                flash('PIN added');
            }
            redirect_to('/manage_pins');
        }

        if ($action === 'edit') {
            $userId = (int) ($_POST['user_id'] ?? 0);
            $label = trim((string) ($_POST['label'] ?? ''));
            $newPin = trim((string) ($_POST['pin'] ?? ''));

            if ($label === '') {
                flash('Label is required');
                redirect_to('/manage_pins');
            }

            $stmt = $db->prepare('SELECT id FROM user WHERE id = :id LIMIT 1');
            $stmt->execute([':id' => $userId]);
            $exists = $stmt->fetch();
            if (!$exists) {
                flash('User not found');
                redirect_to('/manage_pins');
            }

            if ($newPin !== '' && !ctype_digit($newPin)) {
                flash('PIN must be numeric');
                redirect_to('/manage_pins');
            }

            if ($newPin === '') {
                $update = $db->prepare('UPDATE user SET label = :label WHERE id = :id');
                $update->execute([':label' => $label, ':id' => $userId]);
            } else {
                $update = $db->prepare('UPDATE user SET label = :label, pin_hash = :pin_hash WHERE id = :id');
                $update->execute([
                    ':label' => $label,
                    ':pin_hash' => hash_pin($newPin),
                    ':id' => $userId,
                ]);
            }
            flash('PIN updated');
            redirect_to('/manage_pins');
        }

        if ($action === 'delete') {
            $userId = (int) ($_POST['user_id'] ?? 0);
            if ($userId === 0 || $userId === (int) $currentUser['id']) {
                flash('Cannot delete this user');
                redirect_to('/manage_pins');
            }

            $db->beginTransaction();
            try {
                $deleteLinks = $db->prepare('DELETE FROM entry_viewers WHERE user_id = :user_id');
                $deleteLinks->execute([':user_id' => $userId]);
                $deleteUser = $db->prepare('DELETE FROM user WHERE id = :id');
                $deleteUser->execute([':id' => $userId]);
                $db->commit();
                flash('PIN deleted');
            } catch (Throwable $e) {
                $db->rollBack();
                flash('Delete failed');
            }
            redirect_to('/manage_pins');
        }

        flash('Unknown action');
        redirect_to('/manage_pins');
    }

    $pins = $db->query('SELECT id, label FROM user WHERE id != 0 ORDER BY id')->fetchAll();

    ob_start();
    ?>
<h2>Manage Users</h2>

<h3>Add New PIN</h3>
<form method="post" action="/manage_pins">
    <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
    <input type="hidden" name="action" value="add">
    <input type="text" name="label" placeholder="Label" required>
    <input type="password" name="pin" placeholder="PIN" required>
    <button type="submit" class="button">Add</button>
</form>

<h3>Existing Users</h3>
<?php foreach ($pins as $pin): ?>
    <form method="post" class="stack-form" action="/manage_pins">
        <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
        <input type="hidden" name="action" value="edit">
        <input type="hidden" name="user_id" value="<?= (int) $pin['id'] ?>">
        <input type="text" name="label" value="<?= h((string) $pin['label']) ?>" required>
        <input type="password" name="pin" placeholder="New PIN">
        <button type="submit" class="button">Update</button>
        <?php if ((int) $pin['id'] !== (int) $currentUser['id'] && (int) $pin['id'] !== 0): ?>
            <button type="submit" name="action" value="delete" onclick="return confirm('Delete this user?')" class="button">Delete</button>
        <?php endif; ?>
    </form>
<?php endforeach; ?>
<?php
    $content = ob_get_clean();
    layout($content, $currentUser, fetch_recent_entries_for_sidebar($db, $currentUser), 'Manage Users');
    exit;
}

// Route: /add and /edit/{id}
if ($path === '/add' || preg_match('#^/edit/(\d+)$#', $path, $m)) {
    require_login();
    $currentUser = auth_current_user($db);
    require_editor($currentUser);

    $editing = $path !== '/add';
    $entryId = $editing ? (int) $m[1] : null;

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
        $createdAt = parse_datetime_or_now($_POST['date'] ?? null, $_POST['time'] ?? null);
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
        } catch (Throwable $e) {
            $db->rollBack();
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

    $date = $editing ? (new DateTimeImmutable((string) $entry['created_at']))->format('Y-m-d') : (new DateTimeImmutable())->format('Y-m-d');
    $time = $editing ? (new DateTimeImmutable((string) $entry['created_at']))->format('H:i') : (new DateTimeImmutable())->format('H:i');
    $entryContent = $editing ? (string) $entry['content'] : '';

    ob_start();
    ?>
<h2><?= $editing ? 'Edit Entry' : 'New Entry' ?></h2>
<form method="post" action="<?= $editing ? '/edit/' . $entryId : '/add' ?>">
    <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
    <input type="text" name="title" placeholder="Entry Title" value="<?= h($editing ? (string) $entry['title'] : '') ?>" required>

    <label for="date">Date:</label>
    <input type="date" name="date" value="<?= h($date) ?>" required>

    <label for="time">Time:</label>
    <input type="time" name="time" value="<?= h($time) ?>" required>

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
    document.querySelector('form').addEventListener('submit', function() {
        document.querySelector('#content').value = quill.root.innerHTML;
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
    $currentUser = auth_current_user($db);
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
        $db->rollBack();
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
        $dt = new DateTimeImmutable((string) $entry['created_at']);
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
