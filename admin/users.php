<?php
declare(strict_types=1);

require_once __DIR__ . '/../auth/admin_guard.php';

$pdo = DB::conn();
$message = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'invite') {
    $userId = (int)$_POST['user_id'];

    $token = bin2hex(random_bytes(32));
    $expires = (new DateTimeImmutable('+24 hours', new DateTimeZone('UTC')))
        ->format('Y-m-d H:i:s');

    $pdo->prepare("
        INSERT INTO ts_user_invites (user_id, token, expires_at)
        VALUES (?, ?, ?)
    ")->execute([$userId, $token, $expires]);

    $inviteLink = sprintf(
        'https://%s/auth/set_password.php?token=%s',
        $_SERVER['HTTP_HOST'],
        $token
    );

    $message = "Password setup link (expires in 24h): <br><code>{$inviteLink}</code>";
}


// -----------------------------
// Handle create user
// -----------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username && $password) {
        $hash = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $pdo->prepare("
            INSERT INTO ts_users (username, password_hash, enabled)
            VALUES (?, ?, 1)
        ");
        try {
            $stmt->execute([$username, $hash]);
            $message = "User '{$username}' created.";
        } catch (PDOException $e) {
            $message = "Error creating user (username may already exist).";
        }
    }
}

// -----------------------------
// Handle password reset
// -----------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'reset') {
    $userId = (int)$_POST['user_id'];
    $password = $_POST['password'] ?? '';

    if ($userId && $password) {
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $pdo->prepare("
            UPDATE ts_users
            SET password_hash = ?
            WHERE id = ?
        ")->execute([$hash, $userId]);

        $message = "Password updated.";
    }
}

// -----------------------------
// Handle enable/disable
// -----------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'toggle') {
    $userId = (int)$_POST['user_id'];
    $pdo->prepare("
        UPDATE ts_users
        SET enabled = IF(enabled = 1, 0, 1)
        WHERE id = ?
    ")->execute([$userId]);

    $message = "User status updated.";
}

// -----------------------------
// Load users
// -----------------------------
$users = $pdo->query("
    SELECT id, username, enabled, is_admin, last_login, created_at
    FROM ts_users
    ORDER BY created_at ASC
")->fetchAll();
?>

<!DOCTYPE html>
<html>
<head>
    <title>ThreatScope – User Admin</title>
    <style>
        body { font-family: sans-serif; background:#0f172a; color:#e5e7eb; padding:20px; }
        table { width:100%; border-collapse: collapse; margin-top:20px; }
        th, td { padding:8px; border-bottom:1px solid #334155; }
        th { text-align:left; background:#020617; }
        .badge { padding:2px 6px; border-radius:4px; background:#334155; font-size:12px; }
        .btn { padding:4px 8px; }
        input { padding:6px; }
        form.inline { display:inline; }
        .msg { margin:10px 0; color:#93c5fd; }
    </style>
</head>
<body>

<h1>User Administration</h1>
<a href="/index.php">&larr; Back to Dashboard</a>

<?php if ($message): ?>
    <div class="msg"><?= $message ?></div>
<?php endif; ?>


<h3>Create User</h3>
<form method="post">
    <input type="hidden" name="action" value="create">
    <input name="username" placeholder="username" required>
    <input name="password" type="password" placeholder="password" required>
    <button class="btn">Create</button>
</form>

<h3>Existing Users</h3>
<table>
<tr>
    <th>User</th>
    <th>Status</th>
    <th>Admin</th>
    <th>Last Login</th>
    <th>Actions</th>
</tr>

<?php foreach ($users as $u): ?>
<tr>
    <td><?= htmlspecialchars($u['username']) ?></td>
    <td>
        <span class="badge"><?= $u['enabled'] ? 'Enabled' : 'Disabled' ?></span>
    </td>
    <td><?= $u['is_admin'] ? 'Yes' : 'No' ?></td>
    <td><?= htmlspecialchars($u['last_login'] ?? '-') ?></td>
    <td>
        <form method="post" class="inline">
            <input type="hidden" name="action" value="toggle">
            <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
            <button class="btn"><?= $u['enabled'] ? 'Disable' : 'Enable' ?></button>
        </form>

        <form method="post" class="inline">
            <input type="hidden" name="action" value="reset">
            <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
            <input type="password" name="password" placeholder="new password" required>
            <button class="btn">Reset</button>
        </form>
    </td>
</tr>
<?php endforeach; ?>
</table>
<h3>Generate Password Setup Link</h3>

<form method="post">
    <input type="hidden" name="action" value="invite">
    <select name="user_id" required>
        <?php foreach ($users as $u): ?>
            <?php if ($u['enabled']): ?>
                <option value="<?= (int)$u['id'] ?>">
                    <?= htmlspecialchars($u['username']) ?>
                </option>
            <?php endif; ?>
        <?php endforeach; ?>
    </select>
    <button class="btn">Generate Link</button>
</form>

</body>
</html>
