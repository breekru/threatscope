<?php
declare(strict_types=1);

require_once __DIR__ . '/../app/bootstrap.php';

$token = $_GET['token'] ?? '';
$errors = [];
$success = false;

$stmt = DB::conn()->prepare("
    SELECT i.id AS invite_id, i.user_id, u.username
    FROM ts_user_invites i
    JOIN ts_users u ON u.id = i.user_id
    WHERE i.token = ?
      AND i.used_at IS NULL
      AND i.expires_at > UTC_TIMESTAMP()
    LIMIT 1
");
$stmt->execute([$token]);
$invite = $stmt->fetch();

if (!$invite) {
    echo "Invalid or expired password setup link.";
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pw = $_POST['password'] ?? '';
    $confirm = $_POST['confirm'] ?? '';

    if ($pw !== $confirm) {
        $errors[] = 'Passwords do not match.';
    }

    $policyErrors = PasswordPolicy::validate($pw);
    $errors = array_merge($errors, $policyErrors);

    if (!$errors) {
        DB::conn()->prepare("
            UPDATE ts_users
            SET password_hash = ?
            WHERE id = ?
        ")->execute([
            password_hash($pw, PASSWORD_DEFAULT),
            $invite['user_id']
        ]);

        DB::conn()->prepare("
            UPDATE ts_user_invites
            SET used_at = UTC_TIMESTAMP()
            WHERE id = ?
        ")->execute([$invite['invite_id']]);

        $success = true;
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Set Your Password</title>
    <style>
        body { font-family:sans-serif; background:#0f172a; color:#e5e7eb; padding:40px; }
        .box { max-width:400px; margin:auto; background:#020617; padding:20px; border-radius:8px; }
        input { width:100%; padding:8px; margin:6px 0; }
        button { width:100%; padding:8px; margin-top:10px; }
        .error { color:#f87171; font-size:13px; }
        .ok { color:#4ade80; }
    </style>
</head>
<body>

<div class="box">
<h2>Set Password for <?= htmlspecialchars($invite['username']) ?></h2>

<?php if ($success): ?>
    <div class="ok">
        Password set successfully.<br>
        <a href="/auth/login.php">Login</a>
    </div>
<?php else: ?>
    <?php foreach ($errors as $e): ?>
        <div class="error"><?= htmlspecialchars($e) ?></div>
    <?php endforeach; ?>

    <form method="post">
        <input type="password" name="password" placeholder="New password" required>
        <input type="password" name="confirm" placeholder="Confirm password" required>
        <button>Set Password</button>
    </form>

    <p style="font-size:12px;color:#94a3b8;">
        Password must be 10+ characters, with upper, lower, number, and special character.
    </p>
<?php endif; ?>
</div>

</body>
</html>
