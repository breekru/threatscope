<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_once __DIR__ . '/../auth/auth.php';

$lastRunUtc = SystemStatus::lastSchedulerRun();
?>
<div style="
    display:flex;
    justify-content:space-between;
    align-items:right;
    background:#020617;
    color:#e5e7eb;
    padding:10px 16px;
    border-bottom:1px solid #1e293b;
    font-size:14px;
">
    <div>
        <strong>ThreatScope</strong>
        <?php if ($lastRunUtc): ?>
            <span id="cron-time"
                  data-utc="<?= htmlspecialchars($lastRunUtc) ?>"
                  style="margin-left:12px;color:#94a3b8;">
                Last scan: converting…
            </span>
        <?php endif; ?>
    </div>

    <?php
        $stmt = DB::conn()->prepare("SELECT is_admin FROM ts_users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
            if ((int)$stmt->fetchColumn() === 1):
    ?>
            <a href="/admin/users.php" style="margin-left:10px;color:#93c5fd;">Admin</a>
    <?php endif; ?>


    <?php if (Auth::check()): ?>
        <a href="/auth/logout.php"
           style="color:#93c5fd;text-decoration:none;">
            Logout
        </a>
    <?php endif; ?>
</div>

<script>
(() => {
    const el = document.getElementById('cron-time');
    if (!el) return;

    const date = new Date(el.dataset.utc + ' UTC');


    if (!isNaN(date)) {
        el.textContent = 'Last scan: ' + date.toLocaleString();
    } else {
        el.textContent = 'Last scan: unknown';
    }
})();
</script>
