<?php
require_once __DIR__ . '/auth/guard.php';
require_once __DIR__ . '/partials/header.php';
//require __DIR__ . '/app/bootstrap.php';
$pdo = DB::conn();

function riskLabel(int $score): string {
  if ($score >= 70) return 'HIGH';
  if ($score >= 40) return 'MEDIUM';
  return 'LOW';
}


$domains = $pdo->query("
SELECT d.id, d.domain, d.status, d.risk_score,
       GROUP_CONCAT(CONCAT(ls.signal_name, '=', ls.signal_value) SEPARATOR ', ') AS signals
FROM ts_domains d
LEFT JOIN ts_latest_signals ls ON d.id = ls.domain_id
GROUP BY d.id
ORDER BY d.updated_at DESC
")->fetchAll();
?>

<!DOCTYPE html>
<html>
<head>
  <title>ThreatScope</title>
  <style>
    body { font-family: sans-serif; background:#0f172a; color:#e5e7eb; }
    table { width:100%; border-collapse: collapse; }
    th, td { padding:8px; border-bottom:1px solid #334155; }
    th { text-align:left; background:#020617; }
    tr:hover { background:#1e293b; }
    .badge { padding:2px 6px; border-radius:4px; background:#334155; }
  </style>
</head>
<body>
<h1>ThreatScope</h1>

<table>
<tr>
  <th>Domain</th>
  <th>Status</th>
  <th>Risk</th>
  <th>Signals</th>
</tr>
<?php foreach ($domains as $d): ?>
  <?php var_dump($d); ?>
  <tr onclick="window.location='/domain.php?id=<?= (int)$d['id'] ?>'" style="cursor:pointer;">

  <td><?= htmlspecialchars($d['domain']) ?></td>
  <td><span class="badge"><?= $d['status'] ?></span></td>
  <td>
  <?= (int)$d['risk_score'] ?>
  <span class="badge"><?= riskLabel((int)$d['risk_score']) ?></span>
</td>

  <td><?= htmlspecialchars($d['signals'] ?? '') ?></td>
</tr>
<?php endforeach; ?>
</table>

<hr>

<h3>Add Domain</h3>
<form method="post" action="add_domain.php">
  <input name="domain" placeholder="example.com" required>
  <button>Add</button>
</form>

</body>
</html>
