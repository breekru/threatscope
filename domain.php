<?php
declare(strict_types=1);

require_once __DIR__ . '/app/bootstrap.php';
require_once __DIR__ . '/auth/guard.php';
//require_once __DIR__ . '/partials/header.php';

// -------------------------
// Validate input
// -------------------------
$domainId = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($domainId <= 0) {
    http_response_code(400);
    echo "Invalid domain ID";
    exit;
}

// -------------------------
// Load domain
// -------------------------
$stmt = DB::conn()->prepare("
    SELECT id, domain, status, risk_score, importance, created_at
    FROM ts_domains
    WHERE id = ?
    LIMIT 1
");
$stmt->execute([$domainId]);
$domain = $stmt->fetch();

if (!$domain) {
    http_response_code(404);
    echo "Domain not found";
    exit;
}

// -------------------------
// Load signals
// -------------------------
$stmt = DB::conn()->prepare("
    SELECT signal_name, signal_value, first_seen_at
    FROM ts_signals
    WHERE domain_id = ?
    ORDER BY first_seen_at DESC
");
$stmt->execute([$domainId]);
$signals = $stmt->fetchAll();

// -------------------------
// Load observations (raw evidence)
// -------------------------
$stmt = DB::conn()->prepare("
    SELECT module, observation_key, observation_value, observed_at
    FROM ts_observations
    WHERE domain_id = ?
    ORDER BY observed_at DESC
    LIMIT 200
");
$stmt->execute([$domainId]);
$observations = $stmt->fetchAll();

// -------------------------
// Helper: human-readable signal names
// -------------------------
function humanSignal(string $name): string
{
    $map = [
        'whois_recent_registration'      => 'WHOIS: Recently Registered',
        'whois_privacy_enabled'          => 'WHOIS: Privacy Protection Enabled',
        'tls_self_signed'                => 'TLS: Self-Signed Certificate',
        'tls_hostname_mismatch'          => 'TLS: Hostname Mismatch',
        'tls_weak_key'                   => 'TLS: Weak Key Length',
        'mx_missing'                     => 'MX: No Mail Exchanger',
        'favicon_hash_reused'            => 'HTTP: Favicon Hash Reused',
        'http_login_brand_impersonation' => 'HTTP: Possible Brand Impersonation',
    ];

    return $map[$name] ?? $name;
}

// -------------------------
// Risk label
// -------------------------
function riskLabel(int $score): string
{
    if ($score >= 90) return 'CRITICAL';
    if ($score >= 70) return 'HIGH';
    if ($score >= 40) return 'MEDIUM';
    return 'LOW';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ThreatScope – Domain Detail</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #0f172a;
            color: #e5e7eb;
            margin: 0;
        }
        .container {
            padding: 20px;
        }
        h1 {
            margin-top: 0;
        }
        .meta {
            margin-bottom: 20px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            margin-right: 6px;
        }
        .risk-low { background: #064e3b; }
        .risk-medium { background: #92400e; }
        .risk-high { background: #7c2d12; }
        .risk-critical { background: #7f1d1d; }

        .section {
            margin-top: 30px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 8px;
            border-bottom: 1px solid #1e293b;
            text-align: left;
            vertical-align: top;
            font-size: 13px;
        }
        th {
            color: #94a3b8;
        }
        .back {
            margin-bottom: 15px;
            display: inline-block;
            color: #93c5fd;
            text-decoration: none;
        }
        .muted {
            color: #94a3b8;
        }
        .mono {
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-all;
        }
    </style>
</head>

<body>

<div class="container">

    <a class="back" href="/index.php">&larr; Back to Dashboard</a>

    <h1><?= htmlspecialchars($domain['domain']) ?></h1>

    <div class="meta">
        <?php
            $risk = riskLabel((int)$domain['risk_score']);
            $riskClass = strtolower($risk);
        ?>
        <span class="badge risk-<?= $riskClass ?>">
            Risk: <?= $risk ?> (<?= (int)$domain['risk_score'] ?>)
        </span>

        <span class="badge">
            Importance: <?= htmlspecialchars($domain['importance']) ?>
        </span>

        <span class="badge">
            Status: <?= htmlspecialchars($domain['status']) ?>
        </span>

        <div class="muted" style="margin-top:6px;">
            Added: <?= htmlspecialchars($domain['created_at']) ?> (UTC)
        </div>
    </div>

    <!-- Signals -->
    <div class="section">
        <h2>Signals</h2>

        <?php if (!$signals): ?>
            <div class="muted">No signals recorded for this domain.</div>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>Signal</th>
                        <th>Value</th>
                        <th>First Seen (UTC)</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($signals as $s): ?>
                    <tr>
                        <td><?= htmlspecialchars(humanSignal($s['signal_name'])) ?></td>
                        <td class="mono"><?= htmlspecialchars((string)$s['signal_value']) ?></td>
                        <td><?= htmlspecialchars($s['first_seen_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- Observations -->
    <div class="section">
        <h2>Observations (Raw Evidence)</h2>

        <?php if (!$observations): ?>
            <div class="muted">No observations recorded.</div>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>Time (UTC)</th>
                        <th>Module</th>
                        <th>Key</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($observations as $o): ?>
                    <tr>
                        <td><?= htmlspecialchars($o['observed_at']) ?></td>
                        <td><?= htmlspecialchars($o['module']) ?></td>
                        <td><?= htmlspecialchars($o['observation_key']) ?></td>
                        <td class="mono"><?= htmlspecialchars((string)$o['observation_value']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

</div>

</body>
</html>
