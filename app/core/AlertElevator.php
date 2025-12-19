<?php
declare(strict_types=1);

final class AlertEvaluator
{
    private array $cfg;

    public function __construct(array $appConfig)
    {
        $this->cfg = $appConfig['alerts'] ?? [];
    }

    public function evaluate(): void
    {
        if (empty($this->cfg['enabled'])) {
            Logger::info("AlertEvaluator: alerts disabled");
            return;
        }

        $pdo = DB::conn();

        $high     = (int)($this->cfg['high_threshold'] ?? 70);
        $critical = (int)($this->cfg['critical_threshold'] ?? 90);

        // ---- 1) Domain risk alerts (HIGH/CRITICAL) ----
        // Idempotent via alert_key: risk_high / risk_critical
        $stmt = $pdo->prepare("
            SELECT id, domain, risk_score
            FROM ts_domains
            WHERE status != 'ignored'
              AND risk_score >= :high
        ");
        $stmt->execute([':high' => $high]);
        $domains = $stmt->fetchAll();

        foreach ($domains as $d) {
            $did   = (int)$d['id'];
            $dom   = (string)$d['domain'];
            $score = (int)$d['risk_score'];

            if ($score >= $critical) {
                $this->insertAlertIfNew(
                    $did,
                    'domain_critical_risk',
                    'risk_critical',
                    'critical',
                    "Domain {$dom} reached CRITICAL risk score ({$score})."
                );
            } else {
                $this->insertAlertIfNew(
                    $did,
                    'domain_high_risk',
                    'risk_high',
                    'high',
                    "Domain {$dom} reached HIGH risk score ({$score})."
                );
            }
        }

        // ---- 2) New high-risk signals since last evaluation ----
        $job = 'evaluate-alerts';
        $last = JobState::getLastRun($job);

        // First run safety: look back 7 days max to avoid missing history,
        // but still prevents ancient alerts on first deploy.
        if (!$last) {
            $last = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
                ->sub(new DateInterval('P7D'))
                ->format('Y-m-d H:i:s');
        }

        $signals = $this->cfg['high_risk_signals'] ?? [];
        if (!is_array($signals) || count($signals) === 0) {
            Logger::info("AlertEvaluator: no high_risk_signals configured");
            JobState::touch($job);
            return;
        }

        // Build placeholders
        $in = implode(',', array_fill(0, count($signals), '?'));

        $q = "
            SELECT s.domain_id, s.signal_name, d.domain
            FROM ts_signals s
            JOIN ts_domains d ON d.id = s.domain_id
            WHERE d.status != 'ignored'
              AND s.first_seen_at > ?
              AND s.signal_name IN ($in)
        ";

        $params = array_merge([$last], $signals);
        $stmt = $pdo->prepare($q);
        $stmt->execute($params);
        $rows = $stmt->fetchAll();

        foreach ($rows as $r) {
            $did = (int)$r['domain_id'];
            $sig = (string)$r['signal_name'];
            $dom = (string)$r['domain'];

            $this->insertAlertIfNew(
                $did,
                'signal_high_risk',
                "signal_{$sig}",
                'high',
                "New high-risk signal first seen: {$sig} on {$dom}."
            );
        }

        JobState::touch($job);
        Logger::info("AlertEvaluator: evaluation complete");
    }

    private function insertAlertIfNew(
        int $domainId,
        string $type,
        string $key,
        string $severity,
        string $message
    ): void {
        try {
            $stmt = DB::conn()->prepare("
                INSERT INTO ts_alerts
                    (domain_id, alert_type, alert_key, severity, message, created_at)
                VALUES
                    (:did, :t, :k, :sev, :msg, NOW())
                ON DUPLICATE KEY UPDATE
                    id = id
            ");
            $stmt->execute([
                ':did' => $domainId,
                ':t'   => $type,
                ':k'   => $key,
                ':sev' => $severity,
                ':msg' => $message,
            ]);
        } catch (\Throwable $e) {
            // Never throw alerting errors into the scheduler pipeline
            Logger::warning("Alert insert ignored for domain {$domainId}/{$key}: ".$e->getMessage());
        }
    }
}
