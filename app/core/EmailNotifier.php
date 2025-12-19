<?php
declare(strict_types=1);

final class EmailNotifier
{
    private array $cfg;

    public function __construct(array $appConfig)
    {
        $this->cfg = $appConfig['alerts']['email'] ?? [];
    }

    public function sendPending(): void
    {
        if (empty($this->cfg['enabled'])) {
            Logger::info("EmailNotifier: email disabled");
            return;
        }

        $toList = $this->cfg['to'] ?? [];
        if (!is_array($toList) || count($toList) === 0) {
            Logger::warning("EmailNotifier: no recipients configured");
            return;
        }

        $pdo = DB::conn();

        // Only HIGH/CRITICAL get emailed (noise control)
        $alerts = $pdo->query("
            SELECT a.id, a.domain_id, a.alert_type, a.alert_key, a.severity, a.message, a.created_at,
                   d.domain, d.risk_score
            FROM ts_alerts a
            JOIN ts_domains d ON d.id = a.domain_id
            WHERE a.sent_at IS NULL
              AND a.severity IN ('high','critical')
              AND d.status != 'ignored'
            ORDER BY a.created_at ASC
            LIMIT 200
        ")->fetchAll();

        foreach ($alerts as $a) {
            $subject = $this->buildSubject($a);
            $body    = $this->buildBody($a);

            $ok = $this->sendMail($toList, $subject, $body);

            if ($ok) {
                $stmt = $pdo->prepare("UPDATE ts_alerts SET sent_at = NOW() WHERE id = :id");
                $stmt->execute([':id' => (int)$a['id']]);
            } else {
                Logger::warning("EmailNotifier: failed to send alert_id=".(int)$a['id']);
                // Leave sent_at NULL so it retries next run
            }
        }

        JobState::touch('send-alerts');
        Logger::info("EmailNotifier: sendPending complete");
    }

    private function buildSubject(array $a): string
    {
        $prefix = (string)($this->cfg['subject_prefix'] ?? '[ThreatScope]');
        $sev = strtoupper((string)$a['severity']);
        $dom = (string)$a['domain'];
        return "{$prefix} {$sev} - {$dom} ({$a['alert_type']})";
    }

    private function buildBody(array $a): string
    {
        $lines = [];
        $lines[] = "ThreatScope Alert";
        $lines[] = "----------------";
        $lines[] = "Domain:      ".(string)$a['domain'];
        $lines[] = "Severity:    ".strtoupper((string)$a['severity']);
        $lines[] = "Alert Type:  ".(string)$a['alert_type'];
        $lines[] = "Alert Key:   ".(string)$a['alert_key'];
        $lines[] = "Risk Score:  ".(string)$a['risk_score'];
        $lines[] = "Created At:  ".(string)$a['created_at'];
        $lines[] = "";
        $lines[] = "Details:";
        $lines[] = (string)$a['message'];
        $lines[] = "";
        $lines[] = "Next Steps:";
        $lines[] = "- Review signals for this domain";
        $lines[] = "- Decide block / takedown / ignore";
        $lines[] = "";
        return implode("\n", $lines);
    }

    private function sendMail(array $toList, string $subject, string $body): bool
    {
        $to = implode(',', $toList);

        $from = (string)($this->cfg['from'] ?? 'threatscope@localhost');
        $headers = [];
        $headers[] = "From: {$from}";
        $headers[] = "MIME-Version: 1.0";
        $headers[] = "Content-Type: text/plain; charset=UTF-8";

        // Shared hosting friendly
        return @mail($to, $subject, $body, implode("\r\n", $headers));
    }
}
