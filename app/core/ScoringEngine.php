<?php
declare(strict_types=1);

class ScoringEngine {

    public function recalcDomain(int $domainId): void {
        $pdo = DB::conn();

        // Load active risk model
        $model = $pdo->query("
            SELECT version, config
            FROM ts_risk_models
            WHERE active = 1
            ORDER BY created_at DESC
            LIMIT 1
        ")->fetch();

        if (!$model) return;

        $config = json_decode($model['config'], true);
        if (!is_array($config)) return;

        // Get latest signals
        $stmt = $pdo->prepare("
            SELECT signal_name, signal_value
            FROM ts_latest_signals
            WHERE domain_id = :did
        ");
        $stmt->execute([':did' => $domainId]);
        $signals = $stmt->fetchAll();

        $score = 0;
        foreach ($signals as $s) {
            $name = $s['signal_name'];
            $val  = strtolower((string)$s['signal_value']);

            if ($val === 'true' && isset($config['signals'][$name])) {
                $score += (int)$config['signals'][$name];
            }
        }

        // Persist score
        $upd = $pdo->prepare("
            UPDATE ts_domains
            SET risk_score = :rs, risk_version = :rv, updated_at = NOW()
            WHERE id = :id
        ");
        $upd->execute([
            ':rs' => $score,
            ':rv' => $model['version'],
            ':id' => $domainId
        ]);
    }
}
