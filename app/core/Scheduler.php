<?php
declare(strict_types=1);

class Scheduler {
    private ModuleLoader $loader;

    public function __construct() {
        $this->loader = new ModuleLoader();
    }

    public function run(): void {
        Logger::info("ThreatScope scheduler started");

        $modules = $this->loader->loadEnabledModules();
        if (empty($modules)) {
            Logger::info("No enabled modules found. Exiting.");
            return;
        }

        foreach ($modules as $m) {
            $this->runModuleForBatch($m['db_id'], $m['object']);
        }

        Logger::info("ThreatScope scheduler finished");
    }

    private function runModuleForBatch(int $moduleDbId, ModuleInterface $module): void {
        $pdo = DB::conn();
        $moduleName = $module->getName();

        // Mark run start
        $runId = $this->createRun($moduleDbId);

        try {
            // Basic rate limit: max N domains per scheduler run for this module
            $limit = max(1, $module->getRateLimit());

            // Select domains. MVP policy:
            // - skip ignore/mitigated
            // - prioritize new/triage
            $stmt = $pdo->prepare("
                SELECT id, domain
                FROM ts_domains
                WHERE status IN ('new','triage','investigating')
                ORDER BY FIELD(status,'new','triage','investigating'), updated_at ASC
                LIMIT :lim
            ");
            $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
            $stmt->execute();
            $domains = $stmt->fetchAll();

            $processed = 0;
            foreach ($domains as $d) {
                $domainId = (int)$d['id'];
                $domain   = (string)$d['domain'];

                $result = $module->run($domain);

                $this->persistModuleResult($domainId, $moduleDbId, $result);

                // Touch last_seen
                $upd = $pdo->prepare("UPDATE ts_domains SET last_seen = NOW() WHERE id = :id");
                $upd->execute([':id' => $domainId]);

                $processed++;
            }

            $this->finishRun($runId, 'success', null);
            $this->touchModule($moduleDbId, null);

            Logger::info("Module {$moduleName} completed. Domains processed: {$processed}");
        } catch (Throwable $e) {
            $msg = $e->getMessage();
            $this->finishRun($runId, 'error', $msg);
            $this->touchModule($moduleDbId, $msg);

            Logger::error("Module {$moduleName} failed: {$msg}");
        }
    }

    private function createRun(int $moduleDbId): int {
        $pdo = DB::conn();
        $stmt = $pdo->prepare("INSERT INTO ts_runs (module_id, started_at, status) VALUES (:mid, NOW(), 'partial')");
        $stmt->execute([':mid' => $moduleDbId]);
        return (int)$pdo->lastInsertId();
    }

    private function finishRun(int $runId, string $status, ?string $error): void {
        $pdo = DB::conn();
        $stmt = $pdo->prepare("
            UPDATE ts_runs
            SET finished_at = NOW(), status = :st, error_message = :err
            WHERE id = :id
        ");
        $stmt->execute([
            ':st'  => $status,
            ':err' => $error,
            ':id'  => $runId
        ]);
    }

    private function touchModule(int $moduleDbId, ?string $error): void {
        $pdo = DB::conn();
        $stmt = $pdo->prepare("
            UPDATE ts_modules
            SET last_run = NOW(), last_error = :err
            WHERE id = :id
        ");
        $stmt->execute([
            ':err' => $error,
            ':id'  => $moduleDbId
        ]);
    }

    private function persistModuleResult(int $domainId, int $moduleId, array $result): void {
        $pdo = DB::conn();

        $observations = $result['observations'] ?? [];
        $signals      = $result['signals'] ?? [];

        // Observations are immutable: insert rows; do not update older rows.
        if (is_array($observations)) {
            $stmt = $pdo->prepare("
                INSERT INTO ts_observations (domain_id, module_id, key_name, value, observed_at)
                VALUES (:did, :mid, :k, :v, NOW())
            ");
            foreach ($observations as $o) {
                if (!isset($o['key'])) continue;
                $stmt->execute([
                    ':did' => $domainId,
                    ':mid' => $moduleId,
                    ':k'   => (string)$o['key'],
                    ':v'   => isset($o['value']) ? (string)$o['value'] : null,
                ]);
            }
        }

        // Signals are recomputable. MVP approach: store a new snapshot row each run.
        if (is_array($signals)) {
            $stmt = $pdo->prepare("
                INSERT INTO ts_signals (domain_id, signal_name, signal_value, computed_at)
                VALUES (:did, :n, :v, NOW())
            ");
            foreach ($signals as $s) {
                if (!isset($s['name'])) continue;
                $stmt->execute([
                    ':did' => $domainId,
                    ':n'   => (string)$s['name'],
                    ':v'   => isset($s['value']) ? (string)$s['value'] : null,
                ]);
            }
        }
        // Recalculate risk score after new signals
        $scorer = new ScoringEngine();
        $scorer->recalcDomain($domainId);

    }
}
