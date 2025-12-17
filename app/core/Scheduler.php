<?php
declare(strict_types=1);

class Scheduler {

    private ModuleLoader $loader;

    public function __construct() {
        $this->loader = new ModuleLoader();
    }

    public function run(): void {
        Logger::info('ThreatScope scheduler started');

        $moduleDefs = $this->loader->loadEnabledModules();
        $domains    = $this->loadDomains();
        
        foreach ($moduleDefs as $def) {
        
            // Convert snake_case to StudlyCaps class name
            $class = str_replace(' ', '', ucwords(str_replace('_', ' ', $def['name'])));
        
            if (!class_exists($class)) {
                Logger::error("Module class {$class} not found for module {$def['name']}");
                continue;
            }
        
            $module = new $class();
            $module->id = (int)$def['id'];
        
            if (!($module instanceof ModuleInterface)) {
                Logger::error("Module {$class} does not implement ModuleInterface");
                continue;
            }
        
            foreach ($domains as $domain) {
                $this->runModuleForDomain($module, $domain);
            }
        }
        
        

        Logger::info('ThreatScope scheduler finished');
    }

    /* ============================
       Core Execution
       ============================ */

    private function runModuleForDomain(ModuleInterface $module, array $domain): void {
        $pdo = DB::conn();

        $runId = $this->startRun($module, (int)$domain['id']);

        try {
            $result = $module->run($domain['domain']);
            $this->persistModuleResult(
                (int)$domain['id'],
                (int)$module->id,
                $result
            );

            $this->finishRun($runId, 'success');
        } catch (\Throwable $e) {
            $this->finishRun($runId, 'error', $e->getMessage());
            Logger::error("Module {$module->getName()} failed: {$e->getMessage()}");
        }
    }

    /* ============================
       Persistence
       ============================ */

    private function persistModuleResult(int $domainId, int $moduleId, array $result): void {
        $pdo = DB::conn();

        // ---- Observations ----
        foreach ($result['observations'] ?? [] as $obs) {
            $stmt = $pdo->prepare("
                INSERT INTO ts_observations (domain_id, module_id, key_name, value, observed_at)
                VALUES (:did, :mid, :k, :v, NOW())
            ");
            $stmt->execute([
                ':did' => $domainId,
                ':mid' => $moduleId,
                ':k'   => $obs['key'],
                ':v'   => $obs['value']
            ]);
        }

        // ---- Signals ----
        foreach ($result['signals'] ?? [] as $sig) {
            $this->upsertSignal(
                $domainId,
                $sig['name'],
                $sig['value']
            );
        }

        // ---- Derived Signal: favicon_hash_reused ----
        $this->handleFaviconReuse($domainId);

        // ---- Recalculate Risk ----
        $scorer = new ScoringEngine();
        $scorer->recalcDomain($domainId);
    }

    /* ============================
       Signal Handling (FIXES LIVE HERE)
       ============================ */

    private function upsertSignal(int $domainId, string $name, string $value): void {
        $pdo = DB::conn();

        // Does this signal already exist?
        $stmt = $pdo->prepare("
            SELECT first_seen_at
            FROM ts_signals
            WHERE domain_id = :did
              AND signal_name = :name
            LIMIT 1
        ");
        $stmt->execute([
            ':did'  => $domainId,
            ':name' => $name
        ]);

        $existing = $stmt->fetch();

        if ($existing) {
            // Update value + computed_at ONLY
            $upd = $pdo->prepare("
                UPDATE ts_signals
                SET signal_value = :val,
                    computed_at = NOW()
                WHERE domain_id = :did
                  AND signal_name = :name
            ");
            $upd->execute([
                ':val'  => $value,
                ':did'  => $domainId,
                ':name' => $name
            ]);
        } else {
            // Insert with first_seen_at
            $ins = $pdo->prepare("
                INSERT INTO ts_signals
                (domain_id, signal_name, signal_value, first_seen_at, computed_at)
                VALUES (:did, :name, :val, NOW(), NOW())
            ");
            $ins->execute([
                ':did'  => $domainId,
                ':name' => $name,
                ':val'  => $value
            ]);
        }
    }

    private function handleFaviconReuse(int $domainId): void {
        $pdo = DB::conn();

        // Get favicon hash for this domain
        $stmt = $pdo->prepare("
            SELECT value
            FROM ts_observations
            WHERE domain_id = :did
              AND key_name = 'favicon_hash_md5'
            ORDER BY observed_at DESC
            LIMIT 1
        ");
        $stmt->execute([':did' => $domainId]);
        $hash = $stmt->fetchColumn();

        if (!$hash) return;

        // Count other domains with same hash
        $stmt = $pdo->prepare("
            SELECT COUNT(DISTINCT domain_id)
            FROM ts_observations
            WHERE key_name = 'favicon_hash_md5'
              AND value = :hash
        ");
        $stmt->execute([':hash' => $hash]);
        $count = (int)$stmt->fetchColumn();

        if ($count <= 1) return;

        // Deduplicate derived signal
        if ($this->signalExists($domainId, 'favicon_hash_reused')) {
            return;
        }

        $pdo->prepare("
            INSERT INTO ts_signals
            (domain_id, signal_name, signal_value, first_seen_at, computed_at)
            VALUES (:did, 'favicon_hash_reused', 'true', NOW(), NOW())
        ")->execute([':did' => $domainId]);
    }

    private function signalExists(int $domainId, string $signal): bool {
        $stmt = DB::conn()->prepare("
            SELECT 1
            FROM ts_signals
            WHERE domain_id = :did
              AND signal_name = :sig
            LIMIT 1
        ");
        $stmt->execute([
            ':did' => $domainId,
            ':sig' => $signal
        ]);

        return (bool)$stmt->fetchColumn();
    }

    /* ============================
       Helpers
       ============================ */

    private function loadDomains(): array {
        return DB::conn()->query("
            SELECT id, domain
            FROM ts_domains
            WHERE status != 'ignored'
        ")->fetchAll();
    }

    private function startRun(ModuleInterface $module, int $domainId): int {
        $stmt = DB::conn()->prepare("
            INSERT INTO ts_runs (module_id, domain_id, started_at, status)
            VALUES (:mid, :did, NOW(), 'running')
        ");
        $stmt->execute([
            ':mid' => $module->id,
            ':did' => $domainId
        ]);

        return (int)DB::conn()->lastInsertId();
    }

    private function finishRun(int $runId, string $status, ?string $error = null): void {
        $stmt = DB::conn()->prepare("
            UPDATE ts_runs
            SET finished_at = NOW(),
                status = :st,
                error_message = :err
            WHERE id = :id
        ");
        $stmt->execute([
            ':st'  => $status,
            ':err' => $error,
            ':id'  => $runId
        ]);
    }
}
