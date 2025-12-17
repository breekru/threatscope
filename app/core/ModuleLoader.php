<?php
declare(strict_types=1);

class ModuleLoader {
    /**
     * Loads enabled modules from DB and instantiates module classes from app/modules/<name>/...
     * Convention:
     *  - module name: dns_basic
     *  - class file:  app/modules/dns_basic/DnsBasic.php
     *  - class name:  DnsBasic
     */
    public function loadEnabledModules(): array {
        $pdo = DB::conn();
        $rows = $pdo->query("SELECT id, name, version, enabled, rate_limit FROM ts_modules WHERE enabled = 1")->fetchAll();

        $modules = [];
        foreach ($rows as $r) {
            $name = $r['name'];
            $className = $this->classFromModuleName($name);
            $filePath  = __DIR__ . '/../modules/' . $name . '/' . $className . '.php';

            if (!file_exists($filePath)) {
                Logger::error("Module enabled in DB but file not found: {$name} -> {$filePath}");
                continue;
            }

            require_once $filePath;

            if (!class_exists($className)) {
                Logger::error("Module class not found after require: {$name} -> {$className}");
                continue;
            }

            $obj = new $className();

            if (!($obj instanceof ModuleInterface)) {
                Logger::error("Module does not implement ModuleInterface: {$name}");
                continue;
            }

            // Allow DB to override rate_limit if set (otherwise module default)
            if (!empty($r['rate_limit']) && (int)$r['rate_limit'] > 0) {
                $obj = $this->wrapRateLimitOverride($obj, (int)$r['rate_limit']);
            }

            $modules[] = [
                'db_id'  => (int)$r['id'],
                'name'   => $name,
                'object' => $obj,
            ];
        }

        return $modules;
    }

    private function classFromModuleName(string $moduleName): string {
        // dns_basic -> DnsBasic
        $parts = explode('_', $moduleName);
        $parts = array_map(fn($p) => ucfirst(strtolower($p)), $parts);
        return implode('', $parts);
    }

    private function wrapRateLimitOverride(ModuleInterface $module, int $rateLimit): ModuleInterface {
        // Simple anonymous wrapper
        return new class($module, $rateLimit) implements ModuleInterface {
            private ModuleInterface $inner;
            private int $rateLimit;
            public function __construct(ModuleInterface $inner, int $rateLimit) {
                $this->inner = $inner;
                $this->rateLimit = $rateLimit;
            }
            public function getName(): string { return $this->inner->getName(); }
            public function getVersion(): string { return $this->inner->getVersion(); }
            public function getRateLimit(): int { return $this->rateLimit; }
            public function run(string $domain): array { return $this->inner->run($domain); }
        };
    }
}
