<?php
declare(strict_types=1);

class WhoisBasic implements ModuleInterface {
    public function getName(): string { return 'whois_basic'; }
    public function getVersion(): string { return '1.0.0'; }

    // Keep this low — WHOIS rate limits are real
    public function getRateLimit(): int { return 10; }

    public function run(string $domain): array {
        $domain = strtolower(trim($domain));
        $obs = [];
        $sig = [];

        // Run whois via shell (most reliable on shared hosting)
        $cmd = escapeshellcmd("whois {$domain}");
        $output = @shell_exec($cmd);

        if (!$output) {
            return [
                'observations' => [],
                'signals' => [['name' => 'whois_available', 'value' => 'false']]
            ];
        }

        // Store raw WHOIS (truncated for sanity)
        $obs[] = ['key' => 'whois_raw', 'value' => substr($output, 0, 8000)];
        $sig[] = ['name' => 'whois_available', 'value' => 'true'];

        // Parse creation date
        if (preg_match('/Creation Date:\s*(.+)/i', $output, $m) ||
            preg_match('/Created On:\s*(.+)/i', $output, $m)) {

            $dateStr = trim($m[1]);
            $obs[] = ['key' => 'domain_created', 'value' => $dateStr];

            $createdTs = strtotime($dateStr);
            if ($createdTs) {
                $ageDays = (int)floor((time() - $createdTs) / 86400);
                $obs[] = ['key' => 'domain_age_days', 'value' => (string)$ageDays];

                if ($ageDays <= 30) {
                    $sig[] = ['name' => 'new_domain', 'value' => 'true'];
                }
            }
        }

        // Parse registrar
        if (preg_match('/Registrar:\s*(.+)/i', $output, $m)) {
            $obs[] = ['key' => 'registrar', 'value' => trim($m[1])];
        }

        return ['observations' => $obs, 'signals' => $sig];
    }
}
