<?php
declare(strict_types=1);

class DnsBasic implements ModuleInterface {
    public function getName(): string { return 'dns_basic'; }
    public function getVersion(): string { return '1.0.0'; }
    public function getRateLimit(): int { return 60; }

    public function run(string $domain): array {
        $domain = strtolower(trim($domain));
        $obs = [];
        $sig = [];

        // A / AAAA
        $a = @dns_get_record($domain, DNS_A);
        if (is_array($a)) {
            foreach ($a as $r) {
                if (!empty($r['ip'])) $obs[] = ['key' => 'dns_a', 'value' => $r['ip']];
            }
        }

        $aaaa = @dns_get_record($domain, DNS_AAAA);
        if (is_array($aaaa)) {
            foreach ($aaaa as $r) {
                if (!empty($r['ipv6'])) $obs[] = ['key' => 'dns_aaaa', 'value' => $r['ipv6']];
            }
        }

        // CNAME
        $cname = @dns_get_record($domain, DNS_CNAME);
        if (is_array($cname)) {
            foreach ($cname as $r) {
                if (!empty($r['target'])) $obs[] = ['key' => 'dns_cname', 'value' => $r['target']];
            }
        }

        // NS
        $ns = @dns_get_record($domain, DNS_NS);
        if (is_array($ns)) {
            foreach ($ns as $r) {
                if (!empty($r['target'])) $obs[] = ['key' => 'dns_ns', 'value' => $r['target']];
            }
        }

        $hasAny = !empty($obs);
        $sig[] = ['name' => 'has_dns', 'value' => $hasAny ? 'true' : 'false'];

        return ['observations' => $obs, 'signals' => $sig];
    }
}
