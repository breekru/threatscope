<?php
declare(strict_types=1);

class WhoisBasic implements ModuleInterface {
    public function getName(): string { return 'whois_basic'; }
    public function getVersion(): string { return '1.1.0'; }

    // Keep conservative
    public function getRateLimit(): int { return 10; }

    public function run(string $domain): array {
        $domain = strtolower(trim($domain));
        $obs = [];
        $sig = [];

        // Use IANA bootstrap to find RDAP server
        $rdapUrl = $this->discoverRdapEndpoint($domain);
        if (!$rdapUrl) {
            return [
                'observations' => [],
                'signals' => [['name' => 'whois_available', 'value' => 'false']]
            ];
        }

        $json = $this->httpGetJson($rdapUrl);
        if (!$json) {
            return [
                'observations' => [],
                'signals' => [['name' => 'whois_available', 'value' => 'false']]
            ];
        }

        $obs[] = ['key' => 'rdap_source', 'value' => $rdapUrl];
        $sig[] = ['name' => 'whois_available', 'value' => 'true'];

        // Registrar
        if (!empty($json['registrar']['name'])) {
            $obs[] = ['key' => 'registrar', 'value' => $json['registrar']['name']];
        }

        // Events (creation date)
        if (!empty($json['events']) && is_array($json['events'])) {
            foreach ($json['events'] as $e) {
                if (($e['eventAction'] ?? '') === 'registration' && !empty($e['eventDate'])) {
                    $obs[] = ['key' => 'domain_created', 'value' => $e['eventDate']];

                    $ts = strtotime($e['eventDate']);
                    if ($ts) {
                        $ageDays = (int)floor((time() - $ts) / 86400);
                        $obs[] = ['key' => 'domain_age_days', 'value' => (string)$ageDays];

                        if ($ageDays <= 30) {
                            $sig[] = ['name' => 'new_domain', 'value' => 'true'];
                        }
                    }
                }
            }
        }

        return ['observations' => $obs, 'signals' => $sig];
    }

    private function discoverRdapEndpoint(string $domain): ?string {
        // Basic TLD extraction
        $parts = explode('.', $domain);
        if (count($parts) < 2) return null;
        $tld = '.' . end($parts);

        // Minimal static map (expand later if needed)
        $map = [
            '.com' => 'https://rdap.verisign.com/com/v1/domain/',
            '.net' => 'https://rdap.verisign.com/net/v1/domain/',
            '.org' => 'https://rdap.publicinterestregistry.org/rdap/domain/',
            '.info' => 'https://rdap.afilias.net/rdap/domain/',
        ];

        if (!isset($map[$tld])) return null;
        return $map[$tld] . $domain;
    }

    private function httpGetJson(string $url): ?array {
        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 10,
                'header'  => "Accept: application/json\r\nUser-Agent: ThreatScope/1.0\r\n"
            ]
        ]);

        $raw = @file_get_contents($url, false, $ctx);
        if (!$raw) return null;

        $json = json_decode($raw, true);
        return is_array($json) ? $json : null;
    }
}
