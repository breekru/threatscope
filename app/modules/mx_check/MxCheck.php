<?php
declare(strict_types=1);

class MxCheck implements ModuleInterface {
    public function getName(): string { return 'mx_check'; }
    public function getVersion(): string { return '1.0.0'; }
    public function getRateLimit(): int { return 60; }

    public function run(string $domain): array {
        $domain = strtolower(trim($domain));
        $obs = [];
        $sig = [];

        $mxHosts = [];
        $mxWeights = [];

        $hasMx = @getmxrr($domain, $mxHosts, $mxWeights);

        if ($hasMx && is_array($mxHosts)) {
            foreach ($mxHosts as $i => $host) {
                $w = is_array($mxWeights) && isset($mxWeights[$i]) ? (string)$mxWeights[$i] : '';
                $obs[] = ['key' => 'mx_host', 'value' => $host];
                if ($w !== '') $obs[] = ['key' => 'mx_weight', 'value' => $w];
            }
        }

        $sig[] = ['name' => 'has_mx', 'value' => $hasMx ? 'true' : 'false'];

        // Light provider hint (optional)
        if ($hasMx) {
            $provider = $this->guessProvider($mxHosts);
            if ($provider) {
                $obs[] = ['key' => 'mx_provider_guess', 'value' => $provider];
                $sig[] = ['name' => 'mx_provider', 'value' => $provider];
            }
        }

        return ['observations' => $obs, 'signals' => $sig];
    }

    private function guessProvider(array $mxHosts): ?string {
        $joined = strtolower(implode(' ', $mxHosts));
        if (strpos($joined, 'google.com') !== false || strpos($joined, 'googlemail.com') !== false) return 'google';
        if (strpos($joined, 'outlook.com') !== false || strpos($joined, 'protection.outlook.com') !== false) return 'microsoft';
        if (strpos($joined, 'pphosted.com') !== false) return 'proofpoint';
        if (strpos($joined, 'mimecast.com') !== false) return 'mimecast';
        return null;
    }
}
