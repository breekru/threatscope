<?php
declare(strict_types=1);

class TlsIntel implements ModuleInterface {
    public function getName(): string { return 'tls_intel'; }
    public function getVersion(): string { return '1.0.0'; }
    public function getRateLimit(): int { return 30; } // TLS handshakes are heavier than DNS

    public function run(string $domain): array {
        $domain = strtolower(trim($domain));
        $obs = [];
        $sig = [];

        // Defensive: only valid-ish hostnames
        if (!preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/', $domain)) {
            return [
                'observations' => [],
                'signals' => [['name' => 'tls_present', 'value' => 'false']]
            ];
        }

        $cert = $this->fetchPeerCertificate($domain, 443, 10);
        if (!$cert) {
            $sig[] = ['name' => 'tls_present', 'value' => 'false'];
            return ['observations' => $obs, 'signals' => $sig];
        }

        $sig[] = ['name' => 'tls_present', 'value' => 'true'];

        $parsed = @openssl_x509_parse($cert);
        if (!is_array($parsed)) {
            $obs[] = ['key' => 'tls_cert_parse', 'value' => 'failed'];
            return ['observations' => $obs, 'signals' => $sig];
        }

        // Subject / Issuer
        $subjectCN = $parsed['subject']['CN'] ?? null;
        $issuerCN  = $parsed['issuer']['CN'] ?? null;

        if ($subjectCN) $obs[] = ['key' => 'tls_subject_cn', 'value' => (string)$subjectCN];
        if ($issuerCN)  $obs[] = ['key' => 'tls_issuer_cn', 'value' => (string)$issuerCN];

        // Validity
        $notBeforeTs = $parsed['validFrom_time_t'] ?? null;
        $notAfterTs  = $parsed['validTo_time_t'] ?? null;

        if ($notBeforeTs) {
            $obs[] = ['key' => 'tls_not_before', 'value' => gmdate('c', (int)$notBeforeTs)];
            $ageDays = (int)floor((time() - (int)$notBeforeTs) / 86400);
            $obs[] = ['key' => 'tls_cert_age_days', 'value' => (string)$ageDays];

            // "Recently issued" is a strong brand-abuse indicator when combined with other signals
            if ($ageDays >= 0 && $ageDays <= 14) {
                $sig[] = ['name' => 'tls_recently_issued', 'value' => 'true'];
            }
        }

        if ($notAfterTs) {
            $obs[] = ['key' => 'tls_not_after', 'value' => gmdate('c', (int)$notAfterTs)];
        }

        // SANs
        $sans = $this->extractSANs($parsed);
        if (!empty($sans)) {
            $obs[] = ['key' => 'tls_sans', 'value' => implode(', ', $sans)];
            $obs[] = ['key' => 'tls_sans_count', 'value' => (string)count($sans)];
        }

        // Fingerprint SHA256
        $fp = $this->fingerprintSha256($cert);
        if ($fp) {
            $obs[] = ['key' => 'tls_fingerprint_sha256', 'value' => $fp];
        }

        return ['observations' => $obs, 'signals' => $sig];
    }

    private function fetchPeerCertificate(string $host, int $port, int $timeoutSec): mixed {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'SNI_enabled' => true,
                'peer_name' => $host,

                // For intel collection we do NOT need validation; validation failures are common on malicious infra.
                // You can later add a "tls_valid_chain" signal if you want to verify.
                'verify_peer' => false,
                'verify_peer_name' => false,

                // Avoid negotiation issues
                'disable_compression' => true,
            ]
        ]);

        $errno = 0; $errstr = '';
        $client = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errno,
            $errstr,
            $timeoutSec,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$client) {
            return null;
        }

        $params = stream_context_get_params($client);
        fclose($client);

        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        return $cert ?: null;
    }

    private function extractSANs(array $parsed): array {
        $sansRaw = $parsed['extensions']['subjectAltName'] ?? '';
        if (!$sansRaw || !is_string($sansRaw)) return [];

        // Example: "DNS:example.com, DNS:www.example.com"
        $parts = array_map('trim', explode(',', $sansRaw));
        $sans = [];

        foreach ($parts as $p) {
            if (stripos($p, 'DNS:') === 0) {
                $sans[] = strtolower(trim(substr($p, 4)));
            }
        }

        // De-dup
        $sans = array_values(array_unique(array_filter($sans)));
        return $sans;
    }

    private function fingerprintSha256($cert): ?string {
        // PHP 8+ usually has openssl_x509_fingerprint
        if (function_exists('openssl_x509_fingerprint')) {
            $fp = @openssl_x509_fingerprint($cert, 'sha256');
            return $fp ? strtolower((string)$fp) : null;
        }

        // Fallback: export PEM and hash it
        $pem = '';
        if (@openssl_x509_export($cert, $pem) && $pem) {
            return hash('sha256', $pem);
        }
        return null;
    }
}
