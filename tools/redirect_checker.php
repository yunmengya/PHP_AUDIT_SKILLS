<?php
/**
 * Redirect Checker - 开放重定向漏洞检测工具
 * 检测 HTTP 301/302 重定向中 Location 头的可控性，自动测试常见绕过 Payload
 *
 * Usage: php redirect_checker.php <target_url> [redirect_param] [cookie]
 *   <target_url>      - 目标 URL（含重定向参数的基础 URL）
 *   [redirect_param]  - 重定向参数名（默认: url）
 *   [cookie]          - 可选的 Cookie 值
 *
 * Example: php redirect_checker.php "http://target.com/login" "redirect" ""
 *
 * Output: JSON format test results
 */

class RedirectChecker {

    private string $targetUrl;
    private string $redirectParam;
    private string $cookie;
    private array $results = [];

    /** Common redirect parameter names to auto-detect */
    private array $commonParamNames = [
        'url', 'redirect', 'redirect_url', 'redirect_uri', 'return',
        'return_url', 'returnTo', 'next', 'next_url', 'goto', 'go',
        'target', 'dest', 'destination', 'redir', 'rurl', 'out',
        'continue', 'forward', 'ref', 'callback', 'path', 'to',
    ];

    /** Evil domain used for testing open redirect */
    private string $evilDomain = 'evil.com';

    public function __construct(string $targetUrl, string $redirectParam = 'url', string $cookie = '') {
        $this->targetUrl = rtrim($targetUrl, '/');
        $this->redirectParam = $redirectParam;
        $this->cookie = $cookie;
    }

    /**
     * Send a GET request and capture redirect info without following
     */
    private function sendRequest(string $url): array {
        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (audit)',
            ],
        ]);

        if ($this->cookie) {
            curl_setopt($ch, CURLOPT_COOKIE, $this->cookie);
        }

        $response = curl_exec($ch);
        if ($response === false) {
            $error = curl_error($ch);
            fwrite(STDERR, "[FATAL] curl request failed: {$error}\n");
            curl_close($ch);
            exit(1);
        }
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $responseHeaders = substr($response, 0, $headerSize);
        $responseBody = substr($response, $headerSize);
        $redirectUrl = curl_getinfo($ch, CURLINFO_REDIRECT_URL);

        curl_close($ch);

        // Extract Location header
        $location = '';
        if (preg_match('/^Location:\s*(.+)$/mi', $responseHeaders, $matches)) {
            $location = trim($matches[1]);
        }

        return [
            'status' => $httpCode,
            'headers' => $responseHeaders,
            'body' => $responseBody,
            'location' => $location,
            'redirect_url' => $redirectUrl,
            'is_redirect' => in_array($httpCode, [301, 302, 303, 307, 308]),
        ];
    }

    /**
     * Build test URL with redirect payload
     */
    private function buildTestUrl(string $payload): string {
        $separator = (strpos($this->targetUrl, '?') !== false) ? '&' : '?';
        return $this->targetUrl . $separator . $this->redirectParam . '=' . urlencode($payload);
    }

    /**
     * Check if a Location header points to the evil domain
     */
    private function isRedirectToEvil(string $location): bool {
        if (empty($location)) {
            return false;
        }

        $parsed = parse_url($location);
        if ($parsed === false) {
            // Try checking raw string
            return (stripos($location, $this->evilDomain) !== false);
        }

        $host = $parsed['host'] ?? '';
        return (
            $host === $this->evilDomain ||
            str_ends_with($host, '.' . $this->evilDomain) ||
            stripos($location, $this->evilDomain) !== false
        );
    }

    /**
     * Test baseline: normal redirect behavior
     */
    public function testBaseline(): array {
        $normalUrl = $this->buildTestUrl('https://www.google.com');
        $resp = $this->sendRequest($normalUrl);

        $result = [
            'test' => 'baseline',
            'url' => $normalUrl,
            'status' => $resp['status'],
            'location' => $resp['location'],
            'is_redirect' => $resp['is_redirect'],
            'description' => 'Baseline test with a normal URL to check redirect behavior',
        ];

        $this->results['baseline'] = $result;
        return $result;
    }

    /**
     * Test common open redirect bypass payloads
     */
    public function testBypassPayloads(): array {
        $evil = $this->evilDomain;

        $payloads = [
            // Protocol-relative URL
            '//' . $evil                           => 'protocol_relative',
            // Backslash variants
            '\\\\' . $evil                         => 'backslash_double',
            '/\\' . $evil                          => 'slash_backslash',
            // At-sign trick
            'http://target.com@' . $evil           => 'at_sign_authority',
            '@' . $evil                            => 'at_sign_bare',
            // Dot variants
            '////' . $evil                         => 'quadruple_slash',
            'http://' . $evil                      => 'direct_http',
            'https://' . $evil                     => 'direct_https',
            // CRLF injection in redirect
            '%0d%0aLocation:%20http://' . $evil    => 'crlf_injection',
            // URL encoding tricks
            'http://%65%76%69%6c%2e%63%6f%6d'      => 'url_encoded_domain',
            // Mixed scheme
            'HtTp://' . $evil                      => 'mixed_case_scheme',
            '///' . $evil                          => 'triple_slash',
            // JavaScript protocol (for meta/JS redirects)
            'javascript:alert(1)'                  => 'javascript_protocol',
            // Data URI
            'data:text/html,<h1>redirected</h1>'   => 'data_uri',
            // Null byte
            'http://' . $evil . '%00.target.com'   => 'null_byte',
            // Tab/newline in URL
            "http://\t" . $evil                    => 'tab_in_url',
            // Whitespace prefix
            ' http://' . $evil                     => 'whitespace_prefix',
            // Fragment trick
            '#@' . $evil                           => 'fragment_at',
            // Subdomain confusion
            $evil . '.target.com'                  => 'subdomain_prepend',
            // Dot-dot-slash to external
            '/../http://' . $evil                  => 'dotdot_external',
        ];

        $testResults = [];
        $vulnerableCount = 0;

        foreach ($payloads as $payload => $name) {
            $url = $this->buildTestUrl($payload);
            $resp = $this->sendRequest($url);

            $redirectsToEvil = $this->isRedirectToEvil($resp['location']);
            if ($redirectsToEvil) {
                $vulnerableCount++;
            }

            $testResults[] = [
                'name' => $name,
                'payload' => $payload,
                'response_status' => $resp['status'],
                'location_header' => $resp['location'],
                'is_redirect' => $resp['is_redirect'],
                'redirects_to_evil' => $redirectsToEvil,
                'vulnerable' => $redirectsToEvil && $resp['is_redirect'],
            ];
        }

        $result = [
            'test' => 'bypass_payloads',
            'total_payloads' => count($payloads),
            'vulnerable_count' => $vulnerableCount,
            'payloads' => $testResults,
        ];

        $this->results['bypass_payloads'] = $result;
        return $result;
    }

    /**
     * Auto-detect which redirect parameter names the target responds to
     */
    public function detectRedirectParams(): array {
        $detected = [];

        foreach ($this->commonParamNames as $param) {
            $separator = (strpos($this->targetUrl, '?') !== false) ? '&' : '?';
            $url = $this->targetUrl . $separator . $param . '=' . urlencode('https://www.google.com');
            $resp = $this->sendRequest($url);

            if ($resp['is_redirect'] && !empty($resp['location'])) {
                $detected[] = [
                    'param' => $param,
                    'status' => $resp['status'],
                    'location' => $resp['location'],
                    'reflects_input' => (stripos($resp['location'], 'google.com') !== false),
                ];
            }
        }

        $result = [
            'test' => 'param_detection',
            'params_tested' => count($this->commonParamNames),
            'params_with_redirect' => count($detected),
            'detected' => $detected,
        ];

        $this->results['param_detection'] = $result;
        return $result;
    }

    /**
     * Analyze all results
     */
    private function analyzeResults(): array {
        $vulnerablePayloads = [];
        if (isset($this->results['bypass_payloads']['payloads'])) {
            foreach ($this->results['bypass_payloads']['payloads'] as $p) {
                if (!empty($p['vulnerable'])) {
                    $vulnerablePayloads[] = $p['name'];
                }
            }
        }

        $assessment = 'safe';
        if (count($vulnerablePayloads) >= 3) {
            $assessment = 'highly_vulnerable';
        } elseif (count($vulnerablePayloads) >= 1) {
            $assessment = 'vulnerable';
        }

        return [
            'assessment' => $assessment,
            'vulnerable_payloads' => $vulnerablePayloads,
            'remediation' => [
                'Use an allowlist of permitted redirect domains',
                'Validate redirect URL starts with / for relative redirects only',
                'Never reflect user input directly into Location header',
                'Strip protocol-relative URLs (//), backslashes, and encoded variants',
            ],
        ];
    }

    /**
     * Run all redirect tests
     */
    public function runAllTests(): array {
        $this->testBaseline();
        $this->detectRedirectParams();
        $this->testBypassPayloads();

        $analysis = $this->analyzeResults();

        return [
            'target' => $this->targetUrl,
            'redirect_param' => $this->redirectParam,
            'tests' => $this->results,
            'analysis' => $analysis,
            'timestamp' => date('c'),
        ];
    }
}

// CLI entry
if (php_sapi_name() === 'cli') {
    if (!isset($argv[1])) {
        echo "Usage: php redirect_checker.php <target_url> [redirect_param] [cookie]\n";
        exit(1);
    }

    $targetUrl = $argv[1];
    $redirectParam = $argv[2] ?? 'url';
    $cookie = $argv[3] ?? '';

    $checker = new RedirectChecker($targetUrl, $redirectParam, $cookie);
    $results = $checker->runAllTests();

    echo json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
}
