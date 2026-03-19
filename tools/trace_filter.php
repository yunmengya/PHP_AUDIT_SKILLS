<?php
/**
 * Xdebug Trace 精简过滤器
 * 读取 Xdebug Trace 文件（格式 1: 机器可读），按 Sink 函数名过滤调用栈
 *
 * 用法: php trace_filter.php <trace_file> [sink_function1,sink_function2,...]
 * 输出: JSON 格式的精简调用链到 stdout
 *
 * 功能:
 *   - 按 Sink 函数名过滤调用栈
 *   - 保留从入口到 Sink 的完整调用路径
 *   - 丢弃无关的框架引导代码
 *   - > 10MB 自动精简到 500 行
 */

// ============================================================
// Sink 函数列表（与 sink_definitions.md 保持一致）
// ============================================================

$DEFAULT_SINKS = [
    // RCE
    'eval', 'assert', 'preg_replace', 'create_function',
    'system', 'exec', 'passthru', 'shell_exec', 'popen', 'proc_open', 'pcntl_exec',
    'call_user_func', 'call_user_func_array', 'array_map', 'array_filter',
    'usort', 'uasort', 'uksort', 'array_walk',
    'extract', 'parse_str', 'mb_parse_str',
    // SQLi
    'mysql_query', 'pg_query', 'sqlite_query',
    'query', 'exec', 'multi_query',
    'raw', 'whereRaw', 'havingRaw', 'orderByRaw', 'selectRaw', 'groupByRaw',
    'findBySql',
    // LFI
    'include', 'include_once', 'require', 'require_once',
    'highlight_file', 'show_source', 'file_get_contents', 'readfile', 'fread', 'file', 'fpassthru',
    // FileWrite
    'file_put_contents', 'fwrite', 'fputs', 'move_uploaded_file', 'copy', 'rename',
    'extractTo',
    // Deserialization
    'unserialize',
    // SSRF
    'curl_exec', 'curl_multi_exec', 'get_headers', 'getimagesize',
    // XXE
    'simplexml_load_string', 'simplexml_load_file', 'loadXML',
    // XSS
    'echo', 'print',
    // GraphQL resolver chain
    'resolve', 'resolveField', 'resolveType', 'resolveRootValue',
    'GraphQL\\Executor\\Executor::execute',
    'GraphQL\\Type\\Definition\\ResolveInfo',
];

// 框架引导噪声函数（过滤掉）
$NOISE_PATTERNS = [
    // Composer / Autoload
    'Composer\\Autoload\\',
    'spl_autoload_call',
    '__autoload',
    'spl_autoload_register',
    // Laravel
    'Illuminate\\Foundation\\Bootstrap\\',
    'Illuminate\\Container\\Container::',
    // Symfony
    'Symfony\\Component\\HttpKernel\\',
    'Symfony\\Component\\DependencyInjection\\',
    'Symfony\\Bundle\\FrameworkBundle\\',
    // ThinkPHP
    'think\\App::',
    'think\\Container::',
    // Yii
    'yii\\base\\Application::bootstrap',
    // WordPress
    'wp-settings.php',
    'wp-includes/plugin.php',
    'wp-includes/class-wp-hook.php',
    'wp-load.php',
    // CakePHP
    'Cake\\Http\\Server',
    'Cake\\Routing\\Router',
    'Cake\\Controller\\Controller',
    // CodeIgniter
    'CodeIgniter\\CodeIgniter',
    'CodeIgniter\\HTTP\\IncomingRequest',
    // Generic noise
    'class_exists',
    'is_file',
    'file_exists',
];

// ============================================================
// Trace 解析器
// ============================================================

class TraceParser
{
    private array $sinkFunctions;
    private array $noisePatterns;
    private int $maxOutputLines;

    public function __construct(array $sinkFunctions, array $noisePatterns, int $maxOutputLines = 500)
    {
        $this->sinkFunctions = array_map('strtolower', $sinkFunctions);
        $this->noisePatterns = $noisePatterns;
        $this->maxOutputLines = $maxOutputLines;
    }

    /**
     * 解析 Xdebug Trace 格式 1 文件
     * 格式: level\tfunc_nr\t{0=enter|1=exit|R=return}\ttime\tmemory[\tfunction\tuser_defined\tinclude_file\tfilename\tline]
     */
    public function parse(string $filePath): array
    {
        if (!file_exists($filePath)) {
            return ['error' => "File not found: {$filePath}"];
        }

        $fileSize = filesize($filePath);
        $isLargeFile = $fileSize > 10 * 1024 * 1024; // 10MB

        $handle = fopen($filePath, 'r');
        if (!$handle) {
            return ['error' => "Cannot open file: {$filePath}"];
        }

        // 第一遍：收集所有调用栈帧
        $entries = [];
        $callStack = [];     // 当前调用栈
        $sinkHits = [];      // 命中 Sink 的帧
        $lineNumber = 0;

        while (($line = fgets($handle)) !== false) {
            $lineNumber++;
            $line = rtrim($line, "\r\n");

            // 跳过头部注释
            if (empty($line) || $line[0] === 'V' || $line[0] === 'F' || $line[0] === 'S' || $line[0] === '#') {
                continue;
            }

            $parts = explode("\t", $line);
            if (count($parts) < 5) {
                continue;
            }

            $level = (int)$parts[0];
            $funcNr = $parts[1];
            $entryExit = $parts[2];

            // 仅处理函数进入（0）
            if ($entryExit !== '0') {
                continue;
            }

            if (count($parts) < 9) {
                continue;
            }

            $functionName = $parts[5] ?? '';
            $isUserDefined = ($parts[6] ?? '0') === '1';
            $includeFile = $parts[7] ?? '';
            $filename = $parts[8] ?? '';
            $fileLine = (int)($parts[9] ?? 0);

            // 过滤噪声
            if ($this->isNoise($functionName)) {
                continue;
            }

            $entry = [
                'level'         => $level,
                'func_nr'       => $funcNr,
                'function'      => $functionName,
                'user_defined'  => $isUserDefined,
                'file'          => $filename,
                'line'          => $fileLine,
            ];

            $entries[$funcNr] = $entry;

            // 维护调用栈
            while (count($callStack) >= $level) {
                array_pop($callStack);
            }
            $callStack[] = $funcNr;

            // 检查是否命中 Sink
            $funcBaseName = $this->extractBaseName($functionName);
            if (in_array(strtolower($funcBaseName), $this->sinkFunctions)) {
                $sinkHits[] = [
                    'sink_entry' => $entry,
                    'call_stack' => $callStack,
                ];
            }
        }

        fclose($handle);

        // 第二遍：为每个 Sink 命中构建完整调用路径
        $result = [
            'trace_file'    => $filePath,
            'file_size_mb'  => round($fileSize / 1024 / 1024, 2),
            'total_entries'  => count($entries),
            'sink_hits'     => count($sinkHits),
            'large_file_trimmed' => $isLargeFile,
            'chains'        => [],
        ];

        $chainCount = 0;
        foreach ($sinkHits as $hit) {
            if ($isLargeFile && $chainCount >= $this->maxOutputLines) {
                break;
            }

            $chain = [];
            foreach ($hit['call_stack'] as $funcNr) {
                if (isset($entries[$funcNr])) {
                    $e = $entries[$funcNr];
                    $chain[] = [
                        'level'    => $e['level'],
                        'function' => $e['function'],
                        'file'     => $e['file'],
                        'line'     => $e['line'],
                    ];
                }
            }

            $result['chains'][] = [
                'sink_function' => $hit['sink_entry']['function'],
                'sink_file'     => $hit['sink_entry']['file'],
                'sink_line'     => $hit['sink_entry']['line'],
                'depth'         => count($chain),
                'call_path'     => $chain,
            ];

            $chainCount += count($chain);
        }

        return $result;
    }

    private function isNoise(string $functionName): bool
    {
        foreach ($this->noisePatterns as $pattern) {
            if (strpos($functionName, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }

    private function extractBaseName(string $functionName): string
    {
        // Class::method → method
        if (strpos($functionName, '::') !== false) {
            $parts = explode('::', $functionName);
            return end($parts);
        }
        // ->method → method
        if (strpos($functionName, '->') !== false) {
            $parts = explode('->', $functionName);
            return end($parts);
        }
        return $functionName;
    }
}

// ============================================================
// 主程序
// ============================================================

if ($argc < 2) {
    fwrite(STDERR, "Usage: php trace_filter.php <trace_file> [sink1,sink2,...]\n");
    fwrite(STDERR, "\n");
    fwrite(STDERR, "Arguments:\n");
    fwrite(STDERR, "  trace_file   Xdebug trace file (format 1)\n");
    fwrite(STDERR, "  sink1,...    Optional comma-separated list of sink functions to filter\n");
    fwrite(STDERR, "               (defaults to built-in list)\n");
    exit(1);
}

$traceFile = $argv[1];

// 自定义 Sink 列表
$sinks = $DEFAULT_SINKS;
if ($argc >= 3) {
    $sinks = array_map('trim', explode(',', $argv[2]));
}

$parser = new TraceParser($sinks, $NOISE_PATTERNS, 500);
$result = $parser->parse($traceFile);

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
echo "\n";
