<?php
/**
 * AST Sink 扫描器
 * 基于 nikic/PHP-Parser，扫描 PHP 项目中所有危险 Sink 函数调用
 *
 * 用法: php sink_finder.php <目标目录>
 * 输出: JSON 格式结果到 stdout
 *
 * 前置依赖: composer require nikic/php-parser
 */

// 自动加载（容器内执行，vendor 在项目根目录）
$autoloadPaths = [
    __DIR__ . '/vendor/autoload.php',
    __DIR__ . '/../vendor/autoload.php',
    '/var/www/html/vendor/autoload.php',
];

$loaded = false;
foreach ($autoloadPaths as $path) {
    if (file_exists($path)) {
        require_once $path;
        $loaded = true;
        break;
    }
}

if (!$loaded) {
    fwrite(STDERR, "Error: Cannot find vendor/autoload.php. Run: composer require nikic/php-parser\n");
    exit(1);
}

use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use PhpParser\Node;

// ============================================================
// Sink 定义
// ============================================================

$SINK_DEFINITIONS = [
    // RCE - 代码执行
    'eval'                  => 'RCE',
    'assert'                => 'RCE',
    'preg_replace'          => 'RCE',  // 需检查 /e 修饰符
    'create_function'       => 'RCE',
    // RCE - 命令执行
    'system'                => 'RCE',
    'exec'                  => 'RCE',
    'passthru'              => 'RCE',
    'shell_exec'            => 'RCE',
    'popen'                 => 'RCE',
    'proc_open'             => 'RCE',
    'pcntl_exec'            => 'RCE',
    // RCE - 回调
    'call_user_func'        => 'RCE',
    'call_user_func_array'  => 'RCE',
    'array_map'             => 'RCE',
    'array_filter'          => 'RCE',
    'usort'                 => 'RCE',
    'uasort'                => 'RCE',
    'uksort'                => 'RCE',
    'array_walk'            => 'RCE',
    // RCE - 变量覆盖
    'extract'               => 'RCE',
    'parse_str'             => 'RCE',
    'mb_parse_str'          => 'RCE',

    // SQL 注入 - 原生
    'mysql_query'           => 'SQLi',
    'pg_query'              => 'SQLi',
    'sqlite_query'          => 'SQLi',

    // 文件包含
    'highlight_file'        => 'LFI',
    'show_source'           => 'LFI',
    'file_get_contents'     => 'LFI',
    'readfile'              => 'LFI',
    'fread'                 => 'LFI',
    'file'                  => 'LFI',
    'fpassthru'             => 'LFI',
    'fopen'                 => 'LFI',

    // 文件写入
    'file_put_contents'     => 'FileWrite',
    'fwrite'                => 'FileWrite',
    'fputs'                 => 'FileWrite',
    'move_uploaded_file'    => 'FileWrite',
    'copy'                  => 'FileWrite',
    'rename'                => 'FileWrite',

    // 反序列化
    'unserialize'           => 'Deserialization',

    // SSRF
    'curl_exec'             => 'SSRF',
    'curl_multi_exec'       => 'SSRF',
    'get_headers'           => 'SSRF',
    'getimagesize'          => 'SSRF',

    // XSS（仅标记直接输出函数，模板在别处检测）
    'printf'                => 'XSS',
    'vprintf'               => 'XSS',

    // XXE
    'simplexml_load_string' => 'XXE',
    'simplexml_load_file'   => 'XXE',
    'libxml_disable_entity_loader' => 'XXE',

    // WordPress - 全局函数
    'update_option'         => 'WordPress',
    'update_user_meta'      => 'WordPress',
    'wp_set_auth_cookie'    => 'WordPress',
    'do_shortcode'          => 'WordPress',
    'wp_remote_get'         => 'WordPress',
    'wp_remote_post'        => 'WordPress',
    'is_admin'              => 'WordPress',  // 标记为可疑授权检查

    // Crypto - 弱哈希/弱随机数/已弃用
    'md5'                   => 'Crypto',
    'sha1'                  => 'Crypto',
    'rand'                  => 'Crypto',
    'mt_rand'               => 'Crypto',
    'mcrypt_encrypt'        => 'Crypto',
    'mcrypt_decrypt'        => 'Crypto',
    'mcrypt_cbc'            => 'Crypto',
    'mcrypt_cfb'            => 'Crypto',
    'mcrypt_ecb'            => 'Crypto',
    'mcrypt_ofb'            => 'Crypto',
    'mcrypt_create_iv'      => 'Crypto',
    'mcrypt_generic'        => 'Crypto',
    'mcrypt_module_open'    => 'Crypto',
    'openssl_encrypt'       => 'Crypto',
];

// 方法级 Sink（类名::方法名 或 ->方法名）
$METHOD_SINKS = [
    // SQL - PDO
    'query'         => 'SQLi',
    'exec'          => 'SQLi',  // 需区分上下文
    'multi_query'   => 'SQLi',
    // SQL - Laravel
    'raw'           => 'SQLi',
    'whereRaw'      => 'SQLi',
    'havingRaw'     => 'SQLi',
    'orderByRaw'    => 'SQLi',
    'selectRaw'     => 'SQLi',
    'groupByRaw'    => 'SQLi',
    'findBySql'     => 'SQLi',
    // 文件写入
    'extractTo'     => 'FileWrite',
    // XXE
    'loadXML'       => 'XXE',
    'load'          => 'XXE',
    // SSRF
    // SoapClient 在 new 时检测

    // NoSQL - MongoDB Collection 方法
    'find'              => 'NoSQL',
    'findOne'           => 'NoSQL',
    'aggregate'         => 'NoSQL',
    'updateOne'         => 'NoSQL',
    'deleteMany'        => 'NoSQL',
    'insertOne'         => 'NoSQL',
    // NoSQL - Redis
    'eval'              => 'NoSQL',   // Redis->eval()
    'rawCommand'        => 'NoSQL',   // Redis->rawCommand()

    // WordPress - $wpdb 方法
    // (wpdb 上下文在 checkMethodCall 中进一步检测)
    'get_results'       => 'WordPress',
    'get_row'           => 'WordPress',
    'get_var'           => 'WordPress',

    // GraphQL
    'executeQuery'      => 'GraphQL',
];

// 静态方法 Sink
$STATIC_SINKS = [
    'DB::raw'           => 'SQLi',
    'DB::select'        => 'SQLi',
    'DB::statement'     => 'SQLi',
    'Db::query'         => 'SQLi',
    'Db::execute'       => 'SQLi',
    'Model::create'     => 'MassAssignment',

    // GraphQL 静态调用
    'GraphQL::executeQuery'     => 'GraphQL',
    'GraphQLServer::executeQuery' => 'GraphQL',
];

// ============================================================
// AST Visitor
// ============================================================

class SinkVisitor extends NodeVisitorAbstract
{
    private string $currentFile = '';
    private ?string $currentClass = null;
    private ?string $currentFunction = null;
    private ?string $currentNamespace = null;
    private array $sinks = [];
    private array $sinkDefs;
    private array $methodSinks;
    private array $staticSinks;

    public function __construct(array $sinkDefs, array $methodSinks, array $staticSinks)
    {
        $this->sinkDefs = $sinkDefs;
        $this->methodSinks = $methodSinks;
        $this->staticSinks = $staticSinks;
    }

    public function setCurrentFile(string $file): void
    {
        $this->currentFile = $file;
        $this->currentClass = null;
        $this->currentFunction = null;
        $this->currentNamespace = null;
    }

    public function getSinks(): array
    {
        return $this->sinks;
    }

    public function enterNode(Node $node)
    {
        // 追踪命名空间
        if ($node instanceof Node\Stmt\Namespace_) {
            $this->currentNamespace = $node->name ? $node->name->toString() : null;
        }

        // 追踪类
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClass = $node->name ? $node->name->toString() : null;
        }

        // 追踪函数/方法
        if ($node instanceof Node\Stmt\Function_ || $node instanceof Node\Stmt\ClassMethod) {
            $this->currentFunction = $node->name->toString();
        }

        // 检测全局函数调用
        if ($node instanceof Node\Expr\FuncCall) {
            $this->checkFuncCall($node);
        }

        // 检测静态方法调用
        if ($node instanceof Node\Expr\StaticCall) {
            $this->checkStaticCall($node);
        }

        // 检测实例方法调用
        if ($node instanceof Node\Expr\MethodCall) {
            $this->checkMethodCall($node);
        }

        // 检测动态函数调用: $func()
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Expr\Variable) {
            $this->addSink($node, 'RCE', '$' . $node->name->name . '()', 'dynamic_call');
        }

        // 检测 include/require
        if ($node instanceof Node\Expr\Include_) {
            $this->checkInclude($node);
        }

        // 检测弱比较
        if ($node instanceof Node\Expr\BinaryOp\Equal || $node instanceof Node\Expr\BinaryOp\NotEqual) {
            $this->checkWeakComparison($node);
        }

        // 检测魔术方法定义
        if ($node instanceof Node\Stmt\ClassMethod) {
            $this->checkMagicMethod($node);
        }

        // 检测 Mass Assignment: $guarded = []
        if ($node instanceof Node\Stmt\Property) {
            $this->checkGuardedProperty($node);
        }

        // 检测 WordPress $wpdb 方法调用
        if ($node instanceof Node\Expr\MethodCall) {
            $this->checkWpdbCall($node);
        }

        // 检测 NoSQL 上下文感知方法调用
        if ($node instanceof Node\Expr\MethodCall) {
            $this->checkNoSqlCall($node);
        }

        // 检测 Crypto 弱用法（密码哈希、安全上下文随机数、ECB 模式）
        if ($node instanceof Node\Expr\FuncCall) {
            $this->checkCryptoMisuse($node);
        }

        // 检测 Race Condition 模式（TOCTOU: file_exists + include）
        if ($node instanceof Node\Stmt\If_) {
            $this->checkToctouPattern($node);
        }

        // 检测文件写入缺少 flock
        if ($node instanceof Node\Expr\FuncCall) {
            $this->checkFileWriteWithoutLock($node);
        }

        // 检测 GraphQL resolve 方法定义
        if ($node instanceof Node\Stmt\ClassMethod) {
            $this->checkGraphQLResolve($node);
        }

        // 检测 GraphQL resolve 闭包（在数组键 'resolve' 中）
        if ($node instanceof Node\Expr\ArrayItem) {
            $this->checkGraphQLResolveArray($node);
        }

        return null;
    }

    public function leaveNode(Node $node)
    {
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClass = null;
        }
        if ($node instanceof Node\Stmt\Function_ || $node instanceof Node\Stmt\ClassMethod) {
            $this->currentFunction = null;
        }
        if ($node instanceof Node\Stmt\Namespace_) {
            $this->currentNamespace = null;
        }
        return null;
    }

    private function checkFuncCall(Node\Expr\FuncCall $node): void
    {
        if (!($node->name instanceof Node\Name)) {
            return;
        }

        $funcName = $node->name->toString();

        if (isset($this->sinkDefs[$funcName])) {
            $sinkType = $this->sinkDefs[$funcName];

            // preg_replace 特殊处理：只有 /e 修饰符才是 RCE
            if ($funcName === 'preg_replace') {
                $sinkType = 'RCE';  // 标记但需人工确认 /e
            }

            // libxml_disable_entity_loader(false) 才是问题
            if ($funcName === 'libxml_disable_entity_loader') {
                if (isset($node->args[0]) && $node->args[0]->value instanceof Node\Expr\ConstFetch) {
                    $val = $node->args[0]->value->name->toString();
                    if (strtolower($val) === 'true') {
                        return; // 安全调用
                    }
                }
            }

            $this->addSink($node, $sinkType, $funcName, 'func_call');
        }
    }

    private function checkStaticCall(Node\Expr\StaticCall $node): void
    {
        if (!($node->class instanceof Node\Name) || !($node->name instanceof Node\Identifier)) {
            return;
        }

        $className = $node->class->toString();
        $methodName = $node->name->toString();
        $fullName = $className . '::' . $methodName;

        if (isset($this->staticSinks[$fullName])) {
            $sinkType = $this->staticSinks[$fullName];

            // Mass Assignment: Model::create($request->all()) 检测
            if ($sinkType === 'MassAssignment') {
                $this->addSink($node, $sinkType, $fullName, 'static_call');
                return;
            }

            $this->addSink($node, $sinkType, $fullName, 'static_call');
        }
    }

    private function checkMethodCall(Node\Expr\MethodCall $node): void
    {
        if (!($node->name instanceof Node\Identifier)) {
            // 动态方法调用: $obj->$method()
            if ($node->name instanceof Node\Expr\Variable) {
                $this->addSink($node, 'RCE', '->$' . $node->name->name . '()', 'dynamic_method');
            }
            return;
        }

        $methodName = $node->name->toString();

        if (isset($this->methodSinks[$methodName])) {
            $this->addSink($node, $this->methodSinks[$methodName], '->' . $methodName . '()', 'method_call');
        }

        // Mass Assignment: $model->fill($request->all()) / $model->update($request->all())
        if (in_array($methodName, ['fill', 'update', 'create'])) {
            if ($this->hasRequestAll($node->args)) {
                $this->addSink($node, 'MassAssignment', '->' . $methodName . '($request->all())', 'method_call');
            }
        }
    }

    private function checkInclude(Node\Expr\Include_ $node): void
    {
        $types = [
            Node\Expr\Include_::TYPE_INCLUDE      => 'include',
            Node\Expr\Include_::TYPE_INCLUDE_ONCE  => 'include_once',
            Node\Expr\Include_::TYPE_REQUIRE       => 'require',
            Node\Expr\Include_::TYPE_REQUIRE_ONCE  => 'require_once',
        ];

        $typeName = $types[$node->type] ?? 'include';

        // 如果包含路径是变量 → 危险
        if ($node->expr instanceof Node\Expr\Variable ||
            $node->expr instanceof Node\Expr\BinaryOp\Concat) {
            $this->addSink($node, 'LFI', $typeName, 'dynamic_include');
        }
    }

    private function checkWeakComparison(Node $node): void
    {
        // 只在可能涉及密码/Token 的上下文中标记
        // 简单启发式：变量名包含 password/token/key/secret/hash
        $sensitivePatterns = ['password', 'passwd', 'token', 'key', 'secret', 'hash', 'sign', 'verify'];

        $left = $this->getVarName($node->left);
        $right = $this->getVarName($node->right);

        foreach ($sensitivePatterns as $pattern) {
            if (($left && stripos($left, $pattern) !== false) ||
                ($right && stripos($right, $pattern) !== false)) {
                $op = $node instanceof Node\Expr\BinaryOp\Equal ? '==' : '!=';
                $this->addSink($node, 'WeakComparison', $op . ' on sensitive var', 'weak_comparison');
                break;
            }
        }
    }

    private function checkMagicMethod(Node\Stmt\ClassMethod $node): void
    {
        $magicMethods = ['__destruct', '__wakeup', '__toString', '__call', '__get'];
        $name = $node->name->toString();

        if (in_array($name, $magicMethods)) {
            $this->addSink($node, 'Deserialization', $name . '() definition', 'magic_method');
        }
    }

    private function checkGuardedProperty(Node\Stmt\Property $node): void
    {
        foreach ($node->props as $prop) {
            if ($prop->name->toString() === 'guarded') {
                // 检查是否 $guarded = []
                if ($prop->default instanceof Node\Expr\Array_ && count($prop->default->items) === 0) {
                    $this->addSink($node, 'MassAssignment', '$guarded = []', 'property');
                }
            }
        }
    }

    /**
     * 检测 WordPress $wpdb 方法调用: $wpdb->query(), $wpdb->get_results() 等
     */
    private function checkWpdbCall(Node\Expr\MethodCall $node): void
    {
        if (!($node->name instanceof Node\Identifier)) {
            return;
        }

        $methodName = $node->name->toString();
        $wpdbMethods = ['query', 'get_results', 'get_row', 'get_var'];

        if (!in_array($methodName, $wpdbMethods)) {
            return;
        }

        // 检查调用对象是否为 $wpdb 变量
        if ($node->var instanceof Node\Expr\Variable && $node->var->name === 'wpdb') {
            $this->addSink($node, 'WordPress', '$wpdb->' . $methodName . '()', 'method_call');
        }
    }

    /**
     * 检测 NoSQL 上下文感知调用: MongoDB Collection 和 Redis
     */
    private function checkNoSqlCall(Node\Expr\MethodCall $node): void
    {
        if (!($node->name instanceof Node\Identifier)) {
            return;
        }

        $methodName = $node->name->toString();

        // MongoDB Collection 方法
        $mongoMethods = ['find', 'findOne', 'aggregate', 'updateOne', 'deleteMany', 'insertOne'];
        // Redis 方法
        $redisMethods = ['eval', 'rawCommand'];

        if (in_array($methodName, $mongoMethods) || in_array($methodName, $redisMethods)) {
            // 检测变量名是否包含有意义的 NoSQL 关键词
            $varName = $this->getVarName($node->var);
            $nosqlHints = ['collection', 'mongo', 'redis', 'client', 'db', 'database', 'conn'];

            if ($varName !== null) {
                foreach ($nosqlHints as $hint) {
                    if (stripos($varName, $hint) !== false) {
                        $label = in_array($methodName, $redisMethods) ? 'Redis' : 'MongoDB';
                        $this->addSink($node, 'NoSQL', $label . '->' . $methodName . '()', 'method_call');
                        return;
                    }
                }
            }
        }
    }

    /**
     * 检测 Crypto 弱用法:
     * - md5()/sha1() 用于密码相关变量
     * - rand()/mt_rand() 在安全上下文中
     * - openssl_encrypt 使用 ECB 模式
     */
    private function checkCryptoMisuse(Node\Expr\FuncCall $node): void
    {
        if (!($node->name instanceof Node\Name)) {
            return;
        }

        $funcName = $node->name->toString();

        // md5/sha1 用于密码变量
        if (in_array($funcName, ['md5', 'sha1'])) {
            if (isset($node->args[0]) && $node->args[0] instanceof Node\Arg) {
                $argName = $this->getVarName($node->args[0]->value);
                $passwordHints = ['password', 'passwd', 'pass', 'pwd'];
                if ($argName !== null) {
                    foreach ($passwordHints as $hint) {
                        if (stripos($argName, $hint) !== false) {
                            $this->addSink($node, 'Crypto', $funcName . '() on password variable', 'crypto_weak_hash');
                            return;
                        }
                    }
                }
            }
        }

        // rand/mt_rand 在安全上下文中（变量赋值名含 token/key/password/secret/nonce）
        if (in_array($funcName, ['rand', 'mt_rand'])) {
            $parent = $this->findAssignmentTarget($node);
            if ($parent !== null) {
                $securityHints = ['token', 'key', 'password', 'secret', 'nonce', 'salt', 'csrf', 'otp'];
                foreach ($securityHints as $hint) {
                    if (stripos($parent, $hint) !== false) {
                        $this->addSink($node, 'Crypto', $funcName . '() for security purpose ($' . $parent . ')', 'crypto_weak_random');
                        return;
                    }
                }
            }
        }

        // openssl_encrypt 使用 ECB 模式
        if ($funcName === 'openssl_encrypt') {
            // 第二个参数是加密方法，检查是否包含 ECB
            if (isset($node->args[1]) && $node->args[1] instanceof Node\Arg) {
                $methodArg = $node->args[1]->value;
                if ($methodArg instanceof Node\Scalar\String_ && stripos($methodArg->value, 'ecb') !== false) {
                    $this->addSink($node, 'Crypto', 'openssl_encrypt() with ECB mode', 'crypto_ecb');
                    return;
                }
            }
        }

        // mcrypt_* 函数（已弃用）
        if (strpos($funcName, 'mcrypt_') === 0) {
            $this->addSink($node, 'Crypto', $funcName . '() (deprecated)', 'crypto_deprecated');
        }
    }

    /**
     * 检测 TOCTOU（Time-of-Check Time-of-Use）模式:
     * if (file_exists($x)) { include $x; }
     */
    private function checkToctouPattern(Node\Stmt\If_ $node): void
    {
        // 检查条件是否包含 file_exists 调用
        $hasFileExists = false;
        $this->walkExpr($node->cond, function ($expr) use (&$hasFileExists) {
            if ($expr instanceof Node\Expr\FuncCall &&
                $expr->name instanceof Node\Name &&
                $expr->name->toString() === 'file_exists') {
                $hasFileExists = true;
            }
        });

        if (!$hasFileExists) {
            return;
        }

        // 检查 if 体中是否包含 include/require
        $hasInclude = false;
        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Expression && $stmt->expr instanceof Node\Expr\Include_) {
                $hasInclude = true;
                break;
            }
            // 也检查嵌套块
            $this->walkStmts([$stmt], function ($innerNode) use (&$hasInclude) {
                if ($innerNode instanceof Node\Expr\Include_) {
                    $hasInclude = true;
                }
            });
        }

        if ($hasInclude) {
            $this->addSink($node, 'RaceCondition', 'file_exists() + include/require (TOCTOU)', 'race_condition');
        }
    }

    /**
     * 检测文件写入缺少 flock（简单启发式：在同一函数中有 fwrite/file_put_contents 但无 flock）
     * 注意：此检测在 func_call 级别标记 fwrite/file_put_contents，并在 leaveNode 中汇总
     * 为简化实现，仅标记 file_put_contents 不带 LOCK_EX 标志的情况
     */
    private function checkFileWriteWithoutLock(Node\Expr\FuncCall $node): void
    {
        if (!($node->name instanceof Node\Name)) {
            return;
        }

        $funcName = $node->name->toString();

        if ($funcName === 'file_put_contents') {
            // 检查第三个参数是否包含 LOCK_EX
            $hasLockEx = false;
            if (isset($node->args[2]) && $node->args[2] instanceof Node\Arg) {
                $flagArg = $node->args[2]->value;
                // 检查常量 LOCK_EX 或包含 LOCK_EX 的位运算
                $this->walkExpr($flagArg, function ($expr) use (&$hasLockEx) {
                    if ($expr instanceof Node\Expr\ConstFetch &&
                        $expr->name->toString() === 'LOCK_EX') {
                        $hasLockEx = true;
                    }
                });
            }
            if (!$hasLockEx) {
                $this->addSink($node, 'RaceCondition', 'file_put_contents() without LOCK_EX', 'race_condition');
            }
        }
    }

    /**
     * 检测 GraphQL resolve 方法定义
     */
    private function checkGraphQLResolve(Node\Stmt\ClassMethod $node): void
    {
        $name = $node->name->toString();
        if ($name === 'resolve' || $name === 'resolveField') {
            // 启发式：检查类名是否包含 GraphQL/Type/Query/Mutation 等关键词
            $classHints = ['type', 'query', 'mutation', 'graphql', 'resolver', 'schema', 'field'];
            if ($this->currentClass !== null) {
                foreach ($classHints as $hint) {
                    if (stripos($this->currentClass, $hint) !== false) {
                        $this->addSink($node, 'GraphQL', $name . '() in ' . $this->currentClass, 'graphql_resolve');
                        return;
                    }
                }
            }
        }
    }

    /**
     * 检测 GraphQL resolve 闭包（在数组中定义 'resolve' => function(...) {}）
     */
    private function checkGraphQLResolveArray(Node\Expr\ArrayItem $node): void
    {
        if ($node->key instanceof Node\Scalar\String_ && $node->key->value === 'resolve') {
            if ($node->value instanceof Node\Expr\Closure || $node->value instanceof Node\Expr\ArrowFunction) {
                $this->addSink($node, 'GraphQL', "'resolve' => closure (GraphQL field resolver)", 'graphql_resolve');
            }
        }
    }

    /**
     * 辅助：遍历表达式树
     */
    private function walkExpr(Node $node, callable $callback): void
    {
        $callback($node);
        foreach ($node->getSubNodeNames() as $name) {
            $sub = $node->$name;
            if ($sub instanceof Node) {
                $this->walkExpr($sub, $callback);
            } elseif (is_array($sub)) {
                foreach ($sub as $item) {
                    if ($item instanceof Node) {
                        $this->walkExpr($item, $callback);
                    }
                }
            }
        }
    }

    /**
     * 辅助：遍历语句列表
     */
    private function walkStmts(array $stmts, callable $callback): void
    {
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Node) {
                $this->walkExpr($stmt, $callback);
            }
        }
    }

    /**
     * 辅助：尝试找到当前表达式被赋值的目标变量名
     * 简单启发式：向上查找，目前仅在同节点中返回 null
     * 实际使用时依赖变量名匹配
     */
    private function findAssignmentTarget(Node $node): ?string
    {
        // PHP-Parser 不直接支持父节点引用，
        // 所以我们检查节点属性中是否有父赋值上下文
        // 这里返回 currentFunction 作为上下文线索
        // 更精确的实现需要 ParentConnectingVisitor
        if ($this->currentFunction !== null) {
            return $this->currentFunction;
        }
        return null;
    }

    private function addSink(Node $node, string $sinkType, string $function, string $callType): void
    {
        $args = [];
        $argSafety = [];

        if (method_exists($node, 'getArgs') || property_exists($node, 'args')) {
            $nodeArgs = property_exists($node, 'args') ? $node->args : [];
            foreach ($nodeArgs as $arg) {
                if (!($arg instanceof Node\Arg)) continue;
                $argInfo = $this->analyzeArg($arg->value);
                $args[] = $argInfo['name'];
                $argSafety[] = $argInfo['safety'];
            }
        }

        $inFunction = $this->currentFunction;
        if ($this->currentClass && $this->currentFunction) {
            $inFunction = $this->currentClass . '::' . $this->currentFunction;
        }

        $this->sinks[] = [
            'file'          => $this->currentFile,
            'line'          => $node->getStartLine(),
            'sink_type'     => $sinkType,
            'function'      => $function,
            'call_type'     => $callType,
            'args'          => $args,
            'arg_safety'    => $argSafety,
            'in_function'   => $inFunction,
            'in_class'      => $this->currentClass ? ($this->currentNamespace ? $this->currentNamespace . '\\' . $this->currentClass : $this->currentClass) : null,
            'namespace'     => $this->currentNamespace,
        ];
    }

    private function analyzeArg(Node\Expr $expr): array
    {
        // 字面量 → safe
        if ($expr instanceof Node\Scalar\String_ ||
            $expr instanceof Node\Scalar\Int_ ||
            $expr instanceof Node\Scalar\Float_) {
            return ['name' => var_export($expr->value, true), 'safety' => 'safe'];
        }

        // 变量 → needs_trace
        if ($expr instanceof Node\Expr\Variable) {
            $name = is_string($expr->name) ? '$' . $expr->name : '$<dynamic>';
            return ['name' => $name, 'safety' => 'needs_trace'];
        }

        // 拼接 → suspicious
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return ['name' => '<concat>', 'safety' => 'suspicious'];
        }

        // 函数调用 → needs_trace
        if ($expr instanceof Node\Expr\FuncCall || $expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall) {
            return ['name' => '<call>', 'safety' => 'needs_trace'];
        }

        // 数组访问 → needs_trace
        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            return ['name' => '<array_access>', 'safety' => 'needs_trace'];
        }

        // 其他 → needs_trace
        return ['name' => '<expr>', 'safety' => 'needs_trace'];
    }

    private function getVarName($expr): ?string
    {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return $expr->name;
        }
        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            return $expr->name->toString();
        }
        return null;
    }

    private function hasRequestAll(array $args): bool
    {
        foreach ($args as $arg) {
            if (!($arg instanceof Node\Arg)) continue;
            if ($arg->value instanceof Node\Expr\MethodCall &&
                $arg->value->name instanceof Node\Identifier &&
                $arg->value->name->toString() === 'all') {
                return true;
            }
        }
        return false;
    }
}

// ============================================================
// 主程序
// ============================================================

if ($argc < 2) {
    fwrite(STDERR, "Usage: php sink_finder.php <target_directory>\n");
    exit(1);
}

$targetDir = realpath($argv[1]);
if (!$targetDir || !is_dir($targetDir)) {
    fwrite(STDERR, "Error: Directory not found: {$argv[1]}\n");
    exit(1);
}

// 递归收集 .php 文件（排除 vendor/）
function collectPhpFiles(string $dir): array
{
    $files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $file) {
        $path = $file->getPathname();

        // 跳过 vendor/ 目录
        if (strpos($path, DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR) !== false) {
            continue;
        }
        // 跳过 node_modules/
        if (strpos($path, DIRECTORY_SEPARATOR . 'node_modules' . DIRECTORY_SEPARATOR) !== false) {
            continue;
        }
        // 跳过 .git/
        if (strpos($path, DIRECTORY_SEPARATOR . '.git' . DIRECTORY_SEPARATOR) !== false) {
            continue;
        }

        if ($file->isFile() && $file->getExtension() === 'php') {
            $files[] = $path;
        }
    }

    return $files;
}

$phpFiles = collectPhpFiles($targetDir);

$parser = (new ParserFactory())->createForNewestSupportedVersion();
$traverser = new NodeTraverser();
$visitor = new SinkVisitor($SINK_DEFINITIONS, $METHOD_SINKS, $STATIC_SINKS);
$traverser->addVisitor($visitor);

$totalFiles = count($phpFiles);
$errorFiles = [];

foreach ($phpFiles as $file) {
    $relativePath = str_replace($targetDir . DIRECTORY_SEPARATOR, '', $file);
    $visitor->setCurrentFile($relativePath);

    $code = file_get_contents($file);
    try {
        $ast = $parser->parse($code);
        if ($ast !== null) {
            $traverser->traverse($ast);
        }
    } catch (\PhpParser\Error $e) {
        $errorFiles[] = ['file' => $relativePath, 'error' => $e->getMessage()];
        fwrite(STDERR, "Parse error in {$relativePath}: {$e->getMessage()}\n");
    }
}

// 输出结果
$result = [
    'scan_time'    => date('c'),
    'target_dir'   => $targetDir,
    'total_files'  => $totalFiles,
    'parse_errors' => count($errorFiles),
    'error_files'  => $errorFiles,
    'total_sinks'  => count($visitor->getSinks()),
    'sinks'        => $visitor->getSinks(),
];

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
echo "\n";
