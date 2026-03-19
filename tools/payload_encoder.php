<?php
/**
 * Payload Encoder - 统一 Payload 编码工具
 * 供所有 Phase 4 审计器复用
 *
 * Usage: php payload_encoder.php <payload> <encoding_type>
 * Types: url, double_url, base64, hex, unicode, wide_byte, html_entity, rot13
 */

class PayloadEncoder {

    /**
     * URL 编码
     */
    public static function urlEncode(string $payload): string {
        return urlencode($payload);
    }

    /**
     * 双重 URL 编码
     */
    public static function doubleUrlEncode(string $payload): string {
        return urlencode(urlencode($payload));
    }

    /**
     * Base64 编码
     */
    public static function base64Encode(string $payload): string {
        return base64_encode($payload);
    }

    /**
     * Hex 编码 (\xNN 格式)
     */
    public static function hexEncode(string $payload): string {
        $result = '';
        for ($i = 0; $i < strlen($payload); $i++) {
            $result .= '\\x' . bin2hex($payload[$i]);
        }
        return $result;
    }

    /**
     * Unicode 编码 (\uNNNN 格式)
     */
    public static function unicodeEncode(string $payload): string {
        $result = '';
        for ($i = 0; $i < strlen($payload); $i++) {
            $result .= '\\u00' . bin2hex($payload[$i]);
        }
        return $result;
    }

    /**
     * 宽字节注入 (GBK 编码，吞反斜杠)
     */
    public static function wideByteEncode(string $payload): string {
        return str_replace("'", "%bf%27", $payload);
    }

    /**
     * HTML 实体编码
     */
    public static function htmlEntityEncode(string $payload): string {
        $result = '';
        for ($i = 0; $i < strlen($payload); $i++) {
            $result .= '&#' . ord($payload[$i]) . ';';
        }
        return $result;
    }

    /**
     * ROT13 编码
     */
    public static function rot13Encode(string $payload): string {
        return str_rot13($payload);
    }

    /**
     * MySQL Hex 编码 (0xNNNN 格式)
     */
    public static function mysqlHexEncode(string $payload): string {
        return '0x' . bin2hex($payload);
    }

    /**
     * PHP Octal 编码
     */
    public static function octalEncode(string $payload): string {
        $result = '';
        for ($i = 0; $i < strlen($payload); $i++) {
            $result .= '\\' . decoct(ord($payload[$i]));
        }
        return $result;
    }

    /**
     * 空格替代编码 (用于命令注入)
     */
    public static function spaceBypass(string $payload): array {
        return [
            'ifs'     => str_replace(' ', '${IFS}', $payload),
            'tab'     => str_replace(' ', '%09', $payload),
            'brace'   => '{' . str_replace(' ', ',', $payload) . '}',
            'newline' => str_replace(' ', '%0a', $payload),
        ];
    }

    /**
     * 生成所有编码变体
     */
    public static function allVariants(string $payload): array {
        return [
            'original'     => $payload,
            'url'          => self::urlEncode($payload),
            'double_url'   => self::doubleUrlEncode($payload),
            'base64'       => self::base64Encode($payload),
            'hex'          => self::hexEncode($payload),
            'unicode'      => self::unicodeEncode($payload),
            'wide_byte'    => self::wideByteEncode($payload),
            'html_entity'  => self::htmlEntityEncode($payload),
            'rot13'        => self::rot13Encode($payload),
            'mysql_hex'    => self::mysqlHexEncode($payload),
            'octal'        => self::octalEncode($payload),
        ];
    }
}

// CLI 入口
if (php_sapi_name() === 'cli' && isset($argv[1])) {
    $payload = $argv[1];
    $type = $argv[2] ?? 'all';

    if ($type === 'all') {
        $variants = PayloadEncoder::allVariants($payload);
        echo json_encode($variants, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
    } else {
        $method = $type . 'Encode';
        if (method_exists(PayloadEncoder::class, $method)) {
            echo PayloadEncoder::$method($payload) . "\n";
        } else {
            fprintf(STDERR, "Unknown encoding type: %s\n", $type);
            fprintf(STDERR, "Available: url, doubleUrl, base64, hex, unicode, wideByte, htmlEntity, rot13, mysqlHex, octal, all\n");
            exit(1);
        }
    }
}
