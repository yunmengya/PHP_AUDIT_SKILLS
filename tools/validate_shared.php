<?php
/**
 * validate_shared.php — Validation script for shared/ directory
 *
 * Usage: php tools/validate_shared.php [shared_dir]
 *   shared_dir defaults to shared/ relative to project root
 *
 * Checks performed:
 *   1. All .md files in shared/ are readable
 *   2. PHP code blocks (```php ... ```) pass syntax check (php -l)
 *   3. JSON code blocks (```json ... ```) are valid JSON
 *   4. URL-encoded sequences (%xx) in waf_bypass.md are valid hex
 *   5. Reports PASS / FAIL / WARNING per check
 */

$sharedDir = $argv[1] ?? dirname(__DIR__) . '/shared';

if (!is_dir($sharedDir)) {
    fwrite(STDERR, "FAIL: shared directory not found: $sharedDir\n");
    exit(1);
}

$pass = 0;
$fail = 0;
$warn = 0;

function report(string $status, string $file, string $msg): void {
    global $pass, $fail, $warn;
    $tag = strtoupper($status);
    echo "[$tag] $file — $msg\n";
    if ($tag === 'PASS') $pass++;
    elseif ($tag === 'FAIL') $fail++;
    else $warn++;
}

$mdFiles = glob("$sharedDir/*.md");
if (empty($mdFiles)) {
    report('warn', $sharedDir, 'No .md files found in shared directory');
}

foreach ($mdFiles as $mdFile) {
    $basename = basename($mdFile);
    $content = file_get_contents($mdFile);

    if ($content === false) {
        report('fail', $basename, 'Could not read file');
        continue;
    }
    report('pass', $basename, 'File readable');

    // Extract and validate PHP code blocks
    if (preg_match_all('/```php\s*\n(.*?)```/s', $content, $phpBlocks)) {
        foreach ($phpBlocks[1] as $i => $code) {
            $tmpFile = tempnam(sys_get_temp_dir(), 'php_validate_');
            // Ensure code starts with <?php if it doesn't already
            $codeToCheck = $code;
            if (strpos(trim($code), '<?php') !== 0 && strpos(trim($code), '<?') !== 0) {
                $codeToCheck = "<?php\n" . $code;
            }
            file_put_contents($tmpFile, $codeToCheck);

            $output = [];
            $rc = 0;
            exec("php -l " . escapeshellarg($tmpFile) . " 2>&1", $output, $rc);
            unlink($tmpFile);

            $blockNum = $i + 1;
            if ($rc === 0) {
                report('pass', $basename, "PHP block #$blockNum syntax OK");
            } else {
                $err = implode(' ', $output);
                report('fail', $basename, "PHP block #$blockNum syntax error: $err");
            }
        }
    }

    // Extract and validate JSON code blocks
    if (preg_match_all('/```json\s*\n(.*?)```/s', $content, $jsonBlocks)) {
        foreach ($jsonBlocks[1] as $i => $jsonStr) {
            $blockNum = $i + 1;
            json_decode(trim($jsonStr));
            if (json_last_error() === JSON_ERROR_NONE) {
                report('pass', $basename, "JSON block #$blockNum valid");
            } else {
                $err = json_last_error_msg();
                report('fail', $basename, "JSON block #$blockNum invalid: $err");
            }
        }
    }

    // Special check for waf_bypass.md: validate %xx URL-encoded sequences
    if ($basename === 'waf_bypass.md') {
        if (preg_match_all('/%([0-9A-Fa-f]{0,2})/', $content, $encMatches, PREG_SET_ORDER)) {
            $badEncodings = [];
            foreach ($encMatches as $m) {
                if (strlen($m[1]) !== 2) {
                    $badEncodings[] = $m[0];
                }
            }
            if (empty($badEncodings)) {
                report('pass', $basename, 'All %xx URL encodings are valid hex');
            } else {
                $examples = implode(', ', array_slice($badEncodings, 0, 5));
                report('fail', $basename, "Invalid URL encodings found: $examples");
            }
        } else {
            report('warn', $basename, 'No %xx URL encodings found to validate');
        }
    }
}

echo "\n=== Summary ===\n";
echo "PASS: $pass  FAIL: $fail  WARNING: $warn\n";
exit($fail > 0 ? 1 : 0);
