> **Skill ID**: S-037g | **Phase**: 3 | **Parent**: S-037 (Trace-Worker)
> **Input**: File upload route entry
> **Output**: File-handling call-chain trace (`$_FILES` → `move_uploaded_file()`)

# File Upload Tracer

## Purpose

Routes that accept file uploads require multipart/form-data requests and follow
a distinct processing path through `$_FILES`, type checking, and
`move_uploaded_file()`. This sub-skill constructs the appropriate multipart
request and traces the complete file-handling call chain.

## Procedure

### 1. Prepare Test File

Create a minimal test file inside the container:

```bash
docker exec php sh -c 'echo "test file content" > /tmp/test.txt'
```

For routes that validate file types, prepare type-appropriate files:

| Expected Type | Test File |
|---------------|-----------|
| Image | 1×1 PNG (minimal valid header) |
| PDF | Minimal valid PDF header |
| CSV | `col1,col2\nval1,val2` |
| Generic | Plain text `test.txt` |

### 2. Send Multipart Request

```bash
docker exec php curl -s -X POST http://nginx:80$ROUTE_URL \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -F "file=@/tmp/test.txt;filename=test.txt" \
  -F "name=test_file"
```

If the route expects a specific form field name for the file (e.g., `avatar`,
`document`), use that name instead of `file`.

### 3. Tracing Focus Points

The trace MUST capture these file-handling stages:

| Stage | Key Functions | What to Record |
|-------|---------------|----------------|
| Reception | `$_FILES` access | Temporary file path |
| Type validation | `finfo_file()`, `getimagesize()`, `pathinfo()`, `mime_content_type()` | Which checks are performed |
| Size validation | `$_FILES['file']['size']` comparison | Size limits enforced |
| Name sanitisation | `basename()`, `preg_replace()`, custom filters | Whether filename is sanitised |
| Storage | `move_uploaded_file()`, `rename()`, `copy()` | **Destination path** — critical for file upload vulns |
| Post-processing | `imagecreatefrom*()`, `exec('convert ...')` | Any processing that might be exploitable |

### 4. Record Destination Path

The `move_uploaded_file()` destination is a key security indicator:

- **Web-accessible directory** (e.g., `public/uploads/`) → potential webshell risk.
- **Outside webroot** → lower risk.
- **Predictable filename** → enumeration risk.

Record in the trace:
```json
{
  "file_upload": {
    "dest_path": "/var/www/html/public/uploads/test.txt",
    "web_accessible": true,
    "filename_sanitised": false,
    "type_check_functions": ["pathinfo"]
  }
}
```

## Input Contract

| Source | Path | Required | Fields Used |
|--------|------|----------|-------------|
| Task package (S-036e) | (in-memory) | Yes | `route_url`, `method`, `params` (file field name) |
| Credentials (S-037a) | (in-memory) | Yes | Auth headers/cookies |

## Output Contract

| Output | Path | Description |
|--------|------|-------------|
| File handling trace | (in-memory / piped to S-037c) | Call chain covering `$_FILES` through `move_uploaded_file()` |
| `file_upload` metadata | Embedded in trace record | Destination path, web accessibility, sanitisation status |

## Error Handling

| Error | Action |
|-------|--------|
| Upload rejected (413 / size limit) | Retry with a smaller file; log the size limit |
| Upload rejected (422 / type mismatch) | Retry with the expected file type; log accepted types |
| `move_uploaded_file()` not in trace | Check for alternative storage functions (`Storage::put`, `fwrite`) |
| Route requires multiple files | Send multiple `-F` fields; trace each file's handling path |
