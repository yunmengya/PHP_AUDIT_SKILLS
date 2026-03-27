## Identity

| Field | Value |
|-------|-------|
| Skill ID | S-037g |
| Phase | 3 |
| Responsibility | Construct multipart upload requests and trace file-handling call chains |

# File Upload Tracer

## Purpose

Routes that accept file uploads require multipart/form-data requests and follow
a distinct processing path through `$_FILES`, type checking, and
`move_uploaded_file()`. This sub-skill constructs the appropriate multipart
request and traces the complete file-handling call chain.

## Input Contract

| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Task package | From S-036e (in-memory) | Yes | `route_url`, `method`, `params` (file field name) |
| Credentials | Request Constructor S-037a (in-memory) | Yes | Auth headers/cookies |

## Fill-in Procedure

### Step 1 — Prepare Test File

| Field | Fill-in Value |
|-------|---------------|
| `test_file_path` | {/tmp/test.txt inside container} |
| `test_file_content` | {test file content — plain text default} |
| `expected_type` | {image / PDF / CSV / generic — based on route validation} |

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

### Step 2 — Send Multipart Request

| Field | Fill-in Value |
|-------|---------------|
| `route_url` | {target upload route path} |
| `cookie_header` | {XDEBUG_TRIGGER=1; + session cookie} |
| `file_field_name` | {file / avatar / document — from route params} |
| `file_path` | {/tmp/test.txt} |
| `filename` | {test.txt} |
| `additional_fields` | {other form fields, e.g., name=test_file} |

```bash
docker exec php curl -s -X POST http://nginx:80$ROUTE_URL \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -F "file=@/tmp/test.txt;filename=test.txt" \
  -F "name=test_file"
```

If the route expects a specific form field name for the file (e.g., `avatar`, `document`), use that name instead of `file`.

### Step 3 — Tracing Focus Points

| Field | Fill-in Value |
|-------|---------------|
| `reception_function` | {$_FILES access — record temporary file path} |
| `type_validation` | {finfo_file() / getimagesize() / pathinfo() / mime_content_type()} |
| `size_validation` | {$_FILES['file']['size'] comparison — record limits} |
| `name_sanitisation` | {basename() / preg_replace() / custom filters} |
| `storage_function` | {move_uploaded_file() / rename() / copy() — record destination path} |
| `post_processing` | {imagecreatefrom*() / exec('convert ...') — exploitable processing} |

The trace MUST capture these file-handling stages:

| Stage | Key Functions | What to Record |
|-------|---------------|----------------|
| Reception | `$_FILES` access | Temporary file path |
| Type validation | `finfo_file()`, `getimagesize()`, `pathinfo()`, `mime_content_type()` | Which checks are performed |
| Size validation | `$_FILES['file']['size']` comparison | Size limits enforced |
| Name sanitisation | `basename()`, `preg_replace()`, custom filters | Whether filename is sanitised |
| Storage | `move_uploaded_file()`, `rename()`, `copy()` | **Destination path** — critical for file upload vulns |
| Post-processing | `imagecreatefrom*()`, `exec('convert ...')` | Any processing that might be exploitable |

### Step 4 — Record Destination Path

| Field | Fill-in Value |
|-------|---------------|
| `dest_path` | {destination path from move_uploaded_file()} |
| `web_accessible` | {true / false — is destination under webroot?} |
| `filename_sanitised` | {true / false — was filename cleaned?} |
| `type_check_functions` | {list of type validation functions used} |

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

## Output Contract

| Output File | Path | Description |
|-------------|------|-------------|
| File handling trace | (in-memory / piped to S-037c) | Call chain covering `$_FILES` through `move_uploaded_file()` |
| `file_upload` metadata | Embedded in trace record | Destination path, web accessibility, sanitisation status |

## Examples

### ✅ GOOD — Complete file upload trace

```json
{
  "route_id": "route_022",
  "file_upload": {
    "dest_path": "/var/www/html/public/uploads/test.txt",
    "web_accessible": true,
    "filename_sanitised": false,
    "type_check_functions": ["pathinfo"]
  },
  "call_chain": [
    "App\\Http\\Controllers\\UploadController::store",
    "$_FILES access",
    "pathinfo",
    "move_uploaded_file"
  ]
}
```

All stages documented, destination path recorded, web accessibility assessed.

### ❌ BAD — Missing upload metadata

```json
{
  "route_id": "route_022",
  "call_chain": ["move_uploaded_file"]
}
```

Problems: No `file_upload` metadata, no `dest_path`, no `web_accessible`, no `type_check_functions`, call chain missing reception/validation stages.

## Error Handling

| Error | Action |
|-------|--------|
| Upload rejected (413 / size limit) | Retry with a smaller file; log the size limit |
| Upload rejected (422 / type mismatch) | Retry with the expected file type; log accepted types |
| `move_uploaded_file()` not in trace | Check for alternative storage functions (`Storage::put`, `fwrite`) |
| Route requires multiple files | Send multiple `-F` fields; trace each file's handling path |
