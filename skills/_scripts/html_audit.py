#!/usr/bin/env python3
"""
HTML Security Audit Tool
审计 HTML 文件中的安全漏洞：XSS、CSRF、敏感信息泄露、不安全资源引用等
"""
import argparse
import json
import os
import re
import sys
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

# 跳过的目录
SKIP_DIRS = {".git", "node_modules", "vendor", ".idea", ".vscode", "dist", "build"}


def walk_html_files(root: str) -> List[str]:
    """遍历项目中的所有 HTML 文件"""
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.lower().endswith((".html", ".htm", ".xhtml", ".vue", ".svelte")):
                results.append(os.path.join(dirpath, name))
    return results


def read_text(path: str) -> str:
    """读取文件内容"""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def write_json(path: str, data) -> None:
    """写入 JSON 文件"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


class TagInfo:
    """存储 HTML 标签信息"""
    def __init__(self, tag: str, attrs: List[tuple], line: int):
        self.tag = tag.lower()
        self.attrs = {k.lower(): v for k, v in attrs}
        self.line = line


class HTMLSecurityParser(HTMLParser):
    """HTML 安全解析器，检测安全问题"""

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
        self.findings = []
        self.current_line = 1
        self.tags: List[TagInfo] = []
        self.script_content = ""
        self.in_script = False
        self.forms: List[TagInfo] = []
        self.anchors: List[TagInfo] = []
        self.iframes: List[TagInfo] = []
        self.metatags: List[TagInfo] = []

    def handle_starttag(self, tag, attrs):
        line = self.current_line
        tag_info = TagInfo(tag, attrs, line)
        self.tags.append(tag_info)

        # 记录表单
        if tag.lower() == "form":
            self.forms.append(tag_info)

        # 记录锚点
        if tag.lower() == "a":
            self.anchors.append(tag_info)

        # 记录 iframe
        if tag.lower() == "iframe":
            self.iframes.append(tag_info)

        # 记录 meta 标签
        if tag.lower() == "meta":
            self.metatags.append(tag_info)

        # 检测 script 标签
        if tag.lower() == "script":
            self.in_script = True

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self.in_script = False

    def handle_data(self, data):
        lines = data.split("\n")
        self.current_line += len(lines) - 1

        if self.in_script:
            self.script_content += data

    def handle_comment(self, data):
        lines = data.split("\n")
        self.current_line += len(lines) - 1

    def analyze(self):
        """执行安全分析"""
        self.check_xss_in_event_handlers()
        self.check_csrf_protection()
        self.check_sensitive_info()
        self.check_insecure_iframe()
        self.check_insecure_resources()
        self.check_content_security_policy()
        self.check_http_mixed_content()
        self.check_unsafe_eval()
        self.check_dom_xss_patterns()

    def check_xss_in_event_handlers(self):
        """检查事件处理器中的 XSS 风险"""
        dangerous_events = [
            "onload", "onerror", "onclick", "onmouseover", "onmouseout",
            "onfocus", "onblur", "onsubmit", "onkeydown", "onkeyup",
            "onchange", "oninput", "ondblclick", "onmousedown", "onmouseup",
            "onmouseenter", "onmouseleave", "onscroll", "onresize",
            "ontouchstart", "ontouchend", "ontouchmove", "onanimationend",
        ]

        for tag_info in self.tags:
            for event in dangerous_events:
                if event in tag_info.attrs:
                    handler = tag_info.attrs[event]
                    # 检测可能的变量注入
                    if re.search(r'\$\{[^}]+\}|\{[^}]*\}|\{\{.*?\}\}|\%[0-9a-f]+', handler):
                        self.findings.append({
                            "id": f"xss_event_{len(self.findings)}",
                            "title": "Potential XSS via Event Handler with Template",
                            "severity": "high",
                            "confidence": "medium",
                            "category": "xss",
                            "file": self.file_path,
                            "line": tag_info.line,
                            "tag": tag_info.tag,
                            "attribute": event,
                            "code": handler,
                            "description": f"Event handler {event} contains potential template injection.",
                            "remediation": "Avoid using template variables in event handlers. Use textContent or properly escape values.",
                            "poc": f"Inject malicious script into the {event} handler.",
                        })

                    # 检测直接输出
                    if "javascript:" in handler or handler.startswith("http"):
                        self.findings.append({
                            "id": f"xss_event_{len(self.findings)}",
                            "title": "Potential XSS via JavaScript Protocol or Direct URL",
                            "severity": "high",
                            "confidence": "high",
                            "category": "xss",
                            "file": self.file_path,
                            "line": tag_info.line,
                            "tag": tag_info.tag,
                            "attribute": event,
                            "code": handler[:200],
                            "description": f"Event handler uses javascript: protocol or direct URL.",
                            "remediation": "Use proper event listeners instead of inline javascript: handlers.",
                            "poc": f"Set {event}='javascript:alert(1)' to trigger XSS.",
                        })

    def check_csrf_protection(self):
        """检查 CSRF 保护"""
        # 检查是否有 meta 中设置了 CSRF token
        has_csrf_meta = False
        for meta in self.metatags:
            name = meta.attrs.get("name", "").lower()
            if name in ["csrf-token", "_token", "csrf"]:
                has_csrf_meta = True

        for form in self.forms:
            method = form.attrs.get("method", "get").upper()
            action = form.attrs.get("action", "")

            # POST/PUT/DELETE 请求需要 CSRF 保护
            if method in ["POST", "PUT", "DELETE", "PATCH"]:
                # 检查表单中是否有 CSRF token 输入
                has_csrf_input = False
                for i, tag_info in enumerate(self.tags):
                    if tag_info.tag == "input" and tag_info.line > form.line:
                        # 找到下一个 form 或结束
                        if i < len(self.tags) - 1 and self.tags[i + 1].tag == "form":
                            break
                        input_type = tag_info.attrs.get("type", "text").lower()
                        input_name = tag_info.attrs.get("name", "").lower()
                        if input_type == "hidden" and any(csrf in input_name for csrf in ["csrf", "token", "_token"]):
                            has_csrf_input = True
                            break

                if not has_csrf_input and not has_csrf_meta:
                    self.findings.append({
                        "id": f"csrf_form_{len(self.findings)}",
                        "title": "Missing CSRF Token in Form",
                        "severity": "medium",
                        "confidence": "high",
                        "category": "csrf",
                        "file": self.file_path,
                        "line": form.line,
                        "form_action": action,
                        "form_method": method,
                        "description": f"Form with {method} method lacks CSRF token protection.",
                        "remediation": "Add a hidden input field with CSRF token: <input type='hidden' name='_token' value='{{ csrf_token() }}'>",
                        "poc": "Attacker can submit form from different origin without CSRF protection.",
                    })

    def check_sensitive_info(self):
        """检查敏感信息泄露"""
        sensitive_keywords = [
            "password", "passwd", "secret", "api_key", "apikey", "token",
            "private_key", "ssh_key", "auth_token", "access_token",
            "session_id", "sessionid", "jwt", "bearer",
        ]

        for tag_info in self.tags:
            if tag_info.tag == "input":
                input_type = tag_info.attrs.get("type", "text").lower()
                name = tag_info.attrs.get("name", "").lower()
                placeholder = tag_info.attrs.get("placeholder", "").lower()

                # 检查密码字段是否没有 autocomplete="off" 或 autocomplete="new-password"
                if input_type == "password":
                    autocomplete = tag_info.attrs.get("autocomplete", "").lower()
                    if autocomplete not in ["off", "new-password", "current-password"]:
                        self.findings.append({
                            "id": f"sensitive_autocomplete_{len(self.findings)}",
                            "title": "Password Field Lacks Proper Autocomplete",
                            "severity": "low",
                            "confidence": "medium",
                            "category": "sensitive_data",
                            "file": self.file_path,
                            "line": tag_info.line,
                            "description": "Password field should use autocomplete='new-password' or 'off'.",
                            "remediation": "Add autocomplete='new-password' to password input fields.",
                            "poc": "Browser may auto-fill sensitive password information.",
                        })

            # 检查 URL 中的敏感参数
            if tag_info.tag == "a" and "href" in tag_info.attrs:
                href = tag_info.attrs["href"]
                for keyword in sensitive_keywords:
                    if f"{keyword}=" in href.lower():
                        self.findings.append({
                            "id": f"sensitive_url_{len(self.findings)}",
                            "title": f"Sensitive Parameter '{keyword}' in URL",
                            "severity": "medium",
                            "confidence": "high",
                            "category": "sensitive_data",
                            "file": self.file_path,
                            "line": tag_info.line,
                            "code": href[:200],
                            "description": f"URL contains potentially sensitive parameter: {keyword}",
                            "remediation": "Move sensitive parameters to POST body or session storage.",
                            "poc": "Sensitive data may leak via browser history, server logs, or referer headers.",
                        })

    def check_insecure_iframe(self):
        """检查不安全的 iframe"""
        for iframe in self.iframes:
            src = iframe.attrs.get("src", "")
            sandbox = iframe.attrs.get("sandbox", "")

            # 检查 http 协议
            if src.startswith("http://"):
                self.findings.append({
                    "id": f"insecure_http_iframe_{len(self.findings)}",
                    "title": "Iframe Uses HTTP Protocol",
                    "severity": "medium",
                    "confidence": "high",
                    "category": "insecure_protocol",
                    "file": self.file_path,
                    "line": iframe.line,
                    "code": src[:200],
                    "description": "Iframe uses insecure HTTP protocol.",
                    "remediation": "Use HTTPS protocol for iframe src.",
                    "poc": "Content can be intercepted or modified in transit.",
                })

            # 检查没有 sandbox 属性（允许外部域）
            if not sandbox and src.startswith("http"):
                parsed = urlparse(src)
                if parsed.netloc and parsed.netloc != "about:blank":
                    self.findings.append({
                        "id": f"missing_sandbox_{len(self.findings)}",
                        "title": "Iframe Missing Sandbox Attribute",
                        "severity": "low",
                        "confidence": "medium",
                        "category": "sandbox",
                        "file": self.file_path,
                        "line": iframe.line,
                        "code": src[:200],
                        "description": "Iframe lacks sandbox attribute for security restrictions.",
                        "remediation": "Add sandbox attribute to restrict iframe capabilities.",
                        "poc": "Iframe may execute scripts, submit forms, or navigate top-level window.",
                    })

            # 检查 allow-same-origin 且没有其他限制
            if sandbox and "allow-same-origin" in sandbox:
                restrictions = sandbox.split()
                if len(restrictions) == 1:  # 只有 allow-same-origin
                    self.findings.append({
                        "id": f"weak_sandbox_{len(self.findings)}",
                        "title": "Iframe Sandbox Only Allows Same-Origin",
                        "severity": "low",
                        "confidence": "medium",
                        "category": "sandbox",
                        "file": self.file_path,
                        "line": iframe.line,
                        "code": sandbox,
                        "description": "Sandbox with only allow-same-origin provides minimal protection.",
                        "remediation": "Add more sandbox restrictions or remove allow-same-origin.",
                        "poc": "Iframe can access same-origin resources and scripts.",
                    })

    def check_insecure_resources(self):
        """检查不安全的外部资源引用"""
        for tag_info in self.tags:
            src_attrs = []
            if tag_info.tag == "script":
                src_attrs = [("src", "javascript")]
            elif tag_info.tag == "link":
                rel = tag_info.attrs.get("rel", "").lower()
                if rel in ["stylesheet", "icon"]:
                    src_attrs = [("href", "css/icon")]
            elif tag_info.tag == "img":
                src_attrs = [("src", "image")]

            for attr, resource_type in src_attrs:
                if attr in tag_info.attrs:
                    value = tag_info.attrs[attr]
                    if value.startswith("http://"):
                        self.findings.append({
                            "id": f"insecure_resource_{len(self.findings)}",
                            "title": f"External {resource_type} Resource Uses HTTP",
                            "severity": "medium",
                            "confidence": "high",
                            "category": "insecure_protocol",
                            "file": self.file_path,
                            "line": tag_info.line,
                            "code": value[:200],
                            "description": f"{resource_type} resource loaded over insecure HTTP.",
                            "remediation": "Use HTTPS for all external resources.",
                            "poc": "Resource can be intercepted or modified (MITM attack).",
                        })

    def check_content_security_policy(self):
        """检查 Content-Security-Policy"""
        has_csp = False
        for meta in self.metatags:
            http_equiv = meta.attrs.get("http-equiv", "").lower()
            if http_equiv == "content-security-policy":
                has_csp = True
                csp_content = meta.attrs.get("content", "")

                # 检查 unsafe-inline
                if "unsafe-inline" in csp_content:
                    self.findings.append({
                        "id": f"csp_unsafe_inline_{len(self.findings)}",
                        "title": "CSP Contains unsafe-inline",
                        "severity": "medium",
                        "confidence": "high",
                        "category": "csp",
                        "file": self.file_path,
                        "line": meta.line,
                        "code": csp_content[:200],
                        "description": "Content-Security-Policy allows unsafe-inline, which defeats XSS protection.",
                        "remediation": "Remove unsafe-inline and use nonces or hashes for inline scripts.",
                        "poc": "Inline scripts bypass CSP protections.",
                    })

                # 检查 unsafe-eval
                if "unsafe-eval" in csp_content:
                    self.findings.append({
                        "id": f"csp_unsafe_eval_{len(self.findings)}",
                        "title": "CSP Contains unsafe-eval",
                        "severity": "high",
                        "confidence": "high",
                        "category": "csp",
                        "file": self.file_path,
                        "line": meta.line,
                        "code": csp_content[:200],
                        "description": "Content-Security-Policy allows unsafe-eval, which enables eval() and similar functions.",
                        "remediation": "Remove unsafe-eval to prevent dynamic code execution.",
                        "poc": "eval() calls can execute arbitrary code.",
                    })

        # 如果没有 CSP，给出建议
        if not has_csp:
            self.findings.append({
                "id": f"missing_csp_{len(self.findings)}",
                "title": "Missing Content-Security-Policy",
                "severity": "low",
                "confidence": "high",
                "category": "csp",
                "file": self.file_path,
                "line": 1,
                "description": "No Content-Security-Policy meta tag found.",
                "remediation": "Add CSP meta tag to restrict resource loading and prevent XSS.",
                "poc": "XSS attacks are easier without CSP restrictions.",
            })

    def check_http_mixed_content(self):
        """检查混合内容（HTTPS 页面引用 HTTP 资源）"""
        for tag_info in self.tags:
            for attr, value in tag_info.attrs.items():
                if isinstance(value, str) and value.startswith("http://"):
                    self.findings.append({
                        "id": f"mixed_content_{len(self.findings)}",
                        "title": "Mixed Content: HTTP Resource",
                        "severity": "low",
                        "confidence": "medium",
                        "category": "mixed_content",
                        "file": self.file_path,
                        "line": tag_info.line,
                        "tag": tag_info.tag,
                        "attribute": attr,
                        "code": value[:200],
                        "description": f"{tag_info.tag} tag with {attr} attribute uses HTTP.",
                        "remediation": "Use HTTPS for all external resources.",
                        "poc": "Resource may be blocked or cause security warnings.",
                    })

    def check_unsafe_eval(self):
        """检查脚本中的 eval() 使用"""
        if not self.script_content:
            return

        eval_patterns = [
            (r'\beval\s*\(', "eval() function"),
            (r'\bFunction\s*\(', "Function() constructor"),
            (r'\bsetTimeout\s*\(\s*["\'].*?\b\b', "setTimeout with string"),
            (r'\bsetInterval\s*\(\s*["\'].*?\b\b', "setInterval with string"),
        ]

        for pattern, desc in eval_patterns:
            for match in re.finditer(pattern, self.script_content, re.IGNORECASE):
                # 计算行号
                line_before = self.script_content[:match.start()].count("\n") + 1
                self.findings.append({
                    "id": f"unsafe_eval_{len(self.findings)}",
                    "title": f"Use of {desc}",
                    "severity": "high",
                    "confidence": "high",
                    "category": "unsafe_eval",
                    "file": self.file_path,
                    "line": line_before,
                    "code": self.script_content[match.start():match.start() + 50].strip(),
                    "description": f"Script contains unsafe {desc}, which can lead to code injection.",
                    "remediation": "Avoid eval() and Function(). Use function references instead.",
                    "poc": "User input can be passed to eval() leading to arbitrary code execution.",
                })

    def check_dom_xss_patterns(self):
        """检查 DOM XSS 模式"""
        dangerous_sinks = [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'document\.write\s*\(',
            r'\.insertAdjacentHTML\s*\(',
            r'eval\s*\(',
            r'new\s+Function\s*\(',
            r'location\s*=',
            r'window\.location\s*=',
            r'location\.href\s*=',
            r'location\.hash\s*=',
        ]

        user_input_sources = [
            r'window\.location',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.referrer',
            r'\.cookie',
            r'localStorage',
            r'sessionStorage',
        ]

        # 在脚本内容中检查
        if self.script_content:
            for sink in dangerous_sinks:
                for match in re.finditer(sink, self.script_content, re.IGNORECASE):
                    # 检查附近是否有用户输入
                    context_start = max(0, match.start() - 200)
                    context_end = min(len(self.script_content), match.end() + 200)
                    context = self.script_content[context_start:context_end]

                    for source in user_input_sources:
                        if re.search(source, context, re.IGNORECASE):
                            line_before = self.script_content[:match.start()].count("\n") + 1
                            self.findings.append({
                                "id": f"dom_xss_{len(self.findings)}",
                                "title": "Potential DOM XSS",
                                "severity": "high",
                                "confidence": "medium",
                                "category": "dom_xss",
                                "file": self.file_path,
                                "line": line_before,
                                "code": self.script_content[match.start():match.end() + 50].strip(),
                                "description": f"DOM XSS sink {sink.strip()} may be influenced by user input.",
                                "remediation": "Use textContent, setAttribute, or sanitize HTML before inserting.",
                                "poc": "Attacker can inject HTML/JavaScript via URL parameters or other sources.",
                            })
                            break


class HTMIAudit:
    """HTML 审计主类"""

    def __init__(self, project_root: str, output_dir: str):
        self.project_root = os.path.abspath(project_root)
        self.output_dir = os.path.abspath(output_dir)
        self.all_findings = []

    def run(self):
        """运行审计"""
        print(f"Starting HTML Security Audit...")
        print(f"Project: {self.project_root}")
        print(f"Output: {self.output_dir}")

        html_files = walk_html_files(self.project_root)
        print(f"Found {len(html_files)} HTML files to analyze")

        for file_path in html_files:
            self.audit_file(file_path)

        self.write_report()
        self.print_summary()

    def audit_file(self, file_path: str):
        """审计单个文件"""
        try:
            content = read_text(file_path)
            parser = HTMLSecurityParser(file_path)
            parser.feed(content)
            parser.analyze()

            for finding in parser.findings:
                finding["relative_path"] = os.path.relpath(file_path, self.project_root)

            self.all_findings.extend(parser.findings)
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")

    def write_report(self):
        """写入审计报告"""
        os.makedirs(self.output_dir, exist_ok=True)

        # 写入 JSON 报告
        report = {
            "summary": self.get_summary(),
            "findings": self.all_findings,
        }

        json_path = os.path.join(self.output_dir, "html_audit_report.json")
        write_json(json_path, report)
        print(f"\nReport written to: {json_path}")

        # 写入 Markdown 报告
        md_path = os.path.join(self.output_dir, "html_audit_report.md")
        self.write_markdown_report(md_path)
        print(f"Markdown report: {md_path}")

    def get_summary(self) -> Dict:
        """获取审计摘要"""
        summary = {
            "total_findings": len(self.all_findings),
            "by_category": {},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_file": {},
        }

        for finding in self.all_findings:
            category = finding.get("category", "unknown")
            severity = finding.get("severity", "low")
            file_path = finding.get("file", "")

            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
            summary["by_file"][file_path] = summary["by_file"].get(file_path, 0) + 1

        return summary

    def write_markdown_report(self, path: str):
        """写入 Markdown 格式报告"""
        summary = self.get_summary()

        lines = [
            "# HTML Security Audit Report",
            "",
            f"**Project**: {self.project_root}",
            f"**Total Findings**: {summary['total_findings']}",
            "",
            "## Summary by Severity",
            "",
            f"- **Critical**: {summary['by_severity']['critical']}",
            f"- **High**: {summary['by_severity']['high']}",
            f"- **Medium**: {summary['by_severity']['medium']}",
            f"- **Low**: {summary['by_severity']['low']}",
            "",
            "## Summary by Category",
            "",
        ]

        for category, count in sorted(summary["by_category"].items()):
            lines.append(f"- **{category}**: {count}")

        lines.extend(["", "## Detailed Findings", ""])

        # 按严重程度分组
        severity_order = ["critical", "high", "medium", "low"]
        for severity in severity_order:
            severity_findings = [f for f in self.all_findings if f.get("severity") == severity]
            if not severity_findings:
                continue

            lines.extend([
                f"### {severity.upper()} ({len(severity_findings)})",
                "",
            ])

            for finding in severity_findings:
                rel_path = finding.get("relative_path", finding.get("file", "unknown"))
                line = finding.get("line", "?")
                title = finding.get("title", "Unknown")
                description = finding.get("description", "")
                remediation = finding.get("remediation", "")

                lines.extend([
                    f"#### {title}",
                    "",
                    f"- **File**: `{rel_path}:{line}`",
                    f"- **Category**: {finding.get('category', 'unknown')}",
                    f"- **Description**: {description}",
                    f"- **Remediation**: {remediation}",
                    "",
                ])

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def print_summary(self):
        """打印审计摘要"""
        summary = self.get_summary()
        print("\n" + "=" * 60)
        print("AUDIT SUMMARY")
        print("=" * 60)
        print(f"Total Findings: {summary['total_findings']}")
        print("\nBy Severity:")
        for severity in ["critical", "high", "medium", "low"]:
            count = summary["by_severity"][severity]
            if count > 0:
                print(f"  {severity.upper()}: {count}")
        print("\nBy Category:")
        for category, count in sorted(summary["by_category"].items()):
            print(f"  {category}: {count}")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="HTML Security Audit Tool")
    parser.add_argument("--project", required=True, help="Project root directory")
    parser.add_argument("--out", default=None, help="Output directory")
    args = parser.parse_args()

    project_root = os.path.abspath(args.project)

    if args.out:
        output_dir = os.path.abspath(args.out)
    else:
        output_dir = os.path.join(os.path.dirname(project_root), f"{os.path.basename(project_root)}_html_audit")

    auditor = HTMIAudit(project_root, output_dir)
    auditor.run()


if __name__ == "__main__":
    main()
