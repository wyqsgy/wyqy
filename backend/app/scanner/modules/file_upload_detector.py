"""
File Upload Vulnerability Scanner
Detects unrestricted file upload, double extension bypass, MIME type bypass
"""
import os
import re
import urllib.parse
from app.scanner.base import BaseScanner
from app.core.http_client import get_client


class FileUploadDetector(BaseScanner):
    name = "文件上传漏洞"
    description = "检测目标是否存在任意文件上传漏洞，攻击者可上传WebShell获取服务器控制权"
    category = "file-upload"
    module = "file_upload_detector"
    risk_level = "critical"
    risk_score = 90
    cve_ids = []
    references = [
        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
    ]
    fix_suggestion = "实施文件类型白名单验证，限制上传目录执行权限，对上传文件进行病毒扫描，使用随机文件名存储。"

    TEST_EXTENSIONS = [
        ".php", ".php5", ".phtml", ".pht", ".php7",
        ".jsp", ".jspx", ".jspf",
        ".asp", ".aspx", ".asa", ".cer", ".cdx",
        ".war", ".jar",
        ".py", ".pl", ".cgi",
        ".shtml", ".stm",
    ]

    BYPASS_EXTENSIONS = [
        ".php.jpg", ".php;.jpg", ".php%00.jpg", ".php%0d%0a.jpg",
        ".php.", ".php .jpg", ".PhP", ".PHP",
        ".php/.jpg", ".php\\x00.jpg",
    ]

    def __init__(self, target: str):
        super().__init__(target)
        self._client = get_client()

    def _find_upload_forms(self, html: str) -> list:
        forms = []
        pattern = r'<form[^>]*?(?:enctype\s*=\s*["\']multipart/form-data["\'])[^>]*?>'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            form_start = match.start()
            form_end = html.find('</form>', match.end())
            if form_end == -1:
                form_end = len(html)
            form_html = html[form_start:form_end + 7]
            action_match = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            input_pattern = r'<input[^>]*?type\s*=\s*["\']file["\'][^>]*?>'
            file_inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            if file_inputs:
                name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', file_inputs[0], re.IGNORECASE)
                input_name = name_match.group(1) if name_match else "file"
                forms.append({"action": action, "input_name": input_name})
        return forms

    def check(self) -> bool:
        found_any = False

        try:
            resp = self._client.get(self.target, timeout=10)
            if not resp.status or not resp.body:
                return False
            html = resp.body.decode("utf-8", errors="replace")
            forms = self._find_upload_forms(html)

            if not forms:
                test_paths = ["/upload", "/upload.php", "/upload.aspx", "/file/upload",
                              "/admin/upload", "/api/upload", "/wp-admin/media-new.php",
                              "/ckeditor/upload", "/ueditor/upload", "/kindeditor/upload"]
                for path in test_paths:
                    try:
                        test_url = urllib.parse.urljoin(self.target, path)
                        test_resp = self._client.get(test_url, timeout=8)
                        if test_resp.status and test_resp.status == 200:
                            forms.append({"action": path, "input_name": "file"})
                    except Exception:
                        continue

            for form in forms[:3]:
                action_url = urllib.parse.urljoin(self.target, form["action"])
                test_content = b"<?php echo 'VULN_TEST_' . md5('upload_test'); ?>"

                for ext in self.TEST_EXTENSIONS[:5]:
                    try:
                        files = {form["input_name"]: (f"test{ext}", test_content, "application/octet-stream")}
                        upload_resp = self._client.post(action_url, files=files, timeout=10)
                        if upload_resp.status:
                            text = upload_resp.body.decode("utf-8", errors="replace") if upload_resp.body else ""
                            if "VULN_TEST_" in text or "upload" in text.lower():
                                found_any = True
                                self.add_result(
                                    name="任意文件上传漏洞",
                                    target_url=action_url,
                                    description=f"检测到文件上传漏洞，可上传{ext}文件，可能导致服务器被完全控制。",
                                    detail=f"上传接口: {action_url}\n测试扩展名: {ext}",
                                    payload=f"test{ext}",
                                    evidence=text[:500],
                                )
                                return True
                    except Exception:
                        continue

                for ext in self.BYPASS_EXTENSIONS[:5]:
                    try:
                        files = {form["input_name"]: (f"test{ext}", test_content, "image/jpeg")}
                        upload_resp = self._client.post(action_url, files=files, timeout=10)
                        if upload_resp.status:
                            text = upload_resp.body.decode("utf-8", errors="replace") if upload_resp.body else ""
                            if "VULN_TEST_" in text:
                                found_any = True
                                self.add_result(
                                    name="文件上传漏洞 (扩展名绕过)",
                                    target_url=action_url,
                                    description=f"检测到文件上传漏洞，可通过扩展名绕过技术上传恶意文件。",
                                    detail=f"上传接口: {action_url}\n绕过扩展名: {ext}",
                                    payload=f"test{ext}",
                                    evidence=text[:500],
                                )
                                return True
                    except Exception:
                        continue

        except Exception:
            pass

        return found_any
