import base64
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("shiro_deserialization")


@register_scanner
class ShiroDeserializationScanner(BaseScanner):
    name = "Apache Shiro RememberMe 反序列化漏洞"
    description = "Shiro框架RememberMe功能使用硬编码AES密钥，可构造恶意Cookie实现反序列化RCE"
    category = "shiro"
    module = "shiro_deserialization"
    risk_level = "critical"
    risk_score = 9
    cve_ids = ["CVE-2016-4437", "CVE-2020-1957", "CVE-2020-11989"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2016-4437",
        "https://issues.apache.org/jira/browse/SHIRO-550",
    ]
    fix_suggestion = "升级Shiro至1.4.2+，使用随机生成的密钥替换默认密钥，禁用RememberMe功能"

    DEFAULT_KEYS = [
        "kPH+bIxk5D2deZiIxcaaaA==",
        "4AvVhmFLUs0KTA3Kprsdag==",
        "Z3VucwAAAAAAAAAAAAAAAA==",
        "fCq+/xW488hMTCD+cmJ3aQ==",
        "0AvVhmFLUs0KTA3Kprsdag==",
        "1AvVhdsgUs0FSA3SDFAdag==",
        "2AvVhdsgUs0FSA3SDFAdag==",
        "3AvVhmFLUs0KTA3Kprsdag==",
        "wGiHplamyXlVB11UXWol8g==",
        "6ZmI6I2j5Y+R5aSn5ZOlAA==",
        "r0e3c16IdVkouZgk1TKVMg==",
        "5aaC5qKm5oqA5pyvAAAAAA==",
        "bWljcm9zAAAAAAAAAAAAAA==",
        "ZUdsaGJByDAsScdg6hKfJQ==",
        "L7RioUULEFhRyxM7a2R/Yg==",
        "RVZBTl9XSUxMX0JZUEFSQU0=",
    ]

    def check(self) -> bool:
        found = False
        login_paths = ["/", "/login", "/admin/login", "/index.html"]
        for path in login_paths:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            has_shiro = False
            if "rememberMe" in resp.text:
                has_shiro = True
            set_cookie = resp.headers.get("Set-Cookie", "")
            if "rememberMe" in set_cookie:
                has_shiro = True

            if has_shiro:
                self.add_result(
                    name="Shiro RememberMe功能检测",
                    risk_level="info",
                    risk_score=0,
                    target_url=url,
                    description="检测到Shiro框架RememberMe功能",
                    evidence="响应中包含rememberMe字段",
                )

                for key in self.DEFAULT_KEYS:
                    try:
                        test_data = b"test_vulnark_check"
                        padded_key = base64.b64decode(key)

                        from app.utils.helper import md5 as md5_func
                        import os
                        random_iv = os.urandom(16)

                        cookie_payload = self._encrypt_payload(padded_key, random_iv, test_data)
                        cookie_value = base64.b64encode(cookie_payload).decode()

                        headers = {"Cookie": f"rememberMe={cookie_value}"}
                        check_resp = http_request("GET", url, headers=headers)
                        if check_resp is None:
                            continue

                        set_cookie_check = check_resp.headers.get("Set-Cookie", "")
                        if "rememberMe=deleteMe" not in set_cookie_check and check_resp.status_code == 200:
                            self.add_result(
                                name=f"Shiro默认密钥 (Key: {key[:8]}...)",
                                risk_level="critical",
                                risk_score=9,
                                target_url=url,
                                detail=f"Shiro使用默认AES密钥，密钥: {key}",
                                payload=f"rememberMe={cookie_value}",
                                evidence=f"使用默认密钥 {key} 未被拒绝(未返回deleteMe)",
                            )
                            found = True
                            break
                    except Exception as e:
                        logger.debug(f"Key test failed for {key[:8]}...: {e}")
                        continue

                break

        return found

    @staticmethod
    def _encrypt_payload(key, iv, data):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ct
