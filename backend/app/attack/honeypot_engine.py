import re
import time
from typing import Dict, List, Optional
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("honeypot_engine")

HONEYPOT_SIGNATURES = {
    "hfish": {
        "indicators": [
            "/api/v1/getip", "/terminal", "/tmp/",
            "hfish", "蜜罐", "honeypot",
        ],
        "headers": ["x-powered-by: hfish"],
        "title": ["HFish", "蜜罐管理平台"],
    },
    "opencanary": {
        "indicators": [
            "opencanary", "OpenCanary",
        ],
        "ports": {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP",
                  3306: "MySQL", 6379: "Redis", 9200: "Elasticsearch"},
    },
    "canarytokens": {
        "indicators": [
            "canarytokens", "canary", "thinkst",
        ],
    },
    "kippo": {
        "indicators": [
            "kippo", "SSH-2.0-OpenSSH_5.",
        ],
        "ports": {22: "SSH"},
    },
    "cowrie": {
        "indicators": [
            "cowrie", "SSH-2.0-OpenSSH_6.",
        ],
        "ports": {22: "SSH", 23: "Telnet"},
    },
    "dionaea": {
        "indicators": [
            "dionaea", "SMB",
        ],
        "ports": {21: "FTP", 445: "SMB", 3306: "MySQL"},
    },
    "glastopf": {
        "indicators": [
            "glastopf", "webhoneypot",
        ],
    },
    "snare": {
        "indicators": [
            "snare", "tanner",
        ],
    },
    "honeypy": {
        "indicators": [
            "honeypy", "HoneyPy",
        ],
    },
    "elasticpot": {
        "indicators": [
            "elasticpot", "You Know, for Search",
        ],
        "ports": {9200: "Elasticsearch"},
    },
    "redis_honeypot": {
        "indicators": [
            "+OK\r\n$-1", "redis_version:9",
        ],
        "ports": {6379: "Redis"},
    },
    "mysql_honeypot": {
        "indicators": [
            "mysql_native_password", "honeypot",
        ],
        "ports": {3306: "MySQL"},
    },
    "weblogic_honeypot": {
        "indicators": [
            "Console", "WebLogic", "bea_wls",
        ],
        "ports": {7001: "WebLogic"},
    },
}


class HoneypotDetector:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def detect(self, target_url: str) -> Dict:
        result = {
            "is_honeypot": False,
            "honeypot_type": None,
            "confidence": 0,
            "indicators": [],
            "risk_warning": "",
        }

        indicators = []
        max_confidence = 0

        indicators.extend(self._check_http_behavior(target_url))
        indicators.extend(self._check_response_anomaly(target_url))
        indicators.extend(self._check_known_signatures(target_url))
        indicators.extend(self._check_time_anomaly(target_url))
        indicators.extend(self._check_service_fingerprint(target_url))

        honeypot_scores = {}
        for ind in indicators:
            h_type = ind.get("type", "unknown")
            honeypot_scores.setdefault(h_type, 0)
            honeypot_scores[h_type] += ind.get("score", 0)

        for h_type, score in honeypot_scores.items():
            if score > max_confidence:
                max_confidence = score
                result.update({
                    "is_honeypot": True,
                    "honeypot_type": h_type,
                    "confidence": min(score, 100),
                    "indicators": [i for i in indicators if i.get("type") == h_type],
                    "risk_warning": f"目标疑似{h_type}蜜罐，置信度{min(score, 100)}%，建议停止扫描",
                })

        if not result["is_honeypot"] and indicators:
            result["indicators"] = indicators
            result["risk_warning"] = "检测到部分可疑特征，但未确认为蜜罐"

        return result

    def _check_http_behavior(self, url: str) -> List[Dict]:
        indicators = []
        try:
            resp1 = http_request("GET", url, timeout=self.timeout, verify=False)
            if not resp1:
                return indicators
            resp2 = http_request("GET", url, timeout=self.timeout, verify=False)
            if resp1.get("status_code") == 200 and resp2.get("status_code") == 200:
                body1 = str(resp1.get("text", ""))
                body2 = str(resp2.get("text", ""))
                if body1 == body2 and len(body1) > 1000:
                    if "login" in body1.lower() and "password" in body1.lower():
                        if len(body1) < 3000:
                            indicators.append({
                                "type": "static_login_page",
                                "detail": "登录页面完全静态，无动态内容",
                                "score": 25,
                            })
            error_paths = ["/nonexistent_path_12345", "/admin/config.php.bak", "/wp-config.php"]
            for path in error_paths:
                resp = http_request("GET", f"{url}{path}", timeout=self.timeout, verify=False)
                if resp and resp.get("status_code") == 200:
                    indicators.append({
                        "type": "all_paths_200",
                        "detail": f"任意路径{path}返回200，疑似蜜罐",
                        "score": 40,
                    })
                    break
        except Exception as e:
            logger.debug(f"HTTP行为检测异常: {e}")
        return indicators

    def _check_response_anomaly(self, url: str) -> List[Dict]:
        indicators = []
        try:
            resp = http_request("GET", url, timeout=self.timeout, verify=False)
            if not resp:
                return indicators
            headers = resp.get("headers", {})
            server = headers.get("server", "").lower()
            if any(hp in server for hp in ["honeypot", "canary", "kippo", "cowrie"]):
                indicators.append({
                    "type": "honeypot_header",
                    "detail": f"Server头包含蜜罐标识: {server}",
                    "score": 60,
                })
            if "set-cookie" not in str(headers).lower() and resp.get("status_code") == 200:
                indicators.append({
                    "type": "no_cookies",
                    "detail": "200响应不设置任何Cookie",
                    "score": 15,
                })
            resp_time = resp.get("response_time", 0)
            if resp_time and resp_time < 0.01:
                indicators.append({
                    "type": "instant_response",
                    "detail": f"响应速度异常快({resp_time:.4f}s)，可能是本地服务",
                    "score": 20,
                })
        except Exception as e:
            logger.debug(f"响应异常检测失败: {e}")
        return indicators

    def _check_known_signatures(self, url: str) -> List[Dict]:
        indicators = []
        check_paths = [
            "/api/v1/getip", "/api/v1/getsysteminfo",
            "/admin/setting", "/login", "/",
        ]
        for path in check_paths:
            try:
                resp = http_request("GET", f"{url}{path}", timeout=self.timeout, verify=False)
                if not resp:
                    continue
                body = str(resp.get("text", "")).lower()
                headers = str(resp.get("headers", {})).lower()
                for hp_name, hp_info in HONEYPOT_SIGNATURES.items():
                    for indicator in hp_info.get("indicators", []):
                        if indicator.lower() in body or indicator.lower() in headers:
                            indicators.append({
                                "type": hp_name,
                                "detail": f"路径{path}匹配{hp_name}特征: {indicator}",
                                "score": 50,
                            })
                    title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).lower()
                        for hp_title in hp_info.get("title", []):
                            if hp_title.lower() in title:
                                indicators.append({
                                    "type": hp_name,
                                    "detail": f"页面标题匹配{hp_name}: {title}",
                                    "score": 45,
                                })
            except Exception:
                continue
        return indicators

    def _check_time_anomaly(self, url: str) -> List[Dict]:
        indicators = []
        try:
            times = []
            for _ in range(3):
                start = time.time()
                http_request("GET", url, timeout=self.timeout, verify=False)
                times.append(time.time() - start)
            if times:
                avg_time = sum(times) / len(times)
                variance = sum((t - avg_time) ** 2 for t in times) / len(times)
                if variance < 0.0001 and avg_time < 0.05:
                    indicators.append({
                        "type": "timing_anomaly",
                        "detail": f"响应时间方差极低({variance:.6f})，疑似模拟服务",
                        "score": 20,
                    })
        except Exception:
            pass
        return indicators

    def _check_service_fingerprint(self, url: str) -> List[Dict]:
        indicators = []
        resp = http_request("GET", url, timeout=self.timeout, verify=False)
        if not resp:
            return indicators
        body = str(resp.get("text", ""))
        honeypot_frameworks = [
            ("Bootstrap 3", 10), ("jQuery 1.", 5),
            ("font-awesome 4", 5), ("adminlte", 15),
        ]
        for framework, score in honeypot_frameworks:
            if framework.lower() in body.lower():
                indicators.append({
                    "type": "generic_admin_template",
                    "detail": f"使用通用管理后台模板: {framework}",
                    "score": score,
                })
        if len(body) < 200 and "<form" in body.lower():
            indicators.append({
                "type": "minimal_form",
                "detail": "页面内容极简但包含表单",
                "score": 10,
            })
        return indicators


def detect_honeypot(target_url: str, timeout: int = 10) -> Dict:
    detector = HoneypotDetector(timeout)
    return detector.detect(target_url)
