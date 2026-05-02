import hashlib
import json
import re
import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("fingerprint")

WEB_FRAMEWORKS = {
    "Spring": {
        "headers": {"x-application-context": "", "server": "nginx"},
        "cookies": ["JSESSIONID", "SPRING_SECURITY_REMEMBER_ME_COOKIE"],
        "body_patterns": ["Whitelabel Error Page", "spring", "org.springframework"],
        "default_paths": ["/actuator/env", "/actuator/health"],
    },
    "Django": {
        "cookies": ["csrftoken", "sessionid"],
        "body_patterns": ["csrfmiddlewaretoken", "django", "DisallowedHost"],
        "default_paths": ["/admin/"],
    },
    "Flask": {
        "headers": {"server": "Werkzeug"},
        "body_patterns": ["werkzeug", "flask", "jinja2"],
    },
    "Laravel": {
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "body_patterns": ["laravel", "Illuminate\\"],
        "default_paths": ["/storage/logs/laravel.log"],
    },
    "ThinkPHP": {
        "body_patterns": ["thinkphp", "ThinkPHP", "think\\\\app"],
        "default_paths": ["/index.php?s=captcha"],
    },
    "Express": {
        "headers": {"x-powered-by": "Express"},
        "body_patterns": ["express"],
    },
    "Next.js": {
        "headers": {"x-powered-by": "Next.js"},
        "body_patterns": ["__NEXT_DATA__", "_next/static"],
    },
    "Ruby on Rails": {
        "cookies": ["_session_id", "_rails_session"],
        "headers": {"x-powered-by": "Phusion Passenger"},
        "body_patterns": ["rails", "ruby"],
    },
    "ASP.NET": {
        "headers": {"x-powered-by": "ASP.NET", "x-aspnet-version": ""},
        "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
        "body_patterns": ["__VIEWSTATE", "__EVENTVALIDATION", "asp.net"],
    },
    "PHP": {
        "headers": {"x-powered-by": "PHP/"},
        "cookies": ["PHPSESSID"],
    },
}

MIDDLEWARE_FINGERPRINTS = {
    "Nginx": {"headers": {"server": "nginx"}},
    "Apache": {"headers": {"server": "apache"}},
    "IIS": {"headers": {"server": "microsoft-iis"}},
    "Tomcat": {"headers": {"server": "apache-coyote"}, "body_patterns": ["Apache Tomcat"]},
    "WebLogic": {"body_patterns": ["WebLogic", "bea_wls"], "default_paths": ["/console"]},
    "JBoss": {"body_patterns": ["JBoss", "jboss"], "default_paths": ["/jmx-console/"]},
    "WildFly": {"body_patterns": ["WildFly"]},
    "Undertow": {"headers": {"server": "undertow"}},
    "Gunicorn": {"headers": {"server": "gunicorn"}},
    "Uvicorn": {"headers": {"server": "uvicorn"}},
    "Caddy": {"headers": {"server": "caddy"}},
    "LiteSpeed": {"headers": {"server": "litespeed"}},
    "OpenResty": {"headers": {"server": "openresty"}},
    "Tengine": {"headers": {"server": "tengine"}},
    "Jetty": {"body_patterns": ["Jetty"]},
    "WebSphere": {"body_patterns": ["WebSphere"]},
    "Resin": {"headers": {"server": "Resin"}},
}

CDN_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "cname": ["cloudflare"]},
    "AWS CloudFront": {"headers": ["x-amz-cf-id", "x-amz-cf-pop"], "cname": ["cloudfront"]},
    "Akamai": {"headers": ["x-akamai-transformed"], "cname": ["akamaiedge"]},
    "Fastly": {"headers": ["x-served-by", "x-cache"], "cname": ["fastly"]},
    "KeyCDN": {"headers": ["x-edge-location"], "cname": ["keycdn"]},
    "阿里云CDN": {"headers": ["eagleid", "x-swift-savetime"], "cname": ["alicdn", "cdngslb"]},
    "腾讯云CDN": {"headers": ["x-nws-log-uuid"], "cname": ["cdn"]},
    "华为云CDN": {"headers": ["x-hw-"], "cname": ["huaweicloud"]},
    "百度云CDN": {"headers": ["yunjiasu"], "cname": ["bdydns"]},
}

WAF_SIGNATURES_SIMPLE = {
    "Cloudflare WAF": {"headers": ["cf-ray", "server: cloudflare"], "block": ["cloudflare-nginx"]},
    "AWS WAF": {"headers": ["x-amzn-requestid"]},
    "ModSecurity": {"headers": ["server: apache"], "block": ["mod_security"]},
    "SafeDog": {"headers": ["waf/2.0", "safedog"]},
    "云盾": {"headers": ["yun-cdn"], "block": ["yundun"]},
    "创宇盾": {"headers": ["cdxy-yundun"], "block": ["yunsuo"]},
    "FortiWeb": {"headers": ["server: fortiweb"]},
}


class FingerprintEngine:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.parsed = urlparse(target_url)
        self.result = {
            "url": target_url,
            "framework": [],
            "language": [],
            "middleware": [],
            "cdn": [],
            "waf": [],
            "os": None,
            "server_info": {},
            "security_headers": {},
            "technologies": [],
        }

    def scan(self) -> Dict:
        resp = http_request("GET", self.target_url, timeout=self.timeout, verify=False)
        if not resp:
            return self.result
        headers = resp.get("headers", {})
        body = str(resp.get("text", ""))
        self._detect_framework(headers, body)
        self._detect_language(headers, body)
        self._detect_middleware(headers, body)
        self._detect_cdn(headers)
        self._detect_waf(headers, body)
        self._detect_os(headers, body)
        self._extract_server_info(headers)
        self._check_security_headers(headers)
        self._detect_technologies(headers, body)
        return self.result

    def _detect_framework(self, headers: dict, body: str):
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        cookies = headers.get("set-cookie", "").lower()
        body_lower = body.lower()
        for fw_name, sig in WEB_FRAMEWORKS.items():
            score = 0
            details = []
            for h_key, h_val in sig.get("headers", {}).items():
                if h_key.lower() in headers_lower:
                    if not h_val or h_val.lower() in headers_lower.get(h_key.lower(), ""):
                        score += 30
                        details.append(f"Header: {h_key}")
            for cookie in sig.get("cookies", []):
                if cookie.lower() in cookies:
                    score += 25
                    details.append(f"Cookie: {cookie}")
            for pattern in sig.get("body_patterns", []):
                if pattern.lower() in body_lower:
                    score += 20
                    details.append(f"Body: {pattern}")
            if score >= 30:
                self.result["framework"].append({
                    "name": fw_name,
                    "confidence": min(score, 100),
                    "evidence": details,
                })

    def _detect_language(self, headers: dict, body: str):
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        lang_signatures = {
            "PHP": ["x-powered-by: php", "phpsessid", ".php"],
            "Java": ["jsessionid", "x-application-context", "spring", "java.lang"],
            "Python": ["wsgi", "werkzeug", "gunicorn", "uvicorn", "django", "flask"],
            "Ruby": ["_session_id", "phusion passenger", "x-powered-by: phusion"],
            "Go": ["go-http-client", "gin"],
            "Node.js": ["x-powered-by: express", "__next_data"],
            "ASP.NET": ["x-aspnet-version", "aspxauth", "__viewstate"],
            "Perl": ["perl/", "cgi-bin"],
        }
        for lang, signs in lang_signatures.items():
            for sign in signs:
                if sign.lower() in str(headers_lower) or sign.lower() in body.lower():
                    self.result["language"].append({"name": lang, "evidence": sign})
                    break

    def _detect_middleware(self, headers: dict, body: str):
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()
        for mw_name, sig in MIDDLEWARE_FINGERPRINTS.items():
            for h_key, h_val in sig.get("headers", {}).items():
                if h_key.lower() in headers_lower:
                    if not h_val or h_val.lower() in headers_lower.get(h_key.lower(), ""):
                        self.result["middleware"].append({"name": mw_name, "evidence": f"Header: {h_key}"})
            for pattern in sig.get("body_patterns", []):
                if pattern.lower() in body_lower:
                    self.result["middleware"].append({"name": mw_name, "evidence": f"Body: {pattern}"})

    def _detect_cdn(self, headers: dict):
        headers_str = str(headers).lower()
        for cdn_name, sig in CDN_SIGNATURES.items():
            for header in sig.get("headers", []):
                if header.lower() in headers_str:
                    self.result["cdn"].append({"name": cdn_name, "evidence": header})
                    break

    def _detect_waf(self, headers: dict, body: str):
        headers_str = str(headers).lower()
        body_lower = body.lower()
        for waf_name, sig in WAF_SIGNATURES_SIMPLE.items():
            for header in sig.get("headers", []):
                if header.lower() in headers_str:
                    self.result["waf"].append({"name": waf_name, "evidence": header})
                    break
            for pattern in sig.get("block", []):
                if pattern.lower() in body_lower:
                    self.result["waf"].append({"name": waf_name, "evidence": f"Block: {pattern}"})

    def _detect_os(self, headers: dict, body: str):
        server = headers.get("server", "").lower()
        if any(w in server for w in ["win", "iis", "microsoft"]):
            self.result["os"] = "Windows"
        elif "ubuntu" in server or "debian" in server:
            self.result["os"] = "Linux (Debian/Ubuntu)"
        elif "centos" in server or "redhat" in server or "rhel" in server:
            self.result["os"] = "Linux (CentOS/RHEL)"
        elif "amzn" in server:
            self.result["os"] = "Linux (Amazon)"
        elif "alpine" in server:
            self.result["os"] = "Linux (Alpine)"
        elif "freebsd" in server:
            self.result["os"] = "FreeBSD"
        elif "ubuntu" in body.lower() or "debian" in body.lower():
            self.result["os"] = "Linux (Debian/Ubuntu)"

    def _extract_server_info(self, headers: dict):
        important_headers = [
            "server", "x-powered-by", "x-aspnet-version", "x-runtime",
            "x-request-id", "x-served-by", "x-cache", "via",
            "x-application-context", "x-frame-options",
        ]
        for h in important_headers:
            val = headers.get(h, "")
            if val:
                self.result["server_info"][h] = val

    def _check_security_headers(self, headers: dict):
        security_headers = {
            "strict-transport-security": {"name": "HSTS", "risk": "medium"},
            "content-security-policy": {"name": "CSP", "risk": "high"},
            "x-frame-options": {"name": "X-Frame-Options", "risk": "medium"},
            "x-content-type-options": {"name": "X-Content-Type-Options", "risk": "low"},
            "x-xss-protection": {"name": "X-XSS-Protection", "risk": "low"},
            "referrer-policy": {"name": "Referrer-Policy", "risk": "low"},
            "permissions-policy": {"name": "Permissions-Policy", "risk": "low"},
            "cross-origin-opener-policy": {"name": "COOP", "risk": "medium"},
        }
        for header, info in security_headers.items():
            value = headers.get(header, "")
            self.result["security_headers"][header] = {
                "name": info["name"],
                "present": bool(value),
                "value": value if value else None,
                "risk": info["risk"] if not value else None,
            }

    def _detect_technologies(self, headers: dict, body: str):
        tech_signatures = {
            "jQuery": r"jquery[.-](\d+\.\d+\.\d+)",
            "Bootstrap": r"bootstrap[.-](\d+\.\d+\.\d+)",
            "Vue.js": r"vue[.-](\d+\.\d+\.\d+)|vue\.js",
            "React": r"react[.-](\d+\.\d+\.\d+)|reactjs",
            "Angular": r"angular[.-](\d+\.\d+\.\d+)|angularjs",
            "WordPress": r"wp-content|wp-includes|wordpress",
            "Drupal": r"drupal|sites/default/files",
            "Joomla": r"joomla|/media/jui/",
            "Webpack": r"webpack",
            "Vite": r"/@vite/",
            "GraphQL": r"graphql|__schema",
            "Swagger": r"swagger|api-docs",
        }
        for tech, pattern in tech_signatures.items():
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex and match.group(1) else None
                self.result["technologies"].append({
                    "name": tech,
                    "version": version,
                })


def fingerprint_target(target_url: str, timeout: int = 10) -> Dict:
    engine = FingerprintEngine(target_url, timeout)
    return engine.scan()
