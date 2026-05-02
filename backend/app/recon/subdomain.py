import concurrent.futures
import socket
import time
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
from app.utils.logger import get_logger

logger = get_logger("subdomain")

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "manage", "manager", "dashboard", "panel",
    "api", "api2", "api3", "v1", "v2", "dev", "test",
    "staging", "pre", "preprod", "prod", "production",
    "stage", "demo", "sandbox", "beta", "alpha", "canary",
    "app", "apps", "mobile", "m", "wap", "h5",
    "blog", "forum", "bbs", "wiki", "docs", "doc",
    "shop", "store", "pay", "payment", "wallet",
    "cdn", "static", "assets", "media", "img", "image",
    "oss", "s3", "img", "video", "download", "file",
    "db", "database", "mysql", "redis", "mongo", "es",
    "git", "gitlab", "svn", "jenkins", "ci", "cd",
    "k8s", "kubernetes", "docker", "registry", "harbor",
    "monitor", "grafana", "prometheus", "zabbix", "nagios",
    "log", "elk", "kibana", "splunk", "graylog",
    "vpn", "ssl", "cert", "dns", "ns", "ns1", "ns2",
    "gateway", "proxy", "lb", "load", "ha",
    "oa", "crm", "erp", "hr", "finance", "bi",
    "security", "waf", "ids", "ips", "soc",
    "backup", "bak", "old", "archive", "temp", "tmp",
    "internal", "intranet", "corp", "office",
    "auth", "sso", "oauth", "cas", "ldap", "ad",
    "search", "sphinx", "solr", "elastic",
    "mq", "rabbitmq", "kafka", "activemq", "rocketmq",
    "cache", "memcached", "varnish",
    "config", "nacos", "consul", "etcd", "zookeeper",
    "msg", "notify", "push", "sms", "email",
    "data", "bigdata", "hadoop", "spark", "hive",
    "ai", "ml", "model", "train",
    "open", "public", "external", "edge",
    "www2", "www3", "m1", "m2",
    "mx", "mx1", "mx2", "relay",
    "ntp", "time", "whois",
    "vpn2", "sslvpn", "remote", "rdp",
    "chat", "im", "websocket", "ws",
    "cloud", "aws", "azure", "gcp", "aliyun",
    "status", "health", "ping", "alive",
]


class SubdomainEnumerator:
    def __init__(self, domain: str, timeout: float = 2.0, max_workers: int = 50):
        self.domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        self.timeout = timeout
        self.max_workers = max_workers
        self.found: List[Dict] = []
        self.resolved_ips: Set[str] = set()

    def enumerate(self, wordlist: Optional[List[str]] = None) -> Dict:
        if wordlist is None:
            wordlist = COMMON_SUBDOMAINS
        logger.info(f"Starting subdomain enumeration for {self.domain} with {len(wordlist)} words")
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {
                executor.submit(self._resolve_subdomain, f"{word}.{self.domain}"): word
                for word in wordlist
            }
            for future in concurrent.futures.as_completed(future_map):
                result = future.result()
                if result:
                    self.found.append(result)
                    self.resolved_ips.add(result["ip"])
        elapsed = time.time() - start_time
        self.found.sort(key=lambda x: x["subdomain"])
        return {
            "domain": self.domain,
            "total_found": len(self.found),
            "unique_ips": len(self.resolved_ips),
            "subdomains": self.found,
            "elapsed_seconds": round(elapsed, 2),
        }

    def _resolve_subdomain(self, subdomain: str) -> Optional[Dict]:
        try:
            ip = socket.gethostbyname(subdomain)
            return {
                "subdomain": subdomain,
                "ip": ip,
                "is_cdn": self._check_cdn(ip, subdomain),
                "ports": [],
            }
        except (socket.gaierror, socket.timeout):
            return None
        except Exception as e:
            logger.debug(f"Error resolving {subdomain}: {e}")
            return None

    def _check_cdn(self, ip: str, subdomain: str) -> bool:
        cdn_cnames = ["cdn", "cloudfront", "akamaiedge", "fastly",
                      "alicdn", "cdngslb", "cloudflare", "cdn77"]
        return any(c in subdomain for c in cdn_cnames)

    def quick_enum(self) -> Dict:
        quick_words = [
            "www", "mail", "api", "admin", "dev", "test",
            "staging", "app", "cdn", "static", "blog",
            "git", "jenkins", "monitor", "vpn", "portal",
        ]
        return self.enumerate(quick_words)


def enumerate_subdomains(domain: str, timeout: float = 2.0,
                         max_workers: int = 50,
                         wordlist: Optional[List[str]] = None) -> Dict:
    enumerator = SubdomainEnumerator(domain, timeout, max_workers)
    return enumerator.enumerate(wordlist)


def quick_enum_subdomains(domain: str) -> Dict:
    enumerator = SubdomainEnumerator(domain)
    return enumerator.quick_enum()
