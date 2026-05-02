import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'wyqy.db'}")

HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "10"))
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

SCAN_CATEGORIES = {
    "spring": {
        "name": "Spring Framework",
        "description": "Spring生态漏洞集合",
        "modules": [
            "spring4shell",
            "spring_spel",
            "spring_actuator",
            "spring_cloud_gateway",
            "spring_cloud_function",
            "spring_cloud_dataflow",
            "spring_h2_rce",
        ],
    },
    "shiro": {
        "name": "Apache Shiro",
        "description": "Shiro认证框架漏洞",
        "modules": [
            "shiro_deserialization",
            "shiro_auth_bypass",
        ],
    },
    "log4j2": {
        "name": "Log4j2",
        "description": "Log4j2漏洞集合",
        "modules": [
            "log4j2_jndi",
        ],
    },
    "fastjson": {
        "name": "Fastjson",
        "description": "Fastjson反序列化漏洞",
        "modules": [
            "fastjson_rce",
        ],
    },
    "nacos": {
        "name": "Nacos",
        "description": "Nacos配置中心漏洞",
        "modules": [
            "nacos_auth_bypass",
            "nacos_rce",
        ],
    },
    "druid": {
        "name": "Druid",
        "description": "Druid监控面板漏洞",
        "modules": [
            "druid_unauth",
        ],
    },
    "tomcat": {
        "name": "Apache Tomcat",
        "description": "Tomcat服务器漏洞",
        "modules": [
            "tomcat_manager_unauth",
            "tomcat_cve_2023_28708",
        ],
    },
    "struts2": {
        "name": "Apache Struts2",
        "description": "Struts2框架漏洞",
        "modules": [
            "struts2_ognl",
            "struts2_devmode",
        ],
    },
    "thinkphp": {
        "name": "ThinkPHP",
        "description": "ThinkPHP框架RCE漏洞",
        "modules": [
            "thinkphp_rce",
        ],
    },
    "weblogic": {
        "name": "Oracle WebLogic",
        "description": "WebLogic反序列化/SSRF漏洞",
        "modules": [
            "weblogic_vuln",
        ],
    },
    "redis": {
        "name": "Redis",
        "description": "Redis未授权访问漏洞",
        "modules": [
            "redis_unauth",
        ],
    },
    "confluence": {
        "name": "Atlassian Confluence",
        "description": "Confluence RCE漏洞",
        "modules": [
            "confluence_rce",
        ],
    },
    "f5": {
        "name": "F5 BIG-IP",
        "description": "F5 BIG-IP设备漏洞",
        "modules": [
            "f5_bigip_rce",
        ],
    },
    "jenkins": {
        "name": "Jenkins",
        "description": "Jenkins CI/CD漏洞",
        "modules": [
            "jenkins_vuln",
        ],
    },
    "flink": {
        "name": "Apache Flink",
        "description": "Flink未授权访问漏洞",
        "modules": [
            "flink_unauth",
        ],
    },
    "xxljob": {
        "name": "XXL-JOB",
        "description": "XXL-JOB执行器RCE漏洞",
        "modules": [
            "xxljob_rce",
        ],
    },
    "nginx": {
        "name": "Nginx",
        "description": "Nginx配置错误漏洞",
        "modules": [
            "nginx_vuln",
        ],
    },
    "elasticsearch": {
        "name": "Elasticsearch",
        "description": "Elasticsearch未授权访问漏洞",
        "modules": [
            "elasticsearch_unauth",
        ],
    },
}

RISK_LEVELS = {
    "critical": {"score": 10, "color": "#ff0000", "label": "严重"},
    "high": {"score": 7, "color": "#ff6600", "label": "高危"},
    "medium": {"score": 4, "color": "#ffcc00", "label": "中危"},
    "low": {"score": 1, "color": "#00cc00", "label": "低危"},
    "info": {"score": 0, "color": "#0066ff", "label": "信息"},
}
