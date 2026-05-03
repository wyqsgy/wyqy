"""
Fingerprint-to-POC Mapping Engine
DDDD2-style: match fingerprints to vulnerability modules, reduce 70%+ invalid requests
"""
from typing import Dict, List

FINGERPRINT_POC_MAP = {
    "Spring Framework": ["spring", "spring4shell", "spring_cloud_gateway", "spring_actuator"],
    "Spring Boot": ["spring", "spring4shell", "spring_actuator", "spring_cloud_gateway"],
    "Apache Shiro": ["shiro", "shiro_deserialization"],
    "Apache Tomcat": ["tomcat", "ajp_ghostcat"],
    "Apache Struts2": ["struts2"],
    "Apache Log4j": ["log4j2"],
    "Apache Flink": ["flink"],
    "Apache Nginx": ["nginx"],
    "Alibaba Fastjson": ["fastjson"],
    "Alibaba Nacos": ["nacos"],
    "Alibaba Druid": ["druid"],
    "ThinkPHP": ["thinkphp"],
    "Laravel": ["laravel"],
    "Yii2": ["yii2"],
    "WebLogic": ["weblogic"],
    "WebSphere": ["websphere"],
    "JBoss": ["jboss"],
    "Jetty": ["jetty"],
    "Redis": ["redis"],
    "MySQL": ["mysql"],
    "PostgreSQL": ["postgresql"],
    "MongoDB": ["mongodb"],
    "Elasticsearch": ["elasticsearch"],
    "Jenkins": ["jenkins"],
    "Confluence": ["confluence"],
    "Jira": ["jira"],
    "GitLab": ["gitlab"],
    "F5 BIG-IP": ["f5"],
    "Citrix": ["citrix"],
    "VMware": ["vmware"],
    "XXL-JOB": ["xxljob"],
    "Kubernetes": ["kubernetes"],
    "Docker": ["docker"],
    "PHP": ["php_common"],
    "Python": ["python_common"],
    "Java": ["java_common"],
    "Node.js": ["nodejs_common"],
    "IIS": ["iis"],
    "Express": ["express"],
    "Django": ["django"],
    "Flask": ["flask"],
    "Rails": ["rails"],
    "ASP.NET": ["aspnet"],
}

LANGUAGE_MODULE_MAP = {
    "Java": ["spring", "shiro", "log4j2", "fastjson", "tomcat", "struts2",
             "weblogic", "jenkins", "flink", "xxljob", "nacos", "druid",
             "confluence", "jira", "elasticsearch"],
    "PHP": ["thinkphp", "laravel", "yii2", "php_common"],
    "Python": ["django", "flask", "python_common"],
    "Ruby": ["rails"],
    "Node.js": ["express", "nodejs_common"],
    "C#": ["aspnet", "iis"],
}

MIDDLEWARE_MODULE_MAP = {
    "Nginx": ["nginx"],
    "Apache": ["apache_common"],
    "IIS": ["iis"],
    "Tomcat": ["tomcat", "ajp_ghostcat"],
    "WebLogic": ["weblogic"],
    "JBoss": ["jboss"],
    "Jetty": ["jetty"],
}


def match_modules(fingerprint: Dict) -> List[str]:
    matched = set()

    for fw in fingerprint.get("framework", []):
        name = fw.get("name", "")
        if name in FINGERPRINT_POC_MAP:
            matched.update(FINGERPRINT_POC_MAP[name])

    for lang in fingerprint.get("language", []):
        name = lang.get("name", "")
        if name in LANGUAGE_MODULE_MAP:
            matched.update(LANGUAGE_MODULE_MAP[name])

    for mw in fingerprint.get("middleware", []):
        name = mw.get("name", "")
        if name in MIDDLEWARE_MODULE_MAP:
            matched.update(MIDDLEWARE_MODULE_MAP[name])

    if not matched:
        matched.update(["common_web", "portscan", "fingerprint"])

    return sorted(matched)


def get_module_priority(module_name: str) -> int:
    priorities = {
        "spring4shell": 1, "log4j2": 1, "shiro_deserialization": 1,
        "fastjson": 1, "struts2": 1, "weblogic": 1,
        "spring_cloud_gateway": 2, "spring_actuator": 2,
        "nacos": 2, "druid": 2, "tomcat": 2, "flink": 2,
        "thinkphp": 2, "jenkins": 2, "confluence": 2,
        "redis": 3, "elasticsearch": 3, "xxljob": 3,
        "nginx": 3, "f5": 3, "gitlab": 3,
    }
    return priorities.get(module_name, 5)
