from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("elasticsearch_unauth")


@register_scanner
class ElasticsearchUnauthScanner(BaseScanner):
    name = "Elasticsearch 未授权访问"
    description = "Elasticsearch未授权访问可导致数据泄露、索引删除"
    category = "elasticsearch"
    module = "elasticsearch_unauth"
    risk_level = "critical"
    risk_score = 9
    cve_ids = []
    references = [
        "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html",
    ]
    fix_suggestion = "启用X-Pack安全模块，配置认证和IP白名单"

    ENDPOINTS = [
        {"path": "/", "name": "Elasticsearch 集群信息泄露", "marker": "cluster_name", "risk_level": "high", "risk_score": 7},
        {"path": "/_cat/indices?v", "name": "Elasticsearch 索引列表泄露", "marker": "health", "risk_level": "critical", "risk_score": 9},
        {"path": "/_cat/nodes?v", "name": "Elasticsearch 节点信息泄露", "marker": "ip", "risk_level": "high", "risk_score": 7},
        {"path": "/_nodes/stats", "name": "Elasticsearch 节点统计信息泄露", "marker": "nodes", "risk_level": "medium", "risk_score": 6},
        {"path": "/_cluster/health", "name": "Elasticsearch 集群健康状态泄露", "marker": "status", "risk_level": "medium", "risk_score": 5},
        {"path": "/_cluster/settings", "name": "Elasticsearch 集群配置泄露", "marker": "persistent", "risk_level": "high", "risk_score": 7},
        {"path": "/_aliases", "name": "Elasticsearch 索引别名泄露", "risk_level": "medium", "risk_score": 5},
        {"path": "/_snapshot", "name": "Elasticsearch 快照仓库泄露", "marker": "type", "risk_level": "medium", "risk_score": 5},
        {"path": "/_plugins/security/authinfo", "name": "Elasticsearch 安全插件信息泄露", "marker": "user", "risk_level": "medium", "risk_score": 5},
    ]

    def check(self) -> bool:
        found = False
        for ep in self.ENDPOINTS:
            url = f"{self.target}{ep['path']}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code != 200:
                continue

            marker = ep.get("marker", "")
            if marker and marker not in resp.text:
                continue

            try:
                if ep["path"] in ["/", "/_cluster/health", "/_cluster/settings", "/_nodes/stats"]:
                    data = resp.json()
                    if "cluster_name" not in data and "status" not in data and "nodes" not in data and "persistent" not in data:
                        continue
            except Exception:
                pass

            self.add_result(
                name=ep["name"],
                risk_level=ep["risk_level"],
                risk_score=ep["risk_score"],
                target_url=url,
                detail=f"Elasticsearch端点未授权访问: {ep['path']}",
                response_snippet=resp.text[:500],
                evidence=f"未授权访问成功，状态码: {resp.status_code}",
            )
            found = True

        if found:
            self.add_result(
                name="Elasticsearch 敏感索引数据泄露风险",
                risk_level="critical",
                risk_score=9,
                target_url=f"{self.target}/_cat/indices?v",
                detail="未授权可列出所有索引并读取数据，可能包含用户敏感信息",
                fix_suggestion="1. 启用X-Pack安全\n2. 配置用户认证\n3. 限制监听IP",
            )

        return found
