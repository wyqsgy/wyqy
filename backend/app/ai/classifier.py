import json
import os
from pathlib import Path
from app.ai.feature_extractor import extract_features, VulnFeatures
from app.config import DATA_DIR
from app.utils.logger import get_logger

logger = get_logger("ai_classifier")

MODEL_PATH = DATA_DIR / "classifier_model.json"


class VulnClassifier:
    """
    AI漏洞误报过滤分类器。
    使用基于规则的特征评分系统 + 可选的ML模型。
    """

    FEATURE_WEIGHTS = {
        "has_error_keyword": -2,
        "has_stacktrace": 3,
        "has_db_error": 5,
        "has_sql_keyword": 2,
        "has_command_output": 10,
        "has_file_read": 10,
        "has_jndi_error": 8,
        "has_auth_bypass": 4,
        "has_version_leak": -1,
        "has_default_creds": 6,
        "has_sensitive_data": 7,
        "content_type_match": -1,
        "payload_reflected": 5,
    }

    def __init__(self):
        self.ml_model = None
        self._load_ml_model()

    def _load_ml_model(self):
        if MODEL_PATH.exists():
            try:
                with open(MODEL_PATH, "r") as f:
                    self.ml_model = json.load(f)
                logger.info("Loaded ML classifier model")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")

    def classify(self, response_text: str, response_code: int = 0,
                 response_headers: dict = None, payload: str = "",
                 risk_level: str = "") -> dict:
        features = extract_features(response_text, response_code, response_headers, payload)

        rule_score = self._rule_based_score(features)

        ml_score = 0
        if self.ml_model:
            ml_score = self._ml_predict(features)

        combined_score = rule_score * 0.6 + ml_score * 0.4 if self.ml_model else rule_score

        confidence = min(max(int((combined_score + 10) / 20 * 100), 0), 100)
        is_true_positive = combined_score > 0
        false_positive_risk = max(0, min(100, 100 - confidence))

        return {
            "is_true_positive": is_true_positive,
            "confidence": confidence,
            "false_positive_risk": false_positive_risk,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "combined_score": combined_score,
            "features": {
                "has_error_keyword": features.has_error_keyword,
                "has_stacktrace": features.has_stacktrace,
                "has_db_error": features.has_db_error,
                "has_command_output": features.has_command_output,
                "has_jndi_error": features.has_jndi_error,
                "payload_reflected": features.payload_reflected,
                "has_sensitive_data": features.has_sensitive_data,
            },
            "verdict": self._get_verdict(combined_score, confidence),
        }

    def _rule_based_score(self, features: VulnFeatures) -> float:
        score = 0
        if features.has_command_output:
            score += self.FEATURE_WEIGHTS["has_command_output"]
        if features.has_file_read:
            score += self.FEATURE_WEIGHTS["has_file_read"]
        if features.has_jndi_error:
            score += self.FEATURE_WEIGHTS["has_jndi_error"]
        if features.has_db_error:
            score += self.FEATURE_WEIGHTS["has_db_error"]
        if features.has_sensitive_data:
            score += self.FEATURE_WEIGHTS["has_sensitive_data"]
        if features.has_default_creds:
            score += self.FEATURE_WEIGHTS["has_default_creds"]
        if features.has_stacktrace:
            score += self.FEATURE_WEIGHTS["has_stacktrace"]
        if features.payload_reflected:
            score += self.FEATURE_WEIGHTS["payload_reflected"]
        if features.has_auth_bypass:
            score += self.FEATURE_WEIGHTS["has_auth_bypass"]
        if features.has_sql_keyword:
            score += self.FEATURE_WEIGHTS["has_sql_keyword"]
        if features.has_error_keyword:
            score += self.FEATURE_WEIGHTS["has_error_keyword"]
        if features.has_version_leak:
            score += self.FEATURE_WEIGHTS["has_version_leak"]
        if features.content_type_match:
            score += self.FEATURE_WEIGHTS["content_type_match"]
        return score

    def _ml_predict(self, features: VulnFeatures) -> float:
        if not self.ml_model or "weights" not in self.ml_model:
            return 0
        weights = self.ml_model["weights"]
        bias = self.ml_model.get("bias", 0)
        vec = features.to_vector()
        if len(vec) != len(weights):
            return 0
        dot = sum(w * v for w, v in zip(weights, vec)) + bias
        return max(-10, min(10, dot))

    @staticmethod
    def _get_verdict(score: float, confidence: int) -> str:
        if score >= 8 and confidence >= 80:
            return "HIGH_CONFIDENCE_TRUE"
        elif score >= 4 and confidence >= 60:
            return "LIKELY_TRUE"
        elif score >= 0 and confidence >= 40:
            return "UNCERTAIN"
        elif score < 0 and confidence < 40:
            return "LIKELY_FALSE_POSITIVE"
        else:
            return "NEEDS_MANUAL_REVIEW"
