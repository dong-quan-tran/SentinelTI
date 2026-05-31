from __future__ import annotations

from typing import Any, Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field


AI_EXPLAIN_SCORE_REQUEST_EXAMPLES = {
    "benign_example": {
        "summary": "Generate an AI rewrite for a low-risk URL result",
        "description": "Example request for a URL that is likely benign.",
        "value": {"url": "https://example.com"},
    },
    "suspicious_example": {
        "summary": "Generate an AI rewrite for a suspicious login-style URL",
        "description": "Example request for a URL with phishing-like indicators.",
        "value": {
            "url": "https://secure-account-check.example/login/verify",
            "ai_model": "deepseek-r1:1.5b",
        },
    },
}


AI_EXPLAIN_SCORE_SUCCESS_EXAMPLE = {
    "deterministic_explanation": {
        "summary": "This URL appears suspicious.",
        "why_flagged": "The URL contains several phishing-like signals and should be treated cautiously.",
        "user_action": "Avoid entering credentials until the destination is verified independently.",
        "technical_notes": [
            "Suspicious login-related tokens detected in path.",
            "Heuristic score exceeded the suspicious threshold.",
        ],
        "risk": "medium",
        "final_label": "suspicious",
    },
    "ai": {
        "summary": "This link shows some warning signs commonly seen in phishing attempts.",
        "guidance": "Treat this result as a warning. Double-check the sender and open the site only if you trust it.",
    },
}


AI_EXPLAIN_SCORE_DISABLED_EXAMPLE = {
    "detail": "AI-assisted explanations are currently disabled.",
    "error_type": "ai_disabled",
}


AI_EXPLAIN_SCORE_ERROR_EXAMPLE = {
    "detail": "AI provider unavailable",
    "error_type": "ai_explanation_error",
}


AI_EXPLAIN_SCORE_MODEL_UNAVAILABLE_EXAMPLE = {
    "detail": "Requested AI model is not available: missing:model",
    "error_type": "ai_model_unavailable",
}


class HeuristicResult(BaseModel):
    score: float
    reasons: List[str]


class ModelMetricsSummary(BaseModel):
    roc_auc: float | None = None
    average_precision: float | None = None


class ModelClassLabels(BaseModel):
    benign: int | None = None
    malicious: int | None = None


class ModelClassCounts(BaseModel):
    train_0: int | None = None
    train_1: int | None = None
    test_0: int | None = None
    test_1: int | None = None


class ModelTopFeature(BaseModel):
    feature: str
    importance: float


class ModelSummaryResponse(BaseModel):
    model_type: str
    dataset_name: str | None = None
    trained_at: str | None = None
    top_features: List[ModelTopFeature] = Field(default_factory=list)


class ModelMetadataResponse(BaseModel):
    artifact_version: str | None = None
    model_type: str
    trained_at: str | None = None
    dataset_name: str | None = None
    dataset_source: Dict[str, Any] = Field(default_factory=dict)
    feature_version: str | None = None
    threshold: float
    threshold_source: Literal["metadata", "env", "default"] | None = None
    recommended_threshold: float | None = None
    recommended_threshold_source: str | None = None
    metrics: ModelMetricsSummary = Field(default_factory=ModelMetricsSummary)
    class_labels: ModelClassLabels = Field(default_factory=ModelClassLabels)
    class_counts: ModelClassCounts = Field(default_factory=ModelClassCounts)
    training_params: Dict[str, Any] = Field(default_factory=dict)
    training_notes: List[str] = Field(default_factory=list)
    top_features: List[ModelTopFeature] = Field(default_factory=list)
    artifact_path: str | None = None
    model_summary: ModelSummaryResponse


class ExplanationResponse(BaseModel):
    summary: str
    why_flagged: str
    user_action: str
    technical_notes: List[str] = Field(default_factory=list)
    risk: Literal["low", "medium", "high"]
    final_label: Literal["benign", "suspicious", "malicious"]


class ModelInfoResponse(BaseModel):
    schema_version: Literal["1.1"] = "1.1"
    model_meta: ModelMetadataResponse


class ScoreResponse(BaseModel):
    schema_version: Literal["1.2"] = "1.2"
    url: str
    label: int
    prob_malicious: float
    threshold: float
    heuristic: HeuristicResult
    final_label: Literal["benign", "suspicious", "malicious"]
    risk: Literal["low", "medium", "high"]
    reasons: List[str]
    explanation: ExplanationResponse
    model_meta: ModelMetadataResponse


class ScoreUrlRequest(BaseModel):
    url: str = Field(
        ...,
        examples=["https://example.com"],
        description="URL to score",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"url": "https://example.com"},
                {"url": "https://phishy.example/login"},
            ]
        }
    )


class ScoreUrlsRequest(BaseModel):
    urls: List[str] = Field(
        ...,
        examples=[
            "https://example.com",
            "https://phishy.example/login",
        ],
        description="List of URLs to score",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "urls": [
                        "https://example.com",
                        "https://phishy.example/login",
                    ]
                }
            ]
        }
    )


class ScoreUrlsResponse(BaseModel):
    results: List[ScoreResponse]


class ScoringErrorResponse(BaseModel):
    detail: str = Field(
        ...,
        description="High-level error message.",
        examples=["Internal scoring error"],
    )
    error_type: str = Field(
        ...,
        description="Machine-readable error category.",
        examples=["runtime_error"],
    )


class UnauthorizedErrorResponse(BaseModel):
    detail: str = Field(
        ...,
        description="Authentication error message.",
        examples=["Unauthorized"],
    )


class RateLimitErrorResponse(BaseModel):
    detail: str = Field(
        ...,
        description="High-level rate limit error message.",
        examples=["Rate limit exceeded. Try again later."],
    )


class AIModelsResponse(BaseModel):
    provider: str
    default_model: str | None = None
    models: List[str] = Field(default_factory=list)


class AIRewriteExplanation(BaseModel):
    summary: str = Field(
        ...,
        description="Short AI-generated summary of the deterministic verdict.",
    )
    guidance: str = Field(
        ...,
        description=(
            "Additional user-facing guidance generated by AI. "
            "Does not change the deterministic label."
        ),
    )


class AIExplainScoreRequest(BaseModel):
    url: str = Field(
        ...,
        examples=["https://example.com"],
        description="URL to score and rewrite with AI assistance.",
    )
    ai_model: str | None = Field(
        default=None,
        examples=["llama3.1:8b", "deepseek-r1:1.5b"],
        description=(
            "Optional Ollama model override. If omitted, the configured default "
            "AI model is used."
        ),
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"url": "https://example.com"},
                {
                    "url": "https://secure-account-check.example/login/verify",
                    "ai_model": "deepseek-r1:1.5b",
                },
            ]
        }
    )


class AIExplainScoreResponse(BaseModel):
    deterministic_explanation: ExplanationResponse
    ai: AIRewriteExplanation