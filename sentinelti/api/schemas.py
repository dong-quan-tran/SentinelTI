from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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


class ModelMetadataResponse(BaseModel):
    artifact_version: str | None = None
    model_type: str
    trained_at: str | None = None
    dataset_name: str | None = None
    dataset_source: dict[str, Any] = Field(default_factory=dict)
    feature_version: str | None = None
    threshold: float
    metrics: ModelMetricsSummary = Field(default_factory=ModelMetricsSummary)
    class_labels: ModelClassLabels = Field(default_factory=ModelClassLabels)
    class_counts: ModelClassCounts = Field(default_factory=ModelClassCounts)
    training_params: dict[str, Any] = Field(default_factory=dict)
    artifact_path: str | None = None


class UrlScoreResponse(BaseModel):
    url: str
    label: int
    prob_malicious: float
    threshold: float
    model_meta: ModelMetadataResponse


class UrlBatchScoreResponse(BaseModel):
    results: list[UrlScoreResponse]