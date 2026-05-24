from __future__ import annotations

from sentinelti.services.model_metadata import (
    build_model_meta,
    coerce_top_features,
    coerce_training_notes,
)


def test_coerce_top_features_filters_invalid_items():
    result = coerce_top_features(
        [
            {"feature": "url_length", "importance": 0.91},
            {"feature": "has_ip", "importance": "0.75"},
            {"feature": None, "importance": 0.2},
            {"importance": 0.3},
            {"feature": "broken", "importance": None},
            "not-a-dict",
        ]
    )

    assert result == [
        {"feature": "url_length", "importance": 0.91},
        {"feature": "has_ip", "importance": 0.75},
    ]


def test_coerce_training_notes_filters_empty_values():
    result = coerce_training_notes(
        [
            "logreg did not fully converge",
            "",
            "   ",
            None,
            123,
        ]
    )

    assert result == [
        "logreg did not fully converge",
        "123",
    ]


def test_build_model_meta_returns_defaults_for_minimal_metadata():
    result = build_model_meta(
        {
            "model_type": "xgb",
            "threshold": 0.75,
        }
    )

    assert result["model_type"] == "xgb"
    assert result["threshold"] == 0.75
    assert result["threshold_source"] == "metadata"
    assert result["dataset_source"] == {}
    assert result["metrics"] == {
        "roc_auc": None,
        "average_precision": None,
    }
    assert result["class_labels"] == {}
    assert result["class_counts"] == {}
    assert result["training_params"] == {}
    assert result["training_notes"] == []
    assert result["top_features"] == []
    assert result["artifact_path"] is None
    assert result["model_summary"] == {
        "model_type": "xgb",
        "dataset_name": None,
        "trained_at": None,
        "top_features": [],
    }


def test_build_model_meta_uses_top_level_training_notes_when_present():
    result = build_model_meta(
        {
            "model_type": "logreg",
            "threshold": 0.75,
            "training_notes": ["top-level note"],
            "metrics": {
                "training_notes": ["nested note"],
            },
        }
    )

    assert result["training_notes"] == ["top-level note"]


def test_build_model_meta_falls_back_to_metrics_training_notes():
    result = build_model_meta(
        {
            "model_type": "logreg",
            "threshold": 0.75,
            "metrics": {
                "training_notes": ["nested note"],
            },
        }
    )

    assert result["training_notes"] == ["nested note"]


def test_build_model_meta_preserves_threshold_source_when_valid():
    result = build_model_meta(
        {
            "model_type": "xgb",
            "threshold": 0.82,
            "threshold_source": "env",
        }
    )

    assert result["threshold"] == 0.82
    assert result["threshold_source"] == "env"


def test_build_model_meta_defaults_invalid_threshold_source_to_metadata():
    result = build_model_meta(
        {
            "model_type": "xgb",
            "threshold": 0.82,
            "threshold_source": "weird-value",
        }
    )

    assert result["threshold_source"] == "metadata"


def test_build_model_meta_limits_model_summary_top_features_to_three():
    result = build_model_meta(
        {
            "model_type": "xgb",
            "threshold": 0.75,
            "top_features": [
                {"feature": "f1", "importance": 0.9},
                {"feature": "f2", "importance": 0.8},
                {"feature": "f3", "importance": 0.7},
                {"feature": "f4", "importance": 0.6},
            ],
        }
    )

    assert result["top_features"] == [
        {"feature": "f1", "importance": 0.9},
        {"feature": "f2", "importance": 0.8},
        {"feature": "f3", "importance": 0.7},
        {"feature": "f4", "importance": 0.6},
    ]
    assert result["model_summary"]["top_features"] == [
        {"feature": "f1", "importance": 0.9},
        {"feature": "f2", "importance": 0.8},
        {"feature": "f3", "importance": 0.7},
    ]


def test_build_model_meta_uses_top_feature_importance_fallback():
    result = build_model_meta(
        {
            "model_type": "xgb",
            "threshold": 0.75,
            "top_feature_importance": [
                {"feature": "fallback_feature", "importance": 0.55},
            ],
        }
    )

    assert result["top_features"] == [
        {"feature": "fallback_feature", "importance": 0.55},
    ]
    assert result["model_summary"]["top_features"] == [
        {"feature": "fallback_feature", "importance": 0.55},
    ]