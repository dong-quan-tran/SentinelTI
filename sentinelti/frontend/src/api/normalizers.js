function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function toNumberOrNull(value) {
  if (value === null || value === undefined || value === "") return null;
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

function toStringOrNull(value) {
  if (value === null || value === undefined || value === "") return null;
  return String(value);
}

function toStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => (item === null || item === undefined ? "" : String(item).trim()))
    .filter(Boolean);
}

function normalizeTopFeatures(value) {
  if (!Array.isArray(value)) return [];

  return value
    .filter((item) => isObject(item) && item.feature !== undefined)
    .map((item) => ({
      feature: String(item.feature),
      importance: toNumberOrNull(item.importance),
    }))
    .filter((item) => item.importance !== null);
}

function normalizeModelSummary(value, fallbackMeta) {
  const summary = isObject(value) ? value : {};

  return {
    model_type: toStringOrNull(summary.model_type) || fallbackMeta.model_type || "unknown",
    dataset_name: toStringOrNull(summary.dataset_name) || fallbackMeta.dataset_name,
    trained_at: toStringOrNull(summary.trained_at) || fallbackMeta.trained_at,
    top_features: normalizeTopFeatures(summary.top_features).slice(0, 3),
  };
}

export function normalizeModelMeta(value) {
  const meta = isObject(value) ? value : {};
  const metrics = isObject(meta.metrics) ? meta.metrics : {};

  const normalized = {
    artifact_version: toStringOrNull(meta.artifact_version),
    model_type: toStringOrNull(meta.model_type) || "unknown",
    trained_at: toStringOrNull(meta.trained_at),
    dataset_name: toStringOrNull(meta.dataset_name),
    dataset_source: isObject(meta.dataset_source) ? meta.dataset_source : {},
    feature_version: toStringOrNull(meta.feature_version),
    threshold: toNumberOrNull(meta.threshold) ?? 0.75,
    threshold_source:
      toStringOrNull(meta.threshold_source) || "metadata",
    recommended_threshold: toNumberOrNull(meta.recommended_threshold),
    recommended_threshold_source: toStringOrNull(meta.recommended_threshold_source),
    metrics: {
      roc_auc: toNumberOrNull(metrics.roc_auc),
      average_precision: toNumberOrNull(metrics.average_precision),
    },
    class_labels: isObject(meta.class_labels) ? meta.class_labels : {},
    class_counts: isObject(meta.class_counts) ? meta.class_counts : {},
    training_params: isObject(meta.training_params) ? meta.training_params : {},
    training_notes: toStringArray(meta.training_notes),
    top_features: normalizeTopFeatures(meta.top_features),
    artifact_path: toStringOrNull(meta.artifact_path),
  };

  normalized.model_summary = normalizeModelSummary(meta.model_summary, normalized);

  return normalized;
}

export function normalizeModelInfoResponse(value) {
  const payload = isObject(value) ? value : {};

  return {
    schema_version: toStringOrNull(payload.schema_version) || "1.1",
    model_meta: normalizeModelMeta(payload.model_meta),
  };
}

export function normalizeScoreResponse(value) {
  const payload = isObject(value) ? value : {};
  const heuristic = isObject(payload.heuristic) ? payload.heuristic : {};
  const explanation = isObject(payload.explanation) ? payload.explanation : {};

  return {
    schema_version: toStringOrNull(payload.schema_version) || "1.2",
    url: toStringOrNull(payload.url) || "",
    label: toNumberOrNull(payload.label) ?? 0,
    prob_malicious: toNumberOrNull(payload.prob_malicious) ?? 0,
    threshold: toNumberOrNull(payload.threshold) ?? 0.75,
    heuristic: {
      score: toNumberOrNull(heuristic.score) ?? 0,
      reasons: toStringArray(heuristic.reasons),
    },
    final_label: toStringOrNull(payload.final_label) || "benign",
    risk: toStringOrNull(payload.risk) || "low",
    reasons: toStringArray(payload.reasons),
    explanation: {
      summary: toStringOrNull(explanation.summary) || "",
      why_flagged: toStringOrNull(explanation.why_flagged) || "",
      user_action: toStringOrNull(explanation.user_action) || "",
      technical_notes: toStringArray(explanation.technical_notes),
      risk: toStringOrNull(explanation.risk) || "low",
      final_label: toStringOrNull(explanation.final_label) || "benign",
    },
    model_meta: normalizeModelMeta(payload.model_meta),
  };
}