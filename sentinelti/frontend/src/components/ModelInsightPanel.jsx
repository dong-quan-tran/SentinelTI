import "./ModelInsightPanel.css";

function formatThresholdSource(source) {
  if (source === "metadata") return "from model metadata";
  if (source === "env") return "from environment override";
  if (source === "default") return "from application default";
  return "from model settings";
}

function formatDate(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatFeatureName(name) {
  if (!name) return "Unknown feature";
  return String(name)
    .replaceAll("_", " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function featurePlainLanguage(featureName) {
  const key = String(featureName || "").toLowerCase();

  const known = {
    has_ip: "Uses a raw IP address instead of a normal domain, which is often suspicious.",
    url_length: "Has an unusually long URL, which can be a phishing signal.",
    has_at_symbol: "Contains an @ symbol, which can be used to disguise the real destination.",
    has_redirect: "Contains redirect-style patterns that can hide the final destination.",
    num_dots: "Uses many subdomains or dot-separated sections, which can look deceptive.",
    num_hyphens: "Contains many hyphens, which can sometimes indicate impersonation.",
    has_https_token_in_path:
      "Mentions HTTPS-like text in the wrong place, which can mislead users.",
    suspicious_words:
      "Contains words commonly associated with login, account, or urgent actions.",
  };

  return (
    known[key] ||
    `${formatFeatureName(featureName)} was one of the stronger signals used by the model.`
  );
}

function LoadingState() {
  return (
    <aside className="panel-card model-insight-panel">
      <div className="panel-label">Model insight</div>
      <h2>Loading model details...</h2>
      <p className="muted-copy">
        Fetching the active model configuration and metadata.
      </p>

      <div className="insight-summary insight-summary--loading">
        <div className="summary-item skeleton-block" />
        <div className="summary-item skeleton-block" />
        <div className="summary-item skeleton-block" />
      </div>

      <div className="panel-section">
        <div className="skeleton-line skeleton-line--lg" />
        <div className="skeleton-line" />
        <div className="skeleton-line skeleton-line--sm" />
      </div>
    </aside>
  );
}

function ErrorState({ errorMessage }) {
  return (
    <aside className="panel-card model-insight-panel">
      <div className="panel-label panel-label--warning">Model insight</div>
      <h2>Model info unavailable</h2>
      <p className="muted-copy">{errorMessage}</p>
      <div className="panel-note">
        The scanner can still work, but this panel cannot describe the active model right now.
      </div>
    </aside>
  );
}

export default function ModelInsightPanel({ modelInfo, loading, errorMessage }) {
  const modelMeta = modelInfo?.model_meta;

  if (loading) {
    return <LoadingState />;
  }

  if (errorMessage) {
    return <ErrorState errorMessage={errorMessage} />;
  }

  if (!modelMeta) {
    return (
      <aside className="panel-card model-insight-panel">
        <div className="panel-label">Model insight</div>
        <h2>No model metadata available</h2>
        <p className="muted-copy">
          The API did not return model details, so the panel cannot describe the active model yet.
        </p>
      </aside>
    );
  }

  const topFeatures = Array.isArray(modelMeta.top_features)
    ? modelMeta.top_features.slice(0, 3)
    : [];

  const trainingNotes = Array.isArray(modelMeta.training_notes)
    ? modelMeta.training_notes
    : [];

  const hasMetrics =
    modelMeta.metrics &&
    (modelMeta.metrics.roc_auc != null || modelMeta.metrics.average_precision != null);

  return (
    <aside className="panel-card model-insight-panel">
      <div className="panel-label">Model insight</div>
      <h2>{modelMeta.model_type?.toUpperCase?.() || "Unknown"} model</h2>
      <p className="muted-copy">
        Using the **effective** decision threshold of{" "}
        <span className="metric-value">{modelMeta.threshold}</span>{" "}
        ({formatThresholdSource(modelMeta.threshold_source)}).
      </p>

      <div className="insight-summary">
        <div className="summary-item">
          <span className="summary-label">Dataset</span>
          <span className="summary-value">{modelMeta.dataset_name || "Unknown"}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Trained</span>
          <span className="summary-value">{formatDate(modelMeta.trained_at)}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Feature version</span>
          <span className="summary-value">{modelMeta.feature_version || "Unknown"}</span>
        </div>
      </div>

      {modelMeta.recommended_threshold != null && (
        <div className="info-chip-row">
          <span className="info-chip">
            Recommended threshold: {modelMeta.recommended_threshold}
          </span>
          {modelMeta.recommended_threshold_source && (
            <span className="info-chip subtle-chip">
              Source: {modelMeta.recommended_threshold_source}
            </span>
          )}
        </div>
      )}

      <section className="panel-section">
        <h3>What the model pays attention to</h3>
        {topFeatures.length > 0 ? (
          <ul className="insight-list">
            {topFeatures.map((item) => (
              <li key={item.feature}>
                <div className="insight-list-title">
                  {formatFeatureName(item.feature)}
                </div>
                <div className="insight-list-copy">
                  {featurePlainLanguage(item.feature)}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted-copy">
            No feature-importance summary is currently available for this model.
          </p>
        )}
      </section>

      <section className="panel-section">
        <h3>Model quality</h3>
        {hasMetrics ? (
          <div className="metric-grid">
            <div className="metric-card">
              <span className="metric-label">ROC-AUC</span>
              <span className="metric-value">
                {modelMeta.metrics?.roc_auc != null ? modelMeta.metrics.roc_auc : "N/A"}
              </span>
            </div>
            <div className="metric-card">
              <span className="metric-label">Average precision</span>
              <span className="metric-value">
                {modelMeta.metrics?.average_precision != null
                  ? modelMeta.metrics.average_precision
                  : "N/A"}
              </span>
            </div>
          </div>
        ) : (
          <p className="muted-copy">
            Metrics are partially missing or unavailable for the active model.
          </p>
        )}
      </section>

      {trainingNotes.length > 0 && (
        <section className="panel-section">
          <h3>Training notes</h3>
          <ul className="training-notes-list">
            {trainingNotes.map((note, index) => (
              <li key={`${note}-${index}`}>{note}</li>
            ))}
          </ul>
        </section>
      )}
    </aside>
  );
}