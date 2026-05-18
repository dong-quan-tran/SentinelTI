export default function DetailPanel({ result }) {
  if (!result) return null;

  const meta = result.model_meta || {};
  const metrics = meta.metrics || {};

  return (
    <aside className="card detail-card">
      <div className="detail-section">
        <h3>Quick facts</h3>
        <div className="detail-list">
          <div className="detail-item">
            <strong>Final label</strong>
            <span>{result.final_label}</span>
          </div>
          <div className="detail-item">
            <strong>Model</strong>
            <span>{meta.model_type || "—"}</span>
          </div>
          <div className="detail-item">
            <strong>Threshold</strong>
            <span>{meta.threshold ?? "—"}</span>
          </div>
          <div className="detail-item">
            <strong>Feature version</strong>
            <span>{meta.feature_version || "—"}</span>
          </div>
        </div>
      </div>

      <details className="details-box" open>
        <summary>Technical details</summary>
        <div className="kv-grid">
          <div>Dataset</div><div>{meta.dataset_name || "—"}</div>
          <div>Trained at</div><div>{meta.trained_at || "—"}</div>
          <div>ROC AUC</div><div>{metrics.roc_auc ?? "—"}</div>
          <div>Avg precision</div><div>{metrics.average_precision ?? "—"}</div>
          <div>Artifact path</div><div>{meta.artifact_path || "—"}</div>
        </div>
      </details>

      <details className="details-box">
        <summary>Raw response</summary>
        <pre className="raw-json">{JSON.stringify(result, null, 2)}</pre>
      </details>
    </aside>
  );
}