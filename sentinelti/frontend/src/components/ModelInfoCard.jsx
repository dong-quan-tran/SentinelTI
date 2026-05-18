export default function ModelInfoCard({ modelInfo }) {
  const meta = modelInfo?.model_meta;

  return (
    <aside className="info-stack">
      <div className="card info-card">
        <div className="info-label">Detector</div>
        <div className="info-value">{meta?.model_type || "Unavailable"}</div>
      </div>

      <div className="card info-card">
        <div className="info-label">Threshold</div>
        <div className="info-value">{meta?.threshold ?? "Unavailable"}</div>
      </div>

      <div className="card info-card">
        <div className="info-label">Feature version</div>
        <div className="info-value">{meta?.feature_version || "Unavailable"}</div>
      </div>
    </aside>
  );
}