import { useState } from "react";

function formatProbability(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "N/A";
  }
  return `${(value * 100).toFixed(1)}%`;
}

function formatThreshold(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "N/A";
  }
  return value.toFixed(2);
}

export default function DetailPanel({ result }) {
  const [showRawJson, setShowRawJson] = useState(false);

  if (!result) {
    return null;
  }

  const heuristic = result.heuristic ?? {};
  const modelMeta = result.model_meta ?? {};
  const explanation = result.explanation ?? {};
  const heuristicReasons = Array.isArray(heuristic.reasons) ? heuristic.reasons : [];
  const technicalNotes = Array.isArray(explanation.technical_notes)
    ? explanation.technical_notes
    : [];

  return (
    <section className="detail-panel">
      <div className="detail-panel__grid">
        <article className="detail-card">
          <h3>Decision details</h3>
          <dl className="detail-list">
            <div>
              <dt>Final label</dt>
              <dd>{result.final_label ?? "unknown"}</dd>
            </div>
            <div>
              <dt>Risk</dt>
              <dd>{result.risk ?? "unknown"}</dd>
            </div>
            <div>
              <dt>Malicious probability</dt>
              <dd>{formatProbability(result.prob_malicious)}</dd>
            </div>
            <div>
              <dt>Threshold</dt>
              <dd>{formatThreshold(result.threshold)}</dd>
            </div>
            <div>
              <dt>Raw model label</dt>
              <dd>{result.label ?? "N/A"}</dd>
            </div>
          </dl>
        </article>

        <article className="detail-card">
          <h3>Explanation notes</h3>
          <p className="detail-copy">
            {explanation.why_flagged ?? "No analyst explanation was returned."}
          </p>

          <h4>Technical notes</h4>
          {technicalNotes.length > 0 ? (
            <ul className="detail-bullets">
              {technicalNotes.map((note, index) => (
                <li key={`${note}-${index}`}>{note}</li>
              ))}
            </ul>
          ) : (
            <p className="detail-copy muted">No technical notes available.</p>
          )}
        </article>

        <article className="detail-card">
          <h3>Heuristic signals</h3>
          <dl className="detail-list">
            <div>
              <dt>Heuristic score</dt>
              <dd>
                {typeof heuristic.score === "number"
                  ? heuristic.score.toFixed(2)
                  : "N/A"}
              </dd>
            </div>
          </dl>

          {heuristicReasons.length > 0 ? (
            <ul className="detail-bullets">
              {heuristicReasons.map((reason, index) => (
                <li key={`${reason}-${index}`}>{reason}</li>
              ))}
            </ul>
          ) : (
            <p className="detail-copy muted">No heuristic indicators were returned.</p>
          )}
        </article>

        <article className="detail-card">
          <h3>Model metadata</h3>
          <dl className="detail-list">
            <div>
              <dt>Model type</dt>
              <dd>{modelMeta.model_type ?? "unknown"}</dd>
            </div>
            <div>
              <dt>Feature version</dt>
              <dd>{modelMeta.feature_version ?? "unknown"}</dd>
            </div>
            <div>
              <dt>Artifact version</dt>
              <dd>{modelMeta.artifact_version ?? "unknown"}</dd>
            </div>
            <div>
              <dt>Trained at</dt>
              <dd>{modelMeta.trained_at ?? "unknown"}</dd>
            </div>
            <div>
              <dt>Dataset</dt>
              <dd>{modelMeta.dataset_name ?? "unknown"}</dd>
            </div>
          </dl>
        </article>
      </div>

      <div className="detail-panel__raw">
        <button
          type="button"
          className="details-toggle secondary"
          aria-expanded={showRawJson}
          aria-controls="raw-json-panel"
          onClick={() => setShowRawJson((value) => !value)}
        >
          {showRawJson ? "Hide raw response" : "Show raw response"}
        </button>

        {showRawJson ? (
          <pre id="raw-json-panel" className="raw-json-block">
            {JSON.stringify(result, null, 2)}
          </pre>
        ) : null}
      </div>
    </section>
  );
}