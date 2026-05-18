function formatPercent(value) {
  return `${Math.round((value || 0) * 100)}%`;
}

function getTone(finalLabel, risk) {
  if (finalLabel === "malicious" || risk === "high") return "danger";
  if (finalLabel === "suspicious" || risk === "medium") return "warning";
  return "safe";
}

function getTitle(finalLabel, risk) {
  if (finalLabel === "malicious" || risk === "high") return "Likely malicious";
  if (finalLabel === "suspicious" || risk === "medium") return "Suspicious";
  return "Looks low risk";
}

export default function VerdictCard({ result }) {
  if (!result) return null;

  const probability = result.prob_malicious || 0;
  const threshold = result.threshold || 0.75;
  const explanation = result.explanation || {};
  const tone = getTone(result.final_label, result.risk);
  const title = getTitle(result.final_label, result.risk);

  return (
    <section className="card result-card">
      <div className="result-header">
        <div className={`verdict-pill ${tone}`}>{title}</div>
        <div className="risk-text">Risk: {result.risk}</div>
      </div>

      <div className="score-number">{formatPercent(probability)}</div>
      <div className="score-caption">estimated malicious probability</div>

      <div className="meter">
        <div
          className="meter-fill"
          style={{ width: `${Math.max(0, Math.min(100, probability * 100))}%` }}
        />
        <div
          className="meter-threshold"
          style={{ left: `${Math.max(0, Math.min(100, threshold * 100))}%` }}
        />
      </div>

      <div className="meter-labels">
        <span>Lower risk</span>
        <span>Threshold</span>
        <span>Higher risk</span>
      </div>

      <div className="tip-grid">
        <div className="tip-card">
          <h3>Summary</h3>
          <p>
            {explanation.summary ||
              "No summary was returned for this scan."}
          </p>
        </div>
        <div className="tip-card">
          <h3>Recommended action</h3>
          <p>
            {explanation.user_action ||
              "Proceed carefully and verify the destination independently."}
          </p>
        </div>
      </div>

      <div className="reason-block">
        <h3>Why it was flagged</h3>
        <div className="reason-list">
          <div className="reason-item">
            {explanation.why_flagged || "No explanation details were returned."}
          </div>
          {(explanation.technical_notes || []).map((note, index) => (
            <div className="reason-item" key={`${note}-${index}`}>
              {note}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}