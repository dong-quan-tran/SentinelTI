function formatPercent(value) {
  return `${Math.round((value || 0) * 100)}%`;
}

function getVerdictMeta(finalLabel, risk) {
  if (finalLabel === "malicious" || risk === "high") {
    return {
      title: "Likely malicious",
      tone: "danger",
      summary:
        "This URL shows strong warning signs and should be treated as unsafe until verified.",
      action:
        "Do not open the link or enter credentials. Verify the sender and inspect the domain safely."
    };
  }

  if (finalLabel === "suspicious" || risk === "medium") {
    return {
      title: "Suspicious",
      tone: "warning",
      summary:
        "This URL contains enough risk indicators to justify caution before interacting with it.",
      action:
        "Avoid logging in or downloading anything until you confirm the destination is legitimate."
    };
  }

  return {
    title: "Looks low risk",
    tone: "safe",
    summary:
      "No strong indicators pushed this scan into a suspicious or malicious verdict.",
    action:
      "Proceed carefully and still verify important destinations manually when sensitive data is involved."
  };
}

export default function VerdictCard({ result }) {
  if (!result) return null;

  const verdict = getVerdictMeta(result.final_label, result.risk);
  const probability = result.prob_malicious || 0;
  const threshold = result.threshold || 0.75;

  return (
    <section className="card result-card">
      <div className="result-header">
        <div className={`verdict-pill ${verdict.tone}`}>{verdict.title}</div>
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
          <h3>What this means</h3>
          <p>{verdict.summary}</p>
        </div>
        <div className="tip-card">
          <h3>Recommended action</h3>
          <p>{verdict.action}</p>
        </div>
      </div>

      <div className="reason-block">
        <h3>Why it was flagged</h3>
        <div className="reason-list">
          {(result.reasons || []).length > 0 ? (
            result.reasons.map((reason, index) => (
              <div className="reason-item" key={`${reason}-${index}`}>
                {reason}
              </div>
            ))
          ) : (
            <div className="reason-item">No specific reasons were returned.</div>
          )}
        </div>
      </div>
    </section>
  );
}