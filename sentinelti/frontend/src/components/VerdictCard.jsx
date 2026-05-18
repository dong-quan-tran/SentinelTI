import { useMemo, useState } from "react";
import DetailPanel from "./DetailPanel";

function getVerdictTone(finalLabel, risk) {
  if (finalLabel === "malicious" || risk === "high") {
    return {
      badgeClass: "badge-danger",
      cardClass: "verdict-card verdict-danger",
      title: "Potentially unsafe URL",
    };
  }

  if (risk === "medium" || finalLabel === "suspicious") {
    return {
      badgeClass: "badge-warning",
      cardClass: "verdict-card verdict-warning",
      title: "Use caution",
    };
  }

  return {
    badgeClass: "badge-safe",
    cardClass: "verdict-card verdict-safe",
    title: "Looks relatively safe",
  };
}

function formatPercent(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "N/A";
  }
  return `${Math.round(value * 100)}%`;
}

export default function VerdictCard({ result, isLoading = false }) {
  const [showAdvanced, setShowAdvanced] = useState(false);

  const tone = useMemo(() => {
    return getVerdictTone(result?.final_label, result?.risk);
  }, [result?.final_label, result?.risk]);

  if (isLoading) {
    return (
      <section className="verdict-card verdict-loading" aria-live="polite">
        <div className="skeleton skeleton-title" />
        <div className="skeleton skeleton-line" />
        <div className="skeleton skeleton-line short" />
      </section>
    );
  }

  if (!result) {
    return null;
  }

  const explanation = result.explanation ?? {};
  const summary =
    explanation.summary ??
    "A URL analysis result is available, but no summary was returned.";
  const whyFlagged =
    explanation.why_flagged ??
    "No additional explanation was returned by the backend.";
  const userAction =
    explanation.user_action ??
    "Use caution and verify the destination before visiting the link.";
  const confidenceText = formatPercent(result.prob_malicious);

  return (
    <section className={tone.cardClass} aria-live="polite">
      <div className="verdict-card__header">
        <div>
          <p className="eyebrow">SentinelTI verdict</p>
          <h2>{tone.title}</h2>
        </div>

        <span className={`verdict-badge ${tone.badgeClass}`}>
          {result.final_label ?? "unknown"}
        </span>
      </div>

      <div className="verdict-card__body">
        <p className="verdict-summary">{summary}</p>

        <div className="verdict-key-facts">
          <div className="fact-chip">
            <span className="fact-chip__label">Risk</span>
            <span className="fact-chip__value">{result.risk ?? "unknown"}</span>
          </div>

          <div className="fact-chip">
            <span className="fact-chip__label">Malicious score</span>
            <span className="fact-chip__value">{confidenceText}</span>
          </div>
        </div>

        <div className="verdict-guidance">
          <div className="verdict-guidance__block">
            <h3>Why this was flagged</h3>
            <p>{whyFlagged}</p>
          </div>

          <div className="verdict-guidance__block">
            <h3>What you should do</h3>
            <p>{userAction}</p>
          </div>
        </div>
      </div>

      <div className="verdict-card__actions">
        <button
          type="button"
          className="details-toggle"
          aria-expanded={showAdvanced}
          aria-controls="technical-details-panel"
          onClick={() => setShowAdvanced((value) => !value)}
        >
          {showAdvanced ? "Hide technical details" : "Show technical details"}
        </button>
      </div>

      {showAdvanced ? (
        <div id="technical-details-panel" className="verdict-card__details">
          <DetailPanel result={result} />
        </div>
      ) : null}
    </section>
  );
}