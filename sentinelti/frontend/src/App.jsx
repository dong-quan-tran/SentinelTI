import { useEffect, useState } from "react";
import { scoreUrl } from "./api/scanApi";
import { fetchAIExplanation } from "./api/aiApi";
import UrlForm from "./components/UrlForm";
import VerdictCard from "./components/VerdictCard";
import DetailPanel from "./components/DetailPanel";
import ModelInsightPanel from "./components/ModelInsightPanel";
import ErrorBoundary from "./components/ErrorBoundary";
import useModelInfo from "./hooks/useModelInfo";

export default function App() {
  const { modelInfo, loadingModel, modelInfoError } = useModelInfo();

  const [result, setResult] = useState(null);
  const [loadingScan, setLoadingScan] = useState(false);
  const [status, setStatus] = useState("");
  const [statusKind, setStatusKind] = useState("idle");

  const [aiExplanation, setAIExplanation] = useState(null);
  const [loadingAI, setLoadingAI] = useState(false);
  const [aiError, setAIError] = useState("");
  const [aiExpanded, setAIExpanded] = useState(false);

  useEffect(() => {
    if (modelInfoError) {
      setStatus(modelInfoError);
      setStatusKind("error");
    }
  }, [modelInfoError]);

  async function handleScan(url) {
    setLoadingScan(true);
    setStatus("Analyzing URL...");
    setStatusKind("working");
    setResult(null);
    setAIExplanation(null);
    setAIError("");
    setAIExpanded(false);

    try {
      const data = await scoreUrl(url);
      setResult(data);
      setStatus("Scan complete.");
      setStatusKind("success");
    } catch (error) {
      setStatus(`Scan failed: ${error.message}`);
      setStatusKind("error");
    } finally {
      setLoadingScan(false);
    }
  }

  async function handleGenerateAISummary() {
    if (!result?.url) return;

    try {
      setLoadingAI(true);
      setAIError("");
      setAIExpanded(true);

      const data = await fetchAIExplanation(result.url);
      setAIExplanation(data.ai);
    } catch (error) {
      setAIExplanation(null);
      setAIError(error.message || "Could not generate AI summary.");
    } finally {
      setLoadingAI(false);
    }
  }

  return (
    <main className="app-shell">
      <section className="hero">
        <div className="eyebrow">SentinelTI · URL safety checker</div>
        <h1>Check whether a URL looks safe before you open it.</h1>
        <p className="hero-copy">
          SentinelTI combines malicious-URL model scoring with heuristic analysis
          to give you a simple verdict first and deeper technical detail when you
          want it.
        </p>
      </section>

      <section className="top-grid">
        <div className="scan-column">
          <UrlForm onSubmit={handleScan} loading={loadingScan} />
          <div className={`status-line status-line--${statusKind}`}>
            {loadingModel ? "Loading model info..." : status}
          </div>
        </div>

        <ModelInsightPanel
          modelInfo={modelInfo}
          loading={loadingModel}
          errorMessage={modelInfoError}
        />
      </section>

      {result && (
        <ErrorBoundary>
          <section className="result-grid">
            <div className="result-main-column">
              <VerdictCard result={result} />

              <section className="ai-summary-card card" aria-labelledby="ai-summary-heading">
                <div className="section-header-row ai-summary-header">
                  <div>
                    <h3 id="ai-summary-heading">AI summary</h3>
                    <p className="ai-summary-note">
                      Optional plain-language rewrite of the deterministic explanation.
                      It does not change the score, threshold, risk, or final label.
                    </p>
                  </div>

                  <div className="ai-summary-actions">
                    <button
                      type="button"
                      className="details-toggle"
                      onClick={() => setAIExpanded((value) => !value)}
                      aria-expanded={aiExpanded}
                      aria-controls="ai-summary-panel"
                    >
                      {aiExpanded ? "Hide AI summary" : "Show AI summary"}
                    </button>

                    <button
                      type="button"
                      className="details-toggle secondary"
                      onClick={handleGenerateAISummary}
                      disabled={loadingAI || !result?.url}
                    >
                      {loadingAI
                        ? "Generating..."
                        : aiExplanation
                          ? "Regenerate summary"
                          : "Generate AI summary"}
                    </button>
                  </div>
                </div>

                {aiExpanded ? (
                  <div id="ai-summary-panel" className="ai-summary-panel">
                    {loadingAI ? (
                      <p className="status-muted">
                        Generating a plain-language AI summary...
                      </p>
                    ) : null}

                    {aiError ? (
                      <div className="ai-fallback-message" role="status" aria-live="polite">
                        <p className="status-error">{aiError}</p>
                        <p className="status-muted">
                          You can still rely on the deterministic verdict and detailed reasons.
                        </p>
                      </div>
                    ) : null}

                    {!aiExplanation && !loadingAI && !aiError ? (
                      <p className="status-muted">
                        Generate a plain-language AI summary for this result when you want a simpler explanation.
                      </p>
                    ) : null}

                    {aiExplanation ? (
                      <div className="ai-summary-content">
                        <p>{aiExplanation.summary}</p>
                        <p>{aiExplanation.guidance}</p>
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </section>
            </div>

            <DetailPanel result={result} />
          </section>
        </ErrorBoundary>
      )}
    </main>
  );
}