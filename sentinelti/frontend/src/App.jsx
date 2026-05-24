import { useEffect, useState } from "react";
import { fetchModelInfo, scoreUrl } from "./api/client";
import UrlForm from "./components/UrlForm";
import VerdictCard from "./components/VerdictCard";
import DetailPanel from "./components/DetailPanel";
import ModelInsightPanel from "./components/ModelInsightPanel";

export default function App() {
  const [modelInfo, setModelInfo] = useState(null);
  const [result, setResult] = useState(null);
  const [loadingModel, setLoadingModel] = useState(true);
  const [loadingScan, setLoadingScan] = useState(false);
  const [status, setStatus] = useState("");
  const [statusKind, setStatusKind] = useState("idle");
  const [modelInfoError, setModelInfoError] = useState("");

  useEffect(() => {
    async function loadModelInfo() {
      try {
        setModelInfoError("");
        const data = await fetchModelInfo();
        setModelInfo(data);
      } catch (error) {
        const message = `Could not load model info: ${error.message}`;
        setModelInfoError(message);
        setStatus(message);
        setStatusKind("error");
      } finally {
        setLoadingModel(false);
      }
    }

    loadModelInfo();
  }, []);

  async function handleScan(url) {
    setLoadingScan(true);
    setStatus("Analyzing URL...");
    setStatusKind("working");
    setResult(null);

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

  return (
    <main className="app-shell">
      <section className="hero">
        <div className="eyebrow">SentinelTI · URL safety checker</div>
        <h1>Check whether a URL looks safe before you open it.</h1>
        <p className="hero-copy">
          SentinelTI combines malicious-URL model scoring with heuristic analysis
          to give you a simple verdict first and deeper technical detail when you want it.
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
        <section className="result-grid">
          <VerdictCard result={result} />
          <DetailPanel result={result} />
        </section>
      )}
    </main>
  );
}