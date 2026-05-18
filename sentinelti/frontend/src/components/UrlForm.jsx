import { useState } from "react";

export default function UrlForm({ onSubmit, loading }) {
  const [url, setUrl] = useState("");

  function handleSubmit(event) {
    event.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) return;
    onSubmit(trimmed);
  }

  return (
    <form className="card form-card" onSubmit={handleSubmit}>
      <label className="field-label" htmlFor="url-input">
        URL to inspect
      </label>

      <div className="form-row">
        <input
          id="url-input"
          className="url-input"
          type="text"
          placeholder="https://example.com/login"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          autoComplete="off"
          spellCheck="false"
        />
        <button className="primary-btn" type="submit" disabled={loading}>
          {loading ? "Scanning..." : "Scan URL"}
        </button>
      </div>

      <p className="helper-text">
        Paste a suspicious link here instead of opening it directly.
      </p>
    </form>
  );
}