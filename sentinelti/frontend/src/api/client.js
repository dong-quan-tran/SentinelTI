const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
const API_KEY = import.meta.env.VITE_SENTINELTI_API_KEY || "change-me";

async function apiFetch(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-API-KEY": API_KEY,
      ...(options.headers || {})
    }
  });

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const data = await response.json();
      if (data?.detail) {
        message =
          typeof data.detail === "string"
            ? data.detail
            : JSON.stringify(data.detail);
      }
    } catch (_) {
    }
    throw new Error(message);
  }

  return response.json();
}

export async function fetchModelInfo() {
  return apiFetch("/model-info");
}

export async function scoreUrl(url) {
  return apiFetch("/score-url", {
    method: "POST",
    body: JSON.stringify({ url })
  });
}