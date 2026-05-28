const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.trim() || "http://127.0.0.1:8000";

const API_KEY =
  import.meta.env.VITE_SENTINELTI_API_KEY?.trim() || "change-me";

async function parseJsonResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const error = new Error(
      typeof payload === "object" && payload !== null
        ? payload.detail || payload.error || `Request failed with status ${response.status}`
        : payload || `Request failed with status ${response.status}`
    );

    error.status = response.status;
    error.payload = payload;

    if (typeof payload === "object" && payload !== null) {
      error.detail = payload.detail || "";
      error.errorType = payload.error_type || "";
    }

    throw error;
  }

  return payload;
}

export async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-API-KEY": API_KEY,
      ...(options.headers || {}),
    },
  });

  return parseJsonResponse(response);
}