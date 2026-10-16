const API_BASE_PATH = "/api";

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
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new Error("API path must be a same-origin absolute path.");
  }

  const response = await fetch(`${API_BASE_PATH}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  return parseJsonResponse(response);
}