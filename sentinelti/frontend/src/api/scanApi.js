import { apiRequest } from "./baseClient";
import { normalizeScoreResponse } from "./normalizers";

export async function scoreUrl(url) {
  const response = await apiRequest("/score-url", {
    method: "POST",
    body: JSON.stringify({ url }),
  });

  return normalizeScoreResponse(response);
}

export async function scoreUrls(urls) {
  const response = await apiRequest("/score-urls", {
    method: "POST",
    body: JSON.stringify({ urls }),
  });

  const results = Array.isArray(response?.results) ? response.results : [];
  return {
    results: results.map(normalizeScoreResponse),
  };
}

export async function explainScore(url) {
  return apiRequest("/explain-score", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}