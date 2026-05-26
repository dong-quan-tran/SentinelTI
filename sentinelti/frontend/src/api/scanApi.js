import { apiRequest } from "./baseClient";

export function scoreUrl(url) {
  return apiRequest("/score-url", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

export function scoreUrls(urls) {
  return apiRequest("/score-urls", {
    method: "POST",
    body: JSON.stringify({ urls }),
  });
}

export function explainScore(url) {
  return apiRequest("/explain-score", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}