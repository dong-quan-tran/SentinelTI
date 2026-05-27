import { apiRequest } from "./baseClient";

function normalizeAIExplainResponse(value) {
  const payload = value && typeof value === "object" ? value : {};
  const deterministic =
    payload.deterministic_explanation &&
    typeof payload.deterministic_explanation === "object"
      ? payload.deterministic_explanation
      : {};
  const ai = payload.ai && typeof payload.ai === "object" ? payload.ai : {};

  return {
    deterministic_explanation: {
      summary: deterministic.summary || "",
      why_flagged: deterministic.why_flagged || "",
      user_action: deterministic.user_action || "",
      technical_notes: Array.isArray(deterministic.technical_notes)
        ? deterministic.technical_notes
        : [],
      risk: deterministic.risk || "low",
      final_label: deterministic.final_label || "benign",
    },
    ai: {
      summary: ai.summary || "",
      guidance: ai.guidance || "",
    },
  };
}

export async function fetchAIExplanation(url) {
  const response = await apiRequest("/ai-explain-score", {
    method: "POST",
    body: JSON.stringify({ url }),
  });

  return normalizeAIExplainResponse(response);
}