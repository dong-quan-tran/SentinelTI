import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetchAIExplanation } from "./aiApi";
import { apiRequest } from "./baseClient";

vi.mock("./baseClient", () => ({
  apiRequest: vi.fn(),
}));

describe("fetchAIExplanation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("normalizes a successful AI explanation response", async () => {
    apiRequest.mockResolvedValue({
      deterministic_explanation: {
        summary: "Deterministic summary",
        why_flagged: "Deterministic reason",
        user_action: "Proceed carefully",
        technical_notes: ["note-1"],
        risk: "medium",
        final_label: "suspicious",
      },
      ai: {
        summary: "AI summary",
        guidance: "AI guidance",
      },
    });

    await expect(fetchAIExplanation("https://example.com")).resolves.toEqual({
      deterministic_explanation: {
        summary: "Deterministic summary",
        why_flagged: "Deterministic reason",
        user_action: "Proceed carefully",
        technical_notes: ["note-1"],
        risk: "medium",
        final_label: "suspicious",
      },
      ai: {
        summary: "AI summary",
        guidance: "AI guidance",
      },
    });

    expect(apiRequest).toHaveBeenCalledWith("/ai-explain-score", {
      method: "POST",
      body: JSON.stringify({ url: "https://example.com" }),
    });
  });

  it("fills safe defaults when response fields are missing or malformed", async () => {
    apiRequest.mockResolvedValue({
      deterministic_explanation: {
        summary: "Only summary",
      },
      ai: null,
    });

    await expect(fetchAIExplanation("https://example.com")).resolves.toEqual({
      deterministic_explanation: {
        summary: "Only summary",
        why_flagged: "",
        user_action: "",
        technical_notes: [],
        risk: "low",
        final_label: "benign",
      },
      ai: {
        summary: "",
        guidance: "",
      },
    });
  });

  it("maps ai_disabled to a user-friendly frontend error", async () => {
    apiRequest.mockRejectedValue({
      status: 503,
      detail: "AI-assisted explanations are currently disabled.",
      errorType: "ai_disabled",
    });

    await expect(fetchAIExplanation("https://example.com")).rejects.toThrow(
      "AI summary is currently unavailable. Your deterministic verdict is still valid."
    );
  });

  it("maps ai_explanation_error to a user-friendly frontend error", async () => {
    apiRequest.mockRejectedValue({
      status: 500,
      detail: "AI provider unavailable",
      errorType: "ai_explanation_error",
    });

    await expect(fetchAIExplanation("https://example.com")).rejects.toThrow(
      "AI summary could not be generated right now. Your deterministic verdict is still valid."
    );
  });

  it("maps 401 errors to an authorization message", async () => {
    apiRequest.mockRejectedValue({
      status: 401,
      detail: "Unauthorized",
    });

    await expect(fetchAIExplanation("https://example.com")).rejects.toThrow(
      "AI summary request was not authorized."
    );
  });

  it("falls back to backend detail when no known error type is provided", async () => {
    apiRequest.mockRejectedValue({
      status: 500,
      detail: "Unexpected upstream failure",
    });

    await expect(fetchAIExplanation("https://example.com")).rejects.toThrow(
      "Unexpected upstream failure"
    );
  });

  it("falls back to a generic message when the error is empty", async () => {
    apiRequest.mockRejectedValue({});

    await expect(fetchAIExplanation("https://example.com")).rejects.toThrow(
      "Could not generate AI summary. Your deterministic verdict is still valid."
    );
  });
});