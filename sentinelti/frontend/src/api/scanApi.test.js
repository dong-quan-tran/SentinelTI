import { describe, it, expect, vi, beforeEach } from "vitest";
import { scoreUrl, scoreUrls, explainScore } from "./scanApi";
import { apiRequest } from "./baseClient";
import { normalizeScoreResponse } from "./normalizers";

vi.mock("./baseClient", () => ({
  apiRequest: vi.fn(),
}));

vi.mock("./normalizers", () => ({
  normalizeScoreResponse: vi.fn(),
}));

describe("scanApi", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("scoreUrl posts to /score-url and normalizes the response", async () => {
    const rawResponse = { raw: true };
    const normalizedResponse = { final_label: "benign" };

    apiRequest.mockResolvedValue(rawResponse);
    normalizeScoreResponse.mockReturnValue(normalizedResponse);

    await expect(scoreUrl("https://example.com")).resolves.toEqual(
      normalizedResponse
    );

    expect(apiRequest).toHaveBeenCalledWith("/score-url", {
      method: "POST",
      body: JSON.stringify({ url: "https://example.com" }),
    });
    expect(normalizeScoreResponse).toHaveBeenCalledWith(rawResponse);
  });

  it("scoreUrls posts to /score-urls and normalizes each result", async () => {
    const rawResults = [{ id: 1 }, { id: 2 }];

    apiRequest.mockResolvedValue({ results: rawResults });
    normalizeScoreResponse
      .mockReturnValueOnce({ final_label: "benign" })
      .mockReturnValueOnce({ final_label: "suspicious" });

    await expect(
      scoreUrls(["https://one.test", "https://two.test"])
    ).resolves.toEqual({
      results: [
        { final_label: "benign" },
        { final_label: "suspicious" },
      ],
    });

    expect(apiRequest).toHaveBeenCalledWith("/score-urls", {
      method: "POST",
      body: JSON.stringify({
        urls: ["https://one.test", "https://two.test"],
      }),
    });
    expect(normalizeScoreResponse).toHaveBeenCalledTimes(2);
    expect(normalizeScoreResponse).toHaveBeenNthCalledWith(
    1,
    rawResults[0],
    0,
    rawResults
    );
    expect(normalizeScoreResponse).toHaveBeenNthCalledWith(
    2,
    rawResults[1],
    1,
    rawResults
    );
  });

  it("scoreUrls returns an empty results list when the backend payload is malformed", async () => {
    apiRequest.mockResolvedValue({ results: null });

    await expect(scoreUrls(["https://example.com"])).resolves.toEqual({
      results: [],
    });

    expect(normalizeScoreResponse).not.toHaveBeenCalled();
  });

  it("explainScore posts to /explain-score and returns the raw explanation payload", async () => {
    const explanationPayload = {
      summary: "Low risk",
      why_flagged: "Few suspicious signals",
      user_action: "Proceed carefully",
      technical_notes: [],
      risk: "low",
      final_label: "benign",
    };

    apiRequest.mockResolvedValue(explanationPayload);

    await expect(explainScore("https://example.com")).resolves.toEqual(
      explanationPayload
    );

    expect(apiRequest).toHaveBeenCalledWith("/explain-score", {
      method: "POST",
      body: JSON.stringify({ url: "https://example.com" }),
    });
  });
});