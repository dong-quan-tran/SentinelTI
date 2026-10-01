import { describe, expect, it } from "vitest";
import { normalizeScoreResponse } from "./normalizers";

const validResponse = {
  url: "https://example.com",
  label: 0,
  prob_malicious: 0.08,
  final_label: "benign",
  risk: "low",
  explanation: {
    summary: "No strong warning detected.",
    why_flagged: "Few suspicious signals detected.",
    user_action: "Verify the domain before signing in.",
    technical_notes: [],
    final_label: "benign",
    risk: "low",
  },
};

describe("normalizeScoreResponse", () => {
  it("accepts a valid scoring response", () => {
    expect(normalizeScoreResponse(validResponse).final_label).toBe("benign");
  });

  it.each([
    ["missing verdict", { final_label: undefined }],
    ["unknown verdict", { final_label: "unknown" }],
    ["missing risk", { risk: undefined }],
    ["missing malicious score", { prob_malicious: undefined }],
    ["invalid malicious score", { prob_malicious: 1.5 }],
    ["missing URL", { url: undefined }],
  ])("rejects %s instead of displaying a safe result", (_name, changes) => {
    expect(() =>
      normalizeScoreResponse({ ...validResponse, ...changes })
    ).toThrow(/invalid scoring response/i);
  });
});
