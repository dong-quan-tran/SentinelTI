import { afterEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "./baseClient";

describe("apiRequest", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses the same-origin gateway without embedding an API key", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      headers: { get: () => "application/json" },
      ok: true,
      json: async () => ({ status: "ready" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiRequest("/model-info", { method: "GET" })).resolves.toEqual({
      status: "ready",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/model-info",
      expect.objectContaining({
        method: "GET",
        headers: { "Content-Type": "application/json" },
      }),
    );
    expect(fetchMock.mock.calls[0][1].headers).not.toHaveProperty("X-API-KEY");
  });

  it("rejects non-root-relative API paths", async () => {
    await expect(apiRequest("https://attacker.example")).rejects.toThrow(
      "API path must be a same-origin absolute path.",
    );
  });
});
