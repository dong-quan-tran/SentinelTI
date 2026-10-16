import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import handler from "../../api/[...path].js";

function createResponse() {
  return {
    headers: {},
    statusCode: 200,
    body: "",
    setHeader(name, value) {
      this.headers[name] = value;
    },
    end(value = "") {
      this.body = value;
    },
  };
}

function createRequest(overrides = {}) {
  return {
    method: "POST",
    url: "/api/score-url",
    headers: {
      host: "sentinelti.vercel.app",
      origin: "https://sentinelti.vercel.app",
      "content-type": "application/json",
    },
    body: { url: "https://example.com/login" },
    ...overrides,
  };
}

describe("Vercel API gateway", () => {
  beforeEach(() => {
    vi.stubEnv("SENTINELTI_RENDER_API_URL", "https://sentinelti-api.onrender.com");
    vi.stubEnv("SENTINELTI_RENDER_API_KEY", "x".repeat(48));
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        status: 200,
        headers: { get: () => "application/json" },
        text: async () => '{"final_label":"benign"}',
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("forwards only the server-side API credential to the Render service", async () => {
    const response = createResponse();

    await handler(createRequest(), response);

    expect(response.statusCode).toBe(200);
    expect(response.body).toBe('{"final_label":"benign"}');
    expect(fetch).toHaveBeenCalledWith(
      "https://sentinelti-api.onrender.com/score-url",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "X-API-KEY": "x".repeat(48),
        }),
      }),
    );
  });

  it("rejects routes outside the endpoint allowlist", async () => {
    const response = createResponse();

    await handler(createRequest({ url: "/api/arbitrary" }), response);

    expect(response.statusCode).toBe(404);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects cross-origin browser requests", async () => {
    const response = createResponse();

    await handler(
      createRequest({
        headers: {
          host: "sentinelti.vercel.app",
          origin: "https://attacker.example",
        },
      }),
      response,
    );

    expect(response.statusCode).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects insecure non-local origins on the same host", async () => {
    const response = createResponse();

    await handler(
      createRequest({
        headers: {
          host: "sentinelti.vercel.app",
          origin: "http://sentinelti.vercel.app",
        },
      }),
      response,
    );

    expect(response.statusCode).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects unsupported methods before forwarding", async () => {
    const response = createResponse();

    await handler(createRequest({ method: "GET" }), response);

    expect(response.statusCode).toBe(405);
    expect(response.headers.Allow).toBe("POST");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects batches above the server-side limit", async () => {
    const response = createResponse();

    await handler(
      createRequest({
        url: "/api/score-urls",
        body: { urls: Array.from({ length: 26 }, () => "https://example.com") },
      }),
      response,
    );

    expect(response.statusCode).toBe(422);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects malformed or oversized content lengths", async () => {
    const malformedResponse = createResponse();
    await handler(
      createRequest({
        headers: {
          host: "sentinelti.vercel.app",
          origin: "https://sentinelti.vercel.app",
          "content-length": "not-a-number",
        },
      }),
      malformedResponse,
    );

    const oversizedResponse = createResponse();
    await handler(
      createRequest({
        headers: {
          host: "sentinelti.vercel.app",
          origin: "https://sentinelti.vercel.app",
          "content-length": String(128 * 1024 + 1),
        },
      }),
      oversizedResponse,
    );

    expect(malformedResponse.statusCode).toBe(400);
    expect(oversizedResponse.statusCode).toBe(413);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("fails closed when the Render API key is not configured", async () => {
    vi.stubEnv("SENTINELTI_RENDER_API_KEY", "");
    const response = createResponse();

    await handler(createRequest(), response);

    expect(response.statusCode).toBe(503);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("uses a gateway error rather than leaking upstream connection details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("private network detail")),
    );
    const response = createResponse();

    await handler(createRequest(), response);

    expect(response.statusCode).toBe(502);
    expect(response.body).not.toContain("private network detail");
  });

  it("returns a gateway timeout when the Render service exceeds its deadline", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(Object.assign(new Error("aborted"), { name: "AbortError" })),
    );
    const response = createResponse();

    await handler(createRequest(), response);

    expect(response.statusCode).toBe(504);
    expect(response.body).toContain("timed out");
  });
});
