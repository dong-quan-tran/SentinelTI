const ROUTES = {
  "score-url": "POST",
  "score-urls": "POST",
  "explain-score": "POST",
  "ai-explain-score": "POST",
  "ai-models": "GET",
  "model-info": "GET",
};

const MAX_BODY_BYTES = 128 * 1024;
const MAX_URL_LENGTH = 4096;
const MAX_URLS_PER_BATCH = 25;
const UPSTREAM_TIMEOUT_MS = 90000;

function sendJson(response, statusCode, payload) {
  response.statusCode = statusCode;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.end(JSON.stringify(payload));
}

function validateRequest(route, body) {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return "Expected a JSON object.";
  }

  const validateUrl = (url) =>
    typeof url === "string" &&
    url.trim().length > 0 &&
    url.length <= MAX_URL_LENGTH;

  if (route === "score-urls") {
    if (
      !Array.isArray(body.urls) ||
      body.urls.length === 0 ||
      body.urls.length > MAX_URLS_PER_BATCH ||
      !body.urls.every(validateUrl)
    ) {
      return `Provide 1 to ${MAX_URLS_PER_BATCH} URLs, each no longer than ${MAX_URL_LENGTH} characters.`;
    }
    return null;
  }

  if (
    ["score-url", "explain-score", "ai-explain-score"].includes(route) &&
    !validateUrl(body.url)
  ) {
    return `Provide a URL no longer than ${MAX_URL_LENGTH} characters.`;
  }

  if (
    route === "ai-explain-score" &&
    body.ai_model !== undefined &&
    (typeof body.ai_model !== "string" || body.ai_model.length > 128)
  ) {
    return "AI model name must be no longer than 128 characters.";
  }

  return null;
}

function getUpstreamBaseUrl(value) {
  const base = new URL(value);
  const localDevelopment =
    ["localhost", "127.0.0.1"].includes(base.hostname) &&
    base.protocol === "http:";
  if (
    (base.protocol !== "https:" && !localDevelopment) ||
    base.pathname !== "/" ||
    base.search ||
    base.hash
  ) {
    throw new Error("SENTINELTI_RENDER_API_URL must be an HTTPS origin.");
  }
  return base.origin;
}

export default async function handler(request, response) {
  response.setHeader("Cache-Control", "no-store");

  const origin = request.headers.origin;
  const host = request.headers.host;
  if (origin && host) {
    let originUrl;
    try {
      originUrl = new URL(origin);
    } catch {
      sendJson(response, 403, { detail: "Cross-origin requests are not allowed." });
      return;
    }
    const isLocalHttpOrigin =
      originUrl.protocol === "http:" &&
      ["localhost", "127.0.0.1"].includes(originUrl.hostname);
    if (
      originUrl.host.toLowerCase() !== host.toLowerCase() ||
      (originUrl.protocol !== "https:" && !isLocalHttpOrigin)
    ) {
      sendJson(response, 403, { detail: "Cross-origin requests are not allowed." });
      return;
    }
  }

  const pathname = new URL(request.url, "https://vercel.invalid").pathname;
  const route = pathname.replace(/^\/api\/?/, "");
  const expectedMethod = ROUTES[route];
  if (!expectedMethod) {
    sendJson(response, 404, { detail: "Not found." });
    return;
  }
  if (request.method !== expectedMethod) {
    response.setHeader("Allow", expectedMethod);
    sendJson(response, 405, { detail: "Method not allowed." });
    return;
  }

  if (expectedMethod === "POST") {
    const rawContentLength = request.headers["content-length"];
    if (rawContentLength !== undefined) {
      if (!/^\d+$/.test(String(rawContentLength))) {
        sendJson(response, 400, { detail: "Invalid Content-Length header." });
        return;
      }
      if (Number(rawContentLength) > MAX_BODY_BYTES) {
        sendJson(response, 413, { detail: "Request body exceeds the allowed size." });
        return;
      }
    }
    const validationError = validateRequest(route, request.body);
    if (validationError) {
      sendJson(response, 422, { detail: validationError });
      return;
    }
    if (Buffer.byteLength(JSON.stringify(request.body), "utf8") > MAX_BODY_BYTES) {
      sendJson(response, 413, { detail: "Request body exceeds the allowed size." });
      return;
    }
  }

  const apiKey = process.env.SENTINELTI_RENDER_API_KEY;
  const configuredBaseUrl = process.env.SENTINELTI_RENDER_API_URL;
  if (!apiKey || apiKey.length < 32 || !configuredBaseUrl) {
    sendJson(response, 503, { detail: "Scoring service is not configured." });
    return;
  }

  let upstreamUrl;
  try {
    upstreamUrl = `${getUpstreamBaseUrl(configuredBaseUrl)}/${route}`;
  } catch {
    sendJson(response, 503, { detail: "Scoring service is not configured." });
    return;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const upstream = await fetch(upstreamUrl, {
      method: expectedMethod,
      headers: {
        Accept: "application/json",
        "X-API-KEY": apiKey,
        ...(expectedMethod === "POST"
          ? { "Content-Type": "application/json" }
          : {}),
      },
      ...(expectedMethod === "POST"
        ? { body: JSON.stringify(request.body) }
        : {}),
      signal: controller.signal,
    });

    const payload = await upstream.text();
    response.statusCode = upstream.status;
    response.setHeader(
      "Content-Type",
      upstream.headers.get("content-type") || "application/json; charset=utf-8",
    );
    response.end(payload);
  } catch (error) {
    sendJson(
      response,
      error?.name === "AbortError" ? 504 : 502,
      {
        detail:
          error?.name === "AbortError"
            ? "Scoring service timed out."
            : "Scoring service is temporarily unavailable.",
      },
    );
  } finally {
    clearTimeout(timeout);
  }
}
