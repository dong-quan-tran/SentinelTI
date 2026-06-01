# SentinelTI AI Cheatsheet

This cheatsheet summarizes how SentinelTI's optional AI-assisted explanation layer works, how to configure it, and what responses to expect.

## Purpose

SentinelTI uses deterministic scoring as the source of truth.

The optional AI layer exists only to rewrite the deterministic explanation in clearer, more user-friendly language. It does **not** change the underlying score, label, threshold, or risk.

## Key rule

AI output is advisory only.

These fields always remain deterministic and authoritative:

- `label`
- `prob_malicious`
- `threshold`
- `final_label`
- `risk`

## Main AI endpoint

### `POST /ai-explain-score`

Returns:

- `deterministic_explanation`: the normal explanation generated from scoring + heuristics
- `ai`: a separate plain-language rewrite block

Example response:

```json
{
  "deterministic_explanation": {
    "summary": "This URL appears suspicious.",
    "why_flagged": "Several phishing-like signals were detected.",
    "user_action": "Avoid opening the link until it is verified.",
    "technical_notes": [
      "Contains suspicious lexical patterns."
    ],
    "risk": "high",
    "final_label": "malicious"
  },
  "ai": {
    "summary": "This link shows several warning signs and should be treated as high risk.",
    "guidance": "Use the deterministic verdict as the primary decision signal. The AI summary is only a helper explanation."
  }
}
```

## AI model discovery

### `GET /ai-models`

Returns:

- `provider`: current configured AI provider
- `default_model`: configured default model when applicable
- `models`: available local models when using Ollama

Example response:

```json
{
  "provider": "ollama",
  "default_model": "llama3.1:8b",
  "models": [
    "llama3.1:8b",
    "llama3.1:70b"
  ]
}
```

## Environment variables

### Core AI flags

```bash
SENTINELTI_AI_ENABLED=true
SENTINELTI_AI_PROVIDER=ollama
```

### Ollama config

```bash
SENTINELTI_OLLAMA_ENDPOINT=http://localhost:11434
SENTINELTI_OLLAMA_MODEL=llama3.1:8b
```

### API auth

```bash
SENTINELTI_API_KEY=your-secret-key
```

## Common local setups

### 1. AI disabled

Use this when you want all deterministic scoring endpoints active, but no AI endpoint behavior beyond the documented disabled response.

```bash
SENTINELTI_AI_ENABLED=false
```

Behavior:

- `POST /ai-explain-score` returns `503`
- standard deterministic endpoints still work normally

Disabled response:

```json
{
  "detail": "AI explanations are currently disabled.",
  "error_type": "ai_disabled"
}
```

### 2. AI enabled with Ollama

Use this when running a local Ollama server.

```bash
SENTINELTI_AI_ENABLED=true
SENTINELTI_AI_PROVIDER=ollama
SENTINELTI_OLLAMA_ENDPOINT=http://localhost:11434
SENTINELTI_OLLAMA_MODEL=llama3.1:8b
```

Behavior:

- `POST /ai-explain-score` performs deterministic scoring first
- then it generates a separate AI rewrite
- deterministic fields remain unchanged

## Error behavior

### AI disabled

HTTP status:

```text
503 Service Unavailable
```

Payload:

```json
{
  "detail": "AI explanations are currently disabled.",
  "error_type": "ai_disabled"
}
```

### AI provider failure

HTTP status:

```text
500 Internal Server Error
```

Payload:

```json
{
  "detail": "AI provider unavailable",
  "error_type": "ai_explanation_error"
}
```

### Requested model unavailable

HTTP status:

```text
422 Unprocessable Entity
```

Payload:

```json
{
  "detail": "Requested AI model is not available",
  "error_type": "ai_model_unavailable"
}
```

## Request examples

### AI explain request

```bash
curl -X POST "http://localhost:8000/ai-explain-score" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d '{"url": "https://example.com"}'
```

### AI explain with model override

```bash
curl -X POST "http://localhost:8000/ai-explain-score" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d '{"url": "https://example.com", "ai_model": "llama3.1:8b"}'
```

### List AI models

```bash
curl -X GET "http://localhost:8000/ai-models" \
  -H "X-API-KEY: your-secret-key"
```

## What to remember

- Deterministic scoring is the source of truth.
- AI is a readability layer, not a scoring engine.
- Disabling AI should short-circuit `/ai-explain-score` before any provider call.
- A bad AI response must never overwrite deterministic verdict fields.
- Standard scoring endpoints should keep working even if AI is disabled or failing.