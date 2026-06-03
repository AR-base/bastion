// AI threat briefing — turns the technical scan into a short, plain-English
// risk summary aimed at a non-technical small-business owner, using Claude
// Haiku. This is the "warn the user about threats" layer.
//
// Design choices:
//   - The request body is built by a pure function so it can be unit-tested
//     without any network access.
//   - The whole feature degrades gracefully: if no API key is configured the
//     scanner still returns full technical findings, just without the briefing.
//   - The model only ever sees the structured findings, never the raw target
//     response, keeping the prompt small and predictable.

// Default model if none is configured. Override per deployment via the
// AI_MODEL var (see wrangler.toml). For this task — turning already-structured
// findings into a short plain-English briefing — Haiku is the cost/latency
// sweet spot; Sonnet 4.6 or Opus 4.8 are drop-in upgrades if you want richer
// prose and are willing to pay 3x / 5x per token respectively.
const DEFAULT_MODEL = 'claude-haiku-4-5-20251001';

const SYSTEM_PROMPT = [
  'You are a security advisor for small businesses and startups with no in-house security team.',
  'You will receive the results of a passive website security scan as JSON.',
  'Write a brief, calm, non-alarmist briefing for the business owner.',
  'Rules:',
  '- Plain language, no jargon. If you must use a term, explain it in a few words.',
  '- Lead with the overall risk in one sentence.',
  '- Then give the top 3 priorities to fix, most important first, each with why it matters to the business (lost trust, data leaks, downtime).',
  '- Be concrete and short. No preamble, no sign-off. Under 180 words.',
  '- Never invent issues that are not in the scan data.',
].join('\n');

function buildAnthropicRequest(scanResult, model = DEFAULT_MODEL) {
  const slim = {
    url: scanResult.url,
    grade: scanResult.grade,
    score: scanResult.score,
    failed: scanResult.findings
      .filter((f) => f.status !== 'pass')
      .map((f) => ({ title: f.title, severity: f.severity, status: f.status })),
  };

  return {
    model,
    max_tokens: 400,
    system: SYSTEM_PROMPT,
    messages: [
      {
        role: 'user',
        content: `Here is the scan result. Write the owner briefing.\n\n${JSON.stringify(slim, null, 2)}`,
      },
    ],
  };
}

function extractText(apiResponse) {
  if (!apiResponse || !Array.isArray(apiResponse.content)) return null;
  const text = apiResponse.content
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n')
    .trim();
  return text || null;
}

async function generateBriefing(scanResult, apiKey, fetchImpl = fetch, model = DEFAULT_MODEL) {
  if (!apiKey) return null;
  let resp;
  try {
    resp = await fetchImpl('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(buildAnthropicRequest(scanResult, model)),
    });
  } catch {
    return null; // never let the AI layer break the core scan
  }
  if (!resp.ok) return null;
  try {
    const data = await resp.json();
    return extractText(data);
  } catch {
    return null;
  }
}

export { DEFAULT_MODEL, SYSTEM_PROMPT, buildAnthropicRequest, extractText, generateBriefing };
