import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAnthropicRequest, extractText, generateBriefing, DEFAULT_MODEL } from '../lib/ai-summary.js';

const sampleResult = {
  url: 'https://example.com',
  grade: 'C',
  score: 72,
  findings: [
    { title: 'No HSTS header', severity: 'high', status: 'fail' },
    { title: 'HTTPS available', severity: 'high', status: 'pass' },
    { title: 'No Referrer-Policy', severity: 'low', status: 'warn' },
  ],
};

test('request body defaults to Haiku and excludes passed findings', () => {
  const body = buildAnthropicRequest(sampleResult);
  assert.equal(body.model, DEFAULT_MODEL);
  assert.ok(body.max_tokens > 0);
  assert.equal(body.messages.length, 1);
  const content = body.messages[0].content;
  assert.match(content, /No HSTS header/);
  assert.match(content, /No Referrer-Policy/);
  assert.doesNotMatch(content, /HTTPS available/); // passes are filtered out
});

test('request body honors a configured model override', () => {
  const body = buildAnthropicRequest(sampleResult, 'claude-opus-4-8');
  assert.equal(body.model, 'claude-opus-4-8');
});

test('extractText concatenates text blocks and ignores others', () => {
  const text = extractText({
    content: [
      { type: 'text', text: 'Your site is mostly secure.' },
      { type: 'tool_use', name: 'noop' },
      { type: 'text', text: 'Fix HSTS first.' },
    ],
  });
  assert.equal(text, 'Your site is mostly secure.\nFix HSTS first.');
});

test('extractText returns null for empty/invalid responses', () => {
  assert.equal(extractText(null), null);
  assert.equal(extractText({ content: [] }), null);
  assert.equal(extractText({ content: [{ type: 'tool_use' }] }), null);
});

test('generateBriefing returns null when no API key is set (graceful degradation)', async () => {
  const result = await generateBriefing(sampleResult, undefined, async () => {
    throw new Error('should not be called');
  });
  assert.equal(result, null);
});

test('generateBriefing returns null on API error rather than throwing', async () => {
  const failingFetch = async () => ({ ok: false, status: 500 });
  const result = await generateBriefing(sampleResult, 'key', failingFetch);
  assert.equal(result, null);
});

test('generateBriefing returns text on success', async () => {
  const okFetch = async () => ({
    ok: true,
    json: async () => ({ content: [{ type: 'text', text: 'Mostly fine. Fix HSTS.' }] }),
  });
  const result = await generateBriefing(sampleResult, 'key', okFetch);
  assert.equal(result, 'Mostly fine. Fix HSTS.');
});
