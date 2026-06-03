// Scoring — converts a list of findings into a 0–100 score and a letter grade.
//
// Start at 100 and deduct for each failed or warned check, weighted by
// severity. Passes never add or subtract (the baseline already assumes a
// well-configured site). The mapping is deliberately strict at the top end so
// an "A" actually means something a small business can trust.

const DEDUCTION = {
  high:   { fail: 25, warn: 10 },
  medium: { fail: 12, warn: 6 },
  low:    { fail: 5,  warn: 3 },
  info:   { fail: 2,  warn: 1 },
};

function computeScore(findings) {
  let score = 100;
  const counts = { high: 0, medium: 0, low: 0, info: 0 };

  for (const f of findings) {
    if (f.status === 'pass') continue;
    const weights = DEDUCTION[f.severity] || DEDUCTION.low;
    score -= weights[f.status] ?? 0;
    if (f.status === 'fail') counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  score = Math.max(0, Math.min(100, score));
  return { score, grade: gradeFor(score), counts };
}

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 40) return 'E';
  return 'F';
}

export { computeScore, gradeFor, DEDUCTION };
