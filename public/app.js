'use strict';
// Bastion frontend. Loaded as an external file so the page can run under a
// Content-Security-Policy with no 'unsafe-inline'.
const $ = (id) => document.getElementById(id);
const urlInput = $('url'), scanBtn = $('scan'), msg = $('msg');
const scanning = $('scanning'), scanstep = $('scanstep'), results = $('results');
const STEPS = ['Resolving host', 'Checking transport security', 'Reading response headers', 'Inspecting cookies', 'Evaluating CORS policy', 'Scoring findings', 'Writing your briefing'];
const GRADE_COLOR = { A: '#1c8f5a', B: '#5a9b3e', C: '#b07d10', D: '#c46a1a', E: '#cf3f3a', F: '#cf3f3a' };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const normalizeUrl = (raw) => { let v = raw.trim(); if (!v) return ''; if (!/^https?:\/\//i.test(v)) v = 'https://' + v; return v; };

let stepTimer = null;
function startScan() { let i = 0; scanstep.textContent = STEPS[0]; scanning.classList.add('show');
  stepTimer = setInterval(() => { i = Math.min(i + 1, STEPS.length - 1); scanstep.textContent = STEPS[i]; }, 950); }
function stopScan() { clearInterval(stepTimer); scanning.classList.remove('show'); }

function render(data) {
  const color = GRADE_COLOR[data.grade] || 'var(--ink)';
  const fails = data.findings.filter((f) => f.status === 'fail').length;
  const warns = data.findings.filter((f) => f.status === 'warn').length;
  const passes = data.findings.filter((f) => f.status === 'pass').length;
  const C = 2 * Math.PI * 58;
  let h = '<div class="summary"><div class="ringwrap"><svg class="ring" viewBox="0 0 132 132">';
  h += '<circle class="ring-track" cx="66" cy="66" r="58"></circle>';
  h += '<circle class="ring-fill" cx="66" cy="66" r="58" stroke="' + color + '" stroke-dasharray="' + C.toFixed(1) + '" stroke-dashoffset="' + C.toFixed(1) + '"></circle>';
  h += '</svg><div class="ring-center"><div class="grade grade-' + (GRADE_COLOR[data.grade] ? data.grade : 'X') + '">' + esc(data.grade) + '</div><div class="score">' + data.score + ' / 100</div></div></div>';
  h += '<div class="summary-meta"><div class="scanned">Scan complete</div><h2>' + esc(data.url) + '</h2><div class="tallies">';
  h += '<span class="pill high"><span class="d"></span><b>' + fails + '</b> failing</span>';
  h += '<span class="pill med"><span class="d"></span><b>' + warns + '</b> warnings</span>';
  h += '<span class="pill pass"><span class="d"></span><b>' + passes + '</b> passing</span></div></div></div>';
  if (data.briefing) h += '<div class="briefing"><div class="tag">AI risk briefing</div><p>' + esc(data.briefing) + '</p></div>';
  const actionable = data.findings.filter((f) => f.status !== 'pass');
  const passed = data.findings.filter((f) => f.status === 'pass');
  if (actionable.length) { h += '<div class="section-label">What to fix</div>'; actionable.forEach((f) => h += card(f)); }
  if (passed.length) { h += '<div class="section-label">Passing checks</div>'; passed.forEach((f) => h += card(f)); }
  results.innerHTML = h; results.classList.add('show');
  requestAnimationFrame(() => { const fill = results.querySelector('.ring-fill'); if (fill) fill.style.strokeDashoffset = (C * (1 - data.score / 100)).toFixed(1); });
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function card(f) {
  let c = '<div class="finding' + (f.status === 'pass' ? ' is-pass' : '') + '">';
  c += '<div class="sev"><span class="badge ' + f.severity + '">' + f.severity + '</span><span class="status ' + f.status + '">' + f.status + '</span></div>';
  c += '<div><h3>' + esc(f.title) + '</h3>';
  if (f.detail) c += '<div class="detail">' + esc(f.detail) + '</div>';
  if (f.fix) c += '<div class="fix">' + esc(f.fix) + '</div>';
  return c + '</div></div>';
}
async function runScan() {
  msg.className = 'msg'; results.classList.remove('show');
  const target = normalizeUrl(urlInput.value);
  if (!target) { msg.textContent = 'Enter a website address to scan.'; msg.className = 'msg error show'; return; }
  try { new URL(target); } catch { msg.textContent = "That doesn't look like a valid web address."; msg.className = 'msg error show'; return; }
  scanBtn.disabled = true; startScan();
  try {
    const res = await fetch('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: target }) });
    const data = await res.json(); stopScan();
    if (!res.ok) { msg.textContent = data.error || 'The scan could not be completed.'; msg.className = 'msg error show'; return; }
    render(data);
  } catch (e) {
    stopScan();
    msg.textContent = 'Network error — could not reach the scanner. (If you opened this file directly, deploy it first: the scan runs on the server.)';
    msg.className = 'msg error show';
  } finally { scanBtn.disabled = false; }
}
scanBtn.addEventListener('click', runScan);
document.querySelectorAll('[data-focus-url]').forEach((el) => el.addEventListener('click', (e) => { e.preventDefault(); urlInput.focus(); }));
urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') runScan(); });
