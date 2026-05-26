/* ═══════════════════════════════════════════
   CyberShield Dashboard — app.js
   ═══════════════════════════════════════════ */

'use strict';

// ── STATE ────────────────────────────────────
const state = {
  analyzed: 0,
  generated: 0,
  breached: 0,
  lastScore: null,
  history: [],
  encMode: 'caesar',
  users: {},        // { username: sha256hash }
  qaVisible: false,
};

const COMMON = new Set([
  '123456','password','admin','qwerty','letmein','welcome',
  '111111','password1','abc123','iloveyou','monkey','123456789',
  '1234567890','12345678','dragon','master','pass','root',
  'sunshine','shadow','12345','1234','test','guest','login',
  'hello','superman','batman','trustno1','baseball','football',
]);

// ── CLOCK ─────────────────────────────────────
function updateClock() {
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  document.getElementById('clock').textContent =
    `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}
setInterval(updateClock, 1000);
updateClock();

// ── SIDEBAR NAV ───────────────────────────────
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('breadcrumbCurrent').textContent =
      item.dataset.tab.toUpperCase();
    // All content is on one page; tabs are nav-only decoration
    if (window.innerWidth <= 780) {
      document.querySelector('.sidebar').classList.remove('open');
    }
  });
});

document.getElementById('menuToggle').addEventListener('click', () => {
  document.querySelector('.sidebar').classList.toggle('open');
});

// ── GAUGE ─────────────────────────────────────
const GAUGE_LEN = 283; // approx arc length of the SVG path

function setGauge(pct, label, color) {
  const arc = document.getElementById('gaugeArc');
  const num = document.getElementById('gaugeNum');
  const lbl = document.getElementById('gaugeLabel');
  const filled = (pct / 100) * GAUGE_LEN;
  arc.setAttribute('stroke-dasharray', `${filled} ${GAUGE_LEN}`);
  arc.setAttribute('stroke', color);
  num.textContent = pct + '%';
  num.setAttribute('fill', color);
  lbl.textContent = label.toUpperCase();
}

// ── SECURITY ENGINE ───────────────────────────
function calcEntropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  return pool > 0 ? Math.round(pw.length * Math.log2(pool)) : 0;
}

function crackTime(ent) {
  const secs = Math.pow(2, ent) / 1e10;
  if (secs < 1)        return '<1s';
  if (secs < 60)       return Math.round(secs) + 's';
  if (secs < 3600)     return Math.round(secs / 60) + 'min';
  if (secs < 86400)    return Math.round(secs / 3600) + 'hr';
  if (secs < 31536000) return Math.round(secs / 86400) + 'd';
  if (secs < 3.15e9)   return Math.round(secs / 31536000) + 'yr';
  return '>100yr';
}

function pwScore(pw) {
  if (!pw || COMMON.has(pw.toLowerCase())) return 0;
  let s = 0;
  if (pw.length >= 8)  s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw)) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^a-zA-Z0-9]/.test(pw)) s++;
  return Math.min(s, 5);
}

const SCORE_LABEL = ['', 'Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
const SCORE_COLOR = ['', '#ff3b5c', '#ff3b5c', '#ff9f1c', '#00ff88', '#00ff88'];
const SCORE_PCT   = [0, 15, 30, 55, 80, 100];

function getSuggestions(pw) {
  return [
    [pw.length >= 8,                  '✓ At least 8 characters',          '✗ Use at least 8 characters'],
    [pw.length >= 12,                 '✓ 12+ characters',                  '✗ Add more characters (12+)'],
    [/[A-Z]/.test(pw),               '✓ Uppercase letters',               '✗ Add uppercase (A–Z)'],
    [/[a-z]/.test(pw),               '✓ Lowercase letters',               '✗ Add lowercase (a–z)'],
    [/[0-9]/.test(pw),               '✓ Contains numbers',                '✗ Add numbers (0–9)'],
    [/[^a-zA-Z0-9]/.test(pw),        '✓ Special characters',              '✗ Add special chars (!@#$%)'],
    [!COMMON.has(pw.toLowerCase()),   '✓ Not a common password',           '✗ Avoid common passwords'],
  ].map(([ok, yes, no]) => ({ ok, msg: ok ? yes : no }));
}

function maskPw(pw) {
  if (pw.length <= 4) return '•'.repeat(pw.length);
  return pw.slice(0, 2) + '•'.repeat(Math.max(2, pw.length - 4)) + pw.slice(-2);
}

// ── QUICK ANALYZE (dashboard) ─────────────────
function quickAnalyze() {
  const pw = document.getElementById('qaInput').value;
  const s  = pwScore(pw);
  const ent = calcEntropy(pw);
  const types = [/[a-z]/,/[A-Z]/,/[0-9]/,/[^a-zA-Z0-9]/].filter(r => r.test(pw)).length;

  // Meter fill
  const fill = document.getElementById('meterFill');
  fill.style.width = pw ? SCORE_PCT[s] + '%' : '0%';
  fill.style.background = SCORE_COLOR[s] || '#333';

  // Metrics
  document.getElementById('qm-len').textContent   = pw.length;
  document.getElementById('qm-ent').textContent   = ent;
  document.getElementById('qm-typ').textContent   = types;
  document.getElementById('qm-crack').textContent = pw ? crackTime(ent) : '—';

  // Gauge
  if (pw) setGauge(SCORE_PCT[s], SCORE_LABEL[s] || 'very weak', SCORE_COLOR[s] || '#ff3b5c');
  else    setGauge(0, 'No Input', '#333');

  // Breach
  const breach = document.getElementById('qa-breach');
  if (pw) {
    const isCommon = COMMON.has(pw.toLowerCase());
    breach.classList.remove('hidden', 'danger', 'safe');
    breach.classList.add(isCommon ? 'danger' : 'safe');
    breach.textContent = isCommon
      ? '❌  COMMON PASSWORD — Change immediately!'
      : '✅  Not in common password list';
    if (isCommon) state.breached++;
  } else {
    breach.classList.add('hidden');
  }

  // Suggestions
  const sugBox = document.getElementById('qa-suggestions');
  sugBox.innerHTML = pw
    ? getSuggestions(pw).map(({ ok, msg }) =>
        `<div class="qa-sug ${ok ? 'pass' : 'fail'}">${msg}</div>`
      ).join('')
    : '';

  // Track history
  if (pw.length >= 4) {
    state.analyzed++;
    state.lastScore = SCORE_LABEL[s] || 'Very Weak';
    const masked = maskPw(pw);
    const existing = state.history.findIndex(h => h.masked === masked);
    if (existing === -1) {
      state.history.unshift({ masked, strength: state.lastScore, score: s });
      if (state.history.length > 15) state.history.pop();
    }
    updateStats();
    renderHistory();
  }
}

function toggleQaVis() {
  const inp = document.getElementById('qaInput');
  state.qaVisible = !state.qaVisible;
  inp.type = state.qaVisible ? 'text' : 'password';
  document.getElementById('qaEye').textContent = state.qaVisible ? '🙈' : '👁';
}

// ── STAT COUNTERS ─────────────────────────────
function updateStats() {
  animCount('stat-analyzed', state.analyzed);
  animCount('stat-generated', state.generated);
  animCount('stat-breached', state.breached);
  document.getElementById('stat-score').textContent = state.lastScore || '—';
}

function animCount(id, target) {
  const el = document.getElementById(id);
  const start = parseInt(el.textContent) || 0;
  const diff = target - start;
  if (diff === 0) return;
  let step = 0;
  const steps = 20;
  const interval = setInterval(() => {
    step++;
    el.textContent = Math.round(start + (diff * step / steps));
    if (step >= steps) clearInterval(interval);
  }, 16);
}

// ── ENCRYPTION ────────────────────────────────
function setMode(btn, mode) {
  state.encMode = mode;
  document.querySelectorAll('.enc-mode-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

function caesarCipher(txt, shift) {
  return txt.split('').map(c => {
    if (/[a-zA-Z]/.test(c)) {
      const base = c >= 'a' ? 97 : 65;
      return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26 + 26) % 26 + base);
    }
    return c;
  }).join('');
}
function xorEnc(txt) {
  return Array.from(txt).map(c => (c.charCodeAt(0) ^ 42).toString(16).padStart(2,'0')).join(' ');
}
function xorDec(hex) {
  try { return hex.trim().split(' ').map(h => String.fromCharCode(parseInt(h,16)^42)).join(''); }
  catch { return 'Invalid XOR input'; }
}
function b64Enc(txt) { try { return btoa(unescape(encodeURIComponent(txt))); } catch { return 'Encoding error'; } }
function b64Dec(txt) { try { return decodeURIComponent(escape(atob(txt))); } catch { return 'Invalid Base64'; } }

function doEncrypt() {
  const txt = document.getElementById('encInput').value;
  if (!txt) return;
  let out;
  if (state.encMode === 'caesar') out = caesarCipher(txt, 13);
  else if (state.encMode === 'xor') out = xorEnc(txt);
  else out = b64Enc(txt);
  document.getElementById('encOutput').textContent = out;
}
function doDecrypt() {
  const txt = document.getElementById('encInput').value;
  if (!txt) return;
  let out;
  if (state.encMode === 'caesar') out = caesarCipher(txt, -13);
  else if (state.encMode === 'xor') out = xorDec(txt);
  else out = b64Dec(txt);
  document.getElementById('encOutput').textContent = out;
}
function copyEnc() {
  const txt = document.getElementById('encOutput').textContent;
  if (txt && txt !== '—') { navigator.clipboard.writeText(txt).catch(() => {}); flash('encOutput'); }
}

// ── GENERATOR ─────────────────────────────────
function genPreview() {
  const sets = [];
  if (document.getElementById('gUp').checked)  sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if (document.getElementById('gLo').checked)  sets.push('abcdefghijklmnopqrstuvwxyz');
  if (document.getElementById('gNum').checked) sets.push('0123456789');
  if (document.getElementById('gSym').checked) sets.push('!@#$%^&*()-_=+[]{}|;:,.?');
  const len = parseInt(document.getElementById('genLen').value);
  if (!sets.length) { document.getElementById('genOutput').textContent = 'Select a type'; return; }
  const pool = sets.join('');
  let pw = sets.map(s => s[Math.floor(Math.random() * s.length)]).join('');
  while (pw.length < len) pw += pool[Math.floor(Math.random() * pool.length)];
  pw = pw.split('').sort(() => Math.random() - .5).join('').slice(0, len);
  document.getElementById('genOutput').textContent = pw;
  state.generated++;
  updateStats();
}
function copyGen() {
  const pw = document.getElementById('genOutput').textContent;
  if (pw && pw !== 'Click GENERATE') navigator.clipboard.writeText(pw).catch(() => {});
}
function useGenerated() {
  const pw = document.getElementById('genOutput').textContent;
  if (!pw || pw === 'Click GENERATE') return;
  document.getElementById('qaInput').value = pw;
  quickAnalyze();
}

// ── HISTORY ───────────────────────────────────
function renderHistory() {
  const list = document.getElementById('histList');
  if (!state.history.length) {
    list.innerHTML = '<div class="hist-empty">No passwords analyzed yet.</div>';
    return;
  }
  list.innerHTML = state.history.map(h => {
    const cls = h.score <= 2 ? 'weak' : h.score === 3 ? 'med' : 'str';
    return `<div class="hist-item">
      <span class="hist-mask">${h.masked}</span>
      <span class="hist-badge ${cls}">${h.strength}</span>
    </div>`;
  }).join('');
}
function clearHistory() {
  state.history = [];
  renderHistory();
}

// ── LOGIN SIMULATION ──────────────────────────
async function sha256(msg) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function doLogin() {
  const user = document.getElementById('lUser').value.trim();
  const pass = document.getElementById('lPass').value;
  const resEl = document.getElementById('loginResult');
  const hashWrap = document.getElementById('loginHashWrap');
  const hashEl = document.getElementById('loginHash');

  if (!user || !pass) {
    show(resEl, 'err', '⚠  Enter both username and password.');
    return;
  }
  const hash = await sha256(pass);
  if (!state.users[user]) {
    state.users[user] = hash;
    show(resEl, 'ok', `✅  Account created for "${user}".\nPassword stored as SHA-256 hash.`);
  } else if (state.users[user] === hash) {
    show(resEl, 'ok', `✅  Welcome back, ${user}! Login successful.`);
  } else {
    show(resEl, 'err', `❌  Incorrect password for "${user}".`);
    hashWrap.classList.add('hidden');
    return;
  }
  hashEl.textContent = hash;
  hashWrap.classList.remove('hidden');
}

function show(el, cls, msg) {
  el.className = `login-result ${cls}`;
  el.textContent = msg;
  el.classList.remove('hidden');
}

// ── FLASH FEEDBACK ────────────────────────────
function flash(id) {
  const el = document.getElementById(id);
  el.style.transition = 'background .1s';
  el.style.background = 'rgba(0,255,136,.2)';
  setTimeout(() => el.style.background = '', 300);
}

// ── INIT ──────────────────────────────────────
genPreview();
renderHistory();
updateStats();