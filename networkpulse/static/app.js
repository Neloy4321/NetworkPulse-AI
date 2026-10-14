/* NetworkPulse dashboard — dependency-free, same-origin, read-only by default.
 * Investigation mutation requires explicit operator-provided key (never saved).
 */
'use strict';

const $ = (id) => document.getElementById(id);
const colors = ['#59d5c0', '#7ebaf0', '#e8b67a', '#8c82d7'];
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const fmt = (v) => Number(v ?? 0).toLocaleString('en-US');
let latestTrends = [];
let toastTimer;
let alertsOffset=0;
const alertsLimit=25;
let activeCaseId = null;
let browserSession = null;

async function initializeBrowserAuth() {
  const result = await fetch('/auth/session', {cache: 'no-store'});
  if (result.status === 404) return;
  if (result.status === 401) { window.location.assign('/auth/login'); return; }
  if (!result.ok) throw new Error('OIDC session unavailable');
  browserSession = await result.json();
  const logout = $('logout-button');
  logout.hidden = false;
  logout.addEventListener('click', async () => {
    const r = await fetch('/auth/logout', {
      method: 'POST', headers: {'X-CSRF-Token': browserSession.csrf_token}
    });
    if (r.ok) window.location.assign('/auth/login');
    else toast('Sign-out failed.');
  });
}

async function mutationHeaders() {
  if (browserSession) {
    return {'Content-Type': 'application/json',
            'X-CSRF-Token': browserSession.csrf_token};
  }
  const key = prompt('Operator X-API-Key (not stored by browser)');
  return key ? {'Content-Type': 'application/json', 'X-API-Key': key} : null;
}

async function getJson(url, init = {}) {
  const r = await fetch(url, {cache: 'no-store', ...init});
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  return r.json();
}
function toast(message) {
  const node = $('toast'); node.textContent = message; node.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => node.classList.remove('show'), 4000);
}
function protocolChart(protocols, total) {
  const entries = Object.entries(protocols || {}).sort((a, b) => b[1] - a[1]);
  let offset = 0;
  const segments = entries.map(([key, value], i) => {
    const percent = total ? value / total * 100 : 0;
    const part = `${colors[i % colors.length]} ${offset.toFixed(2)}% ${(offset + percent).toFixed(2)}%`;
    offset += percent;
    return part;
  });
  $('proto-donut').style.background = `conic-gradient(${segments.join(', ') || '#304052 0 100%'})`;
  $('protocol-total').textContent = fmt(total);
  $('protocol-legend').innerHTML = entries.length ? entries.map(([key, value]) =>
    `<div class="proto-line"><span><i></i>${esc(key.toUpperCase())}</span><b>${(value / total * 100).toFixed(1)}%</b></div>`
  ).join('') : '<span class="muted">No protocol data yet</span>';
  // CSSOM is compatible with CSP style-src 'self'; no inline style attributes.
  $('protocol-legend').querySelectorAll('.proto-line i').forEach((dot, i) => {
    dot.style.backgroundColor = colors[i % colors.length];
  });
}
function drawTimeline(data) {
  const canvas = $('traffic-chart');
  const ratio = Math.max(1, window.devicePixelRatio || 1);
  const rect = canvas.getBoundingClientRect();
  const w = rect.width || 600; const h = 245;
  canvas.width = Math.floor(w * ratio); canvas.height = Math.floor(h * ratio);
  const ctx = canvas.getContext('2d');
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, w, h);
  const left = 39, right = w - 12, top = 20, bottom = h - 27;
  ctx.font = '11px monospace';
  if (!data.length) { ctx.fillStyle = '#829bab'; ctx.fillText('Waiting for ingested flow data…', left + 12, h / 2); return; }
  const max = Math.max(2, ...data.map(d => d.flows));
  for (let i = 0; i <= 4; i++) {
    const y = top + (bottom - top) * i / 4;
    ctx.strokeStyle = '#294055'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(right, y); ctx.stroke();
    ctx.fillStyle = '#7890a4'; ctx.fillText(fmt(Math.round(max * (1 - i / 4))), 3, y + 4);
  }
  const xs = (i) => left + (right - left) * i / Math.max(1, data.length - 1);
  const ys = (v) => bottom - (bottom - top) * v / max;
  for (const [key, color] of [['flows', '#59d5c0'], ['anomalies', '#e8b67a']]) {
    ctx.strokeStyle = color; ctx.lineWidth = 2.3; ctx.beginPath();
    data.forEach((d, i) => (i ? ctx.lineTo(xs(i), ys(d[key])) : ctx.moveTo(xs(i), ys(d[key]))));
    ctx.stroke();
  }
  ctx.fillStyle = '#829bab';
  for (let i = 0; i < 4; i++) {
    const idx = Math.round(i * (data.length - 1) / 3);
    const time = data[idx].time.split(' ').slice(1).join(' ');
    ctx.fillText(time.slice(0, 10), xs(idx) - (i === 0 ? 0 : 31), bottom + 18);
  }
}
function renderAlerts(alerts) {
  $('alerts-body').innerHTML = alerts.length ? alerts.map(a => `<tr>
    <td><span class="severity ${esc(a.severity)}">${esc(a.severity.toUpperCase())}</span></td>
    <td>${esc(a.src_ip)} <span class="muted">→</span> ${esc(a.dst_ip)}<span class="muted">:${a.dst_port}</span></td>
    <td><strong>${a.risk}</strong></td><td><span class="status">${esc(a.status.replace('_', ' '))}</span></td>
    <td title="${esc(a.reasons.join('; '))}">${esc(a.reasons.join('; '))}</td>
    <td><button type="button" data-case="${a.id}">DETAILS</button> <button type="button" data-alert="${a.id}">TRIAGE ↗</button></td>
  </tr>`).join('') : '<tr><td colspan="6" class="muted">No alerts match the selected filter.</td></tr>';
  $('alerts-body').querySelectorAll('button[data-alert]').forEach(btn => {
    btn.addEventListener('click', () => triage(Number(btn.dataset.alert)));
  });
  $('alerts-body').querySelectorAll('button[data-case]').forEach(btn => {
    btn.addEventListener('click', () => showCase(Number(btn.dataset.case)));
  });
}

function renderCaseList(id, entries, asText) {
  const list = $(id);
  list.replaceChildren();
  if (!entries.length) {
    const item = document.createElement('li');
    item.textContent = 'No records yet.';
    list.append(item);
    return;
  }
  for (const entry of entries) {
    const item = document.createElement('li');
    // textContent deliberately prevents untrusted note/actor HTML injection.
    item.textContent = asText(entry);
    list.append(item);
  }
}
async function showCase(id) {
  activeCaseId = id;
  $('casework').hidden = false;
  $('case-summary').textContent = 'Loading alert #' + id + '…';
  try {
    const [detail, history] = await Promise.all([
      getJson('/api/v1/alerts/' + id + '/detail'),
      getJson('/api/v1/alerts/' + id + '/history')
    ]);
    if (activeCaseId !== id) return;
    $('case-summary').textContent = 'Alert #' + detail.id + ' · ' +
      detail.severity.toUpperCase() + ' · ' + detail.status.replace('_', ' ') +
      ' · Risk ' + detail.risk;
    const event = detail.event;
    $('case-flow').textContent = event.src_ip + ':' + event.src_port + ' → ' +
      event.dst_ip + ':' + event.dst_port + ' · ' + event.proto.toUpperCase() +
      ' · ' + event.orig_bytes + '/' + event.resp_bytes + ' bytes (sent/received)';
    $('case-owner').textContent = detail.assigned_to || 'Unassigned';
    $('case-reasons').textContent = (detail.reasons || []).join('; ') || 'None recorded';
    renderCaseList('case-history', history, h => h.old_status + ' → ' +
      h.new_status + ' · ' + h.actor + ' · ' + h.changed_at + ' · ' + h.note);
    renderCaseList('case-notes', detail.notes || [], n => n.actor + ': ' +
      n.note + ' · ' + n.created_at);
  } catch (err) {
    $('case-summary').textContent = 'Case detail unavailable: ' + err.message;
  }
}
async function caseMutation(suffix, method, payload) {
  const id = activeCaseId;
  if (id === null) return;
  const headers = await mutationHeaders();
  if (!headers) return;
  try {
    await getJson('/api/v1/alerts/' + id + '/' + suffix, {
      method, headers,
      body: JSON.stringify(payload)
    });
    toast('Case update recorded.');
    await showCase(id);
    await refresh();
  } catch (err) { toast('Case update failed: ' + err.message); }
}
$('case-close').addEventListener('click', () => {
  activeCaseId = null;
  $('casework').hidden = true;
});
$('case-assign').addEventListener('click', async () => {
  const owner = prompt('Analyst name (empty to unassign)');
  if (owner === null) return;
  const name = owner.trim();
  if (name.length > 150) { toast('Analyst name too long.'); return; }
  const note = prompt('Reason for assignment (minimum 3 characters)');
  if (!note || note.trim().length < 3) { toast('Audit reason required.'); return; }
  await caseMutation('assignment', 'PATCH', {assigned_to: name || null, note: note.trim()});
});
$('case-add-note').addEventListener('click', async () => {
  const note = prompt('Analyst note (minimum 3 characters)');
  if (!note || note.trim().length < 3) { toast('A note is required.'); return; }
  await caseMutation('notes', 'POST', {note: note.trim()});
});
async function triage(id) {
  const headers = await mutationHeaders();
  if (!headers) return;
  const state = prompt('New status: open | investigating | resolved | false_positive', 'investigating');
  if (state === null) return;
  if (!['open','investigating','resolved','false_positive'].includes(state)) { toast('Invalid status.'); return; }
  const note = prompt('Audit note (minimum 3 characters)');
  if (note === null || note.trim().length < 3) { toast('A reason of at least 3 characters is required.'); return; }
  try {
    await getJson(`/api/v1/alerts/${id}`, {method: 'PATCH', headers, body: JSON.stringify({status: state, note})});
    toast(`Alert #${id} updated; audit trail recorded.`);
    await refresh();
    if (activeCaseId === id) await showCase(id);
  } catch (err) { toast('Triage failed: ' + err.message); }
}
let lastBehaviorFindingsFetch = 0;
async function refreshBehaviorFindings(force = false) {
  if (!force && Date.now() - lastBehaviorFindingsFetch < 30000) return;
  lastBehaviorFindingsFetch = Date.now();
  try {
    const result = await getJson('/api/v1/intelligence/findings?limit=30');
    const tbody = $('finding-body');
    tbody.replaceChildren();
    if (!result.findings.length) {
      const tr = document.createElement('tr'), td = document.createElement('td');
      td.colSpan = 7; td.textContent = 'No persisted behavioral cases yet.';
      tr.append(td); tbody.append(tr);
    }
    for (const item of result.findings) {
      const tr = document.createElement('tr');
      const values = [
        item.window_start_utc.slice(0, 16).replace('T', ' '),
        item.source_ip, item.severity, item.patterns.join(', '),
        item.status.replace('_', ' '), item.assigned_to || 'Unassigned'
      ];
      for (const value of values) {
        const cell = document.createElement('td');
        cell.textContent = value; // Never interpret stored event text as HTML.
        tr.append(cell);
      }
      const action = document.createElement('td');
      const edit = document.createElement('button');
      edit.type = 'button'; edit.textContent = 'TRIAGE';
      edit.addEventListener('click', () => triageBehaviorFinding(item.id));
      action.append(edit); tr.append(action); tbody.append(tr);
    }
    $('finding-status').textContent = result.findings.length +
      ' cases shown' + (result.has_more ? ' (more through API)' : '') +
      ' · persisted status/assignment · heuristic evidence only.';
  } catch (err) {
    $('finding-status').textContent = 'Behavior cases unavailable: ' + err.message;
  }
}
async function triageBehaviorFinding(id) {
  const status = prompt('New status: open | investigating | resolved | false_positive',
                        'investigating');
  if (status === null) return;
  if (!['open', 'investigating', 'resolved', 'false_positive'].includes(status)) {
    toast('Unsupported case status'); return;
  }
  const note = prompt('Reason for this change (3–1500 characters)');
  if (!note || note.trim().length < 3 || note.length > 1500) {
    toast('A valid audit reason is required'); return;
  }
  const headers = await mutationHeaders();
  if (!headers) return;
  try {
    await getJson('/api/v1/intelligence/findings/' + encodeURIComponent(id), {
      method: 'PATCH', headers, body: JSON.stringify({status, note: note.trim()})
    });
    await refreshBehaviorFindings(true);
    toast('Behavior case reviewed and audit recorded.');
  } catch (err) { toast('Case review failed: ' + err.message); }
}

let lastIncidentsFetch = 0;
async function refreshIncidents(force = false) {
  if (!force && Date.now() - lastIncidentsFetch < 30000) return;
  lastIncidentsFetch = Date.now();
  try {
    const result = await getJson('/api/v1/intelligence/incidents?limit=30');
    const body = $('incident-body');
    body.replaceChildren();
    for (const item of result.incidents) {
      const row = document.createElement('tr');
      for (const value of [
        item.hour_start_utc.slice(0, 16).replace('T', ' '),
        item.source_ip, String(item.window_count),
        item.flow_count + ' / ' + item.flagged_flows,
        item.signals.join(', '), item.status.replace('_', ' ')
      ]) {
        const cell = document.createElement('td');
        cell.textContent = value;
        row.append(cell);
      }
      const action = document.createElement('td');
      const inspect = document.createElement('button');
      inspect.type = 'button'; inspect.textContent = 'TIMELINE';
      inspect.addEventListener('click', () => inspectIncident(item.id));
      const review = document.createElement('button');
      review.type = 'button'; review.textContent = 'TRIAGE';
      review.addEventListener('click', () => triageIncident(item.id));
      action.append(inspect, review); row.append(action); body.append(row);
    }
    if (!result.incidents.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 7; cell.textContent = 'No multiple-window episodes materialized yet.';
      row.append(cell); body.append(row);
    }
    $('incident-status').textContent = result.incidents.length + ' correlated episodes shown' +
      (result.has_more ? ' (more via API)' : '') +
      ' · UTC source-hour groups, not confirmed attacks.';
  } catch (err) { $('incident-status').textContent = 'Incident API unavailable: ' + err.message; }
}
async function inspectIncident(id) {
  try {
    const [evidence, history] = await Promise.all([
      getJson('/api/v1/intelligence/incidents/' + encodeURIComponent(id) + '/evidence'),
      getJson('/api/v1/intelligence/incidents/' + encodeURIComponent(id) + '/history')
    ]);
    $('incident-detail').hidden = false;
    $('incident-detail-heading').textContent =
      'Source ' + evidence.incident.source_ip + ' · ' + evidence.incident.window_count +
      ' evidence windows · ' + evidence.incident.status;
    const steps = $('incident-evidence'); steps.replaceChildren();
    for (const f of evidence.timeline) {
      const li = document.createElement('li');
      li.textContent = f.window_start_utc + ' · ' + f.patterns.join(', ') +
        ' · ' + f.flow_count + ' flows; ' + f.flagged_flows + ' ML flags';
      steps.append(li);
    }
    const changes = $('incident-history'); changes.replaceChildren();
    for (const h of history) {
      const li = document.createElement('li');
      li.textContent = h.changed_at + ' · ' + h.actor + ' · ' +
        h.old_status + ' → ' + h.new_status + ' · ' + h.note;
      changes.append(li);
    }
    $('incident-detail').scrollIntoView({behavior: 'smooth', block: 'nearest'});
  } catch (err) { toast('Incident evidence unavailable: ' + err.message); }
}
async function triageIncident(id) {
  const status = prompt('Incident status: open | investigating | resolved | false_positive', 'investigating');
  if (status === null) return;
  if (!['open', 'investigating', 'resolved', 'false_positive'].includes(status)) {
    toast('Invalid incident status'); return;
  }
  const note = prompt('Reason for incident review (3–1500 characters)');
  if (!note || note.trim().length < 3 || note.length > 1500) {
    toast('Valid audit reason is required'); return;
  }
  const headers = await mutationHeaders();
  if (!headers) return;
  try {
    await getJson('/api/v1/intelligence/incidents/' + encodeURIComponent(id), {
      method: 'PATCH', headers, body: JSON.stringify({status, note: note.trim()})
    });
    await refreshIncidents(true);
    await inspectIncident(id);
    toast('Incident review and audit committed');
  } catch (err) { toast('Incident review failed: ' + err.message); }
}

let lastMLOpsFetch = 0;
async function refreshMLOps(force = false) {
  if (!force && Date.now() - lastMLOpsFetch < 30000) return;
  lastMLOpsFetch = Date.now();
  try {
    const result = await getJson('/api/v1/mlops/drift-runs?limit=1');
    if (!result.runs.length) {
      $('mlops-note').textContent = 'No complete drift report yet; monitoring worker may not have enough recorded flows.';
      return;
    }
    const last = result.runs[0];
    $('mlops-drift').textContent = last.drift_status.toUpperCase();
    $('mlops-flows').textContent = fmt(last.flow_count);
    $('mlops-budget').textContent = last.alert_budget_exceeded ? 'EXCEEDED' : 'WITHIN LIMIT';
    $('mlops-window').textContent = last.window_end_utc.slice(0, 16).replace('T', ' ') + ' UTC';
    $('mlops-note').textContent = 'Model ' + last.model_sha256.slice(0, 12) +
      '… · immutable input fingerprint · PSI is unlabeled distribution drift, not accuracy.';
  } catch (err) {
    $('mlops-note').textContent = err.message === 'Insufficient permissions'
      ? 'Administrator access required.' : 'MLOps evidence unavailable: ' + err.message;
  }
}

let lastBehaviorFetch = 0;
async function refreshBehavior(force = false) {
  if (!force && Date.now() - lastBehaviorFetch < 30000) return;
  lastBehaviorFetch = Date.now();
  const body = $('behavior-body');
  try {
    const params = new URLSearchParams({
      window_minutes: $('behavior-window-size').value,
      lookback_minutes: '60', limit: '30'
    });
    const report = await getJson('/api/v1/intelligence/behavior?' + params.toString());
    body.replaceChildren();
    if (!report.windows.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6; td.textContent = 'No ingested flows in the last 60 minutes.';
      tr.append(td); body.append(tr);
    }
    for (const item of report.windows) {
      const tr = document.createElement('tr');
      const values = [
        item.window_start_utc.slice(0, 16).replace('T', ' '),
        item.source_ip, fmt(item.flow_count),
        item.distinct_destination_ports + ' / ' + item.distinct_destination_hosts,
        fmt(item.flagged_flows),
        item.patterns.length ? item.patterns.join(', ') : 'No configured cue'
      ];
      for (const value of values) {
        const td = document.createElement('td');
        td.textContent = value;  // Untrusted IP/text never becomes HTML.
        tr.append(td);
      }
      body.append(tr);
    }
    $('behavior-status').textContent =
      'UTC · latest 60 minutes · ' + report.windows.length +
      ' windows shown' + (report.has_more ? ' (additional via API)' : '') +
      ' · heuristic cues do not confirm attacks.';
  } catch (err) {
    $('behavior-status').textContent = 'Behavior analytics unavailable: ' + err.message;
  }
}
$('behavior-window-size').addEventListener('change', () => refreshBehavior(true));

async function refresh() {
  try {
    // Omit optional filters that are unset. Sending status= or severity=
    // causes FastAPI query validation to reject the whole dashboard request.
    const alertParams = new URLSearchParams({
      limit: String(alertsLimit), offset: String(alertsOffset), order: $('order-filter').value
    });
    const optionalFilters = {
      status: $('status-filter').value,
      severity: $('severity-filter').value,
      src_ip: $('alert-ip-filter').value.trim()
    };
    for (const [name, value] of Object.entries(optionalFilters)) {
      if (value) alertParams.set(name, value);
    }
    const [summary, alerts, trends, model] = await Promise.all([
      getJson('/api/v1/summary'),
      getJson('/api/v1/alerts?' + alertParams.toString()),
      getJson('/api/v1/trends'), getJson('/api/v1/model'),
    ]);
    $('metric-flows').textContent = fmt(summary.flows);
    $('metric-anomalies').textContent = fmt(summary.alerts);
    $('metric-open').textContent = fmt(summary.open_alerts + summary.investigating_alerts);
    $('metric-risk').textContent = summary.mean_risk.toFixed(1);
    $('pipeline-status').textContent = 'API and detector ready';
    $('system-state').textContent = 'OPERATIONAL';
    $('model-source').textContent = model.source === 'seeded_synthetic_demo' ? 'SYNTHETIC DEMO MODEL' : 'TRAINED MODEL LOADED';
    const source = model.source === 'seeded_synthetic_demo' ? 'Seeded synthetic demo' : model.source;
    $('model-data-source').textContent = source;
    $('model-splits').textContent = `${model.train_count} / ${model.cal_count} / ${model.holdout_count}`;
    $('model-quantile').textContent = (model.quantile * 100).toFixed(1) + '%';
    $('model-f1').textContent = model.metrics?.f1 == null ? 'N/A' : model.metrics.f1.toFixed(3);
    protocolChart(summary.protocols, summary.flows);
    latestTrends = trends; drawTimeline(trends); renderAlerts(alerts);
    await refreshBehavior();
    await refreshBehaviorFindings();
    await refreshIncidents();
    await refreshMLOps();
    $('alerts-page').textContent = `Page ${Math.floor(alertsOffset / alertsLimit)+1}`;
    $('alerts-prev').disabled = alertsOffset === 0;
    $('alerts-next').disabled = alerts.length < alertsLimit;
  } catch(err) {
    $('pipeline-status').textContent = 'Service check failed';
    $('system-state').textContent = 'UNAVAILABLE';
    toast(`API unavailable: ${err.message}`);
  }
}
const resetAndRefresh = () => { alertsOffset = 0; refresh(); };
$('status-filter').addEventListener('change', resetAndRefresh);
$('severity-filter').addEventListener('change', resetAndRefresh);
$('order-filter').addEventListener('change', resetAndRefresh);
let ipFilterTimer;
$('alert-ip-filter').addEventListener('input', () => {
  clearTimeout(ipFilterTimer);
  ipFilterTimer = setTimeout(resetAndRefresh, 400);
});
$('alerts-prev').addEventListener('click', () => {
  alertsOffset = Math.max(0, alertsOffset - alertsLimit); refresh();
});
$('alerts-next').addEventListener('click', () => {
  alertsOffset += alertsLimit; refresh();
});
window.addEventListener('resize', () => drawTimeline(latestTrends));
setInterval(() => $('current-time').textContent = new Date().toLocaleTimeString('en-GB', {hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:'UTC'}) + ' UTC', 1000);
setInterval(refresh, 8000);
initializeBrowserAuth().then(refresh).catch(err => toast(err.message));
