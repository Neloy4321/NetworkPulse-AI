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
  $('protocol-legend').innerHTML = entries.length ? entries.map(([key, value], i) =>
    `<div class="proto-line"><span><i style="background:${colors[i % colors.length]}"></i>${esc(key.toUpperCase())}</span><b>${(value / total * 100).toFixed(1)}%</b></div>`
  ).join('') : '<span class="muted">No protocol data yet</span>';
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
    <td><button type="button" data-alert="${a.id}">TRIAGE ↗</button></td>
  </tr>`).join('') : '<tr><td colspan="6" class="muted">No alerts match the selected filter.</td></tr>';
  $('alerts-body').querySelectorAll('button[data-alert]').forEach(btn => {
    btn.addEventListener('click', () => triage(Number(btn.dataset.alert)));
  });
}
async function triage(id) {
  const key = prompt('Operator X-API-Key (not stored by browser)');
  if (key === null || !key) return;
  const state = prompt('New status: open | investigating | resolved | false_positive', 'investigating');
  if (state === null) return;
  if (!['open','investigating','resolved','false_positive'].includes(state)) { toast('Invalid status.'); return; }
  const note = prompt('Audit note (minimum 3 characters)');
  if (note === null || note.trim().length < 3) { toast('A reason of at least 3 characters is required.'); return; }
  try {
    await getJson(`/api/v1/alerts/${id}`, {method: 'PATCH', headers: {'Content-Type':'application/json', 'X-API-Key': key}, body: JSON.stringify({status: state, note})});
    toast(`Alert #${id} updated; audit trail recorded.`); await refresh();
  } catch (err) { toast('Triage failed: ' + err.message); }
}
async function refresh() {
  try {
    const [summary, alerts, trends, model] = await Promise.all([
      getJson('/api/v1/summary'),
      getJson('/api/v1/alerts?' + new URLSearchParams({limit:String(alertsLimit), offset:String(alertsOffset),
        status:$('status-filter').value, severity:$('severity-filter').value,
        src_ip:$('alert-ip-filter').value.trim(), order:$('order-filter').value}).toString()),
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
refresh();
