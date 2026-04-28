"""
dashboard/app.py
Flask web dashboard for real-time threat intelligence visualisation.
Routes:
  GET  /           → main dashboard HTML
  GET  /api/stats  → JSON aggregated stats
  GET  /api/events → JSON recent events (last 200)
  GET  /api/stream → SSE live event stream
"""

import json
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template_string, Response, request
from core.event_store import EventStore
from utils.logger import get_logger

log = get_logger("dashboard")

# ── Dashboard HTML (single-file, no external files needed) ─────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HoneyShield — Threat Intelligence Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Rajdhani:wght@400;600;700&display=swap');

  :root {
    --bg:       #0a0e1a;
    --panel:    #0f1629;
    --border:   #1e2d50;
    --accent:   #00d4ff;
    --red:      #ff3860;
    --orange:   #ff8c00;
    --green:    #00e676;
    --yellow:   #ffd600;
    --text:     #c8d8ff;
    --muted:    #4a5a80;
    --font:     'Rajdhani', sans-serif;
    --mono:     'JetBrains Mono', monospace;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 15px;
    min-height: 100vh;
  }

  /* ── Header ── */
  header {
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    padding: 14px 28px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .logo {
    font-size: 22px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 2px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .logo-dot { width: 10px; height: 10px; background: var(--red); border-radius: 50%;
    animation: pulse 1.2s infinite; }
  @keyframes pulse {
    0%,100% { box-shadow: 0 0 0 0 rgba(255,56,96,.6); }
    50%      { box-shadow: 0 0 0 8px rgba(255,56,96,0); }
  }
  .status-bar { display: flex; gap: 24px; font-size: 13px; font-family: var(--mono); }
  .status-item { display: flex; flex-direction: column; align-items: center; }
  .status-item .val { color: var(--accent); font-weight: 700; font-size: 17px; }

  /* ── Layout ── */
  .container { padding: 20px 28px; }

  .kpi-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 20px;
  }
  .kpi {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }
  .kpi::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
  }
  .kpi.total::before   { background: var(--accent); }
  .kpi.unique::before  { background: var(--green); }
  .kpi.critical::before{ background: var(--red); }
  .kpi.score::before   { background: var(--orange); }
  .kpi-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }
  .kpi-value { font-size: 38px; font-weight: 700; font-family: var(--mono); margin: 6px 0 2px; }
  .kpi.total   .kpi-value { color: var(--accent); }
  .kpi.unique  .kpi-value { color: var(--green); }
  .kpi.critical .kpi-value { color: var(--red); }
  .kpi.score   .kpi-value { color: var(--orange); }
  .kpi-sub { font-size: 12px; color: var(--muted); }

  /* ── Grid ── */
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 20px; }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
  }
  .panel-title {
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .panel-title span { color: var(--accent); font-size: 16px; }

  /* ── Severity badges ── */
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    font-family: var(--mono);
    letter-spacing: 1px;
  }
  .badge.CRITICAL { background: rgba(255,56,96,.2);  color: var(--red);    border: 1px solid var(--red); }
  .badge.HIGH     { background: rgba(255,140,0,.2);  color: var(--orange); border: 1px solid var(--orange); }
  .badge.MEDIUM   { background: rgba(255,214,0,.2);  color: var(--yellow); border: 1px solid var(--yellow); }
  .badge.LOW      { background: rgba(0,230,118,.15); color: var(--green);  border: 1px solid var(--green); }

  /* ── Event feed ── */
  #event-feed {
    height: 340px;
    overflow-y: auto;
    font-family: var(--mono);
    font-size: 12px;
  }
  #event-feed::-webkit-scrollbar { width: 4px; }
  #event-feed::-webkit-scrollbar-track { background: transparent; }
  #event-feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  .event-row {
    display: grid;
    grid-template-columns: 90px 110px 70px 1fr 80px;
    gap: 8px;
    padding: 7px 10px;
    border-bottom: 1px solid rgba(30,45,80,.5);
    align-items: center;
    animation: fadeIn .3s ease;
  }
  .event-row:hover { background: rgba(0,212,255,.04); }
  @keyframes fadeIn { from { opacity:0; transform: translateY(-4px); } to { opacity:1; } }
  .ev-time  { color: var(--muted); }
  .ev-ip    { color: var(--accent); }
  .ev-svc   { color: var(--yellow); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .ev-path  { color: var(--text);   overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* ── Top IPs table ── */
  .ip-table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 13px; }
  .ip-table th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
    padding: 6px 8px; text-align: left; border-bottom: 1px solid var(--border); }
  .ip-table td { padding: 8px 8px; border-bottom: 1px solid rgba(30,45,80,.4); }
  .ip-table td:first-child { color: var(--accent); }
  .ip-table td:last-child  { text-align: right; }

  .bar-wrap { background: rgba(0,0,0,.3); border-radius: 3px; height: 6px; margin-top: 4px; }
  .bar-fill { background: linear-gradient(90deg, var(--accent), var(--red));
    height: 6px; border-radius: 3px; transition: width .6s ease; }

  /* ── Tag cloud ── */
  .tag-cloud { display: flex; flex-wrap: wrap; gap: 8px; }
  .tag {
    background: rgba(0,212,255,.08);
    border: 1px solid rgba(0,212,255,.2);
    color: var(--accent);
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-family: var(--mono);
    display: flex; align-items: center; gap: 6px;
  }
  .tag-count { background: var(--accent); color: var(--bg); border-radius: 10px;
    padding: 0 6px; font-size: 11px; font-weight: 700; }

  /* ── Chart containers ── */
  .chart-wrap { position: relative; height: 200px; }

  /* ── Responsive ── */
  @media (max-width: 900px) {
    .kpi-row { grid-template-columns: 1fr 1fr; }
    .grid-2, .grid-3 { grid-template-columns: 1fr; }
    .event-row { grid-template-columns: 80px 100px 1fr; }
    .event-row .ev-svc, .event-row .ev-path { display: none; }
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-dot"></div>
    🍯 HONEYSHIELD
  </div>
  <div class="status-bar">
    <div class="status-item"><span class="val" id="hdr-total">0</span>Events</div>
    <div class="status-item"><span class="val" id="hdr-ips">0</span>Unique IPs</div>
    <div class="status-item"><span class="val" id="hdr-crit" style="color:var(--red)">0</span>Critical</div>
    <div class="status-item"><span class="val" id="hdr-uptime">--:--</span>Uptime</div>
  </div>
</header>

<div class="container">

  <!-- KPIs -->
  <div class="kpi-row">
    <div class="kpi total">
      <div class="kpi-label">Total Events</div>
      <div class="kpi-value" id="kpi-total">0</div>
      <div class="kpi-sub">All connection attempts</div>
    </div>
    <div class="kpi unique">
      <div class="kpi-label">Unique Attackers</div>
      <div class="kpi-value" id="kpi-ips">0</div>
      <div class="kpi-sub">Distinct IP addresses</div>
    </div>
    <div class="kpi critical">
      <div class="kpi-label">Critical Threats</div>
      <div class="kpi-value" id="kpi-crit">0</div>
      <div class="kpi-sub">Score ≥ 80</div>
    </div>
    <div class="kpi score">
      <div class="kpi-label">Avg Threat Score</div>
      <div class="kpi-value" id="kpi-score">0</div>
      <div class="kpi-sub">Max: <span id="kpi-max">0</span></div>
    </div>
  </div>

  <!-- Charts row -->
  <div class="grid-3">
    <div class="panel">
      <div class="panel-title"><span>📊</span> Events by Severity</div>
      <div class="chart-wrap"><canvas id="chart-severity"></canvas></div>
    </div>
    <div class="panel">
      <div class="panel-title"><span>🔌</span> Events by Service</div>
      <div class="chart-wrap"><canvas id="chart-service"></canvas></div>
    </div>
    <div class="panel">
      <div class="panel-title"><span>📈</span> Activity Timeline (24h)</div>
      <div class="chart-wrap"><canvas id="chart-timeline"></canvas></div>
    </div>
  </div>

  <!-- Live feed + Top IPs -->
  <div class="grid-2">
    <div class="panel" style="grid-column: span 1;">
      <div class="panel-title"><span>⚡</span> Live Event Feed</div>
      <div style="display:grid;grid-template-columns:90px 110px 70px 1fr 80px;gap:8px;padding:4px 10px;margin-bottom:6px;">
        <span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px">Time</span>
        <span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px">IP</span>
        <span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px">Service</span>
        <span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px">Path / Info</span>
        <span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px;text-align:right">Severity</span>
      </div>
      <div id="event-feed"></div>
    </div>

    <div class="panel">
      <div class="panel-title"><span>🎯</span> Top Attacker IPs</div>
      <table class="ip-table">
        <thead><tr><th>IP Address</th><th>Requests</th><th>Threat</th></tr></thead>
        <tbody id="top-ips-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Attack tags -->
  <div class="panel" style="margin-bottom:20px">
    <div class="panel-title"><span>🏷️</span> Detected Attack Signatures</div>
    <div class="tag-cloud" id="tag-cloud"></div>
  </div>

</div>

<script>
// ── Chart setup ──────────────────────────────────────────────────────────
const chartDefaults = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#4a5a80', font: { family: 'JetBrains Mono', size: 11 } } } },
};

// Severity doughnut
const ctxSev = document.getElementById('chart-severity').getContext('2d');
const severityChart = new Chart(ctxSev, {
  type: 'doughnut',
  data: {
    labels: ['CRITICAL','HIGH','MEDIUM','LOW'],
    datasets: [{ data: [0,0,0,0],
      backgroundColor: ['#ff3860','#ff8c00','#ffd600','#00e676'],
      borderWidth: 0, hoverOffset: 6 }]
  },
  options: { ...chartDefaults, cutout: '65%' }
});

// Service bar
const ctxSvc = document.getElementById('chart-service').getContext('2d');
const serviceChart = new Chart(ctxSvc, {
  type: 'bar',
  data: { labels: [], datasets: [{ data: [], backgroundColor: '#00d4ff44',
    borderColor: '#00d4ff', borderWidth: 1.5, borderRadius: 4 }] },
  options: { ...chartDefaults, indexAxis: 'y',
    scales: { x: { ticks: { color:'#4a5a80' }, grid: { color:'#1e2d50' } },
              y: { ticks: { color:'#c8d8ff', font:{size:11} }, grid: { display:false } } },
    plugins: { legend: { display: false } } }
});

// Timeline line
const ctxTime = document.getElementById('chart-timeline').getContext('2d');
const timelineChart = new Chart(ctxTime, {
  type: 'line',
  data: { labels: [], datasets: [{ data: [], borderColor: '#00d4ff',
    backgroundColor: 'rgba(0,212,255,.08)', fill: true, tension: 0.4,
    pointRadius: 3, pointBackgroundColor: '#00d4ff' }] },
  options: { ...chartDefaults,
    scales: { x: { ticks: { color:'#4a5a80', maxTicksLimit: 8, font:{size:10} }, grid: { color:'#1e2d50' } },
              y: { ticks: { color:'#4a5a80' }, grid: { color:'#1e2d50' } } },
    plugins: { legend: { display: false } } }
});

// ── Helpers ──────────────────────────────────────────────────────────────
const feed     = document.getElementById('event-feed');
const MAX_ROWS = 200;

function formatTime(iso) {
  try { return new Date(iso).toLocaleTimeString('en-GB', {hour12:false}); }
  catch { return '--:--:--'; }
}

function addFeedRow(ev) {
  const row = document.createElement('div');
  row.className = 'event-row';
  const path = ev.path || ev.body_snippet || ev.protocol || '';
  row.innerHTML = `
    <span class="ev-time">${formatTime(ev.timestamp)}</span>
    <span class="ev-ip">${ev.ip}</span>
    <span class="ev-svc">${ev.service || ''}</span>
    <span class="ev-path" title="${path}">${path.substring(0,40)}</span>
    <span style="text-align:right"><span class="badge ${ev.severity}">${ev.severity}</span></span>`;
  feed.insertBefore(row, feed.firstChild);
  while (feed.children.length > MAX_ROWS) feed.removeChild(feed.lastChild);
}

// ── Stats polling ─────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch('/api/stats');
    const s = await r.json();

    // KPIs
    document.getElementById('kpi-total').textContent  = s.total_events;
    document.getElementById('kpi-ips').textContent    = s.unique_ips;
    document.getElementById('kpi-crit').textContent   = s.critical_count;
    document.getElementById('kpi-score').textContent  = s.avg_threat_score;
    document.getElementById('kpi-max').textContent    = s.max_threat_score;
    document.getElementById('hdr-total').textContent  = s.total_events;
    document.getElementById('hdr-ips').textContent    = s.unique_ips;
    document.getElementById('hdr-crit').textContent   = s.critical_count;

    // Severity chart
    const sev = s.by_severity || {};
    severityChart.data.datasets[0].data = [
      sev.CRITICAL||0, sev.HIGH||0, sev.MEDIUM||0, sev.LOW||0];
    severityChart.update('none');

    // Service chart
    const svcKeys = Object.keys(s.by_service || {});
    const svcVals = svcKeys.map(k => s.by_service[k]);
    serviceChart.data.labels = svcKeys;
    serviceChart.data.datasets[0].data = svcVals;
    serviceChart.update('none');

    // Timeline
    const tl = s.timeline || [];
    timelineChart.data.labels = tl.map(x => x.hour.split('T')[1] || x.hour.slice(-5));
    timelineChart.data.datasets[0].data = tl.map(x => x.count);
    timelineChart.update('none');

    // Top IPs
    const tbody = document.getElementById('top-ips-body');
    const topIps = s.top_attacker_ips || [];
    const maxCount = topIps[0]?.count || 1;
    tbody.innerHTML = topIps.slice(0,8).map(x => `
      <tr>
        <td>${x.ip}</td>
        <td>${x.count}
          <div class="bar-wrap"><div class="bar-fill" style="width:${Math.round(x.count/maxCount*100)}%"></div></div>
        </td>
        <td><span class="badge HIGH">HIGH</span></td>
      </tr>`).join('');

    // Tags
    const tagDiv = document.getElementById('tag-cloud');
    const tags = s.by_tag || {};
    tagDiv.innerHTML = Object.entries(tags)
      .sort((a,b)=>b[1]-a[1]).slice(0,20)
      .map(([t,c]) => `<div class="tag">${t}<span class="tag-count">${c}</span></div>`)
      .join('');

  } catch(e) { console.warn('Stats fetch error', e); }
}

// ── Load recent events ────────────────────────────────────────────────────
async function loadRecentEvents() {
  try {
    const r = await fetch('/api/events?n=50');
    const events = await r.json();
    feed.innerHTML = '';
    events.reverse().forEach(addFeedRow);
  } catch(e) {}
}

// ── SSE live stream ───────────────────────────────────────────────────────
function connectSSE() {
  const evtSource = new EventSource('/api/stream');
  evtSource.onmessage = e => {
    try {
      const ev = JSON.parse(e.data);
      addFeedRow(ev);
    } catch {}
  };
  evtSource.onerror = () => {
    setTimeout(connectSSE, 3000);
  };
}

// ── Uptime timer ─────────────────────────────────────────────────────────
const startTime = Date.now();
function updateUptime() {
  const s = Math.floor((Date.now() - startTime) / 1000);
  const h = String(Math.floor(s/3600)).padStart(2,'0');
  const m = String(Math.floor((s%3600)/60)).padStart(2,'0');
  const sec = String(s%60).padStart(2,'0');
  document.getElementById('hdr-uptime').textContent = `${h}:${m}:${sec}`;
}

// ── Boot ──────────────────────────────────────────────────────────────────
loadRecentEvents();
loadStats();
connectSSE();
setInterval(loadStats, 5000);
setInterval(updateUptime, 1000);
</script>
</body></html>"""


# ── Flask App ──────────────────────────────────────────────────────────────

def create_app(store: EventStore, config: dict) -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/stats")
    def api_stats():
        return jsonify(store.stats())

    @app.route("/api/events")
    def api_events():
        n = int(request.args.get("n", 200))
        events = [e.to_dict() for e in store.recent(n)]
        return jsonify(events)

    @app.route("/api/stream")
    def api_stream():
        """Server-Sent Events stream for live dashboard updates."""
        def generate():
            while True:
                ev = store.get_live_event(timeout=1.0)
                if ev:
                    yield f"data: {json.dumps(ev.to_dict())}\n\n"
                else:
                    yield ": heartbeat\n\n"
        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    return app


def start_dashboard(host: str, port: int,
                    store: EventStore, config: dict) -> threading.Thread:
    app = create_app(store, config)

    def run():
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)

    t = threading.Thread(target=run, name="dashboard", daemon=True)
    t.start()
    log.info(f"Dashboard running → http://{host}:{port}")
    return t
