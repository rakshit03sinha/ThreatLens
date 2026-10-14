/**
 * ThreatLens SOC Web Dashboard Frontend Application Logic
 */

const API_BASE = '/api/v1';

// Switch Navigation Tabs
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

  const targetBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick')?.includes(tabId));
  if (targetBtn) targetBtn.classList.add('active');

  const targetContent = document.getElementById(`tab-${tabId}`);
  if (targetContent) targetContent.classList.add('active');

  // Trigger relevant data refresh on tab switch
  if (tabId === 'overview') loadDashboardMetrics();
  if (tabId === 'alerts') loadAlerts();
  if (tabId === 'campaigns') loadCampaigns();
  if (tabId === 'events') loadEvents();
  if (tabId === 'iocs') loadIOCs();
  if (tabId === 'rules') loadRulesCatalogue();
}

// 1. Dashboard Metrics
async function loadDashboardMetrics() {
  try {
    const res = await fetch(`${API_BASE}/metrics/dashboard`);
    if (!res.ok) throw new Error('Failed to load metrics');
    const data = await res.json();

    document.getElementById('metric-events').innerText = data.total_events.toLocaleString();
    document.getElementById('metric-alerts').innerText = data.total_alerts.toLocaleString();
    document.getElementById('metric-crit-high').innerText = (data.critical_alerts + data.high_alerts).toLocaleString();
    document.getElementById('metric-campaigns').innerText = data.active_campaigns.toLocaleString();
    document.getElementById('metric-iocs').innerText = data.ioc_matches.toLocaleString();

    document.getElementById('ai-status-badge').innerText = `AI: ${data.ai_status}`;

    loadOverviewFeeds();
  } catch (err) {
    console.error('Error loading metrics:', err);
  }
}

async function loadOverviewFeeds() {
  try {
    const [alertsRes, campsRes] = await Promise.all([
      fetch(`${API_BASE}/alerts?page=1&page_size=5`),
      fetch(`${API_BASE}/campaigns?page=1&page_size=5`),
    ]);
    const alertsData = await alertsRes.json();
    const campsData = await campsRes.json();

    const alertsFeed = document.getElementById('overview-recent-alerts');
    if (alertsData.items && alertsData.items.length > 0) {
      alertsFeed.innerHTML = alertsData.items.map(a => `
        <div class="feed-item">
          <div class="feed-header">
            <strong>${escapeHtml(a.title)}</strong>
            <span class="badge ${getSevBadgeClass(a.severity)}">${a.severity.toUpperCase()}</span>
          </div>
          <div class="text-muted" style="font-size:0.8rem;">
            Tactic: ${a.attack_tactic} | Technique: ${a.attack_technique} | Score: <strong>${a.risk_score}/100</strong>
          </div>
        </div>
      `).join('');
    } else {
      alertsFeed.innerHTML = '<p class="text-muted">No security alerts triggered yet. Click "Load Demo Telemetry" above to simulate an attack.</p>';
    }

    const campsFeed = document.getElementById('overview-recent-campaigns');
    if (campsData.items && campsData.items.length > 0) {
      campsFeed.innerHTML = campsData.items.map(c => `
        <div class="feed-item">
          <div class="feed-header">
            <strong>${escapeHtml(c.title)}</strong>
            <span class="badge badge-info">${c.status.toUpperCase()}</span>
          </div>
          <div class="text-muted" style="font-size:0.8rem;">
            ${escapeHtml(c.description)} (Risk: <strong>${c.risk_score}</strong>, Linked Alerts: ${c.alerts.length})
          </div>
        </div>
      `).join('');
    } else {
      campsFeed.innerHTML = '<p class="text-muted">No active correlated campaigns.</p>';
    }
  } catch (err) {
    console.error('Error loading overview feeds:', err);
  }
}

// 2. Alerts Triage
async function loadAlerts() {
  const container = document.getElementById('alerts-table-container');
  const sev = document.getElementById('filter-alert-severity')?.value || '';
  const status = document.getElementById('filter-alert-status')?.value || '';

  try {
    let url = `${API_BASE}/alerts?page=1&page_size=50`;
    if (sev) url += `&severity=${encodeURIComponent(sev)}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;

    const res = await fetch(url);
    const data = await res.json();

    if (!data.items || data.items.length === 0) {
      container.innerHTML = '<p class="text-muted">No security alerts matching current criteria.</p>';
      return;
    }

    container.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Alert ID</th>
            <th>Severity</th>
            <th>Title & MITRE Technique</th>
            <th>Risk Score</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${data.items.map(a => `
            <tr>
              <td class="mono"><strong>${a.alert_id}</strong></td>
              <td><span class="badge ${getSevBadgeClass(a.severity)}">${a.severity.toUpperCase()}</span></td>
              <td>
                <div><strong>${escapeHtml(a.title)}</strong></div>
                <div class="text-muted" style="font-size:0.75rem;">${a.attack_tactic} &bull; ${a.attack_technique} (${a.attack_technique_name})</div>
              </td>
              <td><strong class="mono ${a.risk_score >= 80 ? 'text-danger' : 'text-warning'}">${a.risk_score}</strong>/100</td>
              <td><span class="badge">${a.status}</span></td>
              <td>
                <button class="btn btn-sm btn-outline" onclick="investigateAlert('${a.alert_id}')">Investigate</button>
                <button class="btn btn-sm btn-outline" onclick="changeAlertStatus('${a.alert_id}', 'closed')">Close</button>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    container.innerHTML = `<p class="text-danger">Failed to load alerts: ${escapeHtml(err.message)}</p>`;
  }
}

async function changeAlertStatus(alertId, newStatus) {
  try {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus, analyst_disposition: 'analyst_resolved' }),
    });
    if (res.ok) {
      loadAlerts();
      loadDashboardMetrics();
    }
  } catch (err) {
    alert(`Failed to update alert: ${err.message}`);
  }
}

// 3. Campaigns
async function loadCampaigns() {
  const container = document.getElementById('campaigns-container');
  try {
    const res = await fetch(`${API_BASE}/campaigns?page=1&page_size=50`);
    const data = await res.json();

    if (!data.items || data.items.length === 0) {
      container.innerHTML = '<p class="text-muted">No incident campaigns correlated yet.</p>';
      return;
    }

    container.innerHTML = data.items.map(c => `
      <div class="panel" style="margin-bottom:1rem;">
        <div class="panel-header">
          <div>
            <h3>${escapeHtml(c.title)} <span class="badge badge-info">${c.status.toUpperCase()}</span></h3>
            <span class="text-muted" style="font-size:0.8rem;">Campaign ID: ${c.campaign_id} &bull; Risk Score: <strong>${c.risk_score}/100</strong></span>
          </div>
          <div>
            <button class="btn btn-sm btn-outline" onclick="investigateCampaign('${c.campaign_id}')">🤖 AI Investigate Campaign</button>
          </div>
        </div>
        <p>${escapeHtml(c.description)}</p>
        <div style="margin-top:0.75rem;">
          <strong>Correlated Alerts (${c.alerts.length}):</strong>
          <ul style="margin-top:0.5rem; margin-left:1.5rem; font-size:0.85rem;">
            ${c.alerts.map(a => `
              <li><strong>${a.alert_id}</strong>: ${escapeHtml(a.rule_name)} (${a.severity.toUpperCase()}, Score: ${a.risk_score})</li>
            `).join('')}
          </ul>
        </div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<p class="text-danger">Error loading campaigns: ${escapeHtml(err.message)}</p>`;
  }
}

// 4. Events Explorer
async function loadEvents() {
  const container = document.getElementById('events-table-container');
  const search = document.getElementById('event-search-input')?.value || '';

  try {
    let url = `${API_BASE}/events?page=1&page_size=50`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    const res = await fetch(url);
    const data = await res.json();

    if (!data.items || data.items.length === 0) {
      container.innerHTML = '<p class="text-muted">No telemetry events found.</p>';
      return;
    }

    container.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Format</th>
            <th>Source IP</th>
            <th>Dest IP / Port</th>
            <th>User / Host</th>
            <th>Action</th>
            <th>Message Snippet</th>
          </tr>
        </thead>
        <tbody>
          ${data.items.map(e => `
            <tr>
              <td class="mono" style="font-size:0.75rem;">${new Date(e.timestamp).toLocaleTimeString()}</td>
              <td><span class="badge">${e.source_format}</span></td>
              <td class="mono">${e.source_ip || '-'}</td>
              <td class="mono">${e.destination_ip ? `${e.destination_ip}:${e.destination_port || ''}` : '-'}</td>
              <td>${e.username ? `👤 ${escapeHtml(e.username)}` : (e.hostname ? `💻 ${escapeHtml(e.hostname)}` : '-')}</td>
              <td><span class="badge ${e.action === 'failure' || e.action === 'deny' ? 'badge-danger' : 'badge-success'}">${e.action || 'info'}</span></td>
              <td style="font-size:0.8rem; max-width:350px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                ${escapeHtml(e.raw_message)}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    container.innerHTML = `<p class="text-danger">Error loading events: ${escapeHtml(err.message)}</p>`;
  }
}

// 5. AI Investigation
async function submitInvestigation() {
  const query = document.getElementById('investigate-query').value.trim();
  if (!query) return;

  const resultBox = document.getElementById('investigation-result');
  resultBox.style.display = 'block';
  resultBox.innerHTML = '<p class="text-muted">Analyzing evidence and correlating telemetry records...</p>';

  try {
    const res = await fetch(`${API_BASE}/investigations/ask`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: query }),
    });
    const data = await res.json();

    resultBox.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h3>Investigation Report: ${data.inquiry_id}</h3>
        <span class="badge ${data.is_fallback ? 'badge-warning' : 'badge-info'}">
          ${data.is_fallback ? 'Deterministic Fallback' : `AI: ${data.model_used}`}
        </span>
      </div>
      <p style="margin-top:0.75rem; font-size:1.05rem;">${escapeHtml(data.summary)}</p>

      <div class="investigation-section">
        <h4>📋 Verified Facts & Citations</h4>
        <ul>
          ${data.facts.map(f => `<li>${escapeHtml(f)}</li>`).join('')}
        </ul>
      </div>

      <div class="investigation-section">
        <h4>💡 Analyst Hypotheses</h4>
        <ul>
          ${data.hypotheses.map(h => `<li>${escapeHtml(h)}</li>`).join('')}
        </ul>
      </div>

      <div class="investigation-section">
        <h4>🛡️ Recommended Defensive Actions</h4>
        <ul>
          ${data.recommended_defensive_actions.map(a => `<li>${escapeHtml(a)}</li>`).join('')}
        </ul>
      </div>

      <div class="investigation-section">
        <h4>🔎 Evidence Citations</h4>
        <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
          ${data.citations.map(c => `<span class="badge mono">${c}</span>`).join('')}
        </div>
      </div>
    `;
  } catch (err) {
    resultBox.innerHTML = `<p class="text-danger">Investigation failed: ${escapeHtml(err.message)}</p>`;
  }
}

function investigateAlert(alertId) {
  switchTab('investigate');
  document.getElementById('investigate-query').value = `Investigate alert ${alertId}, analyze all supporting telemetry evidence, and recommend containment steps.`;
  submitInvestigation();
}

function investigateCampaign(campaignId) {
  switchTab('investigate');
  document.getElementById('investigate-query').value = `Perform a comprehensive multi-stage incident review for campaign ${campaignId}.`;
  submitInvestigation();
}

// 6. Threat Intel (IOCs)
async function loadIOCs() {
  const container = document.getElementById('iocs-table-container');
  try {
    const res = await fetch(`${API_BASE}/iocs?page=1&page_size=50`);
    const data = await res.json();

    if (!data.items || data.items.length === 0) {
      container.innerHTML = '<p class="text-muted">No IOC indicators stored yet.</p>';
      return;
    }

    container.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Indicator Value</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Source</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          ${data.items.map(i => `
            <tr>
              <td class="mono"><strong>${escapeHtml(i.indicator_value)}</strong></td>
              <td><span class="badge">${i.indicator_type}</span></td>
              <td><span class="badge ${getSevBadgeClass(i.severity)}">${i.severity.toUpperCase()}</span></td>
              <td>${i.confidence}%</td>
              <td>${escapeHtml(i.source)}</td>
              <td class="text-muted">${escapeHtml(i.description || '-')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    container.innerHTML = `<p class="text-danger">Error loading IOCs: ${escapeHtml(err.message)}</p>`;
  }
}

function showAddIOCModal() {
  document.getElementById('ioc-modal').style.display = 'flex';
}

function closeIOCModal() {
  document.getElementById('ioc-modal').style.display = 'none';
}

async function submitNewIOC() {
  const val = document.getElementById('modal-ioc-val').value.trim();
  const type = document.getElementById('modal-ioc-type').value;
  const sev = document.getElementById('modal-ioc-sev').value;

  if (!val) return;

  try {
    const res = await fetch(`${API_BASE}/iocs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator_value: val, indicator_type: type, severity: sev, confidence: 90 }),
    });
    if (res.ok) {
      closeIOCModal();
      loadIOCs();
    }
  } catch (err) {
    alert(`Failed to save IOC: ${err.message}`);
  }
}

// 7. Detection Rules (11)
async function loadRulesCatalogue() {
  const container = document.getElementById('rules-catalogue-container');
  try {
    const res = await fetch(`${API_BASE}/rules`);
    const rules = await res.json();

    container.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Rule ID</th>
            <th>Name</th>
            <th>Severity</th>
            <th>MITRE Tactic & Technique</th>
            <th>Status</th>
            <th>Toggle</th>
          </tr>
        </thead>
        <tbody>
          ${rules.map(r => `
            <tr>
              <td class="mono"><strong>${r.rule_id}</strong></td>
              <td>
                <div><strong>${escapeHtml(r.name)}</strong></div>
                <div class="text-muted" style="font-size:0.75rem;">${escapeHtml(r.description)}</div>
              </td>
              <td><span class="badge ${getSevBadgeClass(r.severity)}">${r.severity.toUpperCase()}</span></td>
              <td>
                <span class="badge badge-info">${r.technique_id}</span>
                <span style="font-size:0.8rem;">${r.tactic}</span>
              </td>
              <td>
                <span class="badge ${r.status === 'enabled' ? 'badge-success' : 'badge-danger'}">${r.status.toUpperCase()}</span>
              </td>
              <td>
                <button class="btn btn-sm ${r.status === 'enabled' ? 'btn-danger' : 'btn-success'}" onclick="toggleRule('${r.rule_id}', '${r.status === 'enabled' ? 'disabled' : 'enabled'}')">
                  ${r.status === 'enabled' ? 'Disable' : 'Enable'}
                </button>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    container.innerHTML = `<p class="text-danger">Error loading rules: ${escapeHtml(err.message)}</p>`;
  }
}

async function toggleRule(ruleId, newStatus) {
  try {
    const res = await fetch(`${API_BASE}/rules/${ruleId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    });
    if (res.ok) {
      loadRulesCatalogue();
    }
  } catch (err) {
    alert(`Failed to toggle rule: ${err.message}`);
  }
}

// 8. Ingestion Testbed
const SAMPLES = {
  windows: `{"Event":{"System":{"EventID":4625,"TimeCreated":{"SystemTime":"2026-10-14T21:00:00Z"},"Computer":"DC01.corp.internal"},"EventData":{"TargetUserName":"admin","IpAddress":"198.51.100.5","IpPort":"54321","Status":"0xC000006D"}}}`,
  linux: `Oct 14 21:00:00 auth-server sshd[12345]: Failed password for invalid user admin from 198.51.100.5 port 54321 ssh2`,
  cisco: `%ASA-4-106023: Deny tcp src outside:198.51.100.5/54321 dst inside:10.0.0.5/4444 by access-group "outside_access" [0x0, 0x0]`,
  paloalto: `1,2026/10/14 21:00:00,001801000001,TRAFFIC,drop,1,2026/10/14 21:00:00,198.51.100.5,10.0.0.5,198.51.100.5,10.0.0.5,rule_block_malicious,admin,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,1,123456,1,54321,4444,54321,4444,0x0,tcp,deny,100,0,100,1,2026/10/14 21:00:00,0,any,0,1234,0x0,192.168.0.0,US,0,1,0`,
  aws_cloudtrail: `{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"attacker_svc"},"eventTime":"2026-10-14T21:00:00Z","eventSource":"iam.amazonaws.com","eventName":"AttachRolePolicy","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.5"}`,
  apache: `198.51.100.5 - - [14/Oct/2026:21:00:00 +0000] "GET /admin/../../etc/passwd HTTP/1.1" 404 153 "-" "curl/7.68.0"`,
  cef: `CEF:0|SecurityCorp|ThreatSensor|1.0|100|Malicious Domain Query|8|src=10.0.0.15 dst=1.1.1.1 spt=54321 dpt=53 dhost=malicious-c2.example.com act=blocked`,
};

function loadPresetSample() {
  const sel = document.getElementById('ingest-preset-select').value;
  if (SAMPLES[sel]) {
    document.getElementById('ingest-raw-text').value = SAMPLES[sel];
  }
}

async function submitRawLog() {
  const raw = document.getElementById('ingest-raw-text').value.trim();
  const format = document.getElementById('ingest-preset-select').value || null;
  const feedback = document.getElementById('ingest-feedback');

  if (!raw) return;
  feedback.innerHTML = '<span class="text-muted">Ingesting and processing...</span>';

  try {
    const res = await fetch(`${API_BASE}/ingest/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_log: raw, format: format }),
    });
    const data = await res.json();
    if (res.ok) {
      feedback.innerHTML = `
        <div class="badge badge-success">
          Ingested Event ${data.event_id} (Format: ${data.source_format}, Alerts Triggered: ${data.alerts_triggered})
        </div>
      `;
      loadDashboardMetrics();
    } else {
      feedback.innerHTML = `<div class="badge badge-danger">Ingestion error: ${escapeHtml(data.detail || 'Failed')}</div>`;
    }
  } catch (err) {
    feedback.innerHTML = `<div class="badge badge-danger">${escapeHtml(err.message)}</div>`;
  }
}

// 9. Demo Seed Action
async function triggerSeedData() {
  const badge = document.getElementById('backend-status-badge');
  badge.innerText = '⚡ Seeding Telemetry...';
  try {
    // Ingest several preset events in a batch
    const events = Object.values(SAMPLES);
    const res = await fetch(`${API_BASE}/ingest/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: events }),
    });
    if (res.ok) {
      badge.innerText = 'API: Online (Seeded)';
      loadDashboardMetrics();
      loadAlerts();
      loadCampaigns();
    }
  } catch (err) {
    badge.innerText = 'API: Online';
    console.error('Seed error:', err);
  }
}

// Helpers
function getSevBadgeClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'badge-danger';
  if (s === 'high') return 'badge-danger';
  if (s === 'medium') return 'badge-warning';
  if (s === 'low') return 'badge-info';
  return 'badge';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Initial Boot
document.addEventListener('DOMContentLoaded', () => {
  loadDashboardMetrics();
});
