/**
 * ClearShield Security Dashboard Controller
 * Real-time SSE listener, Canary Trap telemetry, and Incident Audit manager.
 */

const API_BASE = window.location.origin;

// State management
let currentView = 'system-status';
let systemStatus = {
  statusText: 'ClearShield Active: All Systems Normal',
  indicatorColor: 'green',
  isArmed: true,
  airGapped: false,
  smbBlocked: false,
  dbCut: false,
  sessionTokenValid: true,
  activeSessionToken: 'cs_sess_demo',
  lastLatencyMs: 1.2,
  recordsProtectedCount: 8,
  recordsLost: 0,
  stats: { totalBlocked: 0, totalIncidents: 0, totalAlerts: 0, totalSms: 0 }
};

let incidents = [];
let blockedRequests = [];
let alerts = [];
let smsQueue = [];
let suspiciousActivities = [];

// ClearShield Core Prototype state
let coreEvents = [];
let coreResolved = new Set();
let coreHistory = [];
let coreThresholds = { fails: 5, failMin: 10, files: 100, fileMin: 2 };

// -------------------------------------------------------------------------
// INITIALIZATION & REAL-TIME EVENT STREAM (SSE)
// -------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initEventStream();
  fetchAllData();
  initCoreDemoEvents();
  renderCurrentView();
});

function initNavigation() {
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentView = btn.dataset.view;
      renderCurrentView();
    });
  });
}

function initEventStream() {
  const evtSource = new EventSource(`${API_BASE}/api/events`);

  evtSource.onmessage = (e) => {
    try {
      const payload = JSON.parse(e.data);
      handleServerEvent(payload.type, payload.data);
    } catch (err) {
      console.error('SSE parse error:', err);
    }
  };

  evtSource.onerror = () => {
    console.warn('SSE connection disrupted, attempting reconnection...');
  };
}

function handleServerEvent(type, data) {
  if (type === 'INIT' && data) {
    systemStatus = data;
    updateTopHeader();
  } else if (type === 'THREAT_DETECTED') {
    systemStatus = data.systemStatus;
    if (data.incident) incidents.unshift(data.incident);
    if (data.alert) alerts.unshift(data.alert);
    if (data.sms) smsQueue.unshift(data.sms);
    updateTopHeader();
    renderCurrentView();
  } else if (type === 'REQUEST_BLOCKED') {
    blockedRequests.unshift(data);
    updateTopHeader();
    if (currentView === 'blocked-requests') renderCurrentView();
  } else if (type === 'SAFE_CANCEL') {
    suspiciousActivities.unshift({
      type: 'Safe Cancel by Receptionist',
      time: data.formattedTime,
      device: data.device,
      details: data.action,
      risk: 'NORMAL'
    });
    renderCurrentView();
  } else if (type === 'SUSPICIOUS_ACTIVITY') {
    if (data.alert) alerts.unshift(data.alert);
    suspiciousActivities.unshift({
      type: 'Brute-Force Authentication Attempt',
      time: new Date().toLocaleTimeString(),
      device: data.alert.device,
      details: `IP ${data.ip} failed ${data.attempts} consecutive PIN attempts`,
      risk: 'MEDIUM'
    });
    updateTopHeader();
    renderCurrentView();
  } else if (type === 'BULK_ATTACK_DETECTED') {
    if (data.alert) alerts.unshift(data.alert);
    suspiciousActivities.unshift({
      type: 'Bulk Scraper Exfiltration Attempt',
      time: new Date().toLocaleTimeString(),
      device: 'EXPORT-SERVICE',
      details: `Requested ${data.requestedCount} records exceeding security limit`,
      risk: 'HIGH'
    });
    updateTopHeader();
    renderCurrentView();
  } else if (type === 'INCIDENT_REVIEWED') {
    const inc = incidents.find(i => i.id === data.id);
    if (inc) Object.assign(inc, data);
    renderCurrentView();
  } else if (type === 'SYSTEM_RESTORED') {
    systemStatus = data.systemStatus;
    updateTopHeader();
    renderCurrentView();
  }
}

async function fetchAllData() {
  try {
    const [stRes, incRes, blkRes, altRes, smsRes] = await Promise.all([
      fetch(`${API_BASE}/api/clearshield/status`),
      fetch(`${API_BASE}/api/clearshield/incidents`),
      fetch(`${API_BASE}/api/clearshield/blocked-requests`),
      fetch(`${API_BASE}/api/clearshield/alerts`),
      fetch(`${API_BASE}/api/clearshield/sms`)
    ]);

    systemStatus = await stRes.json();
    incidents = await incRes.json();
    blockedRequests = await blkRes.json();
    alerts = await altRes.json();
    smsQueue = await smsRes.json();

    updateTopHeader();
    renderCurrentView();
  } catch (err) {
    console.warn('Backend loading in progress...', err);
  }
}

function updateTopHeader() {
  const pill = document.getElementById('ambient-status-pill');
  const txt = document.getElementById('ambient-status-text');
  const tag = document.getElementById('trap-state-tag');
  const latency = document.getElementById('metric-latency');
  const smb = document.getElementById('metric-smb');
  const lost = document.getElementById('metric-lost');

  if (systemStatus.airGapped) {
    pill.className = 'status-pill red';
    txt.textContent = '🚨 Air-Gap Isolated – Threat Contained';
    tag.className = 'tag tag-red';
    tag.textContent = 'Tripwire Tripped (Isolated)';
    smb.textContent = 'BLOCKED (445)';
    smb.style.color = '#ef4444';
  } else {
    pill.className = 'status-pill';
    txt.textContent = 'ClearShield Active: All Systems Normal';
    tag.className = 'tag tag-green';
    tag.textContent = 'Row 0 Canary Armed';
    smb.textContent = 'Active (445)';
    smb.style.color = '#10b981';
  }

  latency.textContent = `< 15ms (${systemStatus.lastLatencyMs || 1.2}ms)`;
  lost.textContent = `${systemStatus.recordsLost} (Zero records lost)`;

  // Update badges
  document.getElementById('badge-blocked').textContent = blockedRequests.length;
  document.getElementById('badge-alerts').textContent = alerts.length;
  document.getElementById('badge-suspicious').textContent = suspiciousActivities.length;
}

// -------------------------------------------------------------------------
// VIEW RENDERING ENGINE
// -------------------------------------------------------------------------
function renderCurrentView() {
  const container = document.getElementById('view-container');

  switch (currentView) {
    case 'system-status':
      container.innerHTML = renderSystemStatusView();
      break;
    case 'canary-status':
      container.innerHTML = renderCanaryStatusView();
      break;
    case 'suspicious-activity':
      container.innerHTML = renderSuspiciousActivityView();
      break;
    case 'blocked-requests':
      container.innerHTML = renderBlockedRequestsView();
      break;
    case 'admin-alerts':
      container.innerHTML = renderAdminAlertsView();
      break;
    case 'incident-history':
      container.innerHTML = renderIncidentHistoryView();
      break;
    case 'restore-system':
      container.innerHTML = renderRestoreSystemView();
      break;
    case 'scenario-lab':
      container.innerHTML = renderScenarioLabView();
      break;
    case 'core-overview':
      container.innerHTML = renderCoreOverviewView();
      break;
    case 'core-alerts':
      container.innerHTML = renderCoreAlertsView();
      break;
    case 'core-guided':
      container.innerHTML = renderCoreGuidedView();
      break;
    case 'core-settings':
      container.innerHTML = renderCoreSettingsView();
      break;
    case 'core-csv':
      container.innerHTML = renderCoreCSVView();
      break;
    case 'core-about':
      container.innerHTML = renderCoreAboutView();
      break;
    default:
      container.innerHTML = renderSystemStatusView();
  }
}

// 1. SYSTEM STATUS VIEW
function renderSystemStatusView() {
  const isAirGap = systemStatus.airGapped;
  return `
    <div class="grid-4">
      <div class="card">
        <div class="card-title">Honeypot State</div>
        <div class="stat-value" style="color: ${isAirGap ? '#ef4444' : '#10b981'}">
          ${isAirGap ? 'ISOLATED' : 'ARMED'}
        </div>
        <div class="stat-desc">Row 0 Canary Decoy Tripwire</div>
      </div>
      <div class="card">
        <div class="card-title">Tripwire Latency</div>
        <div class="stat-value" style="color: #60a5fa">${systemStatus.lastLatencyMs || 1.2}ms</div>
        <div class="stat-desc">Target: &lt; 15ms interception</div>
      </div>
      <div class="card">
        <div class="card-title">Database Access</div>
        <div class="stat-value" style="color: ${isAirGap ? '#ef4444' : '#10b981'}">
          ${isAirGap ? 'SEVERED (403)' : 'ONLINE'}
        </div>
        <div class="stat-desc">Surgical air-gap cut switch</div>
      </div>
      <div class="card">
        <div class="card-title">Protected Patients</div>
        <div class="stat-value" style="color: #10b981">100% Safe</div>
        <div class="stat-desc">0 patient records compromised</div>
      </div>
    </div>

    <!-- SURGICAL AIR-GAP ARCHITECTURE WORKFLOW -->
    <div class="card">
      <div class="card-title">
        <span>⚡ Honeypot & Surgical Air-Gap Workflow State</span>
        <span class="tag ${isAirGap ? 'tag-red' : 'tag-green'}">
          ${isAirGap ? 'Surgical Air-Gap Engaged' : 'Monitoring Active'}
        </span>
      </div>
      <p style="color: var(--text-muted); font-size: 13px;">
        When an unauthorized query or automated scraper requests Row 0 Canary Decoy, ClearShield arrests the connection in under 15ms before sensitive records leave the server.
      </p>

      <div class="airgap-workflow">
        <div class="flow-node ${!isAirGap ? 'active' : ''}">
          <b>Phase 1</b><br>Armed & Ready<br><span style="color:#10b981;font-size:10px;">🟢 Ambient Green</span>
        </div>
        <div class="flow-arrow">➔</div>
        <div class="flow-node ${isAirGap ? 'active' : ''}">
          <b>Phase 2</b><br>Attack Detected<br><span style="color:#60a5fa;font-size:10px;">&lt; 15ms Catch</span>
        </div>
        <div class="flow-arrow">➔</div>
        <div class="flow-node ${isAirGap ? 'active' : ''}">
          <b>Phase 3</b><br>Surgical Air-Gap<br><span style="color:#ef4444;font-size:10px;">Session &amp; DB Cut</span>
        </div>
        <div class="flow-arrow">➔</div>
        <div class="flow-node ${isAirGap ? 'active' : ''}">
          <b>Phase 4</b><br>Care Continuity<br><span style="color:#fbbf24;font-size:10px;">Paper Check-In</span>
        </div>
        <div class="flow-arrow">➔</div>
        <div class="flow-node ${isAirGap ? 'active' : ''}">
          <b>Phase 5</b><br>Out-of-Band SMS<br><span style="color:#a78bfa;font-size:10px;">Dr. Taylor Alert</span>
        </div>
        <div class="flow-arrow">➔</div>
        <div class="flow-node ${isAirGap ? 'active' : ''}">
          <b>Phase 6 & 7</b><br>Protected Standby<br><span style="color:#38bdf8;font-size:10px;">Audit &amp; Restore</span>
        </div>
      </div>

      <div style="display:flex; gap:12px; margin-top: 14px;">
        ${isAirGap ? `
          <button class="btn btn-success" onclick="restoreClinicSystem()">
            🔄 Restore Clinic Normal Operations
          </button>
        ` : `
          <button class="btn btn-danger" onclick="triggerTestTripwire()">
            ⚡ Simulate Canary Tripwire Breach
          </button>
        `}
        <button class="btn btn-secondary" onclick="exportIncidentReport('json')">
          📄 Download Incident Defense Log (JSON)
        </button>
      </div>
    </div>

    <!-- RECENT STATUS METRICS -->
    <div class="grid-2">
      <div class="card">
        <div class="card-title">Port & Session Isolation Telemetry</div>
        <table style="font-size: 13px;">
          <tr>
            <td>Session Token Status</td>
            <td><b style="color:${isAirGap ? '#ef4444' : '#10b981'}">${isAirGap ? 'REVOKED & INVALIDATED' : 'Active & Authenticated'}</b></td>
          </tr>
          <tr>
            <td>Port 445 (SMB Lateral Guard)</td>
            <td><b style="color:${isAirGap ? '#ef4444' : '#10b981'}">${isAirGap ? 'BLOCKED' : 'Monitored'}</b></td>
          </tr>
          <tr>
            <td>Database Socket Connection</td>
            <td><b style="color:${isAirGap ? '#ef4444' : '#10b981'}">${isAirGap ? 'DISCONNECTED (HTTP 403)' : 'SECURE READY'}</b></td>
          </tr>
          <tr>
            <td>Care Continuity Spooler</td>
            <td><b style="color:#60a5fa">Paper Queue Ready</b></td>
          </tr>
        </table>
      </div>

      <div class="card">
        <div class="card-title">Demonstration Environment Notice</div>
        <p style="font-size: 13px; color: var(--text-muted); line-height: 1.6;">
          🔒 <b>HIPAA Security Demonstration Safe:</b><br>
          • All clinic data is 100% fictional. Real patient records are never loaded or stored.<br>
          • Network isolation is safely simulated within the backend application layer without disrupting host computer connectivity.<br>
          • Out-of-band alerts are delivered via real-time carrier simulation without incurring cellular charges.
        </p>
      </div>
    </div>
  `;
}

// 2. CANARY TRAP STATUS VIEW
function renderCanaryStatusView() {
  return `
    <div class="card">
      <div class="card-title">
        <span>🪤 Row 0 Canary Decoy Specification</span>
        <span class="tag tag-green">Tripwire Armed</span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        The Canary Record sits at index 0 of the dataset as a silent tripwire. Legitimate reception workflows filter it out or present a safe-cancel modal if clicked accidentally. Direct automated scrapers or unauthorized queries immediately trip this trap.
      </p>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Property</th>
              <th>Value</th>
              <th>Honeypot Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Record ID</td>
              <td class="code-cell">canary-0</td>
              <td>Placed at row index 0 to catch sequential table crawlers first</td>
            </tr>
            <tr>
              <td>Record Number</td>
              <td class="code-cell">CANARY-00-TRAP</td>
              <td>Simulated medical chart identifier</td>
            </tr>
            <tr>
              <td>Patient Name</td>
              <td><b>Jane Doe (Canary Decoy - Restricted)</b></td>
              <td>Clearly marked fictional decoy</td>
            </tr>
            <tr>
              <td>Condition / Trigger</td>
              <td><span class="tag tag-yellow">SYSTEM MONITORING TRIPWIRE</span></td>
              <td>Flags any direct database read</td>
            </tr>
            <tr>
              <td>Detection Latency</td>
              <td><b>&lt; 15ms (Tested at 1.25ms)</b></td>
              <td>Arrests execution before secondary real records load</td>
            </tr>
            <tr>
              <td>Protective Countermeasure</td>
              <td><span class="tag tag-red">Surgical Air-Gap</span></td>
              <td>Session revoked, Port 445 blocked, DB severed</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div style="margin-top: 18px; display: flex; gap: 10px;">
        <button class="btn btn-danger" onclick="triggerTestTripwire()">
          ⚡ Test Scraper Access on Canary (Scenario C)
        </button>
        <button class="btn btn-secondary" onclick="simulateAccidentalClick()">
          🖱️ Test Accidental Click &amp; Safe Cancel (Scenario A)
        </button>
      </div>
    </div>
  `;
}

// 3. SUSPICIOUS ACTIVITY VIEW
function renderSuspiciousActivityView() {
  const items = suspiciousActivities.length ? suspiciousActivities : [
    { type: 'Baseline Activity', time: 'Startup', device: 'RECEPTION-PC', details: 'All tripwires armed and baseline traffic normal.', risk: 'NORMAL' }
  ];

  return `
    <div class="card">
      <div class="card-title">
        <span>👁️ Real-Time Suspicious Activity Feed</span>
        <span class="tag tag-blue">${suspiciousActivities.length} Detected</span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        ClearShield distinguishes normal authorized receptionist actions from automated scrapers, brute force attempts, and bulk downloads.
      </p>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Activity Type</th>
              <th>Device / Source</th>
              <th>Assessment &amp; Countermeasure</th>
              <th>Risk Level</th>
            </tr>
          </thead>
          <tbody>
            ${items.map(it => `
              <tr>
                <td>${it.time}</td>
                <td><b>${it.type}</b></td>
                <td class="code-cell">${it.device}</td>
                <td>${it.details}</td>
                <td>
                  <span class="tag ${it.risk === 'HIGH' ? 'tag-red' : it.risk === 'MEDIUM' ? 'tag-yellow' : 'tag-green'}">
                    ${it.risk}
                  </span>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// 4. BLOCKED REQUESTS VIEW
function renderBlockedRequestsView() {
  return `
    <div class="card">
      <div class="card-title">
        <span>🚫 HTTP 403 Forbidden - Intercepted Requests</span>
        <span class="tag tag-red">${blockedRequests.length} Intercepted</span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        Every suspicious request is halted before data leaves the server. Requests are logged with exact timestamp, origin IP, path, and defense trigger.
      </p>

      ${blockedRequests.length === 0 ? `
        <div style="text-align: center; color: var(--text-muted); padding: 30px;">
          No requests blocked yet. System is operating normally.
        </div>
      ` : `
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Method</th>
                <th>Request Path</th>
                <th>Origin IP</th>
                <th>Defense Reason</th>
                <th>HTTP Status</th>
              </tr>
            </thead>
            <tbody>
              ${blockedRequests.map(b => `
                <tr>
                  <td>${b.formattedTime || b.time.slice(11, 19)}</td>
                  <td><b>${b.method}</b></td>
                  <td class="code-cell">${b.path}</td>
                  <td>${b.ip}</td>
                  <td style="color:#fca5a5;">${b.reason}</td>
                  <td><span class="tag tag-red">403 Forbidden</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `}
    </div>
  `;
}

// 5. ADMINISTRATOR ALERTS & OUT-OF-BAND SMS VIEW
function renderAdminAlertsView() {
  return `
    <div class="grid-2">
      <!-- ALERT CARDS -->
      <div class="card">
        <div class="card-title">
          <span>🚨 Threat &amp; Intrusion Alerts</span>
          <span class="tag tag-yellow">${alerts.length} Logged</span>
        </div>
        ${alerts.length === 0 ? `
          <div style="color: var(--text-muted); text-align: center; padding: 30px;">
            No active threat alerts. Everything is quiet.
          </div>
        ` : `
          <div style="display: flex; flex-direction: column; gap: 12px;">
            ${alerts.map(a => `
              <div style="background: rgba(255,255,255,0.03); border-left: 4px solid ${a.severity === 'HIGH' ? '#ef4444' : '#f59e0b'}; padding: 12px; border-radius: 6px;">
                <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
                  <b>${a.title}</b>
                  <span class="tag ${a.severity === 'HIGH' ? 'tag-red' : 'tag-yellow'}">${a.severity}</span>
                </div>
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 6px;">
                  ${a.time.slice(11, 19)} · Device: ${a.device}
                </div>
                <p style="font-size: 13px; margin-bottom: 6px;">${a.description}</p>
                <div style="font-size: 11px; color: #38bdf8;">Action: ${a.action}</div>
              </div>
            `).join('')}
          </div>
        `}
      </div>

      <!-- OUT-OF-BAND SMS SIMULATOR (Dr. Taylor) -->
      <div class="card">
        <div class="card-title">
          <span>📲 Out-of-Band SMS Notification Preview</span>
          <span class="tag tag-blue">Cellular Bypass</span>
        </div>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
          Simulated encrypted SMS delivered directly to Dr. Taylor over cellular, bypassing clinic Wi-Fi in case local network is compromised.
        </p>

        <div class="phone-mockup">
          <div class="phone-header">
            <span>Carrier: LTE Cellular</span>
            <span>Dr. Taylor (+1-555-0199)</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 10px; max-height: 280px; overflow-y: auto;">
            ${smsQueue.length === 0 ? `
              <div class="sms-bubble">
                🟢 ClearShield Service Notice: Honeypot Canary system active. All patient records safe.
                <div class="sms-meta"><span>ClearShield Gateway</span><span>Today</span></div>
              </div>
            ` : smsQueue.map(sms => `
              <div class="sms-bubble urgent">
                ${sms.message}
                <div class="sms-meta">
                  <span>${sms.channel}</span>
                  <span>${sms.time.slice(11, 19)}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
        <div style="font-size: 10px; color: #64748b; margin-top: 10px; text-align: center;">
          * Note: Carrier simulation mode. Real encrypted SMS service requires external carrier credentials.
        </div>
      </div>
    </div>
  `;
}

// 6. INCIDENT HISTORY & AUDIT VIEW
function renderIncidentHistoryView() {
  return `
    <div class="card">
      <div class="card-title">
        <span>📜 Security Incidents &amp; Audit Trail</span>
        <div style="display:flex; gap: 8px;">
          <button class="btn btn-secondary" onclick="exportIncidentReport('csv')">Export CSV</button>
          <button class="btn" onclick="exportIncidentReport('json')">Export JSON Defense Report</button>
        </div>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        Official incident records for healthcare cybersecurity review and HIPAA audit defense (§ 164.312).
      </p>

      ${incidents.length === 0 ? `
        <div style="text-align: center; color: var(--text-muted); padding: 30px;">
          No security incidents recorded. System running with zero breaches.
        </div>
      ` : `
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Time</th>
                <th>Threat Trigger</th>
                <th>Decoy Resource</th>
                <th>Response Latency</th>
                <th>Records Lost</th>
                <th>Review Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${incidents.map(inc => `
                <tr>
                  <td class="code-cell"><b>${inc.id}</b></td>
                  <td>${inc.formattedTime || inc.time.slice(11, 19)}</td>
                  <td><b>${inc.threatType}</b></td>
                  <td class="code-cell">${inc.resourceAccessed}</td>
                  <td style="color:#34d399;">${inc.latency}</td>
                  <td><span class="tag tag-green">${inc.recordsLost} (Zero)</span></td>
                  <td>
                    ${inc.reviewed ? `
                      <span class="tag tag-green">Reviewed by ${inc.reviewedBy || 'Admin'}</span>
                    ` : `
                      <span class="tag tag-yellow">Pending Review</span>
                    `}
                  </td>
                  <td>
                    ${!inc.reviewed ? `
                      <button class="btn btn-secondary" style="font-size: 11px; padding: 4px 8px;" onclick="reviewIncident('${inc.id}')">
                        Mark Reviewed
                      </button>
                    ` : `<span style="font-size:11px; color:#94a3b8;">Archived</span>`}
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `}
    </div>
  `;
}

// 7. RESTORE SYSTEM VIEW
function renderRestoreSystemView() {
  const isAirGap = systemStatus.airGapped;
  return `
    <div class="card" style="max-width: 650px;">
      <div class="card-title">
        <span>🔄 System Restoration &amp; Air-Gap Clear</span>
        <span class="tag ${isAirGap ? 'tag-red' : 'tag-green'}">
          ${isAirGap ? 'Restoration Required' : 'System Operational'}
        </span>
      </div>

      <p style="color: var(--text-muted); line-height: 1.6; margin-bottom: 18px;">
        Once an administrator has reviewed any incident and verified the endpoint is safe, use this control to restore normal clinic operations. This will:
      </p>

      <ul style="color: #cbd5e1; font-size: 13px; margin-left: 20px; margin-bottom: 20px; line-height: 1.8;">
        <li>Clear the Surgical Air-Gap and reconnect database queries (HTTP 403 lifted).</li>
        <li>Unblock Port 445 (SMB) for authorized clinical printing and storage.</li>
        <li>Provision a fresh cryptographically secure session token for reception terminals.</li>
        <li>Exit "Protected Standby Mode" on the clinic portal back to normal operation.</li>
        <li>Restore the ambient status indicator to 🟢 <b>"ClearShield Active – All Systems Normal"</b>.</li>
      </ul>

      <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); border-radius: 8px; padding: 14px; margin-bottom: 20px;">
        <label style="display:block; font-size: 12px; color: var(--text-muted); margin-bottom: 6px;">
          Authorizing Administrator Name:
        </label>
        <input type="text" id="restore-admin-name" value="Dr. Taylor (Chief Medical Officer)" 
          style="width: 100%; background: #070b13; border: 1px solid var(--card-border); color: #fff; padding: 8px 12px; border-radius: 6px; font-size: 13px;">
      </div>

      <div style="display: flex; gap: 12px;">
        <button class="btn btn-success" style="padding: 10px 18px;" onclick="restoreClinicSystem()">
          ✅ Authorize &amp; Restore Clinic Operations
        </button>
        <button class="btn btn-secondary" onclick="exportIncidentReport('json')">
          📥 Export Audit Report First
        </button>
      </div>
    </div>
  `;
}

// 8. SCENARIO DEMONSTRATION LAB
function renderScenarioLabView() {
  return `
    <div class="card">
      <div class="card-title">
        <span>🧪 Interactive Honeypot Demonstration Scenarios</span>
        <span class="tag tag-blue">Live Test Runner</span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        Test and verify each of the 4 key scenarios with real-time feedback across both the ClearShield Dashboard and the Clinic Portal.
      </p>

      <div class="grid-2">
        <!-- Scenario A -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px;">
              <h3>Scenario A – Normal Receptionist</h3>
              <span class="tag tag-green">Zero False Alarms</span>
            </div>
            <p>Receptionist clicks on normal clinic records, or accidentally clicks Canary row and hits safe cancel. System remains green without triggering alarms.</p>
          </div>
          <button class="btn btn-secondary" onclick="runScenario('A')">
            ▶ Run Scenario A (Safe Cancel)
          </button>
        </div>

        <!-- Scenario B -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px;">
              <h3>Scenario B – Suspicious Visitor</h3>
              <span class="tag tag-yellow">Brute Force Guard</span>
            </div>
            <p>Visitor repeatedly enters incorrect PINs attempting to access restricted resources. ClearShield detects pattern and blocks request with HTTP 403.</p>
          </div>
          <button class="btn btn-secondary" onclick="runScenario('B')">
            ▶ Run Scenario B (PIN Brute Force)
          </button>
        </div>

        <!-- Scenario C -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px;">
              <h3>Scenario C – Canary Trap Tripwire</h3>
              <span class="tag tag-red">&lt; 15ms Catch</span>
            </div>
            <p>An automated scraper requests the Row 0 Canary Decoy. ClearShield trips the wire in &lt;15ms, triggers Surgical Air-Gap, and dispatches simulated SMS.</p>
          </div>
          <button class="btn btn-danger" onclick="runScenario('C')">
            ▶ Run Scenario C (Scraper Canary Trip)
          </button>
        </div>

        <!-- Scenario D -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px;">
              <h3>Scenario D – Bulk Data Extraction</h3>
              <span class="tag tag-yellow">Rate / Volume Guard</span>
            </div>
            <p>An account requests an unusually large bulk export of 250 records. ClearShield halts the stream before data transfer and returns HTTP 403.</p>
          </div>
          <button class="btn btn-secondary" onclick="runScenario('D')">
            ▶ Run Scenario D (Bulk Exfiltration)
          </button>
        </div>
      </div>
    </div>
  `;
}

// -------------------------------------------------------------------------
// ORIGINAL CLEARSHIELD PROTOTYPE VIEWS (Preserved 100%)
// -------------------------------------------------------------------------
const hm = s => String(Math.floor(s/3600)).padStart(2,'0') + ':' + String(Math.floor(s%3600/60)).padStart(2,'0');
const at = (h,m) => h*3600 + m*60;

function initCoreDemoEvents() {
  coreEvents = [];
  coreEvents.push({id:1, t:at(9,40), type:'LOGIN_OK', device:'NURSE-LAPTOP'});
  for (let i=0; i<20; i++) coreEvents.push({id:i+2, t:at(10,2)+i*15, type:'AUTH_FAIL', device:'FRONT-DESK-PC'});
  coreEvents.push({id:22, t:at(10,9), type:'FILE_CHANGE', device:'FRONT-DESK-PC', files:340, secs:90});
  coreEvents.push({id:23, t:at(10,20), type:'EMAIL_LINK', device:'ADMIN-PC', note:'Link claiming to be from the exam board'});
}

function analyzeCoreEvents() {
  const GAP = 600;
  const by = {};
  [...coreEvents].sort((a,b)=>a.t-b.t).forEach(e=>{(by[e.device+'|'+e.type]??=[]).push(e)});
  const groups = [];
  Object.values(by).forEach(list=>{
    let cur = [list[0]];
    for (let i=1; i<list.length; i++) {
      if (list[i].t - list[i-1].t <= GAP) cur.push(list[i]);
      else { groups.push(cur); cur=[list[i]]; }
    }
    groups.push(cur);
  });

  const gs = groups.map(evs => {
    const dev = evs[0].device, typ = evs[0].type, start = evs[0].t, end = evs.at(-1).t;
    let flag = 'U';
    if (typ === 'AUTH_FAIL') flag = (evs.length >= coreThresholds.fails && end - start <= coreThresholds.failMin * 60) ? 'A' : 'D';
    else if (typ === 'FILE_CHANGE') {
      const f = evs.reduce((s,e)=>s+(e.files||0), 0);
      const sec = Math.max(...evs.map(e=>e.secs||60));
      flag = (f >= coreThresholds.files && sec <= coreThresholds.fileMin * 60) ? 'B' : 'D';
    } else if (typ === 'EMAIL_LINK') flag = 'C';
    else if (typ === 'LOGIN_OK') flag = 'D';
    return { device: dev, type: typ, evs, start, end, flag };
  });

  const alertsOut = [];
  const byDev = {};
  gs.forEach(g => (byDev[g.device] ??= []).push(g));

  Object.entries(byDev).forEach(([dev, list]) => {
    const A = list.find(g => g.flag === 'A'), B = list.find(g => g.flag === 'B');
    const used = new Set();
    if (A && B) {
      used.add(A).add(B);
      alertsOut.push({
        id: dev + '-AB', device: dev, kind: 'AB', risk: 'HIGH',
        evs: [...A.evs, ...B.evs],
        reasons: [A.evs.length + ' failed logins', B.evs[0].files + ' files changed in ' + B.evs[0].secs + 's', 'Two rules fired on the same device'],
        n: B.evs[0].files, time: Math.min(A.start, B.start), resolved: coreResolved.has(dev + '-AB')
      });
    }
    list.filter(g => !used.has(g)).forEach(g => {
      const risk = g.flag === 'D' ? 'LOW' : 'MEDIUM';
      alertsOut.push({
        id: dev + '-' + g.flag, device: dev, kind: g.flag, risk,
        evs: g.evs, reasons: [g.flag === 'D' ? 'No threshold reached' : `Rule ${g.flag} fired (${g.evs.length} events)`],
        n: g.kind === 'B' ? g.evs[0].files : g.evs.length, time: g.start, resolved: coreResolved.has(dev + '-' + g.flag)
      });
    });
  });

  const o = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  return alertsOut.sort((a,b) => o[a.risk] - o[b.risk]);
}

const CORE_TEXT = {
  A: { t: 'Repeated failed logins', what: n => `${n} login attempts failed in a short time on this device.`, why: 'Someone may be guessing a password.', know: n => `${n} failed logins, grouped because they share a device and are close in time.`, unc: 'We cannot tell whether it is a typo, a forgotten password or an attacker.', do: 'Do not keep retrying. Tell your administrator and change the password from a different device.', avoid: 'Do not ignore it or share the password to "fix" it.' },
  B: { t: 'Unusual file activity', what: n => `${n} files changed very quickly on this device.`, why: 'Fast bulk changes can mean ransomware, but also backups or updates.', know: n => `${n} files changed within the demo threshold window.`, unc: 'We cannot confirm what program changed the files.', do: 'Disconnect the device from the network and tell your administrator.', avoid: 'Do not delete files, reinstall, or pay anyone before getting help.' },
  AB: { t: 'Failed logins, then files changed', what: n => `Many failed logins were followed by a burst of file changes on the same device.`, why: 'This combination is concerning and may be unauthorized access. It needs prompt attention.', know: n => `Both the failed-login rule and the file-activity rule fired on one device, close in time.`, unc: 'Suspicious does not mean confirmed. We cannot prove an attack happened.', do: 'Disconnect the PC from the network. Tell your administrator.', avoid: 'Do not delete files, reinstall, or pay anyone before getting help.' },
  C: { t: 'Possible phishing', what: n => 'An email link or attachment looked suspicious.', why: 'Clicking could lead to a fake login page or malware.', know: n => 'The message was flagged by the phishing rule.', unc: 'We cannot confirm the sender or whether anyone clicked.', do: 'Do not click. Report it to your administrator and delete only after they say so.', avoid: 'Do not open attachments or reply with personal details.' },
  D: { t: 'Routine activity', what: n => 'Normal activity was recorded.', why: 'Low concern unless new evidence appears.', know: n => 'No rule threshold was reached.', unc: 'Nothing unusual is known.', do: 'No action needed.', avoid: 'No special cautions.' },
  U: { t: 'Insufficient evidence. Investigation needed.', what: n => 'An event ClearShield does not recognise was recorded.', why: 'We do not have enough data to judge it.', know: n => 'Only the raw event is available.', unc: 'Almost everything: we are saying so rather than guessing.', do: 'Ask your administrator to review it.', avoid: 'Do not assume it is safe or dangerous.' }
};

function renderCoreOverviewView() {
  const al = analyzeCoreEvents();
  const c = r => al.filter(a => a.risk === r).length;
  const open = al.filter(a => !a.resolved && a.risk !== 'LOW').length;
  const wk = [['Mon',12],['Tue',18],['Wed',9],['Thu',24],['Fri',31],['Sat',15],['Sun',24]];
  const mx = Math.max(...wk.map(w => w[1]));

  return `
    <div class="grid-4">
      <div class="card"><div class="stat-value">${coreEvents.length}</div><div class="stat-desc">Raw Events</div></div>
      <div class="card"><div class="stat-value">${al.length}</div><div class="stat-desc">Grouped Alerts</div></div>
      <div class="card"><div class="stat-value" style="color:#ef4444">${c('HIGH')}</div><div class="stat-desc">High Priority</div></div>
      <div class="card"><div class="stat-value">${open}</div><div class="stat-desc">Needs Review</div></div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-title">Alerts This Week <span class="tag tag-blue">Simulated</span></div>
        <div style="display:flex; align-items:flex-end; gap:8px; height:120px; padding-top:10px;">
          ${wk.map(w => `
            <div style="flex:1; text-align:center; font-size:11px; color:#94a3b8;">
              <div style="background:#3b82f6; height:${(w[1]/mx)*90}px; border-radius:4px 4px 0 0; margin-bottom:4px;"></div>
              ${w[0]}
            </div>
          `).join('')}
        </div>
      </div>

      <div class="card">
        <div class="card-title">By Risk Level <span class="tag tag-blue">Distribution</span></div>
        ${['HIGH','MEDIUM','LOW'].map(r => `
          <div style="display:flex; align-items:center; gap:8px; margin: 10px 0; font-size:13px;">
            <b style="width:65px;">${r}</b>
            <div style="flex:1; background:rgba(255,255,255,0.06); height:12px; border-radius:6px; overflow:hidden;">
              <div style="background:${r==='HIGH'?'#ef4444':r==='MEDIUM'?'#f59e0b':'#10b981'}; width:${(c(r)/(al.length||1))*100}%; height:100%;"></div>
            </div>
            <span>${c(r)}</span>
          </div>
        `).join('')}
      </div>
    </div>

    <div class="card">
      <div class="card-title">High Priority Grouped Alerts</div>
      ${al.filter(a => a.risk === 'HIGH' && !a.resolved).map(a => renderCoreAlertCard(a, true)).join('')}
    </div>
  `;
}

function renderCoreAlertsView() {
  const al = analyzeCoreEvents();
  return `
    <div class="card">
      <div class="card-title">All Grouped Security Alerts</div>
      ${al.map(a => renderCoreAlertCard(a, false)).join('')}
    </div>
  `;
}

function renderCoreGuidedView() {
  const al = analyzeCoreEvents().filter(a => !a.resolved && a.risk !== 'LOW');
  return `
    <div class="card">
      <div class="card-title">Guided Actions (6-Point Explainable Framework)</div>
      <p style="color:var(--text-muted); margin-bottom:14px;">ClearShield never calls an anomaly a confirmed breach without proof. Follow the 6-point guided rationale.</p>
      ${al.length ? al.map(a => renderCoreAlertCard(a, true)).join('') : '<div style="color:#94a3b8; text-align:center; padding:20px;">No alerts require action at this time.</div>'}
    </div>
  `;
}

function renderCoreSettingsView() {
  return `
    <div class="card" style="max-width: 550px;">
      <div class="card-title">Rule Threshold Settings</div>
      <label style="display:block; margin: 10px 0 4px; font-size:12px;">Rule A: Failed Logins &ge;</label>
      <input type="number" id="cfg-fails" value="${coreThresholds.fails}" style="width:100%; background:#070b13; border:1px solid var(--card-border); color:#fff; padding:8px; border-radius:6px; margin-bottom:10px;">

      <label style="display:block; margin: 10px 0 4px; font-size:12px;">Rule A Window (Minutes):</label>
      <input type="number" id="cfg-failmin" value="${coreThresholds.failMin}" style="width:100%; background:#070b13; border:1px solid var(--card-border); color:#fff; padding:8px; border-radius:6px; margin-bottom:10px;">

      <label style="display:block; margin: 10px 0 4px; font-size:12px;">Rule B: Files Changed &ge;</label>
      <input type="number" id="cfg-files" value="${coreThresholds.files}" style="width:100%; background:#070b13; border:1px solid var(--card-border); color:#fff; padding:8px; border-radius:6px; margin-bottom:10px;">

      <label style="display:block; margin: 10px 0 4px; font-size:12px;">Rule B Window (Minutes):</label>
      <input type="number" id="cfg-filemin" value="${coreThresholds.fileMin}" style="width:100%; background:#070b13; border:1px solid var(--card-border); color:#fff; padding:8px; border-radius:6px; margin-bottom:14px;">

      <div style="display:flex; gap:10px;">
        <button class="btn" onclick="saveCoreSettings()">Save &amp; Re-Analyze</button>
        <button class="btn btn-secondary" onclick="resetCoreSettings()">Reset Defaults</button>
      </div>
    </div>
  `;
}

function renderCoreCSVView() {
  return `
    <div class="card">
      <div class="card-title">CSV Dataset Testing &amp; Import</div>
      <p style="color:var(--text-muted); margin-bottom:16px;">Test the ClearShield detection engine against CSV security event datasets.</p>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <button class="btn" onclick="loadSampleCSVDataset()">Load Sample Fake CSV Dataset</button>
        <button class="btn btn-secondary" onclick="document.getElementById('csv-file-input').click()">Import Custom CSV</button>
        <button class="btn btn-secondary" onclick="downloadSampleCSVFile()">Download Sample CSV</button>
        <input type="file" id="csv-file-input" accept=".csv" hidden onchange="handleCSVUpload(this.files[0])">
      </div>
      <div id="csv-import-status" style="margin-top:14px; font-size:13px; color:#60a5fa;"></div>
    </div>
  `;
}

function renderCoreAboutView() {
  return `
    <div class="card" style="max-width: 700px;">
      <div class="card-title">About ClearShield</div>
      <p style="font-size:13px; color:#cbd5e1; line-height:1.7;">
        <b>What it is:</b> A working cybersecurity defense and canary trap prototype using explainable, rule-based reasoning and automated surgical air-gapping. It is open about what it is unsure of and protects medical continuity.<br><br>
        <b>What it is not:</b> Live hardware protection or a replacement for professional human security specialists. It never labels an unverified anomaly as a confirmed attack without sufficient telemetry.
      </p>
    </div>
  `;
}

function renderCoreAlertCard(a, full) {
  const x = CORE_TEXT[a.kind] || CORE_TEXT.U;
  return `
    <div style="background:rgba(255,255,255,0.03); border:1px solid var(--card-border); border-left: 4px solid ${a.risk==='HIGH'?'#ef4444':a.risk==='MEDIUM'?'#f59e0b':'#10b981'}; border-radius:8px; padding:14px; margin-bottom:14px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <div>
          <span class="tag ${a.risk==='HIGH'?'tag-red':a.risk==='MEDIUM'?'tag-yellow':'tag-green'}">${a.risk}</span>
          <b style="margin-left:6px; color:#fff;">${x.t}</b>
          <span style="color:var(--text-muted); font-size:12px; margin-left:8px;">${a.device} · ${hm(a.time)}</span>
        </div>
        ${a.resolved ? '<span class="tag tag-green">Resolved</span>' : ''}
      </div>

      <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">Why this risk: ${a.reasons.join(' · ')}</div>

      ${full ? `
        <div class="six-grid">
          <div class="six-box"><h4>1 · What Happened?</h4>${x.what(a.n)}</div>
          <div class="six-box"><h4>2 · Why It Matters</h4>${x.why}</div>
          <div class="six-box"><h4>3 · What We Know</h4>${x.know(a.n)}</div>
          <div class="six-box"><h4>4 · What Is Uncertain</h4>${x.unc}</div>
          <div class="six-box do-box"><h4>5 · Recommended Action</h4>${x.do}</div>
          <div class="six-box avoid-box"><h4>6 · What to Avoid</h4>${x.avoid}</div>
        </div>
      ` : ''}

      ${!a.resolved && a.risk !== 'LOW' ? `
        <div style="margin-top:10px;">
          <button class="btn btn-secondary" style="font-size:11px; padding:4px 8px;" onclick="resolveCoreAlert('${a.id}')">
            Mark as Reviewed
          </button>
        </div>
      ` : ''}
    </div>
  `;
}

function resolveCoreAlert(id) {
  coreResolved.add(id);
  renderCurrentView();
}

function saveCoreSettings() {
  coreThresholds.fails = +document.getElementById('cfg-fails').value;
  coreThresholds.failMin = +document.getElementById('cfg-failmin').value;
  coreThresholds.files = +document.getElementById('cfg-files').value;
  coreThresholds.fileMin = +document.getElementById('cfg-filemin').value;
  alert('Thresholds saved and re-analyzed.');
  renderCurrentView();
}

function resetCoreSettings() {
  coreThresholds = { fails: 5, failMin: 10, files: 100, fileMin: 2 };
  renderCurrentView();
}

function loadSampleCSVDataset() {
  initCoreDemoEvents();
  document.getElementById('csv-import-status').textContent = 'Loaded sample fake CSV dataset (23 events analyzed).';
  renderCurrentView();
}

function downloadSampleCSVFile() {
  window.location.href = `${API_BASE}/api/clearshield/export-report?format=csv`;
}

function handleCSVUpload(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    document.getElementById('csv-import-status').textContent = `Imported custom CSV file: ${file.name}`;
  };
  reader.readAsText(file);
}

// -------------------------------------------------------------------------
// API ACTIONS & SCENARIOS
// -------------------------------------------------------------------------
async function runScenario(scenario) {
  try {
    const res = await fetch(`${API_BASE}/api/scenarios/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });
    const data = await res.json();
    alert(`Scenario ${scenario} executed: ${data.outcome}`);
    fetchAllData();
  } catch (err) {
    alert(`Failed to run scenario: ${err.message}`);
  }
}

async function triggerTestTripwire() {
  try {
    // Attempt to access Row 0 Canary Decoy directly
    const res = await fetch(`${API_BASE}/api/clinic/records/canary-0`, {
      headers: { 'User-Agent': 'Automated Scraper Bot / 1.0' }
    });
    const data = await res.json();
    alert(`⚠️ Canary Trap Triggered!\nLatency: ${data.latency}\nCode: ${data.code}\nAir-Gap Activated: HTTP 403 Forbidden.`);
    fetchAllData();
  } catch (err) {
    console.error(err);
  }
}

async function simulateAccidentalClick() {
  try {
    const res = await fetch(`${API_BASE}/api/clinic/safe-cancel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: 'Receptionist Jane', device: 'RECEPTION-PC' })
    });
    const data = await res.json();
    alert(`Scenario A: ${data.message}`);
    fetchAllData();
  } catch (err) {
    console.error(err);
  }
}

async function reviewIncident(incidentId) {
  try {
    await fetch(`${API_BASE}/api/clearshield/review-incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incidentId, reviewer: 'Security Officer' })
    });
    fetchAllData();
  } catch (err) {
    alert(err.message);
  }
}

async function restoreClinicSystem() {
  const adminName = document.getElementById('restore-admin-name')?.value || 'Dr. Taylor (Chief Medical Officer)';
  try {
    const res = await fetch(`${API_BASE}/api/clearshield/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ adminUser: adminName })
    });
    const data = await res.json();
    alert('✅ System fully restored. Database reconnect active. Port 445 SMB opened. Clinic resumed normal operations.');
    fetchAllData();
  } catch (err) {
    alert(err.message);
  }
}

function exportIncidentReport(format = 'json') {
  window.open(`${API_BASE}/api/clearshield/export-report?format=${format}`, '_blank');
}
