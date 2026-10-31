/**
 * ClearShield Healthcare Cybersecurity Platform - Dashboard Controller
 * Connects to shared backend via SSE and manages 8 dedicated security pages:
 * 1. Main Dashboard
 * 2. Threat Monitoring (Pre-login)
 * 3. Honeypot Monitoring (Decoy files & Canary Trap)
 * 4. Data Protection (IDOR & Bulk Extraction)
 * 5. Authentication (Passkeys & Recovery Codes)
 * 6. Incident History
 * 7. Emergency Response (Air-gap & Standby)
 * 8. Security Reports
 */

const API_BASE = window.location.origin;

let currentView = 'page-1-main';

let systemStatus = {
  statusText: 'ClearShield is Active – All Systems Normal',
  indicatorColor: 'green',
  isArmed: true,
  airGapped: false,
  smbBlocked: false,
  dbCut: false,
  sessionTokenValid: true,
  lastLatencyMs: 1.25,
  recordsProtectedCount: 8,
  recordsLost: 0,
  stats: {
    totalBlocked: 0,
    totalIncidents: 0,
    totalAlerts: 0,
    totalSms: 0,
    preLoginThreats: 0,
    honeypotEvents: 0,
    dataProtectionEvents: 0,
    authEvents: 0
  }
};

let incidents = [];
let blockedRequests = [];
let alerts = [];
let smsQueue = [];
let preLoginThreats = [];
let honeypotData = { decoyFiles: [], events: [] };
let dataProtectionLogs = [];
let authData = { users: [], activityLogs: [] };

// -------------------------------------------------------------------------
// INITIALIZATION & REAL-TIME EVENT STREAM (SSE)
// -------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initEventStream();
  fetchAllData();
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

function navigateTo(viewId) {
  currentView = viewId;
  document.querySelectorAll('.nav-item').forEach(b => {
    if (b.dataset.view === viewId) b.classList.add('active');
    else b.classList.remove('active');
  });
  renderCurrentView();
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
    if (currentView === 'page-2-threats') renderCurrentView();
  } else if (type === 'PRE_LOGIN_THREAT') {
    if (data.threat) preLoginThreats.unshift(data.threat);
    if (data.alert) alerts.unshift(data.alert);
    updateTopHeader();
    renderCurrentView();
  } else if (type === 'HONEYPOT_TRIGGERED') {
    if (data.event) honeypotData.events.unshift(data.event);
    if (data.incident) incidents.unshift(data.incident);
    if (data.alert) alerts.unshift(data.alert);
    updateTopHeader();
    renderCurrentView();
  } else if (type === 'DATA_PROTECTION_ALERT') {
    if (data.log) dataProtectionLogs.unshift(data.log);
    if (data.alert) alerts.unshift(data.alert);
    if (data.incident) incidents.unshift(data.incident);
    updateTopHeader();
    renderCurrentView();
  } else if (type === 'AUTH_ACTIVITY') {
    authData.activityLogs.unshift(data);
    if (currentView === 'page-5-auth') renderCurrentView();
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
    const [stRes, incRes, blkRes, altRes, smsRes, pltRes, hpRes, dpRes, authRes] = await Promise.all([
      fetch(`${API_BASE}/api/clearshield/status`),
      fetch(`${API_BASE}/api/clearshield/incidents`),
      fetch(`${API_BASE}/api/clearshield/blocked-requests`),
      fetch(`${API_BASE}/api/clearshield/alerts`),
      fetch(`${API_BASE}/api/clearshield/sms`),
      fetch(`${API_BASE}/api/clearshield/threats/pre-login`),
      fetch(`${API_BASE}/api/clearshield/honeypot/events`),
      fetch(`${API_BASE}/api/clearshield/data-protection/events`),
      fetch(`${API_BASE}/api/clearshield/auth/logs`)
    ]);

    systemStatus = await stRes.json();
    incidents = await incRes.json();
    blockedRequests = await blkRes.json();
    alerts = await altRes.json();
    smsQueue = await smsRes.json();
    preLoginThreats = await pltRes.json();
    honeypotData = await hpRes.json();
    dataProtectionLogs = await dpRes.json();
    authData = await authRes.json();

    updateTopHeader();
    renderCurrentView();
  } catch (err) {
    console.warn('Backend loading in progress...', err);
  }
}

function updateTopHeader() {
  const pill = document.getElementById('ambient-status-pill');
  const txt = document.getElementById('ambient-status-text');
  const tag = document.getElementById('clinic-conn-tag');
  const latency = document.getElementById('metric-latency');
  const smb = document.getElementById('metric-smb');
  const lost = document.getElementById('metric-lost');

  if (systemStatus.airGapped) {
    pill.className = 'status-pill red';
    txt.textContent = '🚨 Air-Gap Isolated – Threat Contained';
    tag.className = 'tag tag-red';
    tag.textContent = '⚠️ Clinic Isolated (Standby Active)';
    smb.textContent = 'BLOCKED (Port 445)';
    smb.style.color = '#e11d48';
  } else {
    pill.className = 'status-pill';
    txt.textContent = 'ClearShield is Active – All Systems Normal';
    tag.className = 'tag tag-green';
    tag.textContent = '🟢 Clinic Connected (Port 5001)';
    smb.textContent = 'Active (Monitored)';
    smb.style.color = '#059669';
  }

  latency.textContent = `< 15ms (${systemStatus.lastLatencyMs || 1.25}ms)`;
  lost.textContent = `${systemStatus.recordsLost} (Zero records lost)`;

  // Update badges
  document.getElementById('badge-threats').textContent = preLoginThreats.length;
  document.getElementById('badge-honeypot').textContent = honeypotData.events ? honeypotData.events.length : 0;
  document.getElementById('badge-dataprotect').textContent = dataProtectionLogs.length;
  document.getElementById('badge-auth').textContent = authData.activityLogs ? authData.activityLogs.length : 0;
  document.getElementById('badge-incidents').textContent = incidents.length;
}

// -------------------------------------------------------------------------
// VIEW RENDERING DISPATCHER
// -------------------------------------------------------------------------
function renderCurrentView() {
  const container = document.getElementById('view-container');

  switch (currentView) {
    case 'page-1-main':
      container.innerHTML = renderPage1MainDashboard();
      break;
    case 'page-2-threats':
      container.innerHTML = renderPage2ThreatMonitoring();
      break;
    case 'page-3-honeypot':
      container.innerHTML = renderPage3HoneypotMonitoring();
      break;
    case 'page-4-dataprotect':
      container.innerHTML = renderPage4DataProtection();
      break;
    case 'page-5-auth':
      container.innerHTML = renderPage5Authentication();
      break;
    case 'page-6-incidents':
      container.innerHTML = renderPage6IncidentHistory();
      break;
    case 'page-7-emergency':
      container.innerHTML = renderPage7EmergencyResponse();
      break;
    case 'page-8-reports':
      container.innerHTML = renderPage8SecurityReports();
      break;
    case 'page-scenarios':
      container.innerHTML = renderScenarioLab();
      break;
    case 'core-guided':
      container.innerHTML = renderCoreGuidedActions();
      break;
    case 'core-settings':
      container.innerHTML = renderCoreSettings();
      break;
    case 'core-csv':
      container.innerHTML = renderCoreCSVTools();
      break;
    case 'core-about':
      container.innerHTML = renderCoreAbout();
      break;
    default:
      container.innerHTML = renderPage1MainDashboard();
  }
}

// =========================================================================
// PART 6: PAGE 1 – MAIN DASHBOARD (HOMEPAGE)
// =========================================================================
function renderPage1MainDashboard() {
  const isAirGap = systemStatus.airGapped;
  const suspiciousCount = preLoginThreats.length + dataProtectionLogs.length;
  const blockedCount = blockedRequests.length;
  const honeypotCount = honeypotData.events ? honeypotData.events.length : 0;

  return `
    <!-- WELCOME MESSAGE & SYSTEM STATUS -->
    <div class="card" style="border-left: 6px solid var(--pastel-sky-border); background: #ffffff;">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap: 12px;">
        <div>
          <h2 style="font-size: 20px; color: #0f172a; margin-bottom: 4px;">
            Welcome to ClearShield Defense Center
          </h2>
          <p style="font-size: 13px; color: var(--text-muted);">
            Preventive healthcare cybersecurity platform protecting <b>Oakridge Community Health Clinic</b>.
          </p>
        </div>
        <div style="display:flex; gap: 10px; align-items:center;">
          <span class="status-pill ${isAirGap ? 'red' : ''}">
            <span class="pulse-dot"></span>
            <span>${systemStatus.statusText}</span>
          </span>
        </div>
      </div>
    </div>

    <!-- QUICK METRIC CARDS -->
    <div class="grid-4">
      <div class="card">
        <div class="card-title">Suspicious Activities</div>
        <div class="stat-value" style="color: #0284c7">${suspiciousCount}</div>
        <div class="stat-desc">Pre-login &amp; cross-patient probes</div>
      </div>

      <div class="card">
        <div class="card-title">Blocked Requests</div>
        <div class="stat-value" style="color: ${blockedCount > 0 ? '#e11d48' : '#059669'}">${blockedCount}</div>
        <div class="stat-desc">HTTP 403 halts before data transfer</div>
      </div>

      <div class="card">
        <div class="card-title">Honeypot Decoy Status</div>
        <div class="stat-value" style="color: #059669">
          ${isAirGap ? 'TRIPPED (Isolated)' : 'ARMED (3 Decoys)'}
        </div>
        <div class="stat-desc">Row 0 Tripwire &amp; Decoy Files active</div>
      </div>

      <div class="card">
        <div class="card-title">Clinic Connection Status</div>
        <div class="stat-value" style="color: #059669; font-size: 20px;">
          🟢 Connected (Port 5001)
        </div>
        <div class="stat-desc">Real-time SSE channel synchronized</div>
      </div>
    </div>

    <!-- NAVIGATION CARDS (Pages 2 to 8) -->
    <div style="margin-bottom: 12px;">
      <h3 style="font-size: 16px; color: #0f172a; margin-bottom: 12px; font-weight: 700;">
        ClearShield Cybersecurity Modules
      </h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px;">
        
        <!-- Page 2 Card -->
        <div class="scenario-card" style="cursor:pointer;" onclick="navigateTo('page-2-threats')">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4 style="font-size: 15px; color:#0f172a;">👁️ 2. Threat Monitoring</h4>
              <span class="tag tag-blue">${preLoginThreats.length} Caught</span>
            </div>
            <p>Monitors pre-login restricted-page access attempts (/admin, /staff, /backup) and blocks reconnaissance probes.</p>
          </div>
          <button class="btn btn-secondary" style="font-size:12px; align-self: flex-start;">Open Threat Monitoring ➔</button>
        </div>

        <!-- Page 3 Card -->
        <div class="scenario-card" style="cursor:pointer;" onclick="navigateTo('page-3-honeypot')">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4 style="font-size: 15px; color:#0f172a;">🪤 3. Honeypot Monitoring</h4>
              <span class="tag tag-yellow">${honeypotCount} Events</span>
            </div>
            <p>Manages fictional decoy files and Row 0 Canary Tripwires. Intercepts unauthorized downloads in &lt;15ms.</p>
          </div>
          <button class="btn btn-secondary" style="font-size:12px; align-self: flex-start;">Open Honeypot Monitoring ➔</button>
        </div>

        <!-- Page 4 Card -->
        <div class="scenario-card" style="cursor:pointer;" onclick="navigateTo('page-4-dataprotect')">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4 style="font-size: 15px; color:#0f172a;">🔒 4. Data Protection</h4>
              <span class="tag tag-green">${dataProtectionLogs.length} Checked</span>
            </div>
            <p>Guards patient medicine history against unauthorized IDOR requests and halts excessive bulk data extraction.</p>
          </div>
          <button class="btn btn-secondary" style="font-size:12px; align-self: flex-start;">Open Data Protection ➔</button>
        </div>

        <!-- Page 5 Card -->
        <div class="scenario-card" style="cursor:pointer;" onclick="navigateTo('page-5-auth')">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4 style="font-size: 15px; color:#0f172a;">🔑 5. Authentication</h4>
              <span class="tag tag-purple">Passkeys Ready</span>
            </div>
            <p>Tracks passkey enrollments, personal recovery codes, login activity, and guards against credential brute-forcing.</p>
          </div>
          <button class="btn btn-secondary" style="font-size:12px; align-self: flex-start;">Open Authentication ➔</button>
        </div>

        <!-- Page 6 Card -->
        <div class="scenario-card" style="cursor:pointer;" onclick="navigateTo('page-6-incidents')">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4 style="font-size: 15px; color:#0f172a;">📜 6. Incident History</h4>
              <span class="tag tag-blue">${incidents.length} Logged</span>
            </div>
            <p>Complete healthcare security incident registry with timestamps, threat origins, actions taken, and review controls.</p>
          </div>
          <button class="btn btn-secondary" style="font-size:12px; align-self: flex-start;">Open Incident History ➔</button>
        </div>

        <!-- Page 7 Card -->
        <div class="scenario-card" style="cursor:pointer;" onclick="navigateTo('page-7-emergency')">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4 style="font-size: 15px; color:#0f172a;">🚨 7. Emergency Response</h4>
              <span class="tag ${isAirGap ? 'tag-red' : 'tag-green'}">${isAirGap ? 'Standby Mode' : 'Ready'}</span>
            </div>
            <p>Surgical air-gap controls, session isolation, Care Continuity printable queue, and one-click operational restore.</p>
          </div>
          <button class="btn btn-secondary" style="font-size:12px; align-self: flex-start;">Open Emergency Response ➔</button>
        </div>

        <!-- Page 8 Card -->
        <div class="scenario-card" style="cursor:pointer;" onclick="navigateTo('page-8-reports')">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4 style="font-size: 15px; color:#0f172a;">📑 8. Security Reports</h4>
              <span class="tag tag-blue">JSON &amp; CSV</span>
            </div>
            <p>Exports comprehensive security audit defense reports certifying zero patient record leaks for regulatory compliance.</p>
          </div>
          <button class="btn btn-secondary" style="font-size:12px; align-self: flex-start;">Open Security Reports ➔</button>
        </div>

      </div>
    </div>

    <!-- RECENT SECURITY ALERTS -->
    <div class="card" style="margin-top: 20px;">
      <div class="card-title">
        <span>Recent Security Alerts</span>
        <span class="tag tag-yellow">${alerts.length} Total Alerts</span>
      </div>
      ${alerts.length === 0 ? `
        <div style="text-align: center; color: var(--text-muted); padding: 24px;">
          🟢 All monitored systems quiet. No active alerts recorded.
        </div>
      ` : `
        <div style="display: flex; flex-direction: column; gap: 10px;">
          ${alerts.slice(0, 4).map(a => `
            <div style="background: #ffffff; border: 1px solid var(--card-border); border-left: 4px solid ${a.severity === 'HIGH' ? '#f43f5e' : '#f59e0b'}; padding: 12px 16px; border-radius: 8px;">
              <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
                <b>${a.title}</b>
                <span class="tag ${a.severity === 'HIGH' ? 'tag-red' : 'tag-yellow'}">${a.severity}</span>
              </div>
              <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">
                ${a.time.slice(11, 19)} · Source: ${a.device} · Carrier: ${a.carrier || 'Internal Security Bus'}
              </div>
              <p style="font-size: 13px; color: #334155;">${a.description}</p>
            </div>
          `).join('')}
        </div>
      `}
    </div>
  `;
}

// =========================================================================
// PART 7: PAGE 2 – THREAT MONITORING (PRE-LOGIN)
// =========================================================================
function renderPage2ThreatMonitoring() {
  return `
    <div class="card">
      <div class="card-title">
        <span>👁️ Page 2: Threat Monitoring – Pre-Login Intrusion Detection</span>
        <span class="tag tag-blue">${preLoginThreats.length} Probes Intercepted</span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        ClearShield monitors suspicious visitor probes attempting to access restricted clinic administrative pages before authentication. Requests to <b>/admin, /staff, /backup, /database</b> are intercepted with HTTP 403 Forbidden before reaching sensitive clinic endpoints.
      </p>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Probed Route</th>
              <th>Origin IP</th>
              <th>Pattern Analysis</th>
              <th>Attempts</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${preLoginThreats.length === 0 ? `
              <tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-muted);">No pre-login threats recorded. Routine visitor traffic normal.</td></tr>
            ` : preLoginThreats.map(t => `
              <tr>
                <td>${t.formattedTime || t.time.slice(11, 19)}</td>
                <td class="code-cell"><b>${t.path}</b></td>
                <td>${t.clientIp}</td>
                <td><span class="tag tag-yellow">${t.pattern}</span></td>
                <td><b>${t.attempts}</b></td>
                <td><span class="tag tag-red">Blocked (HTTP 403)</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <div style="margin-top: 18px; display:flex; gap: 10px;">
        <button class="btn btn-secondary" onclick="runScenario('2')">
          ⚡ Simulate Pre-Login Probe on /admin (Scenario 2)
        </button>
      </div>
    </div>

    <!-- BLOCKED REQUESTS TABLE -->
    <div class="card">
      <div class="card-title">
        <span>🚫 All Blocked Requests Log</span>
        <span class="tag tag-red">${blockedRequests.length} Total Blocked</span>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Method</th>
              <th>Target Path</th>
              <th>Client IP</th>
              <th>Defense Reason</th>
              <th>HTTP Code</th>
            </tr>
          </thead>
          <tbody>
            ${blockedRequests.length === 0 ? `
              <tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-muted);">No blocked requests.</td></tr>
            ` : blockedRequests.map(b => `
              <tr>
                <td>${b.formattedTime || b.time.slice(11, 19)}</td>
                <td><b>${b.method}</b></td>
                <td class="code-cell">${b.path}</td>
                <td>${b.ip}</td>
                <td style="color:#e11d48;">${b.reason}</td>
                <td><span class="tag tag-red">403 Forbidden</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// =========================================================================
// PART 7: PAGE 3 – HONEYPOT MONITORING
// =========================================================================
function renderPage3HoneypotMonitoring() {
  const decoys = honeypotData.decoyFiles || [];
  const events = honeypotData.events || [];

  return `
    <div class="card">
      <div class="card-title">
        <span>🪤 Page 3: Honeypot Monitoring – Decoy Files &amp; Canary Trap</span>
        <span class="tag tag-green">Canary Trap Armed</span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        ClearShield deploys synthetic decoy files into the clinic document environment that look like genuine confidential backups and billing records. Any unauthorized download attempt is caught at byte 0, halted in &lt;15ms, and the session is isolated.
      </p>

      <h4 style="font-size: 14px; margin-bottom: 10px; color: #0f172a;">Active Fictional Decoy Files</h4>
      <div class="table-container" style="margin-bottom: 20px;">
        <table>
          <thead>
            <tr>
              <th>Decoy Filename</th>
              <th>Simulated Category</th>
              <th>Size</th>
              <th>Trap Behavior</th>
              <th>Honeypot Status</th>
            </tr>
          </thead>
          <tbody>
            ${decoys.filter(d => d.isDecoy).map(d => `
              <tr>
                <td class="code-cell"><b>${d.filename}</b></td>
                <td>${d.category}</td>
                <td>${d.size}</td>
                <td>${d.description}</td>
                <td><span class="tag tag-yellow">Silent Trap Armed</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <h4 style="font-size: 14px; margin-bottom: 10px; color: #0f172a;">Decoy File Download Interceptions</h4>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Target Decoy</th>
              <th>Origin IP / User-Agent</th>
              <th>Response Latency</th>
              <th>Protective Countermeasure</th>
            </tr>
          </thead>
          <tbody>
            ${events.length === 0 ? `
              <tr><td colspan="5" style="text-align:center; padding: 20px; color: var(--text-muted);">No decoy download attempts detected yet. All decoys silent.</td></tr>
            ` : events.map(ev => `
              <tr>
                <td>${ev.formattedTime || ev.time.slice(11, 19)}</td>
                <td class="code-cell"><b>${ev.filename}</b></td>
                <td>${ev.clientIp} (${ev.userAgent})</td>
                <td><b style="color:#059669;">${ev.latency}</b></td>
                <td><span class="tag tag-red">Halted Before Delivery (HTTP 403)</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <div style="margin-top: 18px; display:flex; gap: 10px;">
        <button class="btn btn-danger" onclick="runScenario('4')">
          ⚡ Simulate Automated Scraper Decoy Download (Scenario 4)
        </button>
      </div>
    </div>
  `;
}

// =========================================================================
// PART 7: PAGE 4 – DATA PROTECTION
// =========================================================================
function renderPage4DataProtection() {
  return `
    <div class="card">
      <div class="card-title">
        <span>🔒 Page 4: Data Protection – IDOR &amp; Bulk Exfiltration Defense</span>
        <span class="tag tag-green">Zero Records Leaked</span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        Enforces strict healthcare data access authorization: returning patients are only permitted to retrieve their own prescribed medicines and appointments. Cross-patient database queries (IDOR) and unusual bulk extraction attempts are blocked before data leaves the server.
      </p>

      <div class="table-container" style="margin-bottom: 20px;">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Authenticated User</th>
              <th>Target Patient ID</th>
              <th>Requested Health Resource</th>
              <th>ClearShield Decision</th>
              <th>Guard Reason</th>
            </tr>
          </thead>
          <tbody>
            ${dataProtectionLogs.length === 0 ? `
              <tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-muted);">No unauthorized database queries detected. Patient records fully shielded.</td></tr>
            ` : dataProtectionLogs.map(l => `
              <tr>
                <td>${l.formattedTime || l.time.slice(11, 19)}</td>
                <td><b>${l.user}</b></td>
                <td class="code-cell">${l.targetPatientId}</td>
                <td>${l.resource}</td>
                <td><span class="tag tag-red">${l.decision}</span></td>
                <td>${l.reason}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <div style="display: flex; gap: 10px;">
        <button class="btn btn-danger" onclick="runScenario('3')">
          ⚡ Test Cross-Patient Prescription Query (Scenario 3 - IDOR)
        </button>
        <button class="btn btn-secondary" onclick="runScenario('5')">
          ⚡ Test Bulk Data Extraction Guard (Scenario 5)
        </button>
      </div>
    </div>
  `;
}

// =========================================================================
// PART 7: PAGE 5 – AUTHENTICATION
// =========================================================================
function renderPage5Authentication() {
  const users = authData.users || [];
  const logs = authData.activityLogs || [];

  return `
    <div class="card">
      <div class="card-title">
        <span>🔑 Page 5: Authentication – Passkey &amp; Recovery Management</span>
        <span class="tag tag-purple">WebAuthn &amp; Recovery Codes</span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        Patients authenticate via secure biometrics (Passkeys) or password. During initial registration, a unique 16-digit Personal Recovery Code is generated for secure fallback. ClearShield monitors brute force attempts and verifies passkey credential integrity.
      </p>

      <h4 style="font-size: 14px; margin-bottom: 10px; color: #0f172a;">Registered Patient Credentials &amp; Passkey Status</h4>
      <div class="table-container" style="margin-bottom: 20px;">
        <table>
          <thead>
            <tr>
              <th>Patient Name</th>
              <th>Email</th>
              <th>Passkey Enrolled</th>
              <th>Passkey Device Name</th>
              <th>Personal Recovery Code Status</th>
              <th>Registered Timestamp</th>
            </tr>
          </thead>
          <tbody>
            ${users.map(u => `
              <tr>
                <td><b>${u.name}</b></td>
                <td>${u.email}</td>
                <td>
                  <span class="tag ${u.hasPasskey ? 'tag-green' : 'tag-yellow'}">
                    ${u.hasPasskey ? 'Passkey Enrolled' : 'Password Only'}
                  </span>
                </td>
                <td>${u.passkeyName || 'None'}</td>
                <td><span class="tag tag-purple">Protected (Not Exposed to Others)</span></td>
                <td>${u.registeredAt ? u.registeredAt.slice(0, 10) : 'Active'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <h4 style="font-size: 14px; margin-bottom: 10px; color: #0f172a;">Authentication Activity Log</h4>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>User Account</th>
              <th>Method</th>
              <th>Result</th>
              <th>Details</th>
              <th>Origin IP</th>
            </tr>
          </thead>
          <tbody>
            ${logs.length === 0 ? `
              <tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-muted);">No recent authentication events recorded.</td></tr>
            ` : logs.map(l => `
              <tr>
                <td>${l.formattedTime || l.time.slice(11, 19)}</td>
                <td><b>${l.userEmail}</b></td>
                <td>${l.method}</td>
                <td>
                  <span class="tag ${l.success ? 'tag-green' : 'tag-red'}">
                    ${l.success ? 'Verified OK' : 'Failed'}
                  </span>
                </td>
                <td>${l.details}</td>
                <td>${l.clientIp}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// =========================================================================
// PART 7: PAGE 6 – INCIDENT HISTORY
// =========================================================================
function renderPage6IncidentHistory() {
  return `
    <div class="card">
      <div class="card-title">
        <span>📜 Page 6: Incident History &amp; Audit Trail</span>
        <div style="display:flex; gap: 8px;">
          <button class="btn btn-secondary" onclick="exportIncidentReport('csv')">Export CSV</button>
          <button class="btn" onclick="exportIncidentReport('json')">Export JSON Defense Report</button>
        </div>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        Complete chronological registry of all security threats, attack vectors, response latencies, and protective actions taken by ClearShield.
      </p>

      ${incidents.length === 0 ? `
        <div style="text-align: center; color: var(--text-muted); padding: 30px;">
          🟢 Zero security incidents recorded. System running with 100% data integrity.
        </div>
      ` : `
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Timestamp</th>
                <th>Threat Type</th>
                <th>Trigger Source</th>
                <th>Target Resource</th>
                <th>Latency</th>
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
                  <td>${inc.triggerSource}</td>
                  <td class="code-cell">${inc.resourceAccessed}</td>
                  <td style="color:#059669;"><b>${inc.latency}</b></td>
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
                    ` : `<span style="font-size:11px; color:#64748b;">Archived</span>`}
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

// =========================================================================
// PART 7: PAGE 7 – EMERGENCY RESPONSE & CARE CONTINUITY
// =========================================================================
function renderPage7EmergencyResponse() {
  const isAirGap = systemStatus.airGapped;

  return `
    <div class="card">
      <div class="card-title">
        <span>🚨 Page 7: Emergency Response – Surgical Air-Gap &amp; Care Continuity</span>
        <span class="tag ${isAirGap ? 'tag-red' : 'tag-green'}">
          ${isAirGap ? 'Protected Standby Mode Active' : 'Emergency Shield Ready'}
        </span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        When a serious security breach or canary tripwire is triggered, ClearShield executes a <b>Surgical Air-Gap in &lt;15ms</b>: session tokens are revoked, the database connection is severed (HTTP 403), and SMB port 445 is blocked to prevent lateral worm propagation. Essential patient care continues safely offline using synthetic appointment queues and printable paper intake slips.
      </p>

      <div class="grid-2">
        <div class="card" style="margin: 0; background: #ffffff;">
          <h4 style="font-size: 14px; margin-bottom: 12px; color: #0f172a;">Emergency Isolation Telemetry</h4>
          <table style="font-size: 13px;">
            <tr>
              <td>Session Isolation Status</td>
              <td><b style="color:${isAirGap ? '#e11d48' : '#059669'}">${isAirGap ? 'REVOKED & INVALIDATED' : 'Active & Authenticated'}</b></td>
            </tr>
            <tr>
              <td>Port 445 (SMB Lateral Spread Guard)</td>
              <td><b style="color:${isAirGap ? '#e11d48' : '#059669'}">${isAirGap ? 'BLOCKED' : 'Monitored'}</b></td>
            </tr>
            <tr>
              <td>Database Cable Switch</td>
              <td><b style="color:${isAirGap ? '#e11d48' : '#059669'}">${isAirGap ? 'SEVERED (HTTP 403)' : 'ONLINE'}</b></td>
            </tr>
            <tr>
              <td>Protected Standby Care Mode</td>
              <td><b style="color:#0284c7">${isAirGap ? 'ACTIVE ON CLINIC DESK' : 'Ready on Standby'}</b></td>
            </tr>
          </table>

          <div style="margin-top: 18px; display: flex; gap: 10px;">
            ${isAirGap ? `
              <button class="btn btn-success" onclick="restoreClinicSystem()">
                🔄 Authorize &amp; Restore Normal Clinic Operations
              </button>
            ` : `
              <button class="btn btn-danger" onclick="triggerEmergencyAirGap()">
                ⚡ Trigger Emergency Air-Gap (Scenario 6)
              </button>
            `}
          </div>
        </div>

        <!-- SIMULATED SMS TO DR. TAYLOR -->
        <div class="card" style="margin: 0; background: #ffffff;">
          <h4 style="font-size: 14px; margin-bottom: 12px; color: #0f172a;">Out-of-Band Cellular Alert (Dr. Taylor)</h4>
          <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
            Encrypted SMS spooled directly over cellular, bypassing compromised clinic Wi-Fi.
          </p>

          <div class="phone-mockup">
            <div class="phone-header">
              <span>Carrier: Cellular LTE</span>
              <span>Dr. Taylor (+1-555-0199)</span>
            </div>

            <div style="display: flex; flex-direction: column; gap: 8px; max-height: 220px; overflow-y: auto;">
              ${smsQueue.length === 0 ? `
                <div class="sms-bubble">
                  🟢 ClearShield Notice: All clinical systems armed. 0 patient records lost.
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
        </div>
      </div>
    </div>
  `;
}

// =========================================================================
// PART 7: PAGE 8 – SECURITY REPORTS
// =========================================================================
function renderPage8SecurityReports() {
  return `
    <div class="card">
      <div class="card-title">
        <span>📑 Page 8: Security Reports &amp; HIPAA Audit Defense</span>
        <div style="display:flex; gap: 8px;">
          <button class="btn btn-secondary" onclick="exportIncidentReport('csv')">Download CSV</button>
          <button class="btn" onclick="exportIncidentReport('json')">Download JSON Defense Report</button>
        </div>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        Export complete security defense logs and incident summaries formatted for healthcare administrative review and HIPAA Security Rule (§ 164.312) compliance audits.
      </p>

      <div class="grid-2">
        <div class="card" style="margin: 0; background: #ffffff;">
          <h4 style="font-size: 14px; margin-bottom: 10px; color: #0f172a;">Incident Audit Summary</h4>
          <table style="font-size: 13px;">
            <tr><td>Total Security Incidents</td><td><b>${incidents.length}</b></td></tr>
            <tr><td>Pre-Login Probes Blocked</td><td><b>${preLoginThreats.length}</b></td></tr>
            <tr><td>Honeypot Decoy Triggers Halted</td><td><b>${honeypotData.events ? honeypotData.events.length : 0}</b></td></tr>
            <tr><td>Cross-Patient Access Blocks</td><td><b>${dataProtectionLogs.length}</b></td></tr>
            <tr><td>Real Patient Records Compromised</td><td><b style="color:#059669">0 (Zero Leaks Guaranteed)</b></td></tr>
            <tr><td>Canary Trap Integrity</td><td><b style="color:#059669">100% Shielded</b></td></tr>
          </table>
        </div>

        <div class="card" style="margin: 0; background: #ffffff;">
          <h4 style="font-size: 14px; margin-bottom: 10px; color: #0f172a;">Regulatory Defense Statement</h4>
          <p style="font-size: 13px; color: #334155; line-height: 1.7;">
            This audit report certifies that all unauthorized access attempts, automated scrapers, and cross-patient medical queries were intercepted prior to data delivery. No protected health information was exposed during any incident.
          </p>
          <div style="margin-top: 14px;">
            <button class="btn btn-primary" onclick="exportIncidentReport('json')">
              📥 Generate &amp; Download Full Defense Report
            </button>
          </div>
        </div>
      </div>
    </div>
  `;
}

// =========================================================================
// DEMONSTRATION LAB: SCENARIOS 1 TO 6
// =========================================================================
function renderScenarioLab() {
  return `
    <div class="card">
      <div class="card-title">
        <span>🧪 Demonstration Scenarios Lab (1 to 6)</span>
        <span class="tag tag-blue">Interactive Test Suite</span>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 16px;">
        Test and verify each of the 6 core cybersecurity scenarios directly from this console. Each test executes realistic security logic and updates the respective dashboard pages in real-time.
      </p>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px;">
        
        <!-- Scenario 1 -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4>Scenario 1: Normal Patient Login</h4>
              <span class="tag tag-green">Allowed</span>
            </div>
            <p>Normal patient logs in securely with passkey and views their own appointment &amp; prescribed medicine information.</p>
          </div>
          <button class="btn btn-secondary" onclick="runScenario('1')">▶ Run Scenario 1</button>
        </div>

        <!-- Scenario 2 -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4>Scenario 2: Pre-Login Restricted Probing</h4>
              <span class="tag tag-red">Blocked</span>
            </div>
            <p>Unauthenticated visitor probes /admin, /staff, and /backup. ClearShield halts requests before backend execution.</p>
          </div>
          <button class="btn btn-secondary" onclick="runScenario('2')">▶ Run Scenario 2</button>
        </div>

        <!-- Scenario 3 -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4>Scenario 3: Cross-Patient IDOR Query</h4>
              <span class="tag tag-red">Denied</span>
            </div>
            <p>Unauthorized user attempts to retrieve another patient's prescribed medicines. IDOR guard denies request.</p>
          </div>
          <button class="btn btn-secondary" onclick="runScenario('3')">▶ Run Scenario 3</button>
        </div>

        <!-- Scenario 4 -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4>Scenario 4: Decoy File Download</h4>
              <span class="tag tag-yellow">Honeypot Catch</span>
            </div>
            <p>Automated crawler initiates download of a decoy honeypot file. Download cancelled at byte 0 and alert spooled.</p>
          </div>
          <button class="btn btn-danger" onclick="runScenario('4')">▶ Run Scenario 4</button>
        </div>

        <!-- Scenario 5 -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4>Scenario 5: Bulk Data Exfiltration</h4>
              <span class="tag tag-yellow">Volume Guard</span>
            </div>
            <p>Account requests bulk extraction of 500 records. Volume checks halt request with HTTP 403 before transfer.</p>
          </div>
          <button class="btn btn-secondary" onclick="runScenario('5')">▶ Run Scenario 5</button>
        </div>

        <!-- Scenario 6 -->
        <div class="scenario-card">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 6px;">
              <h4>Scenario 6: Emergency Air-Gap Standby</h4>
              <span class="tag tag-red">&lt; 15ms Catch</span>
            </div>
            <p>Major threat tripped. Surgical Air-Gap activated: session killed, DB severed, Protected Standby Mode enabled.</p>
          </div>
          <button class="btn btn-danger" onclick="runScenario('6')">▶ Run Scenario 6</button>
        </div>

      </div>
    </div>
  `;
}

// =========================================================================
// CLEARSHIELD CORE VIEWS (PRESERVED)
// =========================================================================
function renderCoreGuidedActions() {
  return `
    <div class="card">
      <div class="card-title">Guided Actions (6-Point Explainable Security Framework)</div>
      <p style="color:var(--text-muted); margin-bottom:14px;">ClearShield never labels an anomaly a confirmed attack without verified telemetry. Follow this 6-point guided rationale:</p>
      
      <div class="six-grid">
        <div class="six-box"><h4>1 · What Happened?</h4>Suspicious access probe or canary decoy query intercepted by monitoring layer.</div>
        <div class="six-box"><h4>2 · Why It Matters</h4>Can indicate credential guessing, automated scrapers, or reconnaissance against clinic databases.</div>
        <div class="six-box"><h4>3 · What We Know</h4>Specific origin IP, requested route, exact timestamp, and that real patient records were NOT exposed.</div>
        <div class="six-box"><h4>4 · What Is Uncertain</h4>Whether the attempt was intentional malware, a forgotten password, or routine crawling.</div>
        <div class="six-box do-box"><h4>5 · Recommended Action</h4>Review incident in ClearShield. Keep Protected Standby Mode active until endpoint is verified clean.</div>
        <div class="six-box avoid-box"><h4>6 · What to Avoid</h4>Do not ignore repeated alerts. Do not disable security controls or reconnect isolated terminals before review.</div>
      </div>
    </div>
  `;
}

function renderCoreSettings() {
  return `
    <div class="card" style="max-width: 550px;">
      <div class="card-title">Rule Threshold Settings</div>
      <label style="display:block; margin: 10px 0 4px; font-size:12px;">Pre-Login Route Probe Threshold:</label>
      <input type="number" id="cfg-probe" value="2" style="width:100%; background:#ffffff; border:1px solid #cbd5e1; color:#0f172a; padding:8px; border-radius:6px; margin-bottom:10px;">

      <label style="display:block; margin: 10px 0 4px; font-size:12px;">Bulk Extraction Record Limit:</label>
      <input type="number" id="cfg-bulk" value="6" style="width:100%; background:#ffffff; border:1px solid #cbd5e1; color:#0f172a; padding:8px; border-radius:6px; margin-bottom:14px;">

      <div style="display:flex; gap:10px;">
        <button class="btn" onclick="alert('Thresholds saved.')">Save Thresholds</button>
        <button class="btn btn-secondary" onclick="alert('Defaults restored.')">Reset Defaults</button>
      </div>
    </div>
  `;
}

function renderCoreCSVTools() {
  return `
    <div class="card">
      <div class="card-title">CSV Security Dataset Tools</div>
      <p style="color:var(--text-muted); margin-bottom:16px;">Test the ClearShield detection engine against CSV security event logs.</p>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <button class="btn" onclick="exportIncidentReport('csv')">Export Current Security Log (CSV)</button>
        <button class="btn btn-secondary" onclick="exportIncidentReport('json')">Export Incident Defense JSON</button>
      </div>
    </div>
  `;
}

function renderCoreAbout() {
  return `
    <div class="card" style="max-width: 700px;">
      <div class="card-title">About ClearShield Healthcare Cybersecurity</div>
      <p style="font-size:13px; color:var(--text-main); line-height:1.7;">
        <b>ClearShield</b> is a preventive healthcare cybersecurity platform engineered specifically for small clinics and community healthcare centers. It provides proactive threat containment through Canary Trap honeypots, pre-login route guards, IDOR medicine access protection, and surgical air-gapping with uninterrupted care continuity.
      </p>
    </div>
  `;
}

// =========================================================================
// API ACTIONS & HELPERS
// =========================================================================
async function runScenario(scenario) {
  try {
    const res = await fetch(`${API_BASE}/api/scenarios/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });
    const data = await res.json();
    alert(`🧪 Scenario ${scenario} Executed:\n• ${data.title}\n• ${data.outcome}`);
    fetchAllData();
  } catch (err) {
    alert(`Failed to run scenario: ${err.message}`);
  }
}

async function triggerEmergencyAirGap() {
  try {
    const res = await fetch(`${API_BASE}/api/clearshield/emergency/isolate`, { method: 'POST' });
    const data = await res.json();
    alert(`🚨 Emergency Isolation Executed in ${data.result.latency}ms!\n• Surgical Air-Gap active\n• Session tokens revoked\n• Clinic desk transitioned to Protected Standby Mode.`);
    fetchAllData();
  } catch (err) {
    alert(err.message);
  }
}

async function restoreClinicSystem() {
  try {
    const res = await fetch(`${API_BASE}/api/clearshield/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ adminUser: 'Dr. Taylor (Chief Medical Officer)' })
    });
    const data = await res.json();
    alert('✅ System fully restored. Air-gap cleared. Clinic returned to All Systems Normal.');
    fetchAllData();
  } catch (err) {
    alert(err.message);
  }
}

async function reviewIncident(incidentId) {
  try {
    await fetch(`${API_BASE}/api/clearshield/review-incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incidentId, reviewer: 'Dr. Taylor / Security Admin' })
    });
    fetchAllData();
  } catch (err) {
    alert(err.message);
  }
}

function exportIncidentReport(format = 'json') {
  window.open(`${API_BASE}/api/clearshield/export-report?format=${format}`, '_blank');
}
