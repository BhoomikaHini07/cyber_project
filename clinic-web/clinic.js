/**
 * Sample Clinic Portal Controller
 * Manages patient check-in, Row 0 Canary Tripwire, Scenario handlers,
 * and seamless transition into Phase 4 / Phase 6 Protected Standby Mode.
 */

// If on port 5001 or 5000, ensure API points to shared backend
const API_BASE = window.location.origin;

let patientRecords = [];
let standbyQueue = [];
let isStandbyMode = false;
let selectedPatientForPrint = null;

document.addEventListener('DOMContentLoaded', () => {
  initClinicEventStream();
  loadPatientRecords();
  loadStandbyQueue();
});

// -------------------------------------------------------------------------
// REAL-TIME SYNCHRONIZATION WITH CLEARSHIELD VIA SSE
// -------------------------------------------------------------------------
function initClinicEventStream() {
  const evtSource = new EventSource(`${API_BASE}/api/events`);

  evtSource.onmessage = (e) => {
    try {
      const payload = JSON.parse(e.data);
      if (payload.type === 'INIT') {
        applySystemStatus(payload.data);
      } else if (payload.type === 'THREAT_DETECTED') {
        enterStandbyMode(payload.data.incident);
      } else if (payload.type === 'SYSTEM_RESTORED') {
        exitStandbyMode();
      }
    } catch (err) {
      console.error('SSE Error:', err);
    }
  };
}

function applySystemStatus(status) {
  if (status.airGapped) {
    enterStandbyMode();
  } else {
    exitStandbyMode();
  }
}

function enterStandbyMode(incident) {
  isStandbyMode = true;
  document.getElementById('standby-banner').classList.add('visible');
  
  const pill = document.getElementById('clinic-session-pill');
  pill.className = 'session-indicator standby';
  document.getElementById('clinic-session-text').textContent = 'Protected Standby Mode Active';

  // Highlight care continuity card
  const careCard = document.getElementById('care-continuity-card');
  careCard.style.borderColor = '#059669';
  careCard.scrollIntoView({ behavior: 'smooth' });

  // Update records table to indicate air-gap restriction
  renderPatientTable();
}

function exitStandbyMode() {
  isStandbyMode = false;
  document.getElementById('standby-banner').classList.remove('visible');

  const pill = document.getElementById('clinic-session-pill');
  pill.className = 'session-indicator';
  document.getElementById('clinic-session-text').textContent = 'Protected Session Active';

  const careCard = document.getElementById('care-continuity-card');
  careCard.style.borderColor = 'var(--border)';

  loadPatientRecords();
}

// -------------------------------------------------------------------------
// DATA FETCHING & RENDERING
// -------------------------------------------------------------------------
async function loadPatientRecords() {
  try {
    const res = await fetch(`${API_BASE}/api/clinic/records`);
    if (res.status === 403) {
      enterStandbyMode();
      return;
    }
    const data = await res.json();
    patientRecords = data.records || [];
    document.getElementById('records-count-badge').textContent = `${patientRecords.length} Records Loaded`;
    renderPatientTable();
  } catch (err) {
    console.error('Error loading patient records:', err);
  }
}

async function loadStandbyQueue() {
  try {
    const res = await fetch(`${API_BASE}/api/clinic/standby-queue`);
    const data = await res.json();
    standbyQueue = data.appointments || [];
    renderStandbyQueue();
  } catch (err) {
    console.error('Error loading standby queue:', err);
  }
}

function renderPatientTable(filterQuery = '') {
  const tbody = document.getElementById('patient-table-body');
  tbody.innerHTML = '';

  const q = filterQuery.toLowerCase().trim();
  const filtered = patientRecords.filter(p =>
    p.fullName.toLowerCase().includes(q) ||
    p.recordNumber.toLowerCase().includes(q) ||
    p.condition.toLowerCase().includes(q) ||
    p.room.toLowerCase().includes(q)
  );

  filtered.forEach((p, idx) => {
    const tr = document.createElement('tr');
    if (p.isCanary) {
      tr.className = 'canary-row';
    }

    if (isStandbyMode && !p.isCanary) {
      // In air-gap standby mode, protected real patient records are restricted
      tr.innerHTML = `
        <td class="code-cell"><b>${p.recordNumber}</b></td>
        <td><span style="filter: blur(4px); user-select: none;">Protected Patient Record</span></td>
        <td><span style="filter: blur(4px); user-select: none;">1980-00-00</span></td>
        <td><span class="badge badge-yellow">Restricted during Standby</span></td>
        <td>${p.room}</td>
        <td>${p.doctor}</td>
        <td>
          <button class="btn btn-outline" style="font-size: 11px; padding: 4px 8px;" onclick="alert('Access restricted during Protected Standby Mode. Please use paper check-in continuity queue below.')">
            Offline Only
          </button>
        </td>
      `;
    } else {
      tr.innerHTML = `
        <td class="code-cell"><b>${p.recordNumber}</b></td>
        <td>
          <b>${p.fullName}</b>
          ${p.isCanary ? '<span class="badge badge-yellow" style="margin-left: 6px;">Row 0 Honeypot</span>' : ''}
        </td>
        <td>${p.dob}</td>
        <td>
          <span class="badge ${p.isCanary ? 'badge-yellow' : 'badge-green'}">
            ${p.condition}
          </span>
        </td>
        <td>${p.room}</td>
        <td>${p.doctor}</td>
        <td>
          ${p.isCanary ? `
            <button class="btn btn-outline" style="font-size: 11px; padding: 4px 8px; border-color: #d97706; color: #b45309;" onclick="handleCanaryClick()">
              Canary Trap Decoy
            </button>
          ` : `
            <button class="btn btn-outline" style="font-size: 11px; padding: 4px 8px;" onclick="viewPatientChart('${p.id}')">
              Open Chart
            </button>
          `}
        </td>
      `;
    }

    tbody.appendChild(tr);
  });
}

function renderStandbyQueue() {
  const tbody = document.getElementById('standby-queue-body');
  tbody.innerHTML = '';

  standbyQueue.forEach((apt) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><b>${apt.time}</b></td>
      <td><b>${apt.patientName}</b></td>
      <td>${apt.dob}</td>
      <td>${apt.doctor}</td>
      <td>${apt.service}</td>
      <td><span class="badge badge-green">${apt.status}</span></td>
      <td>
        <button class="btn btn-outline" style="font-size: 11px; padding: 4px 8px;" onclick="selectPatientForSlip('${apt.patientName}', '${apt.dob}', '${apt.time}', '${apt.doctor}', '${apt.service}')">
          🖨️ Spool Paper Slip
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function filterPatientTable() {
  const query = document.getElementById('patient-search').value;
  renderPatientTable(query);
}

// -------------------------------------------------------------------------
// SCENARIO HANDLERS
// -------------------------------------------------------------------------

// SCENARIO A: Receptionist Accidental Click on Row 0 Canary
function handleCanaryClick() {
  document.getElementById('accidental-click-modal').classList.add('active');
}

function closeAccidentalClickModal() {
  document.getElementById('accidental-click-modal').classList.remove('active');
}

async function confirmSafeCancel() {
  closeAccidentalClickModal();
  try {
    const res = await fetch(`${API_BASE}/api/clinic/safe-cancel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: 'Receptionist Jane', device: 'RECEPTION-PC' })
    });
    const data = await res.json();
    alert(`🟢 Safe Cancel Verified:\n${data.message}\nAmbient status remains Green: "ClearShield Active – All Systems Normal".`);
  } catch (err) {
    console.error(err);
  }
}

// Force breach canary tripwire (Scenario C direct)
async function confirmTripwireBreach() {
  closeAccidentalClickModal();
  await triggerScraperCrawl();
}

// SCENARIO B: Visitor PIN Guessing / Brute Force
function openPinModal() {
  document.getElementById('pin-error').style.display = 'none';
  document.getElementById('pin-input').value = '';
  document.getElementById('pin-modal').classList.add('active');
}

function closePinModal() {
  document.getElementById('pin-modal').classList.remove('active');
}

async function submitPin() {
  const pin = document.getElementById('pin-input').value;
  try {
    const res = await fetch(`${API_BASE}/api/clinic/auth/verify-pin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin, device: 'RECEPTION-KIOSK' })
    });

    const data = await res.json();
    if (res.ok) {
      alert('Supervisor PIN verified.');
      closePinModal();
    } else {
      const errBox = document.getElementById('pin-error');
      errBox.style.display = 'block';
      errBox.textContent = `${data.error} (Attempts remaining: ${data.attemptsRemaining ?? 0})`;
      if (res.status === 403) {
        alert(`🚫 ClearShield Blocked:\n${data.error}\nLogged as suspicious brute-force activity on ClearShield dashboard.`);
        closePinModal();
      }
    }
  } catch (err) {
    console.error(err);
  }
}

async function simulateBadPin() {
  // Enter 3 rapid bad pins to trigger ClearShield brute-force block
  for (let i = 1; i <= 3; i++) {
    const res = await fetch(`${API_BASE}/api/clinic/auth/verify-pin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin: '000' + i, device: 'VISITOR-KIOSK' })
    });
    if (res.status === 403) {
      const data = await res.json();
      alert(`🚫 Scenario B Triggered!\nSuspicious visitor repeated PIN guessing detected.\nClearShield returned HTTP 403 Forbidden.`);
      closePinModal();
      break;
    }
  }
}

// SCENARIO C: Automated Scraper Bot trips Canary Trap (<15ms)
async function triggerScraperCrawl() {
  try {
    const start = performance.now();
    const res = await fetch(`${API_BASE}/api/clinic/records/canary-0`, {
      headers: {
        'User-Agent': 'Automated Scraper Bot / Bulk-Harvest-v2',
        'X-Device-Id': 'UNAUTHORIZED-SCRAPER-HOST'
      }
    });

    const elapsed = (performance.now() - start).toFixed(2);
    const data = await res.json();

    if (res.status === 403) {
      alert(`⚡ SCENARIO C TRIGGERED (< 15ms Catch):\n` +
        `• Attacker attempted to access Row 0 Canary Decoy.\n` +
        `• ClearShield caught the request in ${data.latency || elapsed + 'ms'}.\n` +
        `• Surgical Air-Gap activated: Session revoked, Database severed (HTTP 403), Port 445 SMB blocked.\n` +
        `• Simulated encrypted SMS sent over cellular to Dr. Taylor.\n` +
        `• Clinic entered Protected Standby Mode with zero patient records lost.`);
      enterStandbyMode();
    }
  } catch (err) {
    console.error(err);
  }
}

// SCENARIO D: Bulk Data Exfiltration Attempt
async function triggerBulkExport() {
  try {
    const res = await fetch(`${API_BASE}/api/clinic/export?limit=500`, {
      headers: { 'X-Device-Id': 'EXFIL-TEST-CLIENT' }
    });
    const data = await res.json();
    if (res.status === 403) {
      alert(`🚫 SCENARIO D TRIGGERED:\n` +
        `• Bulk extraction of 500 records was requested.\n` +
        `• ClearShield verified volume and blocked the request BEFORE data transfer.\n` +
        `• Returned HTTP 403 Forbidden.\n` +
        `• Incident and alert recorded in ClearShield dashboard.`);
    } else {
      alert(`Export received: ${data.count} records`);
    }
  } catch (err) {
    console.error(err);
  }
}

// -------------------------------------------------------------------------
// PATIENT CHART & PAPER CHECK-IN FORM SPOOLING
// -------------------------------------------------------------------------
function viewPatientChart(id) {
  const p = patientRecords.find(x => x.id === id);
  if (!p) return;

  document.getElementById('chart-patient-name').textContent = p.fullName;
  document.getElementById('chart-patient-details').innerHTML = `
    <b>Medical Record Number:</b> ${p.recordNumber}<br>
    <b>Date of Birth:</b> ${p.dob}<br>
    <b>Contact Phone:</b> ${p.phone}<br>
    <b>Chief Complaint:</b> ${p.condition}<br>
    <b>Assigned Room:</b> ${p.room}<br>
    <b>Attending Physician:</b> ${p.doctor}<br>
    <b>Status:</b> <span class="badge badge-green">${p.status}</span>
  `;

  selectedPatientForPrint = p;
  document.getElementById('patient-modal').classList.add('active');
}

function closePatientModal() {
  document.getElementById('patient-modal').classList.remove('active');
}

function selectPatientForSlip(name, dob, time, doctor, reason) {
  document.getElementById('print-patient-name').textContent = name;
  document.getElementById('print-patient-dob').textContent = dob;
  document.getElementById('print-arrival-time').textContent = `Today, ${time}`;
  document.getElementById('print-doctor').textContent = doctor;
  document.getElementById('print-reason').textContent = reason;

  document.getElementById('printable-checkin-area').scrollIntoView({ behavior: 'smooth' });
}

function spoolPatientPaperSlip() {
  if (selectedPatientForPrint) {
    selectPatientForSlip(
      selectedPatientForPrint.fullName,
      selectedPatientForPrint.dob,
      '09:30 AM',
      selectedPatientForPrint.doctor,
      selectedPatientForPrint.condition
    );
  }
  closePatientModal();
  printCheckInSlip();
}

function printCheckInSlip() {
  window.print();
}
