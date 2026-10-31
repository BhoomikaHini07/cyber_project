/**
 * Sample Clinic Portal Controller
 * Implements Passkey Auth, Personal Recovery Codes, IDOR Cross-Patient Protection,
 * Honeypot Decoy Files, Pre-Login Route Probe Simulation, and Care Continuity.
 */

const API_BASE = window.location.origin;

let patientRecords = [];
let standbyQueue = [];
let clinicFiles = [];
let isStandbyMode = false;

// Authenticated Patient State
let currentUser = null;
let currentSessionToken = null;

document.addEventListener('DOMContentLoaded', () => {
  initClinicEventStream();
  loadPatientRecords();
  loadStandbyQueue();
  loadClinicFiles();

  // Auto-login demo user Arthur Pendelton for convenience
  autoLoginDemoPatient();
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

  const careCard = document.getElementById('care-continuity-card');
  careCard.style.borderColor = '#059669';

  renderPatientTable();
}

function exitStandbyMode() {
  isStandbyMode = false;
  document.getElementById('standby-banner').classList.remove('visible');

  const pill = document.getElementById('clinic-session-pill');
  pill.className = 'session-indicator';
  document.getElementById('clinic-session-text').textContent = 'Protected Session Active';

  const careCard = document.getElementById('care-continuity-card');
  careCard.style.borderColor = 'var(--card-border)';

  loadPatientRecords();
}

// -------------------------------------------------------------------------
// PART 1: PATIENT REGISTRATION, PASSKEYS & RECOVERY CODES
// -------------------------------------------------------------------------
function openLoginModal() {
  document.getElementById('login-modal').classList.add('active');
  switchAuthTab('login');
}

function closeLoginModal() {
  document.getElementById('login-modal').classList.remove('active');
}

function switchAuthTab(tab) {
  const loginArea = document.getElementById('login-form-area');
  const regArea = document.getElementById('register-form-area');
  const recovArea = document.getElementById('recovery-code-display');
  const tabLoginBtn = document.getElementById('tab-login-btn');
  const tabRegBtn = document.getElementById('tab-register-btn');

  recovArea.style.display = 'none';

  if (tab === 'login') {
    loginArea.style.display = 'block';
    regArea.style.display = 'none';
    tabLoginBtn.className = 'btn btn-primary';
    tabRegBtn.className = 'btn btn-outline';
    document.getElementById('auth-modal-title').textContent = 'Patient Sign In';
  } else {
    loginArea.style.display = 'none';
    regArea.style.display = 'block';
    tabLoginBtn.className = 'btn btn-outline';
    tabRegBtn.className = 'btn btn-primary';
    document.getElementById('auth-modal-title').textContent = 'New Patient Registration';
  }
}

async function submitPasswordLogin() {
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;

  try {
    const res = await fetch(`${API_BASE}/api/clinic/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, loginType: 'password' })
    });

    const data = await res.json();
    if (res.ok) {
      setAuthenticatedUser(data.user, data.sessionToken);
      closeLoginModal();
      alert(`✅ Welcome back, ${data.user.name}!\nIdentity verified via Password.`);
    } else {
      alert(`Login Failed: ${data.error}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

async function submitPasskeyLogin() {
  const email = document.getElementById('login-email').value;

  try {
    // In production, navigator.credentials.get() would be called here.
    // For reliable demo in all browser environments, we invoke passkey auth on backend:
    const res = await fetch(`${API_BASE}/api/clinic/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, loginType: 'passkey' })
    });

    const data = await res.json();
    if (res.ok) {
      setAuthenticatedUser(data.user, data.sessionToken);
      closeLoginModal();
      alert(`🔐 Biometric Passkey Verified!\nWelcome, ${data.user.name}.\nSigned in seamlessly with FIDO2 / TouchID.`);
    } else {
      alert(`Passkey verification failed: ${data.error}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

async function showRecoveryLoginPrompt() {
  const email = prompt('Enter your registered email address:', 'arthur.pendelton@example.com');
  if (!email) return;

  const code = prompt('Enter your 16-digit Personal Recovery Code (e.g. CS-RECOV-8419-7291-3048):');
  if (!code) return;

  try {
    const res = await fetch(`${API_BASE}/api/clinic/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, recoveryCode: code, loginType: 'recovery' })
    });

    const data = await res.json();
    if (res.ok) {
      setAuthenticatedUser(data.user, data.sessionToken);
      closeLoginModal();
      alert(`🔐 Recovery Login Verified!\nWelcome back, ${data.user.name}.\nPersonal Recovery Code accepted.`);
    } else {
      alert(`Recovery Login Failed: ${data.error}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

async function submitRegistration() {
  const name = document.getElementById('reg-name').value;
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;
  const registerPasskey = document.getElementById('reg-passkey-check').checked;

  if (!name || !email || !password) {
    alert('Please fill in legal name, email, and password.');
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/clinic/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password, registerPasskey, passkeyName: `${name}'s Biometric Passkey` })
    });

    const data = await res.json();
    if (res.ok) {
      currentUser = data.user;
      currentSessionToken = data.sessionToken;

      // Show recovery code display
      document.getElementById('register-form-area').style.display = 'none';
      document.getElementById('displayed-recovery-code').textContent = data.recoveryCode;
      document.getElementById('recovery-code-display').style.display = 'block';
    } else {
      alert(`Registration failed: ${data.error}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

function acknowledgeRecoveryCode() {
  closeLoginModal();
  setAuthenticatedUser(currentUser, currentSessionToken);
  alert(`Account ready. Your passkey and recovery process are configured for future visits.`);
}

function setAuthenticatedUser(user, token) {
  currentUser = user;
  currentSessionToken = token;

  document.getElementById('btn-patient-login').style.display = 'none';
  const badge = document.getElementById('logged-user-badge');
  badge.style.display = 'inline-flex';
  document.getElementById('logged-user-name').textContent = `👤 ${user.name} (${user.hasPasskey ? 'Passkey Enrolled' : 'Password'})`;

  // Display personal portal card
  document.getElementById('patient-portal-card').style.display = 'block';
  document.getElementById('portal-patient-name').textContent = user.name;

  loadPatientPrescriptions();
  loadPatientAppointments();
}

function logoutPatient() {
  currentUser = null;
  currentSessionToken = null;

  document.getElementById('btn-patient-login').style.display = 'inline-flex';
  document.getElementById('logged-user-badge').style.display = 'none';
  document.getElementById('patient-portal-card').style.display = 'none';
}

async function autoLoginDemoPatient() {
  // Demo auto-login as Arthur Pendelton for immediate Scenario 1 evaluation
  try {
    const res = await fetch(`${API_BASE}/api/clinic/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'arthur.pendelton@example.com', password: 'Password123!', loginType: 'password' })
    });
    const data = await res.json();
    if (res.ok) {
      setAuthenticatedUser(data.user, data.sessionToken);
    }
  } catch (e) {}
}

// -------------------------------------------------------------------------
// PART 1: MEDICINE INFORMATION & CROSS-PATIENT IDOR GUARD (SCENARIOS 1 & 3)
// -------------------------------------------------------------------------
async function loadPatientPrescriptions() {
  if (!currentSessionToken) return;

  try {
    const res = await fetch(`${API_BASE}/api/clinic/patient/prescriptions`, {
      headers: { 'Authorization': `Bearer ${currentSessionToken}` }
    });

    const data = await res.json();
    const tbody = document.getElementById('patient-prescriptions-body');
    tbody.innerHTML = '';

    if (data.prescriptions && data.prescriptions.length > 0) {
      data.prescriptions.forEach(rx => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><b>${rx.medication}</b></td>
          <td><span class="badge badge-green">${rx.dosage}</span></td>
          <td>${rx.prescribedDate}</td>
          <td>${rx.doctor}</td>
          <td><b>${rx.refills} refills</b></td>
          <td style="color:var(--text-muted); font-size:12px;">${rx.notes}</td>
        `;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:16px;">No prescribed medicines on file for this patient.</td></tr>`;
    }
  } catch (err) {
    console.error('Error loading prescriptions:', err);
  }
}

async function loadPatientAppointments() {
  if (!currentSessionToken) return;

  try {
    const res = await fetch(`${API_BASE}/api/clinic/patient/appointments`, {
      headers: { 'Authorization': `Bearer ${currentSessionToken}` }
    });

    const data = await res.json();
    const tbody = document.getElementById('patient-appointments-body');
    tbody.innerHTML = '';

    if (data.appointments && data.appointments.length > 0) {
      data.appointments.forEach(apt => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><b>${apt.time}</b></td>
          <td>${apt.doctor}</td>
          <td>${apt.service}</td>
          <td><span class="badge badge-green">${apt.status}</span></td>
        `;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px;">No upcoming visits scheduled.</td></tr>`;
    }
  } catch (err) {
    console.error('Error loading appointments:', err);
  }
}

// SCENARIO 3: Attempt Cross-Patient IDOR Query
async function attemptCrossPatientIDOR() {
  if (!currentSessionToken) {
    alert('Please sign in first.');
    return;
  }

  // Arthur (pat-1) deliberately queries Elena Rostova's medicines (pat-2)
  try {
    const res = await fetch(`${API_BASE}/api/clinic/patient/pat-2/prescriptions`, {
      headers: { 'Authorization': `Bearer ${currentSessionToken}` }
    });

    const data = await res.json();

    if (res.status === 403) {
      alert(`🛡️ SCENARIO 3 TRIGGERED (Cross-Patient Access Denied):\n\n` +
        `• Target: Patient pat-2 (Elena Rostova)\n` +
        `• Result: ${data.error}\n` +
        `• Code: ${data.code}\n` +
        `• Reason: You are authorized ONLY for your own medical records.\n\n` +
        `This unauthorized database access attempt has been logged on the ClearShield dashboard under Data Protection.`);
    } else {
      alert(`Access response: ${JSON.stringify(data)}`);
    }
  } catch (err) {
    alert(err.message);
  }
}

// -------------------------------------------------------------------------
// PART 2: PRE-LOGIN RESTRICTED PROBING SIMULATOR (SCENARIO 2)
// -------------------------------------------------------------------------
async function probeRestrictedPath(path) {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { 'User-Agent': 'Headless Chrome Probe' }
    });

    const data = await res.json();
    if (res.status === 403) {
      alert(`🛡️ SCENARIO 2 TRIGGERED (Pre-Login Probe Blocked):\n\n` +
        `• Probed Route: ${path}\n` +
        `• Result: ${data.error}\n` +
        `• Attempts Recorded: ${data.attempts}\n\n` +
        `ClearShield intercepted the suspicious request before it reached clinic services. Check ClearShield Page 2 (Threat Monitoring).`);
    }
  } catch (err) {
    alert(err.message);
  }
}

// -------------------------------------------------------------------------
// PART 3: CLINIC FILE REPOSITORY & HONEYPOT DECOYS (SCENARIO 4)
// -------------------------------------------------------------------------
async function loadClinicFiles() {
  try {
    const res = await fetch(`${API_BASE}/api/clinic/files`);
    const data = await res.json();
    clinicFiles = data.files || [];
    renderClinicFiles();
  } catch (err) {
    console.error('Error loading files:', err);
  }
}

function renderClinicFiles() {
  const tbody = document.getElementById('clinic-files-body');
  tbody.innerHTML = '';

  clinicFiles.forEach(f => {
    const tr = document.createElement('tr');
    if (f.isDecoy) {
      tr.style.background = '#fefce8';
    }

    tr.innerHTML = `
      <td class="code-cell">
        <b>${f.filename}</b>
        ${f.isDecoy ? '<span class="tag tag-yellow" style="margin-left:6px;">Honeypot Decoy</span>' : ''}
      </td>
      <td>${f.category}</td>
      <td>${f.size}</td>
      <td style="font-size:12px; color:var(--text-muted);">${f.description}</td>
      <td>
        ${f.isDecoy ? `
          <button class="btn btn-danger" style="font-size:11px; padding:4px 10px;" onclick="downloadDecoyFile('${f.id}')">
            ⚡ Attempt Download (Honeypot Trap)
          </button>
        ` : `
          <button class="btn btn-outline" style="font-size:11px; padding:4px 10px;" onclick="downloadPublicFile('${f.id}')">
            📥 Download Public PDF
          </button>
        `}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function downloadPublicFile(fileId) {
  window.open(`${API_BASE}/api/clinic/files/download/${fileId}`, '_blank');
}

// SCENARIO 4: Decoy File Download Interception
async function downloadDecoyFile(fileId) {
  try {
    const start = performance.now();
    const res = await fetch(`${API_BASE}/api/clinic/files/download/${fileId}`, {
      headers: { 'User-Agent': 'Automated Scraper Bot / 1.0' }
    });

    const elapsed = (performance.now() - start).toFixed(2);
    const data = await res.json();

    if (res.status === 403) {
      alert(`🪤 SCENARIO 4 TRIGGERED (Honeypot Decoy Download Blocked):\n\n` +
        `• Target Decoy: ${data.filename}\n` +
        `• Interception Latency: ${data.latency || elapsed + 'ms'} (< 15ms target)\n` +
        `• Countermeasure: Download halted at byte 0 before transmission.\n` +
        `• Alert created in ClearShield Page 3 (Honeypot Monitoring).`);
    }
  } catch (err) {
    alert(err.message);
  }
}

// -------------------------------------------------------------------------
// CLINIC RECEPTION REGISTRY & SCENARIO A, B, C, 5
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
    renderPatientTable();
  } catch (err) {
    console.error('Error loading patient records:', err);
  }
}

function renderPatientTable() {
  const tbody = document.getElementById('patient-table-body');
  tbody.innerHTML = '';

  patientRecords.forEach((p) => {
    const tr = document.createElement('tr');
    if (p.isCanary) tr.className = 'canary-row';

    if (isStandbyMode && !p.isCanary) {
      tr.innerHTML = `
        <td class="code-cell"><b>${p.recordNumber}</b></td>
        <td><span style="filter: blur(4px); user-select: none;">Protected Patient Record</span></td>
        <td><span style="filter: blur(4px); user-select: none;">1980-00-00</span></td>
        <td><span class="badge badge-yellow">Restricted during Standby</span></td>
        <td>${p.room}</td>
        <td>${p.doctor}</td>
        <td><span class="tag tag-yellow">Standby Offline</span></td>
      `;
    } else {
      tr.innerHTML = `
        <td class="code-cell"><b>${p.recordNumber}</b></td>
        <td>
          <b>${p.fullName}</b>
          ${p.isCanary ? '<span class="badge badge-yellow" style="margin-left: 6px;">Row 0 Honeypot</span>' : ''}
        </td>
        <td>${p.dob}</td>
        <td><span class="badge ${p.isCanary ? 'badge-yellow' : 'badge-green'}">${p.condition}</span></td>
        <td>${p.room}</td>
        <td>${p.doctor}</td>
        <td>
          ${p.isCanary ? `
            <button class="btn btn-outline" style="font-size: 11px; padding: 4px 8px; border-color: #d97706; color: #b45309;" onclick="handleCanaryClick()">
              Canary Trap Decoy
            </button>
          ` : `
            <button class="btn btn-outline" style="font-size: 11px; padding: 4px 8px;" onclick="alert('Patient admission record: ' + '${p.fullName}' + ' (${p.condition})')">
              View Chart
            </button>
          `}
        </td>
      `;
    }
    tbody.appendChild(tr);
  });
}

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
    alert(`🟢 Safe Cancel Verified:\n${data.message}\nAmbient status remains Green without alarm.`);
  } catch (err) {
    console.error(err);
  }
}

async function confirmTripwireBreach() {
  closeAccidentalClickModal();
  await triggerScraperCrawl();
}

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
        alert(`🚫 ClearShield Blocked:\n${data.error}\nLogged as suspicious brute-force activity on ClearShield.`);
        closePinModal();
      }
    }
  } catch (err) {
    console.error(err);
  }
}

async function simulateBadPin() {
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

async function triggerScraperCrawl() {
  try {
    const res = await fetch(`${API_BASE}/api/clinic/records/canary-0`, {
      headers: { 'User-Agent': 'Automated Scraper Bot / 1.0' }
    });
    const data = await res.json();
    if (res.status === 403) {
      alert(`⚡ SCENARIO C TRIGGERED (< 15ms Catch):\n` +
        `• Canary Tripwire Intercepted in ${data.latency}.\n` +
        `• Surgical Air-Gap engaged: Session revoked, Database severed.\n` +
        `• Clinic switched to Protected Standby Mode.`);
      enterStandbyMode();
    }
  } catch (err) {
    console.error(err);
  }
}

// Scenario 5: Bulk Data Extraction
async function triggerBulkExport() {
  try {
    const res = await fetch(`${API_BASE}/api/clinic/export?limit=500`, {
      headers: { 'X-Device-Id': 'EXFIL-TEST-CLIENT' }
    });
    const data = await res.json();
    if (res.status === 403) {
      alert(`🚫 SCENARIO 5 TRIGGERED (Bulk Exfiltration Blocked):\n\n` +
        `• Request for 500 patient records exceeded safe volume threshold.\n` +
        `• ClearShield blocked request BEFORE data transfer.\n` +
        `• HTTP 403 returned. Recorded in ClearShield Page 4 (Data Protection).`);
    }
  } catch (err) {
    console.error(err);
  }
}

// -------------------------------------------------------------------------
// CARE CONTINUITY QUEUE & PRINTABLE SLIPS (SCENARIO 6)
// -------------------------------------------------------------------------
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

function renderStandbyQueue() {
  const tbody = document.getElementById('standby-queue-body');
  tbody.innerHTML = '';

  standbyQueue.forEach(apt => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><b>${apt.time}</b></td>
      <td><b>${apt.patientName}</b></td>
      <td>${apt.dob}</td>
      <td>${apt.doctor}</td>
      <td>${apt.service}</td>
      <td><span class="badge badge-green">${apt.status}</span></td>
      <td>
        <button class="btn btn-outline" style="font-size:11px; padding:4px 8px;" onclick="selectPatientForSlip('${apt.patientName}', '${apt.dob}', '${apt.time}', '${apt.doctor}', '${apt.service}')">
          🖨️ Spool Paper Slip
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function selectPatientForSlip(name, dob, time, doctor, reason) {
  document.getElementById('print-patient-name').textContent = name;
  document.getElementById('print-patient-dob').textContent = dob;
  document.getElementById('print-arrival-time').textContent = `Today, ${time}`;
  document.getElementById('print-doctor').textContent = doctor;
  document.getElementById('print-reason').textContent = reason;

  document.getElementById('printable-checkin-area').scrollIntoView({ behavior: 'smooth' });
}

function printCheckInSlip() {
  window.print();
}
