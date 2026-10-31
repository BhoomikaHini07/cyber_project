/**
 * Clinic Guard — Complete Clinical Management & Defense Controller
 * SCREEN 1: Welcome / Landing Page
 * SCREEN 2: After Login / Clinic Dashboard (Role-aware)
 * SCREEN 3: Reception View (Search bar, Clickable Patient Cards, Detail Card)
 * SCREEN 4: Doctor View (Doctor profile, Appointment times, Patients, Previous records, 7-Day History)
 * Plus: Passkey Auth, Canary Trap, Standby Mode, Care Continuity, and Honeypot Decoys.
 */

const API_BASE = window.location.origin;

// Application State
let currentScreen = 'landing'; // 'landing' | 'dashboard'
let currentRole = 'reception'; // 'reception' | 'doctor' | 'patient' | 'security'
let activeDoctor = 'Dr. Taylor'; // 'Dr. Taylor' | 'Dr. Vance' | 'Dr. Evans'

// Clinical Data Collections
let patientRecords = [];
let standbyQueue = [];
let clinicFiles = [];
let clinicPrescriptions = [];
let isStandbyMode = false;

// Selected Patient for Detail & Doctor Charts
let selectedPatientId = 'pat-1';
let receptionFilterStatus = 'all';

// Authenticated Patient/User Session State
let currentUser = null;
let currentSessionToken = null;

// Synthetic Clinical Prescriptions Store (Pre-cached from backend/data/prescriptions.json)
const DEFAULT_PRESCRIPTIONS = [
  { id: "rx-101", patientId: "pat-1", patientName: "Arthur Pendelton", medication: "Lisinopril", dosage: "10 mg daily", prescribedDate: "2026-08-14", doctor: "Dr. Taylor", refills: 3, status: "Active", notes: "Take in morning for hypertension control." },
  { id: "rx-102", patientId: "pat-1", patientName: "Arthur Pendelton", medication: "Atorvastatin", dosage: "20 mg at bedtime", prescribedDate: "2026-09-01", doctor: "Dr. Taylor", refills: 2, status: "Active", notes: "Cholesterol management." },
  { id: "rx-103", patientId: "pat-2", patientName: "Elena Rostova", medication: "Cetirizine HCl", dosage: "10 mg daily PRN", prescribedDate: "2026-07-22", doctor: "Dr. Vance", refills: 4, status: "Active", notes: "For seasonal allergic rhinitis." },
  { id: "rx-104", patientId: "pat-2", patientName: "Elena Rostova", medication: "Fluticasone Propionate", dosage: "50 mcg daily", prescribedDate: "2026-08-10", doctor: "Dr. Vance", refills: 2, status: "Active", notes: "Anti-inflammatory nasal spray." },
  { id: "rx-105", patientId: "pat-3", patientName: "Marcus Holloway", medication: "Metformin HCl", dosage: "500 mg twice daily", prescribedDate: "2026-06-15", doctor: "Dr. Taylor", refills: 5, status: "Active", notes: "Glycemic control for Type 2 Diabetes." },
  { id: "rx-106", patientId: "pat-4", patientName: "Sophia Chen", medication: "Ibuprofen", dosage: "600 mg every 8 hrs PRN", prescribedDate: "2026-10-20", doctor: "Dr. Evans", refills: 1, status: "Active", notes: "Pain relief for wrist sprain." },
  { id: "rx-107", patientId: "pat-5", patientName: "David Kim", medication: "Vitamin D3", dosage: "2000 IU daily", prescribedDate: "2026-05-12", doctor: "Dr. Taylor", refills: 6, status: "Active", notes: "Wellness supplement." },
  { id: "rx-108", patientId: "pat-8", patientName: "Chloe Bennett", medication: "Albuterol Inhaler", dosage: "90 mcg, 2 puffs PRN", prescribedDate: "2026-09-18", doctor: "Dr. Taylor", refills: 3, status: "Active", notes: "Use before exertion or asthma symptoms." }
];

// Doctor Profiles Information
const DOCTOR_PROFILES = {
  'Dr. Taylor': {
    name: 'Dr. Taylor, MD',
    speciality: 'Internal Medicine & Preventive Cardiology',
    room: 'Exam Room 1',
    avatar: '👨‍⚕️',
    license: '#MD-883921-CA',
    bio: 'Chief of Clinical Services with 15+ years managing cardiovascular & metabolic health.'
  },
  'Dr. Vance': {
    name: 'Dr. Vance, MD',
    speciality: 'Allergy, Immunology & Dermatology',
    room: 'Exam Room 2',
    avatar: '👩‍⚕️',
    license: '#MD-910482-CA',
    bio: 'Specialist in allergic rhinitis, respiratory hypersensitivity, and pediatric dermatology.'
  },
  'Dr. Evans': {
    name: 'Dr. Evans, MD',
    speciality: 'Orthopedics & Sports Medicine',
    room: 'Exam Room 3 / Physical Therapy',
    avatar: '👨‍⚕️',
    license: '#MD-772019-CA',
    bio: 'Lead orthopedic physician specializing in musculoskeletal triage and mobility rehab.'
  }
};

// -------------------------------------------------------------------------
// INITIALIZATION
// -------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initClinicEventStream();
  loadPatientRecords();
  loadStandbyQueue();
  loadClinicFiles();
  startClinicClock();

  // Initialize doctor view default
  selectDoctor(activeDoctor);
});

// -------------------------------------------------------------------------
// SCREEN NAVIGATION & ROLE SWITCHING (SCREENS 1 & 2)
// -------------------------------------------------------------------------
function navigateToScreen(screenName) {
  currentScreen = screenName;
  const landingScreen = document.getElementById('screen-landing');
  const dashboardScreen = document.getElementById('screen-dashboard');

  if (screenName === 'landing') {
    landingScreen.classList.add('active');
    dashboardScreen.classList.remove('active');
  } else {
    landingScreen.classList.remove('active');
    dashboardScreen.classList.add('active');
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function quickLoginRole(role) {
  currentRole = role;
  navigateToScreen('dashboard');

  if (role === 'reception') {
    setDashboardProfile('Receptionist Jane', 'Reception', 'Oakridge Community Clinic · Reception Station #1', 'J');
    switchClinicRole('reception');
  } else if (role === 'doctor') {
    setDashboardProfile(DOCTOR_PROFILES[activeDoctor].name, 'Doctor', `${DOCTOR_PROFILES[activeDoctor].speciality} · ${DOCTOR_PROFILES[activeDoctor].room}`, 'DT');
    switchClinicRole('doctor');
  } else if (role === 'patient') {
    switchClinicRole('patient');
  }
}

function setDashboardProfile(name, role, subtitle, avatarInitial) {
  document.getElementById('dash-user-name').innerHTML = `
    <span>${name}</span>
    <span class="badge ${role === 'Doctor' ? 'badge-olive' : role === 'Reception' ? 'badge-green' : 'badge-blue'}" id="dash-role-badge">
      ${role}
    </span>
  `;
  document.getElementById('dash-user-sub').textContent = subtitle;
  document.getElementById('dash-user-avatar').textContent = avatarInitial;

  // Header pill badge
  document.getElementById('header-auth-buttons').style.display = 'none';
  const badge = document.getElementById('logged-user-badge');
  badge.style.display = 'inline-flex';
  document.getElementById('logged-user-name').textContent = `👤 ${name} (${role})`;
}

function logoutClinicUser() {
  currentUser = null;
  currentSessionToken = null;
  document.getElementById('header-auth-buttons').style.display = 'flex';
  document.getElementById('logged-user-badge').style.display = 'none';
  navigateToScreen('landing');
}

function switchClinicRole(role) {
  currentRole = role;

  // Update Navigation Tab Buttons
  document.querySelectorAll('.role-nav-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.role-view').forEach(view => view.classList.remove('active'));

  const navBtn = document.getElementById(`nav-btn-${role}`);
  const viewEl = document.getElementById(`view-${role}`);

  if (navBtn) navBtn.classList.add('active');
  if (viewEl) viewEl.classList.add('active');

  // Trigger role-specific rendering
  if (role === 'reception') {
    renderReceptionPatientCards();
    renderReceptionDetailCard(selectedPatientId);
  } else if (role === 'doctor') {
    renderDoctorDashboard();
  } else if (role === 'patient') {
    if (!currentSessionToken) {
      autoLoginDemoPatient();
    }
  }
}

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
  if (careCard) careCard.style.borderColor = '#059669';

  renderPatientTable();
  renderReceptionPatientCards();
}

function exitStandbyMode() {
  isStandbyMode = false;
  document.getElementById('standby-banner').classList.remove('visible');

  const pill = document.getElementById('clinic-session-pill');
  pill.className = 'session-indicator';
  document.getElementById('clinic-session-text').textContent = 'Protected Session Active';

  const careCard = document.getElementById('care-continuity-card');
  if (careCard) careCard.style.borderColor = 'var(--card-border)';

  loadPatientRecords();
}

// -------------------------------------------------------------------------
// CLINIC DATA LOADERS
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
    
    // Update metric counter on landing page
    const realPatientsCount = patientRecords.filter(p => !p.isCanary).length;
    const metricEl = document.getElementById('metric-patients-count');
    if (metricEl) metricEl.textContent = realPatientsCount;

    const countAllEl = document.getElementById('count-all');
    if (countAllEl) countAllEl.textContent = realPatientsCount;

    renderPatientTable();
    renderReceptionPatientCards();
    renderReceptionDetailCard(selectedPatientId);
  } catch (err) {
    console.error('Error loading patient records:', err);
  }
}

// -------------------------------------------------------------------------
// SCREEN 3: RECEPTION VIEW IMPLEMENTATION
// -------------------------------------------------------------------------
function setReceptionFilter(status, buttonEl) {
  receptionFilterStatus = status;
  document.querySelectorAll('.filter-chip').forEach(btn => btn.classList.remove('active'));
  if (buttonEl) buttonEl.classList.add('active');
  renderReceptionPatientCards();
}

function filterReceptionPatients() {
  renderReceptionPatientCards();
}

function renderReceptionPatientCards() {
  const container = document.getElementById('reception-patient-cards');
  if (!container) return;
  container.innerHTML = '';

  const searchInput = document.getElementById('reception-patient-search');
  const query = (searchInput ? searchInput.value : '').toLowerCase().trim();

  // Filter patients based on query and status filter
  const filtered = patientRecords.filter(patient => {
    // Honeypot canary always available for security testing
    if (patient.isCanary) {
      if (query && !patient.fullName.toLowerCase().includes(query) && !patient.recordNumber.toLowerCase().includes(query)) {
        return false;
      }
      return true;
    }

    // Match query
    const matchQuery = !query || 
      patient.fullName.toLowerCase().includes(query) ||
      patient.recordNumber.toLowerCase().includes(query) ||
      patient.condition.toLowerCase().includes(query) ||
      patient.doctor.toLowerCase().includes(query) ||
      patient.room.toLowerCase().includes(query);

    if (!matchQuery) return false;

    // Match appointment status if filtered
    if (receptionFilterStatus !== 'all') {
      const apt = standbyQueue.find(a => a.patientName.toLowerCase() === patient.fullName.toLowerCase());
      if (!apt || apt.status !== receptionFilterStatus) {
        return false;
      }
    }

    return true;
  });

  const showingCountEl = document.getElementById('reception-showing-count');
  if (showingCountEl) {
    showingCountEl.textContent = `Showing ${filtered.length} patients`;
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="text-align:center; padding:32px 16px; background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; color:#64748b;">
        <span style="font-size:28px; display:block; margin-bottom:8px;">🔍</span>
        <b>No matching patients found</b>
        <p style="font-size:12px; margin-top:4px;">Try searching by patient name, record ID, or condition.</p>
      </div>
    `;
    return;
  }

  filtered.forEach(p => {
    const isSelected = p.id === selectedPatientId;
    const apt = standbyQueue.find(a => a.patientName.toLowerCase() === p.fullName.toLowerCase());
    const aptTime = apt ? apt.time : 'Walk-In';
    const statusText = apt ? apt.status : p.status || 'Active';

    const card = document.createElement('div');
    card.className = `patient-card-item ${isSelected ? 'selected' : ''} ${p.isCanary ? 'canary-item' : ''}`;
    card.onclick = () => selectReceptionPatient(p.id);

    if (p.isCanary) {
      card.innerHTML = `
        <div class="card-item-top">
          <div>
            <span class="card-item-name">⚠️ ${p.fullName}</span>
            <span class="badge badge-yellow" style="margin-left:6px;">Canary Honeypot</span>
          </div>
          <span class="card-item-id">${p.recordNumber}</span>
        </div>
        <div class="card-item-details">
          <span>🔒 Trap: Restricted Decoy Record</span>
          <span>Room: ${p.room}</span>
          <span>Security Tripwire</span>
        </div>
      `;
    } else {
      card.innerHTML = `
        <div class="card-item-top">
          <div>
            <span class="card-item-name">${p.fullName}</span>
            <span class="badge ${statusText === 'Checked In' ? 'badge-green' : statusText === 'Waiting Room' ? 'badge-yellow' : 'badge-blue'}" style="margin-left:6px;">
              ${statusText}
            </span>
          </div>
          <span class="card-item-id">${p.recordNumber}</span>
        </div>
        <div class="card-item-details">
          <span>🕒 ${aptTime}</span>
          <span>🩺 ${p.doctor}</span>
          <span>🚪 ${p.room}</span>
          <span style="color:var(--olive-primary); font-weight:600;">${p.condition}</span>
        </div>
      `;
    }

    container.appendChild(card);
  });
}

function selectReceptionPatient(patientId) {
  selectedPatientId = patientId;

  const patient = patientRecords.find(p => p.id === patientId);
  if (patient && patient.isCanary) {
    handleCanaryClick();
    return;
  }

  renderReceptionPatientCards();
  renderReceptionDetailCard(patientId);

  // Also sync doctor chart if on same patient
  renderDoctorPatientChart(patientId);
}

function renderReceptionDetailCard(patientId) {
  const patient = patientRecords.find(p => p.id === patientId) || patientRecords.find(p => !p.isCanary);
  if (!patient) return;

  const apt = standbyQueue.find(a => a.patientName.toLowerCase() === patient.fullName.toLowerCase());
  const initials = patient.fullName.split(' ').map(n => n[0]).join('').substring(0, 2);

  document.getElementById('detail-patient-avatar').textContent = initials;
  document.getElementById('detail-patient-name').textContent = patient.fullName;
  document.getElementById('detail-record-number').textContent = patient.recordNumber;
  document.getElementById('detail-patient-id').textContent = patient.id;
  
  const statusBadge = document.getElementById('detail-patient-status');
  const status = apt ? apt.status : 'Active';
  statusBadge.textContent = status;
  statusBadge.className = `badge ${status === 'Checked In' ? 'badge-green' : status === 'Waiting Room' ? 'badge-yellow' : 'badge-blue'}`;

  document.getElementById('detail-appointment-time').textContent = apt ? `${apt.time} (Today)` : '10:00 AM (Scheduled)';
  document.getElementById('detail-doctor').textContent = `${patient.doctor} (${patient.room})`;
  document.getElementById('detail-dob').textContent = `${patient.dob} (DOB)`;
  document.getElementById('detail-phone').textContent = patient.phone || '555-0199';
  document.getElementById('detail-condition').textContent = patient.condition;

  // Prescriptions for this patient
  const rxList = DEFAULT_PRESCRIPTIONS.filter(rx => rx.patientId === patient.id || rx.patientName.toLowerCase() === patient.fullName.toLowerCase());
  const rxTbody = document.getElementById('detail-prescriptions-body');
  rxTbody.innerHTML = '';

  if (rxList.length > 0) {
    rxList.forEach(rx => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><b>${rx.medication}</b></td>
        <td><span class="badge badge-green">${rx.dosage}</span></td>
        <td><b>${rx.refills} refills</b></td>
        <td style="color:#64748b; font-size:12px;">${rx.notes}</td>
      `;
      rxTbody.appendChild(tr);
    });
  } else {
    rxTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#64748b; padding:12px;">No active prescriptions on file.</td></tr>`;
  }
}

function markPatientCheckedIn() {
  const patient = patientRecords.find(p => p.id === selectedPatientId);
  if (!patient) return;

  const apt = standbyQueue.find(a => a.patientName.toLowerCase() === patient.fullName.toLowerCase());
  if (apt) {
    apt.status = 'Checked In';
  }
  renderReceptionPatientCards();
  renderReceptionDetailCard(selectedPatientId);
  alert(`✅ Patient ${patient.fullName} marked as Checked In!\nAssigned to ${patient.doctor} in ${patient.room}.`);
}

function spoolSlipForSelectedPatient() {
  const patient = patientRecords.find(p => p.id === selectedPatientId);
  if (!patient) return;

  const apt = standbyQueue.find(a => a.patientName.toLowerCase() === patient.fullName.toLowerCase());
  selectPatientForSlip(
    patient.fullName,
    patient.dob,
    apt ? apt.time : '09:30 AM',
    patient.doctor,
    patient.condition
  );
}

// -------------------------------------------------------------------------
// SCREEN 4: DOCTOR VIEW IMPLEMENTATION
// -------------------------------------------------------------------------
function changeDoctor(doctorName) {
  selectDoctor(doctorName);
}

function selectDoctor(doctorName) {
  activeDoctor = doctorName;
  const doc = DOCTOR_PROFILES[doctorName];
  if (!doc) return;

  // Update Doctor Selector & Profile Banner
  const sel = document.getElementById('doc-selector');
  if (sel) sel.value = doctorName;

  const nameEl = document.getElementById('doc-profile-name');
  if (nameEl) nameEl.textContent = doc.name;

  const specEl = document.getElementById('doc-profile-speciality');
  if (specEl) specEl.textContent = `🩺 ${doc.speciality}`;

  const avatarEl = document.getElementById('doc-avatar-badge');
  if (avatarEl) avatarEl.textContent = doc.avatar;

  renderDoctorDashboard();
}

function renderDoctorDashboard() {
  const doc = DOCTOR_PROFILES[activeDoctor];
  if (!doc) return;

  // Filter Doctor's appointments
  const doctorAppointments = standbyQueue.filter(a => a.doctor === activeDoctor || a.doctor.includes(activeDoctor.replace('Dr. ', '')));
  const doctorPatients = patientRecords.filter(p => !p.isCanary && (p.doctor === activeDoctor || p.doctor.includes(activeDoctor.replace('Dr. ', ''))));

  // Update Counters
  const countTodayEl = document.getElementById('stat-doc-today-count');
  if (countTodayEl) countTodayEl.textContent = doctorAppointments.length;

  const waitingCount = doctorAppointments.filter(a => a.status === 'Waiting Room' || a.status === 'Checked In').length;
  const countWaitingEl = document.getElementById('stat-doc-waiting-count');
  if (countWaitingEl) countWaitingEl.textContent = waitingCount;

  const badgeEl = document.getElementById('doc-apt-badge');
  if (badgeEl) badgeEl.textContent = `${doctorAppointments.length} Scheduled`;

  // Render Upcoming Appointments Table
  const aptTbody = document.getElementById('doc-upcoming-appointments-body');
  if (aptTbody) {
    aptTbody.innerHTML = '';
    if (doctorAppointments.length > 0) {
      doctorAppointments.forEach(a => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.onclick = () => {
          const pat = patientRecords.find(p => p.fullName.toLowerCase() === a.patientName.toLowerCase());
          if (pat) selectDoctorPatient(pat.id);
        };
        tr.innerHTML = `
          <td><b>${a.time}</b></td>
          <td><b>${a.patientName}</b></td>
          <td>${a.service}</td>
          <td><span class="badge ${a.status === 'Checked In' ? 'badge-green' : a.status === 'Waiting Room' ? 'badge-yellow' : 'badge-blue'}">${a.status}</span></td>
        `;
        aptTbody.appendChild(tr);
      });
    } else {
      aptTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#64748b; padding:14px;">No appointments scheduled today for this physician.</td></tr>`;
    }
  }

  // Render Doctor's Assigned Patients List
  const patListContainer = document.getElementById('doc-assigned-patients-list');
  if (patListContainer) {
    patListContainer.innerHTML = '';
    doctorPatients.forEach(p => {
      const isSelected = p.id === selectedPatientId;
      const card = document.createElement('div');
      card.className = `patient-card-item ${isSelected ? 'selected' : ''}`;
      card.onclick = () => selectDoctorPatient(p.id);
      card.innerHTML = `
        <div class="card-item-top">
          <b style="color:#0f172a;">${p.fullName}</b>
          <span class="code-cell">${p.recordNumber}</span>
        </div>
        <div class="card-item-details">
          <span>🚪 ${p.room}</span>
          <span style="color:var(--olive-primary); font-weight:600;">${p.condition}</span>
        </div>
      `;
      patListContainer.appendChild(card);
    });
  }

  // Ensure selected patient belongs to this doctor if possible
  if (doctorPatients.length > 0 && !doctorPatients.some(p => p.id === selectedPatientId)) {
    selectedPatientId = doctorPatients[0].id;
  }

  renderDoctorPatientChart(selectedPatientId);
}

function selectDoctorPatient(patientId) {
  selectedPatientId = patientId;
  renderDoctorDashboard();
}

function renderDoctorPatientChart(patientId) {
  const patient = patientRecords.find(p => p.id === patientId) || patientRecords.find(p => !p.isCanary);
  if (!patient) return;

  const initials = patient.fullName.split(' ').map(n => n[0]).join('').substring(0, 2);
  const chartAvatar = document.getElementById('doc-chart-avatar');
  if (chartAvatar) chartAvatar.textContent = initials;

  const chartName = document.getElementById('doc-chart-name');
  if (chartName) chartName.textContent = patient.fullName;

  const chartRecord = document.getElementById('doc-chart-record');
  if (chartRecord) chartRecord.textContent = patient.recordNumber;

  const chartRoom = document.getElementById('doc-chart-room');
  if (chartRoom) chartRoom.textContent = patient.room;

  const chartCondition = document.getElementById('doc-chart-condition');
  if (chartCondition) chartCondition.textContent = patient.condition;

  // Previous records / prescriptions
  const rxList = DEFAULT_PRESCRIPTIONS.filter(rx => rx.patientId === patient.id || rx.patientName.toLowerCase() === patient.fullName.toLowerCase());
  const tbody = document.getElementById('doc-chart-prescriptions-body');
  if (tbody) {
    tbody.innerHTML = '';
    if (rxList.length > 0) {
      rxList.forEach(rx => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><b>${rx.medication}</b></td>
          <td><span class="badge badge-green">${rx.dosage}</span></td>
          <td>${rx.prescribedDate}</td>
          <td><b>${rx.refills} refills</b></td>
          <td style="color:#64748b; font-size:12px;">${rx.notes}</td>
        `;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#64748b; padding:12px;">No previous prescriptions on file.</td></tr>`;
    }
  }

  // Render 7-Day History Timeline
  renderPatient7DayTimeline(patient);
}

// -------------------------------------------------------------------------
// 7-DAY CLINICAL HISTORY TIMELINE GENERATOR
// -------------------------------------------------------------------------
function renderPatient7DayTimeline(patient) {
  const timelineEl = document.getElementById('patient-7day-timeline');
  if (!timelineEl) return;

  // Dynamic 7-day milestones customized for this patient's clinical condition
  const events = [
    {
      day: 'Day 1 — Today (Active Consultation)',
      title: 'Attending Physician Triage & Vitals Check',
      desc: `Patient arrived for ${patient.condition}. Blood pressure, pulse, and oxygen saturation recorded in ${patient.room}.`,
      vitals: ['BP: 124/80 mmHg', 'Pulse: 72 bpm', 'SpO2: 99%', 'Temp: 98.6°F'],
      isToday: true
    },
    {
      day: 'Day 2 (Yesterday)',
      title: 'Laboratory Diagnostic Bloodwork Panel',
      desc: 'Comprehensive metabolic panel and lipid profile drawn. Liver enzymes and fasting glucose within normal reference thresholds.',
      vitals: ['Glucose: 94 mg/dL', 'Cholesterol: 182 mg/dL', 'Creatinine: 0.9 mg/dL'],
      isToday: false
    },
    {
      day: 'Day 3',
      title: 'Triage Nurse Telephone Follow-Up',
      desc: 'Telephone check-in conducted by Nurse RN-42. Patient reports good tolerance to prescribed therapy with zero adverse reactions.',
      vitals: ['Adherence: 100%', 'Pain Score: 0/10', 'Mobility: Normal'],
      isToday: false
    },
    {
      day: 'Day 4',
      title: 'Pharmacy Medication Reconciliation',
      desc: 'Prescription refill status checked against clinic formulary. Refill authorization updated for electronic transmission.',
      vitals: ['Refills Verified', 'Interaction Check: Clear'],
      isToday: false
    },
    {
      day: 'Day 5',
      title: 'Care Continuity & Dietary Counseling',
      desc: 'Lifestyle modification log reviewed. Recommended daily sodium restriction and regular 30-minute moderate aerobic exercise.',
      vitals: ['Diet: Low Sodium', 'Activity: Light Aerobic'],
      isToday: false
    },
    {
      day: 'Day 6',
      title: 'Routine Health Wellness Check',
      desc: 'Outpatient clinical progress notes logged. Patient reported mild morning stiffness, resolved with light hydration.',
      vitals: ['Hydration: Adequate', 'Sleep: 7.5 hrs'],
      isToday: false
    },
    {
      day: 'Day 7',
      title: 'Initial Admission & Baseline Intake',
      desc: `Patient intake completed at reception desk. Baseline vital parameters and primary care physician (${patient.doctor}) assigned.`,
      vitals: ['Intake Slip: Validated', 'Allergies: Documented'],
      isToday: false
    }
  ];

  timelineEl.innerHTML = '';
  events.forEach(e => {
    const eventItem = document.createElement('div');
    eventItem.className = 'timeline-event';
    eventItem.innerHTML = `
      <div class="timeline-node ${e.isToday ? 'today-node' : ''}"></div>
      <div class="timeline-content">
        <div class="timeline-header">
          <span class="timeline-day">${e.day}</span>
          ${e.isToday ? '<span class="badge badge-purple">Current Session</span>' : ''}
        </div>
        <div class="timeline-title">${e.title}</div>
        <p class="timeline-desc">${e.desc}</p>
        <div class="vitals-chip-row">
          ${e.vitals.map(v => `<span class="vitals-chip">${v}</span>`).join('')}
        </div>
      </div>
    `;
    timelineEl.appendChild(eventItem);
  });
}

function saveDoctorClinicalNote() {
  const noteInput = document.getElementById('doc-note-input');
  if (!noteInput || !noteInput.value.trim()) {
    alert('Please enter a clinical note first.');
    return;
  }

  const noteText = noteInput.value.trim();
  const timelineEl = document.getElementById('patient-7day-timeline');

  // Prepend fresh progress note to the timeline
  const newEvent = document.createElement('div');
  newEvent.className = 'timeline-event';
  newEvent.innerHTML = `
    <div class="timeline-node today-node"></div>
    <div class="timeline-content" style="border-color:var(--light-green-border); background:var(--light-green-tint);">
      <div class="timeline-header">
        <span class="timeline-day" style="color:var(--olive-deep);">Just Now (${activeDoctor})</span>
        <span class="badge badge-green">Appended Note</span>
      </div>
      <div class="timeline-title">Physician Progress Remark</div>
      <p class="timeline-desc" style="color:var(--olive-dark);">${noteText}</p>
    </div>
  `;

  if (timelineEl) {
    timelineEl.insertBefore(newEvent, timelineEl.firstChild);
  }

  noteInput.value = '';
  alert(`✅ Clinical progress note appended to patient chart by ${activeDoctor}!`);
}

function startClinicClock() {
  function updateTime() {
    const now = new Date();
    let hours = now.getHours();
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12 || 12;
    const timeStr = `${String(hours).padStart(2, '0')}:${minutes} ${ampm}`;
    const clockEl = document.getElementById('doc-live-clock');
    if (clockEl) clockEl.textContent = timeStr;
  }
  updateTime();
  setInterval(updateTime, 10000);
}

// -------------------------------------------------------------------------
// CLINIC RECEPTION REGISTRY TABLE (Full Table View)
// -------------------------------------------------------------------------
function renderPatientTable() {
  const tbody = document.getElementById('patient-table-body');
  if (!tbody) return;
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
            <button class="btn btn-outline btn-sm" style="border-color: #d97706; color: #b45309;" onclick="handleCanaryClick()">
              Canary Trap Decoy
            </button>
          ` : `
            <button class="btn btn-outline btn-sm" onclick="selectReceptionPatient('${p.id}')">
              View Chart
            </button>
          `}
        </td>
      `;
    }
    tbody.appendChild(tr);
  });
}

// -------------------------------------------------------------------------
// CANARY NOTIFICATION & ACCIDENTAL CLICK MODAL (SCENARIOS A & C)
// -------------------------------------------------------------------------
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

// -------------------------------------------------------------------------
// SUPERVISOR PIN MODAL (SCENARIO B)
// -------------------------------------------------------------------------
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

// -------------------------------------------------------------------------
// AUTOMATED SCRAPER & BULK EXPORT (SCENARIOS C & 5)
// -------------------------------------------------------------------------
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
// PRE-LOGIN RESTRICTED PROBING SIMULATOR (SCENARIO 2)
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
// CLINIC FILE REPOSITORY & HONEYPOT DECOYS (SCENARIO 4)
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
  if (!tbody) return;
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
          <button class="btn btn-danger btn-sm" onclick="downloadDecoyFile('${f.id}')">
            ⚡ Attempt Download (Honeypot Trap)
          </button>
        ` : `
          <button class="btn btn-outline btn-sm" onclick="downloadPublicFile('${f.id}')">
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
  if (!tbody) return;
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
        <button class="btn btn-outline btn-sm" onclick="selectPatientForSlip('${apt.patientName}', '${apt.dob}', '${apt.time}', '${apt.doctor}', '${apt.service}')">
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

  const printArea = document.getElementById('printable-checkin-area');
  if (printArea) {
    printArea.scrollIntoView({ behavior: 'smooth' });
  }
}

function printCheckInSlip() {
  window.print();
}

// -------------------------------------------------------------------------
// PATIENT AUTHENTICATION & PASSKEYS (SCENARIOS 1 & 3)
// -------------------------------------------------------------------------
function openLoginModal() {
  document.getElementById('login-modal').classList.add('active');
  switchAuthTab('login');
}

function openRegisterModal() {
  document.getElementById('login-modal').classList.add('active');
  switchAuthTab('register');
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
      setAuthenticatedPatient(data.user, data.sessionToken);
      closeLoginModal();
      navigateToScreen('dashboard');
      switchClinicRole('patient');
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
    const res = await fetch(`${API_BASE}/api/clinic/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, loginType: 'passkey' })
    });

    const data = await res.json();
    if (res.ok) {
      setAuthenticatedPatient(data.user, data.sessionToken);
      closeLoginModal();
      navigateToScreen('dashboard');
      switchClinicRole('patient');
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
      setAuthenticatedPatient(data.user, data.sessionToken);
      closeLoginModal();
      navigateToScreen('dashboard');
      switchClinicRole('patient');
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
  setAuthenticatedPatient(currentUser, currentSessionToken);
  navigateToScreen('dashboard');
  switchClinicRole('patient');
  alert(`Account ready. Your passkey and recovery process are configured for future visits.`);
}

function setAuthenticatedPatient(user, token) {
  currentUser = user;
  currentSessionToken = token;

  setDashboardProfile(user.name, 'Patient', `Patient ID: ${user.patientId || 'pat-1'} · Passkey Enrolled`, user.name[0]);

  // Display personal portal card
  const portalCard = document.getElementById('patient-portal-card');
  if (portalCard) portalCard.style.display = 'block';

  const nameEl = document.getElementById('portal-patient-name');
  if (nameEl) nameEl.textContent = user.name;

  loadPatientPrescriptions();
  loadPatientAppointments();
}

async function autoLoginDemoPatient() {
  try {
    const res = await fetch(`${API_BASE}/api/clinic/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'arthur.pendelton@example.com', password: 'Password123!', loginType: 'password' })
    });
    const data = await res.json();
    if (res.ok) {
      setAuthenticatedPatient(data.user, data.sessionToken);
    }
  } catch (e) {}
}

async function loadPatientPrescriptions() {
  if (!currentSessionToken) return;

  try {
    const res = await fetch(`${API_BASE}/api/clinic/patient/prescriptions`, {
      headers: { 'Authorization': `Bearer ${currentSessionToken}` }
    });

    const data = await res.json();
    const tbody = document.getElementById('patient-prescriptions-body');
    if (!tbody) return;
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
    if (!tbody) return;
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
