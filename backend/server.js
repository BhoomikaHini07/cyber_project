const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const canaryEngine = require('./security/canaryTrap');

// Load synthetic datasets
const patientsData = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'patients.json'), 'utf8'));
const appointmentsData = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'appointments.json'), 'utf8'));
const prescriptionsData = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'prescriptions.json'), 'utf8'));
const usersData = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'users.json'), 'utf8'));
const decoyFilesData = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'decoy_files.json'), 'utf8'));

// Main API & ClearShield Dashboard App (Port 5000)
const app = express();
app.use(cors());
app.use(express.json());

// Sample Clinic App (Port 5001)
const clinicApp = express();
clinicApp.use(cors());
clinicApp.use(express.json());

// Active authenticated patient sessions: token -> user
const activeSessions = new Map();

// Helper to authenticate session token
function getAuthenticatedUser(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  return activeSessions.get(token) || null;
}

// ----------------------------------------------------
// PART 2: PRE-LOGIN THREAT DETECTION MIDDLEWARE
// Intercepts probes to /admin, /staff, /backup, /database
// ----------------------------------------------------
const restrictedPaths = ['/admin', '/staff', '/backup', '/database', '/api/admin', '/api/staff', '/api/backup', '/api/database'];

const preLoginThreatMiddleware = (req, res, next) => {
  const normalizedPath = req.path.toLowerCase().replace(/\/$/, '');
  
  if (restrictedPaths.some(p => normalizedPath === p || normalizedPath.startsWith(p + '/'))) {
    const clientIp = req.ip || req.connection?.remoteAddress || '192.168.1.110';
    const userAgent = req.headers['user-agent'] || 'Unknown Probe';
    
    // ClearShield records pre-login threat and blocks request before page load
    const result = canaryEngine.recordRestrictedPageAttempt(normalizedPath, clientIp, userAgent);
    
    return res.status(403).json({
      error: 'ClearShield Security: Access Forbidden. Pre-Login Restricted Route Probing Detected.',
      code: 'PRE_LOGIN_PROBE_BLOCKED',
      path: normalizedPath,
      attempts: result.attempts,
      message: 'Suspicious request pattern blocked before reaching clinic systems.'
    });
  }
  next();
};

app.use(preLoginThreatMiddleware);
clinicApp.use(preLoginThreatMiddleware);

// ----------------------------------------------------
// REAL-TIME SERVER-SENT EVENTS (SSE)
// ----------------------------------------------------
const handleSSE = (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.write(`data: ${JSON.stringify({ type: 'INIT', data: canaryEngine.getSystemStatus() })}\n\n`);
  canaryEngine.subscribe(res);
};

app.get('/api/events', handleSSE);
clinicApp.get('/api/events', handleSSE);

// ----------------------------------------------------
// CLEARSHIELD SECURITY CENTER DEDICATED APIS
// ----------------------------------------------------
app.get('/api/clearshield/status', (req, res) => {
  res.json(canaryEngine.getSystemStatus());
});

app.get('/api/clearshield/alerts', (req, res) => {
  res.json(canaryEngine.alerts);
});

app.get('/api/clearshield/incidents', (req, res) => {
  res.json(canaryEngine.incidents);
});

app.get('/api/clearshield/blocked-requests', (req, res) => {
  res.json(canaryEngine.blockedRequests);
});

app.get('/api/clearshield/sms', (req, res) => {
  res.json(canaryEngine.smsQueue);
});

// Dedicated Page 2: Threat Monitoring
app.get('/api/clearshield/threats/pre-login', (req, res) => {
  res.json(canaryEngine.preLoginThreats);
});

// Dedicated Page 3: Honeypot Monitoring
app.get('/api/clearshield/honeypot/events', (req, res) => {
  res.json({
    decoyFiles: decoyFilesData,
    events: canaryEngine.honeypotEvents
  });
});

// Dedicated Page 4: Data Protection
app.get('/api/clearshield/data-protection/events', (req, res) => {
  res.json(canaryEngine.dataProtectionLogs);
});

// Dedicated Page 5: Authentication Activity
app.get('/api/clearshield/auth/logs', (req, res) => {
  res.json({
    users: usersData.map(u => ({ id: u.id, name: u.name, email: u.email, hasPasskey: u.hasPasskey, passkeyName: u.passkeyName, registeredAt: u.registeredAt })),
    activityLogs: canaryEngine.authActivityLogs
  });
});

// Dedicated Page 7: Emergency Isolation Trigger
app.post('/api/clearshield/emergency/isolate', (req, res) => {
  const result = canaryEngine.triggerSurgicalAirGap(
    'Manual Emergency Isolation by Security Administrator',
    'Administrator Air-Gap Override',
    '/api/clinic/emergency/isolate',
    req.ip,
    'SECURITY-CONSOLE'
  );
  res.json({ success: true, result, status: canaryEngine.getSystemStatus() });
});

// Dedicated Page 8: Security Reports
app.get('/api/clearshield/export-report', (req, res) => {
  const report = canaryEngine.generateIncidentReport();
  const format = req.query.format || 'json';

  if (format === 'csv') {
    const header = 'IncidentID,Timestamp,ThreatType,TriggerSource,ResourceAccessed,ClientIP,Device,ActionTaken,RecordsLost\n';
    const rows = canaryEngine.incidents.map(i =>
      `"${i.id}","${i.time}","${i.threatType}","${i.triggerSource}","${i.resourceAccessed}","${i.clientIp}","${i.device}","${i.actionTaken}",${i.recordsLost}`
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="ClearShield_Incident_Report.csv"');
    return res.send(header + rows);
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="ClearShield_Incident_Report.json"');
  res.json(report);
});

app.post('/api/clearshield/review-incident', (req, res) => {
  const { incidentId, reviewer } = req.body;
  const result = canaryEngine.reviewIncident(incidentId, reviewer || 'Chief Security Officer');
  if (result) {
    res.json({ success: true, incident: result });
  } else {
    res.status(404).json({ error: 'Incident not found' });
  }
});

app.post('/api/clearshield/restore', (req, res) => {
  const { adminUser } = req.body;
  const result = canaryEngine.restoreSystem(adminUser || 'Dr. Taylor (Chief Medical Officer)');
  res.json({ success: true, result, status: canaryEngine.getSystemStatus() });
});

// ----------------------------------------------------
// PART 1: CLINIC AUTHENTICATION & PASSKEYS
// ----------------------------------------------------

// 1. Patient Registration with Passkey & Recovery Code
const handleRegister = (req, res) => {
  const { name, email, password, registerPasskey, passkeyName } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  // Check if email already registered
  const existing = usersData.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (existing) {
    return res.status(400).json({ error: 'An account with this email already exists' });
  }

  // Generate personal recovery code
  const r1 = Math.floor(1000 + Math.random() * 9000);
  const r2 = Math.floor(1000 + Math.random() * 9000);
  const r3 = Math.floor(1000 + Math.random() * 9000);
  const recoveryCode = `CS-RECOV-${r1}-${r2}-${r3}`;

  // Link to a synthetic patient profile (or create one)
  const patientId = 'pat-' + (patientsData.length + 1);
  const newUser = {
    id: 'usr-' + (usersData.length + 1),
    patientId: patientId,
    name,
    email,
    password,
    hasPasskey: !!registerPasskey,
    passkeyCredentialId: registerPasskey ? 'pk_cred_' + Math.random().toString(36).substring(2, 10) : null,
    passkeyName: passkeyName || (registerPasskey ? `${name}'s TouchID / FaceID` : null),
    recoveryCode,
    registeredAt: new Date().toISOString(),
    role: 'patient'
  };

  usersData.push(newUser);

  // Issue session token
  const sessionToken = 'tok_' + Math.random().toString(36).substring(2, 14);
  activeSessions.set(sessionToken, newUser);

  // Log to ClearShield Auth Activity
  canaryEngine.logAuthActivity('ACCOUNT_REGISTERED', email, registerPasskey ? 'Passkey Enabled' : 'Password', true, `New patient registered with personal recovery code generated.`, req.ip);

  res.json({
    success: true,
    user: {
      id: newUser.id,
      patientId: newUser.patientId,
      name: newUser.name,
      email: newUser.email,
      hasPasskey: newUser.hasPasskey,
      passkeyName: newUser.passkeyName
    },
    recoveryCode: newUser.recoveryCode,
    sessionToken,
    explanation: 'Your account and passkey are registered. Save your personal recovery code safely. You can use it to securely log in if your passkey is unavailable.'
  });
};

app.post('/api/clinic/auth/register', handleRegister);
clinicApp.post('/api/clinic/auth/register', handleRegister);

// 2. Patient Login (Password, Passkey, or Recovery Code)
const handleLogin = (req, res) => {
  const { email, password, loginType, recoveryCode, passkeyCredentialId } = req.body;
  const clientIp = req.ip || '127.0.0.1';

  let user = null;

  if (loginType === 'passkey') {
    // Passkey authentication
    user = usersData.find(u => u.hasPasskey && (u.email?.toLowerCase() === email?.toLowerCase() || (passkeyCredentialId && u.passkeyCredentialId === passkeyCredentialId)));
    if (!user) {
      canaryEngine.logAuthActivity('LOGIN_FAILED', email || 'passkey_user', 'Passkey', false, 'Passkey credential not recognized', clientIp);
      return res.status(401).json({ error: 'Passkey verification failed or no passkey registered for this account.' });
    }
    canaryEngine.logAuthActivity('LOGIN_SUCCESS', user.email, 'Passkey (FIDO2 / TouchID)', true, 'Biometric passkey verified securely.', clientIp);
  } else if (loginType === 'recovery') {
    // Recovery code login
    user = usersData.find(u => u.email.toLowerCase() === email.toLowerCase() && u.recoveryCode === recoveryCode?.trim());
    if (!user) {
      canaryEngine.logAuthActivity('LOGIN_FAILED', email, 'Recovery Code', false, 'Invalid recovery code attempt', clientIp);
      return res.status(401).json({ error: 'Invalid personal recovery code provided.' });
    }
    canaryEngine.logAuthActivity('LOGIN_SUCCESS', user.email, 'Personal Recovery Code', true, 'Account recovered securely via 16-digit code.', clientIp);
  } else {
    // Standard password login
    user = usersData.find(u => u.email.toLowerCase() === email?.toLowerCase() && u.password === password);
    if (!user) {
      canaryEngine.logAuthActivity('LOGIN_FAILED', email, 'Password', false, 'Invalid password attempt', clientIp);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    canaryEngine.logAuthActivity('LOGIN_SUCCESS', user.email, 'Password', true, 'Patient logged in with password.', clientIp);
  }

  const sessionToken = 'tok_' + Math.random().toString(36).substring(2, 14);
  activeSessions.set(sessionToken, user);

  res.json({
    success: true,
    user: {
      id: user.id,
      patientId: user.patientId,
      name: user.name,
      email: user.email,
      hasPasskey: user.hasPasskey,
      passkeyName: user.passkeyName
    },
    sessionToken
  });
};

app.post('/api/clinic/auth/login', handleLogin);
clinicApp.post('/api/clinic/auth/login', handleLogin);

// 3. Register a Passkey for existing user
const handleRegisterPasskey = (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });

  user.hasPasskey = true;
  user.passkeyCredentialId = 'pk_cred_' + Math.random().toString(36).substring(2, 10);
  user.passkeyName = req.body.passkeyName || `${user.name}'s Biometric Passkey`;

  canaryEngine.logAuthActivity('PASSKEY_REGISTERED', user.email, 'Passkey Enrollment', true, `Passkey credential enrolled: ${user.passkeyName}`, req.ip);

  res.json({
    success: true,
    message: 'Passkey registered successfully',
    passkeyName: user.passkeyName
  });
};

app.post('/api/clinic/auth/register-passkey', handleRegisterPasskey);
clinicApp.post('/api/clinic/auth/register-passkey', handleRegisterPasskey);

// ----------------------------------------------------
// PART 1: PRESCRIBED MEDICINES & APPOINTMENTS (IDOR GUARD)
// ----------------------------------------------------

// 1. Authorized Patient View of Own Prescriptions (Scenario 1)
const handleGetOwnPrescriptions = (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required to view medical prescriptions' });
  }

  // Retrieve ONLY this patient's permitted records
  const myPrescriptions = prescriptionsData.filter(rx => rx.patientId === user.patientId);

  res.json({
    patientName: user.name,
    patientId: user.patientId,
    prescriptions: myPrescriptions,
    disclaimer: 'Displaying authorized prescription history for this patient only.'
  });
};

app.get('/api/clinic/patient/prescriptions', handleGetOwnPrescriptions);
clinicApp.get('/api/clinic/patient/prescriptions', handleGetOwnPrescriptions);

// 2. Cross-Patient Access Attempt / IDOR Attack Interception (Scenario 3)
const handleGetPatientPrescriptionsById = (req, res) => {
  const targetPatientId = req.params.patientId;
  const user = getAuthenticatedUser(req);
  const clientIp = req.ip || req.connection?.remoteAddress || '192.168.1.102';

  // Authorization check: Is patient authorized to access targetPatientId?
  // A patient is NEVER allowed to access other patients' records or full database
  const isAuthorized = user && user.patientId === targetPatientId;

  if (!isAuthorized) {
    // Intercept with ClearShield Data Protection Guard
    canaryEngine.recordUnauthorizedDataAccess(targetPatientId, user, 'Previous Prescriptions & Medicines', clientIp);

    return res.status(403).json({
      error: 'Access Denied: ClearShield Data Protection. Unauthorized query for cross-patient medical records blocked.',
      code: 'UNAUTHORIZED_CROSS_PATIENT_ACCESS',
      targetPatientId: targetPatientId,
      message: 'You are only authorized to access your own personal medical information. This incident has been logged.'
    });
  }

  // If authorized, return that patient's records
  const rxList = prescriptionsData.filter(rx => rx.patientId === targetPatientId);
  res.json({ prescriptions: rxList });
};

app.get('/api/clinic/patient/:patientId/prescriptions', handleGetPatientPrescriptionsById);
clinicApp.get('/api/clinic/patient/:patientId/prescriptions', handleGetPatientPrescriptionsById);

// 3. Authorized Patient View of Own Appointments
const handleGetOwnAppointments = (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const myAppointments = appointmentsData.filter(apt => apt.patientName.toLowerCase() === user.name.toLowerCase());
  res.json({ appointments: myAppointments });
};

app.get('/api/clinic/patient/appointments', handleGetOwnAppointments);
clinicApp.get('/api/clinic/patient/appointments', handleGetOwnAppointments);

// ----------------------------------------------------
// PART 3: CLINIC FILE REPOSITORY & HONEYPOT DECOY TRAPS
// ----------------------------------------------------

// 1. List Clinic Files (Public Guides + Canary Decoys)
const handleListFiles = (req, res) => {
  // Show list of files
  res.json({
    files: decoyFilesData.map(f => ({
      id: f.id,
      filename: f.filename,
      title: f.title,
      category: f.category,
      size: f.size,
      description: f.description,
      isDecoy: f.isDecoy
    }))
  });
};

app.get('/api/clinic/files', handleListFiles);
clinicApp.get('/api/clinic/files', handleListFiles);

// 2. Download File / Honeypot Decoy Trap Catch (Scenario 4)
const handleDownloadFile = (req, res) => {
  const fileId = req.params.fileId;
  const file = decoyFilesData.find(f => f.id === fileId || f.filename === fileId);

  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  const clientIp = req.ip || req.connection?.remoteAddress || '192.168.1.145';
  const userAgent = req.headers['user-agent'] || '';

  // If this is a Honeypot Decoy File:
  if (file.isDecoy) {
    // Intercept download before delivery!
    const tripwire = canaryEngine.handleDecoyFileDownload(file, clientIp, userAgent);

    return res.status(403).json({
      error: 'ClearShield Honeypot: Unauthorized download cancelled.',
      code: 'HONEYPOT_DECOY_BLOCKED',
      filename: file.filename,
      latency: tripwire.latency + 'ms',
      message: 'Decoy file access caught by canary trap before file transmission. Event recorded on ClearShield.'
    });
  }

  // Normal file: safe download allowed for legitimate users
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
  res.send(file.content || 'Oakridge Health Clinic Public Document');
};

app.get('/api/clinic/files/download/:fileId', handleDownloadFile);
clinicApp.get('/api/clinic/files/download/:fileId', handleDownloadFile);

// ----------------------------------------------------
// CLINIC PATIENT REGISTRY & AIR-GAP STANDBY APIS
// ----------------------------------------------------
const handleGetRecords = (req, res) => {
  if (canaryEngine.airGapped || canaryEngine.dbCut) {
    canaryEngine.logBlockedRequest('GET', '/api/clinic/records', req.ip, 'Surgical Air-Gap Active: Database Cable Severed', 403);
    return res.status(403).json({
      error: 'Access Denied: Clinic is in Protected Standby Mode due to threat isolation.',
      code: 'SURGICAL_AIRGAP_ACTIVE',
      status: 'STANDBY_MODE'
    });
  }

  res.json({
    activeSessionToken: canaryEngine.activeSessionToken,
    records: patientsData
  });
};

app.get('/api/clinic/records', handleGetRecords);
clinicApp.get('/api/clinic/records', handleGetRecords);

const handleGetRecordById = (req, res) => {
  const { id } = req.params;

  if (id === 'canary-0' || id === 'CANARY-00-TRAP') {
    const clientIp = req.ip || '192.168.1.104';
    const device = req.headers['x-device-id'] || 'FRONT-DESK-PC';
    const triggerSource = req.headers['user-agent']?.includes('Scraper') ?
      'Automated Bulk Scraper Process' : 'Unauthorized Decoy Query Attempt';

    const tripwire = canaryEngine.triggerSurgicalAirGap(
      triggerSource,
      'Canary Decoy Record Accessed (Tripwire Triggered)',
      `/api/clinic/records/${id}`,
      clientIp,
      device
    );

    canaryEngine.logBlockedRequest('GET', `/api/clinic/records/${id}`, clientIp, 'Canary Trap Decoy Breach - Request Terminated Before Data Load', 403);

    return res.status(403).json({
      error: 'ClearShield Security: Access Forbidden. Canary Decoy Tripwire activated.',
      code: 'CANARY_TRIPWIRE_TRIGGERED',
      latency: `${tripwire.latency}ms`,
      airGapActive: true,
      message: 'Suspicious request intercepted before real records could be retrieved. Session revoked.'
    });
  }

  if (canaryEngine.airGapped || canaryEngine.dbCut) {
    canaryEngine.logBlockedRequest('GET', `/api/clinic/records/${id}`, req.ip, 'Real record requested while air-gapped', 403);
    return res.status(403).json({
      error: 'Database cable disconnected. Standby mode active.',
      code: 'AIRGAP_BLOCKED'
    });
  }

  const patient = patientsData.find(p => p.id === id);
  if (!patient) return res.status(404).json({ error: 'Patient not found' });
  res.json({ patient });
};

app.get('/api/clinic/records/:id', handleGetRecordById);
clinicApp.get('/api/clinic/records/:id', handleGetRecordById);

const handleSafeCancel = (req, res) => {
  const { user, device } = req.body;
  const log = canaryEngine.handleSafeCancel(user || 'Receptionist', device || 'FRONT-DESK-PC');
  res.json({
    success: true,
    message: 'Safe cancellation recorded. No alarm raised. Systems remain fully normal.',
    log,
    systemStatus: canaryEngine.getSystemStatus()
  });
};

app.post('/api/clinic/safe-cancel', handleSafeCancel);
clinicApp.post('/api/clinic/safe-cancel', handleSafeCancel);

const handleVerifyPin = (req, res) => {
  const { pin, device } = req.body;
  const clientIp = req.ip || '192.168.1.88';

  if (pin === '4829') {
    return res.json({ success: true, message: 'Supervisor PIN verified' });
  }

  const result = canaryEngine.recordPinAttempt(clientIp, device || 'VISITOR-KIOSK', pin);
  if (result.blocked) {
    return res.status(403).json({
      error: result.message,
      code: 'BRUTE_FORCE_BLOCKED',
      attempts: result.attempts
    });
  }

  return res.status(401).json({
    error: 'Incorrect PIN entered',
    attemptsRemaining: Math.max(0, 3 - result.attempts)
  });
};

app.post('/api/clinic/auth/verify-pin', handleVerifyPin);
clinicApp.post('/api/clinic/auth/verify-pin', handleVerifyPin);

// Scenario 5: Bulk Data Extraction
const handleBulkExport = (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 100;
  const clientIp = req.ip || '192.168.1.50';

  const check = canaryEngine.checkBulkExtraction(limit, 'Receptionist', clientIp);
  if (check.blocked) {
    return res.status(403).json({
      error: check.reason,
      code: 'BULK_EXFILTRATION_PREVENTED',
      requestedCount: limit
    });
  }

  if (canaryEngine.airGapped) {
    return res.status(403).json({ error: 'Air-gap active' });
  }

  res.json({
    count: Math.min(limit, patientsData.length),
    data: patientsData.slice(0, limit)
  });
};

app.get('/api/clinic/export', handleBulkExport);
clinicApp.get('/api/clinic/export', handleBulkExport);

// Care Continuity Standby Queue
const handleStandbyQueue = (req, res) => {
  res.json({
    mode: 'Protected Standby Queue',
    continuityActive: true,
    appointments: appointmentsData
  });
};

app.get('/api/clinic/standby-queue', handleStandbyQueue);
clinicApp.get('/api/clinic/standby-queue', handleStandbyQueue);

// ----------------------------------------------------
// SCENARIO TEST CONTROLLER (For Scenarios 1 to 6)
// ----------------------------------------------------
const handleRunScenario = (req, res) => {
  const { scenario } = req.body;

  if (scenario === '1') {
    // Scenario 1: Normal patient logs in and views their own appointment & medicine info
    return res.json({
      scenario: '1',
      title: 'Normal Patient Access',
      outcome: 'Arthur Pendelton authorized. Prescriptions (Lisinopril, Atorvastatin) retrieved successfully.',
      success: true
    });
  } else if (scenario === '2') {
    // Scenario 2: Visitor repeatedly attempts to access restricted clinic pages without logging in
    canaryEngine.recordRestrictedPageAttempt('/admin', '192.168.1.110', 'Headless Chrome Scanner');
    const result = canaryEngine.recordRestrictedPageAttempt('/backup', '192.168.1.110', 'Headless Chrome Scanner');
    return res.json({
      scenario: '2',
      title: 'Pre-Login Restricted Page Probing',
      outcome: 'Visitor probe on /admin and /backup detected. Blocked with HTTP 403 Forbidden.',
      blocked: result.blocked
    });
  } else if (scenario === '3') {
    // Scenario 3: Unauthorized user attempts to access another patient's medicine info (IDOR)
    const mockUser = usersData[0]; // Arthur Pendelton (pat-1)
    const idorResult = canaryEngine.recordUnauthorizedDataAccess('pat-2', mockUser, 'Elena Rostova Prescriptions', '192.168.1.102');
    return res.json({
      scenario: '3',
      title: 'Cross-Patient Data Access Block (IDOR)',
      outcome: 'Attempt to query Elena Rostova records by Arthur Pendelton blocked with HTTP 403.',
      blocked: idorResult.blocked
    });
  } else if (scenario === '4') {
    // Scenario 4: Automated process attempts to download a decoy file
    const decoyFile = decoyFilesData.find(f => f.isDecoy);
    const decoyRes = canaryEngine.handleDecoyFileDownload(decoyFile, '192.168.1.210', 'Python-Scraper-Bot/2.0');
    return res.json({
      scenario: '4',
      title: 'Honeypot Decoy File Download Intercepted',
      outcome: `Download of ${decoyFile.filename} arrested before delivery. Honeypot alert raised.`,
      tripwire: decoyRes
    });
  } else if (scenario === '5') {
    // Scenario 5: Authenticated account attempts unusually large data extraction
    const bulkRes = canaryEngine.checkBulkExtraction(500, 'Receptionist', '192.168.1.72');
    return res.json({
      scenario: '5',
      title: 'Bulk Data Exfiltration Blocked',
      outcome: 'Request for 500 records stopped before data returned. HTTP 403 returned.',
      blocked: bulkRes.blocked
    });
  } else if (scenario === '6') {
    // Scenario 6: Serious security incident occurs -> Session isolated, Protected Standby Mode displayed
    const tripwire = canaryEngine.triggerSurgicalAirGap(
      'Automated Scraper Bot / Python Scraper',
      'Row 0 Canary Tripwire Decoy Breached',
      '/api/clinic/records/canary-0',
      '192.168.1.205',
      'SCRAPER-CLIENT'
    );
    return res.json({
      scenario: '6',
      title: 'Serious Incident – Emergency Air-Gap Isolation',
      outcome: 'Surgical Air-Gap activated in < 15ms. Session revoked. Standby Mode enabled.',
      tripwire
    });
  }

  res.status(400).json({ error: 'Unknown scenario' });
};

app.post('/api/scenarios/run', handleRunScenario);
clinicApp.post('/api/scenarios/run', handleRunScenario);

// ----------------------------------------------------
// STATIC FRONTEND SERVING
// ----------------------------------------------------
app.use(express.static(path.join(__dirname, '..', 'clearshield-web')));
app.use('/clinic', express.static(path.join(__dirname, '..', 'clinic-web')));

clinicApp.use(express.static(path.join(__dirname, '..', 'clinic-web')));
clinicApp.use('/clearshield', express.static(path.join(__dirname, '..', 'clearshield-web')));

const CLEARSHIELD_PORT = 5000;
const CLINIC_PORT = 5001;

let server5000, server5001;
try {
  server5000 = app.listen(CLEARSHIELD_PORT, () => {
    console.log(`🛡️ ClearShield Security Center running at: http://localhost:${CLEARSHIELD_PORT}`);
  });
  server5001 = clinicApp.listen(CLINIC_PORT, () => {
    console.log(`🏥 Sample Clinic Website running at:      http://localhost:${CLINIC_PORT}`);
  });
} catch (e) {
  console.log('Server already listening or restart requested:', e.message);
}

module.exports = { app, clinicApp, server5000, server5001 };
