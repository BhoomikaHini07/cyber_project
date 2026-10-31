const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const canaryEngine = require('./security/canaryTrap');

const patientsData = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'patients.json'), 'utf8'));
const appointmentsData = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'appointments.json'), 'utf8'));

// Main API & ClearShield Dashboard App (Port 5000)
const app = express();
app.use(cors());
app.use(express.json());

// Sample Clinic App (Port 5001)
const clinicApp = express();
clinicApp.use(cors());
clinicApp.use(express.json());

// ----------------------------------------------------
// REAL-TIME SERVER-SENT EVENTS (SSE)
// ----------------------------------------------------
app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.write(`data: ${JSON.stringify({ type: 'INIT', data: canaryEngine.getSystemStatus() })}\n\n`);
  canaryEngine.subscribe(res);
});

// Also allow SSE via clinic port
clinicApp.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.write(`data: ${JSON.stringify({ type: 'INIT', data: canaryEngine.getSystemStatus() })}\n\n`);
  canaryEngine.subscribe(res);
});

// ----------------------------------------------------
// CLEARSHIELD SECURITY CENTER APIS
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

app.get('/api/clearshield/export-report', (req, res) => {
  const report = canaryEngine.generateIncidentReport();
  const format = req.query.format || 'json';

  if (format === 'csv') {
    // Generate CSV version of incidents
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

// ----------------------------------------------------
// CLINIC PORTAL APIS
// ----------------------------------------------------

// 1. Get Clinic Records
const handleGetRecords = (req, res) => {
  // If air-gapped or DB cable severed, block protected data request
  if (canaryEngine.airGapped || canaryEngine.dbCut) {
    canaryEngine.logBlockedRequest('GET', '/api/clinic/records', req.ip, 'Surgical Air-Gap Active: Database Cable Severed', 403);
    return res.status(403).json({
      error: 'Access Denied: Clinic is in Protected Standby Mode due to threat isolation.',
      code: 'SURGICAL_AIRGAP_ACTIVE',
      status: 'STANDBY_MODE'
    });
  }

  // Check session token validity
  const authHeader = req.headers['authorization'];
  if (canaryEngine.sessionRevoked) {
    canaryEngine.logBlockedRequest('GET', '/api/clinic/records', req.ip, 'Invalidated Session Token used', 403);
    return res.status(403).json({
      error: 'Session Revoked by ClearShield Security Monitor',
      code: 'SESSION_REVOKED'
    });
  }

  // Return dataset including Row 0 Canary Decoy
  res.json({
    activeSessionToken: canaryEngine.activeSessionToken,
    records: patientsData
  });
};

app.get('/api/clinic/records', handleGetRecords);
clinicApp.get('/api/clinic/records', handleGetRecords);

// 2. Individual Record Access / Canary Tripwire Catch (<15ms)
const handleGetRecordById = (req, res) => {
  const { id } = req.params;

  // Check if target is Row 0 Canary Decoy
  if (id === 'canary-0' || id === 'CANARY-00-TRAP') {
    const clientIp = req.ip || req.connection.remoteAddress || '192.168.1.104';
    const device = req.headers['x-device-id'] || 'FRONT-DESK-PC';
    const triggerSource = req.headers['user-agent']?.includes('Scraper') ?
      'Automated Bulk Scraper Process' : 'Unauthorized Decoy Query Attempt';

    // TRIGGER SURGICAL AIR-GAP IMMEDIATELY (<15ms)
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

  // If system is air-gapped, block real records
  if (canaryEngine.airGapped || canaryEngine.dbCut) {
    canaryEngine.logBlockedRequest('GET', `/api/clinic/records/${id}`, req.ip, 'Real record requested while air-gapped', 403);
    return res.status(403).json({
      error: 'Database cable disconnected. Standby mode active.',
      code: 'AIRGAP_BLOCKED'
    });
  }

  const patient = patientsData.find(p => p.id === id);
  if (!patient) {
    return res.status(404).json({ error: 'Patient not found' });
  }

  res.json({ patient });
};

app.get('/api/clinic/records/:id', handleGetRecordById);
clinicApp.get('/api/clinic/records/:id', handleGetRecordById);

// 3. Scenario A: Accidental Click Safe Cancel
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

// 4. Scenario B: PIN Verification / Suspicious Visitor Brute Force
const handleVerifyPin = (req, res) => {
  const { pin, device } = req.body;
  const clientIp = req.ip || '192.168.1.88';

  // Valid reception supervisor PIN is "4829"
  if (pin === '4829') {
    return res.json({ success: true, message: 'Supervisor PIN verified' });
  }

  // Record attempt and test brute-force threshold
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

// 5. Scenario D: Bulk Data Extraction
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

  // If within threshold and not air-gapped, return slice of synthetic records
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

// 6. Phase 4: Standby Appointments Queue (Care Continuity)
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
// SCENARIO TEST CONTROLLER (For automated and quick testing)
// ----------------------------------------------------
const handleRunScenario = (req, res) => {
  const { scenario } = req.body;

  if (scenario === 'A') {
    // Scenario A: Normal receptionist accidental click followed by safe cancel
    const log = canaryEngine.handleSafeCancel('Jane (Receptionist)', 'RECEPTION-PC');
    return res.json({
      scenario: 'A',
      title: 'Normal Receptionist – Safe Accidental Click',
      outcome: 'No alarm triggered. Status remains green: ClearShield Active.',
      systemStatus: canaryEngine.getSystemStatus(),
      log
    });
  } else if (scenario === 'B') {
    // Scenario B: Suspicious visitor repeatedly guessing PIN
    canaryEngine.recordPinAttempt('192.168.1.188', 'GUEST-KIOSK', '1111');
    canaryEngine.recordPinAttempt('192.168.1.188', 'GUEST-KIOSK', '2222');
    const bRes = canaryEngine.recordPinAttempt('192.168.1.188', 'GUEST-KIOSK', '3333');
    return res.json({
      scenario: 'B',
      title: 'Suspicious Visitor – PIN Brute Force Detected',
      outcome: '3 repeated invalid attempts flagged. Blocked with HTTP 403.',
      blocked: bRes.blocked,
      systemStatus: canaryEngine.getSystemStatus()
    });
  } else if (scenario === 'C') {
    // Scenario C: Canary Trap triggered by automated scraper hitting Row 0 Canary
    const tripwire = canaryEngine.triggerSurgicalAirGap(
      'Automated Scraper Bot / Python Scraper',
      'Row 0 Canary Tripwire Decoy Breached',
      '/api/clinic/records/canary-0',
      '192.168.1.205',
      'SCRAPER-CLIENT'
    );
    canaryEngine.logBlockedRequest('GET', '/api/clinic/records/canary-0', '192.168.1.205', 'Tripwire Caught Scraper - Real Data Shielded', 403);
    return res.json({
      scenario: 'C',
      title: 'Canary Trap – Automated Scraper Blocked',
      outcome: 'Canary tripwire intercepted request in < 15ms. Surgical Air-Gap engaged.',
      tripwire,
      systemStatus: canaryEngine.getSystemStatus()
    });
  } else if (scenario === 'D') {
    // Scenario D: Bulk data exfiltration attempt
    const dRes = canaryEngine.checkBulkExtraction(250, 'Receptionist', '192.168.1.72');
    return res.json({
      scenario: 'D',
      title: 'Bulk Data Exfiltration Blocked',
      outcome: 'Request for 250 records halted before data returned. HTTP 403 returned.',
      blocked: dRes.blocked,
      systemStatus: canaryEngine.getSystemStatus()
    });
  }

  res.status(400).json({ error: 'Unknown scenario' });
};

app.post('/api/scenarios/run', handleRunScenario);
clinicApp.post('/api/scenarios/run', handleRunScenario);

// ----------------------------------------------------
// STATIC FRONTEND SERVING
// ----------------------------------------------------
// Serve ClearShield Security Dashboard on App (Port 5000)
app.use(express.static(path.join(__dirname, '..', 'clearshield-web')));

// Also allow browsing Clinic on /clinic from Port 5000
app.use('/clinic', express.static(path.join(__dirname, '..', 'clinic-web')));

// Serve Sample Clinic on Clinic App (Port 5001)
clinicApp.use(express.static(path.join(__dirname, '..', 'clinic-web')));

// Also allow browsing ClearShield on /clearshield from Port 5001
clinicApp.use('/clearshield', express.static(path.join(__dirname, '..', 'clearshield-web')));

// Start Servers
const CLEARSHIELD_PORT = 5000;
const CLINIC_PORT = 5001;

const server5000 = app.listen(CLEARSHIELD_PORT, () => {
  console.log(`🛡️ ClearShield Security Center running at: http://localhost:${CLEARSHIELD_PORT}`);
  console.log(`🔗 Clinic shortcut also available at:    http://localhost:${CLEARSHIELD_PORT}/clinic`);
});

const server5001 = clinicApp.listen(CLINIC_PORT, () => {
  console.log(`🏥 Sample Clinic Website running at:      http://localhost:${CLINIC_PORT}`);
  console.log(`🔗 ClearShield shortcut also at:         http://localhost:${CLINIC_PORT}/clearshield`);
});

module.exports = { app, clinicApp, server5000, server5001 };
