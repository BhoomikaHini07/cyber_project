/**
 * Comprehensive Automated Test Suite for ClearShield Healthcare Cybersecurity Platform
 * Validates all 6 Demonstration Scenarios required by specification:
 * - Scenario 1: Normal patient login & authorized medicine retrieval
 * - Scenario 2: Pre-login restricted route probing (/admin, /backup, /database)
 * - Scenario 3: Cross-patient unauthorized medicine query (IDOR protection)
 * - Scenario 4: Automated decoy file download interception
 * - Scenario 5: Large bulk data extraction volume guard
 * - Scenario 6: Serious security incident & Protected Standby Care Continuity
 */

const http = require('http');

const PORT_CLEARSHIELD = 5000;
const PORT_CLINIC = 5001;

function request(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = data ? JSON.parse(data) : {};
          resolve({ status: res.statusCode, headers: res.headers, data: parsed, raw: data });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, data, raw: data });
        }
      });
    });
    req.on('error', reject);
    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runTests() {
  console.log('================================================================');
  console.log('🧪 CLEARSHIELD HEALTHCARE CYBERSECURITY - 6 SCENARIO SUITE');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✅ PASS: ${message}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${message}`);
      failed++;
    }
  }

  try {
    // -------------------------------------------------------------------------
    // Phase 1: Baseline Health & Connectivity
    // -------------------------------------------------------------------------
    console.log('--- Phase 1: Baseline Health & Connection ---');
    const statusRes = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/status',
      method: 'GET'
    });
    assert(statusRes.status === 200, 'ClearShield status returns 200 OK');
    assert(statusRes.data.statusText.includes('ClearShield is Active'), 'System notification: "ClearShield is Active – All Systems Normal"');
    assert(statusRes.data.indicatorColor === 'green', 'Ambient status is Green');
    assert(statusRes.data.airGapped === false, 'System initially not air-gapped');

    // -------------------------------------------------------------------------
    // SCENARIO 1: Normal Patient Auth & Own Medicine/Appointment Access
    // -------------------------------------------------------------------------
    console.log('\n--- Scenario 1: Normal Patient Login & Prescriptions Access ---');
    const loginRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {
      email: 'arthur.pendelton@example.com',
      password: 'Password123!',
      loginType: 'password'
    });
    assert(loginRes.status === 200, 'Patient Arthur Pendelton login succeeds');
    assert(!!loginRes.data.sessionToken, 'Session token issued');
    const arthurToken = loginRes.data.sessionToken;

    // View own prescriptions
    const rxRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/patient/prescriptions',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${arthurToken}` }
    });
    assert(rxRes.status === 200, 'Authorized query for Arthur prescriptions succeeds');
    assert(Array.isArray(rxRes.data.prescriptions) && rxRes.data.prescriptions.length > 0, 'Returns Arthur permitted medicine records (Lisinopril, Atorvastatin)');
    assert(rxRes.data.prescriptions.every(r => r.patientId === 'pat-1'), 'All returned medicines strictly belong to authenticated patient (pat-1)');

    // -------------------------------------------------------------------------
    // SCENARIO 2: Pre-Login Restricted Route Probing Blocked
    // -------------------------------------------------------------------------
    console.log('\n--- Scenario 2: Pre-Login Probes on /admin, /backup, /database ---');
    const probe1 = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/admin',
      method: 'GET'
    });
    assert(probe1.status === 403, 'Pre-login GET /admin is intercepted with HTTP 403 Forbidden');
    assert(probe1.data.code === 'PRE_LOGIN_PROBE_BLOCKED', 'Flagged as PRE_LOGIN_PROBE_BLOCKED');

    const probe2 = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/backup',
      method: 'GET'
    });
    assert(probe2.status === 403, 'Pre-login GET /backup is intercepted with HTTP 403 Forbidden');

    const threatCheck = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/threats/pre-login',
      method: 'GET'
    });
    assert(threatCheck.data.length >= 2, 'Pre-login reconnaissance attempts logged on ClearShield Threat Monitoring');

    // -------------------------------------------------------------------------
    // SCENARIO 3: Cross-Patient IDOR Medicine Query Denied & Recorded
    // -------------------------------------------------------------------------
    console.log('\n--- Scenario 3: Cross-Patient Medicine Query (IDOR Defense) ---');
    // Arthur (pat-1) attempts to query Elena Rostova (pat-2) medicines
    const idorRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/patient/pat-2/prescriptions',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${arthurToken}` }
    });
    assert(idorRes.status === 403, 'Unauthorized cross-patient query is DENIED with HTTP 403 Forbidden');
    assert(idorRes.data.code === 'UNAUTHORIZED_CROSS_PATIENT_ACCESS', 'Code is UNAUTHORIZED_CROSS_PATIENT_ACCESS');

    // Check Data Protection audit log
    const dpCheck = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/data-protection/events',
      method: 'GET'
    });
    assert(dpCheck.data.length > 0, 'IDOR incident logged in ClearShield Data Protection registry');
    assert(dpCheck.data[0].targetPatientId === 'pat-2', 'Logged target patient ID matches target');

    // -------------------------------------------------------------------------
    // SCENARIO 4: Honeypot Decoy File Download Stopped at Byte 0
    // -------------------------------------------------------------------------
    console.log('\n--- Scenario 4: Automated Decoy File Download Interception ---');
    const decoyStart = Date.now();
    const decoyRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/files/download/file-decoy-1',
      method: 'GET',
      headers: { 'User-Agent': 'Automated Scraper Bot / 1.0' }
    });
    const decoyElapsed = Date.now() - decoyStart;

    assert(decoyRes.status === 403, 'Decoy file download halted before delivery with HTTP 403 Forbidden');
    assert(decoyRes.data.code === 'HONEYPOT_DECOY_BLOCKED', 'Code is HONEYPOT_DECOY_BLOCKED');
    console.log(`  ⏱️ Decoy Interception Latency: ${decoyRes.data.latency} (Roundtrip: ${decoyElapsed}ms)`);

    // Verify Honeypot Monitoring registry
    const hpCheck = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/honeypot/events',
      method: 'GET'
    });
    assert(hpCheck.data.events.length > 0, 'Honeypot event logged on ClearShield Page 3 (Honeypot Monitoring)');

    // -------------------------------------------------------------------------
    // SCENARIO 5: Bulk Data Extraction Volume Check
    // -------------------------------------------------------------------------
    console.log('\n--- Scenario 5: Large Bulk Data Extraction Volume Guard ---');
    const bulkRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/export?limit=500',
      method: 'GET'
    });
    assert(bulkRes.status === 403, 'Request for 500 patient records blocked with HTTP 403 Forbidden');
    assert(bulkRes.data.code === 'BULK_EXFILTRATION_PREVENTED', 'Code is BULK_EXFILTRATION_PREVENTED');

    // -------------------------------------------------------------------------
    // SCENARIO 6: Serious Incident – Session Isolated & Protected Standby
    // -------------------------------------------------------------------------
    console.log('\n--- Scenario 6: Serious Incident – Surgical Air-Gap & Continuity ---');
    const canaryRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/records/canary-0',
      method: 'GET',
      headers: { 'User-Agent': 'Automated Scraper Bot / 1.0' }
    });
    assert(canaryRes.status === 403, 'Row 0 Canary Tripwire tripped with HTTP 403');
    assert(canaryRes.data.code === 'CANARY_TRIPWIRE_TRIGGERED', 'Code is CANARY_TRIPWIRE_TRIGGERED');

    // Verify Air-Gap and Standby Telemetry
    const airgapStatus = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/status',
      method: 'GET'
    });
    assert(airgapStatus.data.airGapped === true, 'Surgical Air-Gap state active');
    assert(airgapStatus.data.indicatorColor === 'red', 'Status pill turned RED');
    assert(airgapStatus.data.smbBlocked === true, 'Port 445 (SMB) blocked to prevent lateral movement');
    assert(airgapStatus.data.sessionTokenValid === false, 'Session token revoked & invalidated');
    assert(airgapStatus.data.recordsLost === 0, 'Zero patient records lost');

    // Verify Care Continuity Queue Available
    const queueRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/standby-queue',
      method: 'GET'
    });
    assert(queueRes.status === 200, 'Care Continuity offline appointment queue accessible');
    assert(queueRes.data.appointments.length > 0, 'Emergency queue has pre-cached appointments');

    // Verify Normal Patient Query is Blocked while Air-Gapped
    const blockedQuery = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/records',
      method: 'GET'
    });
    assert(blockedQuery.status === 403, 'Real patient database query blocked during air-gap');

    // Verify Simulated Cellular SMS Spooled for Dr. Taylor
    const smsRes = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/sms',
      method: 'GET'
    });
    assert(smsRes.data.length > 0, 'Simulated Out-of-band cellular SMS spooled');
    assert(smsRes.data[0].to.includes('Dr. Taylor'), 'Recipient is Dr. Taylor');

    // -------------------------------------------------------------------------
    // Phase 7: Audit Report & System Restoration
    // -------------------------------------------------------------------------
    console.log('\n--- Phase 7: Regulatory Audit Defense & Restoration ---');
    const reportRes = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/export-report',
      method: 'GET'
    });
    assert(reportRes.status === 200, 'Security incident defense report generated');
    assert(reportRes.data.summary.realRecordsExposed === 0, 'Report certifies 0 real records exposed');

    const restoreRes = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/restore',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { adminUser: 'Dr. Taylor (Chief Medical Officer)' });
    assert(restoreRes.status === 200, 'System restoration authorized by Dr. Taylor');
    assert(restoreRes.data.status.airGapped === false, 'Air-gap cleared');
    assert(restoreRes.data.status.indicatorColor === 'green', 'Status restored to Green: "ClearShield is Active – All Systems Normal"');

    console.log('\n================================================================');
    console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
    console.log('================================================================\n');

    process.exit(failed > 0 ? 1 : 0);
  } catch (err) {
    console.error('Test execution error:', err);
    process.exit(1);
  }
}

runTests();
