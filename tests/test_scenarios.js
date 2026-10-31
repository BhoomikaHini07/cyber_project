/**
 * Automated Test Suite for ClearShield Canary Trap & Honeypot
 * Validates all 4 Demonstration Scenarios and Restoration Flow
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
  console.log('====================================================');
  console.log('🧪 RUNNING CLEARSHIELD CANARY TRAP INTEGRATION TESTS');
  console.log('====================================================\n');

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
    // 1. Initial State Check (Phase 1: Armed & Ready)
    console.log('--- Phase 1: Checking Armed & Ready Status ---');
    const statusRes = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/status',
      method: 'GET'
    });
    assert(statusRes.status === 200, 'ClearShield status returns 200 OK');
    assert(statusRes.data.isArmed === true, 'Canary trap is ARMED');
    assert(statusRes.data.airGapped === false, 'System is not air-gapped initially');
    assert(statusRes.data.indicatorColor === 'green', 'Status indicator is GREEN: "ClearShield Active"');

    // 2. Scenario A: Normal Receptionist Access & Safe Cancel
    console.log('\n--- Scenario A: Normal Receptionist & Safe Cancel ---');
    const recordsRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/records',
      method: 'GET'
    });
    assert(recordsRes.status === 200, 'Normal clinic records query succeeds');
    assert(Array.isArray(recordsRes.data.records) && recordsRes.data.records.length > 0, 'Returns synthetic clinic records');
    assert(recordsRes.data.records[0].isCanary === true, 'Row 0 contains Canary Decoy record');

    const safeCancelRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/safe-cancel',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { user: 'Receptionist', device: 'RECEPTION-PC' });
    assert(safeCancelRes.status === 200, 'Safe cancel returns 200 OK');
    assert(safeCancelRes.data.systemStatus.indicatorColor === 'green', 'Ambient status remains GREEN with zero alarms');

    // 3. Scenario B: Suspicious Visitor PIN Guessing
    console.log('\n--- Scenario B: Suspicious Visitor PIN Brute Force ---');
    await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/auth/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { pin: '0001', device: 'VISITOR-KIOSK' });

    await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/auth/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { pin: '0002', device: 'VISITOR-KIOSK' });

    const pin3Res = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/auth/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { pin: '0003', device: 'VISITOR-KIOSK' });
    assert(pin3Res.status === 403, '3rd failed PIN attempt is blocked with HTTP 403 Forbidden');
    assert(pin3Res.data.code === 'BRUTE_FORCE_BLOCKED', 'Flagged with BRUTE_FORCE_BLOCKED code');

    // 4. Scenario D: Bulk Data Exfiltration Attempt
    console.log('\n--- Scenario D: Bulk Data Exfiltration Block ---');
    const bulkRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/export?limit=250',
      method: 'GET'
    });
    assert(bulkRes.status === 403, 'Bulk data request of 250 records blocked with HTTP 403');
    assert(bulkRes.data.code === 'BULK_EXFILTRATION_PREVENTED', 'Flagged as BULK_EXFILTRATION_PREVENTED');

    // 5. Scenario C: Canary Trap Triggered by Automated Scraper (<15ms catch)
    console.log('\n--- Scenario C: Canary Trap Tripwire Catch (<15ms) ---');
    const start = Date.now();
    const canaryRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/records/canary-0',
      method: 'GET',
      headers: { 'User-Agent': 'Automated Scraper Bot / 1.0' }
    });
    const elapsed = Date.now() - start;

    assert(canaryRes.status === 403, 'Access to Row 0 Canary returns HTTP 403 Forbidden');
    assert(canaryRes.data.code === 'CANARY_TRIPWIRE_TRIGGERED', 'Code is CANARY_TRIPWIRE_TRIGGERED');
    assert(canaryRes.data.airGapActive === true, 'Surgical Air-Gap activated');
    console.log(`  ⏱️ Canary Interception Latency: ${canaryRes.data.latency} (HTTP roundtrip: ${elapsed}ms)`);

    // Verify System Post-Tripwire State (Phases 3, 4, 5, 6)
    console.log('\n--- Post-Attack System Status Verification ---');
    const postStatusRes = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/status',
      method: 'GET'
    });
    assert(postStatusRes.data.airGapped === true, 'ClearShield is in AIR-GAPPED state');
    assert(postStatusRes.data.indicatorColor === 'red', 'Status indicator turned RED (Threat Contained)');
    assert(postStatusRes.data.smbBlocked === true, 'Port 445 (SMB) blocked to prevent lateral spread');
    assert(postStatusRes.data.sessionTokenValid === false, 'Session token revoked/invalidated');
    assert(postStatusRes.data.recordsLost === 0, 'Zero patient records lost (0 records exposed)');

    // Verify Care Continuity Queue (Phase 4)
    const queueRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/standby-queue',
      method: 'GET'
    });
    assert(queueRes.status === 200, 'Care Continuity Standby Queue available');
    assert(queueRes.data.appointments.length > 0, 'Appointments list accessible for paper check-in');

    // Verify Protected Records Blocked During Air-Gap
    const blockedQueryRes = await request({
      hostname: 'localhost',
      port: PORT_CLINIC,
      path: '/api/clinic/records',
      method: 'GET'
    });
    assert(blockedQueryRes.status === 403, 'Normal patient records query blocked (HTTP 403) while air-gapped');

    // Verify SMS Queue (Phase 5)
    const smsRes = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/sms',
      method: 'GET'
    });
    assert(smsRes.data.length > 0, 'Simulated Out-Of-Band SMS spooled for Dr. Taylor');
    assert(smsRes.data[0].to.includes('Dr. Taylor'), 'SMS recipient is Dr. Taylor');

    // 6. Phase 7: Audit Report & System Restoration
    console.log('\n--- Phase 7: Audit Report & Restoration ---');
    const reportRes = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/export-report',
      method: 'GET'
    });
    assert(reportRes.status === 200, 'Incident audit report export generated');
    assert(reportRes.data.summary.realRecordsExposed === 0, 'Audit report certifies 0 real records exposed');

    const restoreRes = await request({
      hostname: 'localhost',
      port: PORT_CLEARSHIELD,
      path: '/api/clearshield/restore',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { adminUser: 'Dr. Taylor (Chief Medical Officer)' });
    assert(restoreRes.status === 200, 'System restoration authorized and successful');
    assert(restoreRes.data.status.airGapped === false, 'Air-gap cleared');
    assert(restoreRes.data.status.indicatorColor === 'green', 'Ambient status restored to GREEN: "ClearShield Active: All Systems Normal"');

    console.log('\n====================================================');
    console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
    console.log('====================================================\n');

    process.exit(failed > 0 ? 1 : 0);
  } catch (err) {
    console.error('Test execution error:', err);
    process.exit(1);
  }
}

runTests();
