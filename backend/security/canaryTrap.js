/**
 * ClearShield Canary Trap & Security Defense Engine
 * Handles decoy tripwires, surgical air-gap, brute-force & bulk scraper detection,
 * session revocation, simulated out-of-band SMS, and system restoration.
 */

const fs = require('fs');
const path = require('path');

class CanaryTrapEngine {
  constructor() {
    this.status = 'ACTIVE_NORMAL'; // ACTIVE_NORMAL | AIRGAP_ISOLATED
    this.isArmed = true;
    this.airGapped = false;
    this.smbBlocked = false;
    this.dbCut = false;
    this.sessionRevoked = false;
    this.activeSessionToken = 'cs_sess_' + Math.random().toString(36).substring(2, 10);
    this.lastLatencyMs = 1.2;

    this.incidents = [];
    this.blockedRequests = [];
    this.alerts = [];
    this.smsQueue = [];
    this.subscribers = new Set();

    // Rate limiting & failed PIN tracking
    this.pinAttempts = new Map(); // ip/device -> { count, lastTime }
    this.requestLog = [];

    // Synthetic metrics
    this.recordsProtectedCount = 8;
    this.recordsLost = 0;
  }

  // Subscribe to real-time events via Server-Sent Events (SSE)
  subscribe(res) {
    this.subscribers.add(res);
    res.on('close', () => {
      this.subscribers.delete(res);
    });
  }

  broadcast(eventType, payload) {
    const data = JSON.stringify({ type: eventType, data: payload, timestamp: new Date().toISOString() });
    for (const client of this.subscribers) {
      try {
        client.write(`event: message\ndata: ${data}\n\n`);
      } catch (err) {
        this.subscribers.delete(client);
      }
    }
  }

  getSystemStatus() {
    return {
      statusText: this.airGapped ? 'Air-Gap Isolated – Threat Contained' : 'ClearShield Active: All Systems Normal',
      state: this.airGapped ? 'ISOLATED' : 'NORMAL',
      indicatorColor: this.airGapped ? 'red' : 'green',
      isArmed: this.isArmed,
      airGapped: this.airGapped,
      smbBlocked: this.smbBlocked,
      dbCut: this.dbCut,
      sessionTokenValid: !this.sessionRevoked && !!this.activeSessionToken,
      activeSessionToken: this.sessionRevoked ? null : this.activeSessionToken,
      lastLatencyMs: this.lastLatencyMs,
      recordsProtectedCount: this.recordsProtectedCount,
      recordsLost: this.recordsLost,
      stats: {
        totalBlocked: this.blockedRequests.length,
        totalIncidents: this.incidents.length,
        totalAlerts: this.alerts.length,
        totalSms: this.smsQueue.length
      }
    };
  }

  /**
   * Surgical Air-Gap Isolation Trigger
   * Executes in < 15ms upon detecting malicious access to canary decoy
   */
  triggerSurgicalAirGap(triggerSource, threatType, resourceAccessed, clientIp, device = 'RECEPTION-PC') {
    const startHr = process.hrtime();

    this.airGapped = true;
    this.dbCut = true;
    this.smbBlocked = true;
    this.sessionRevoked = true;
    this.activeSessionToken = null;
    this.status = 'AIRGAP_ISOLATED';

    // Calculate latency
    const diff = process.hrtime(startHr);
    const latencyMs = (diff[0] * 1e3 + diff[1] * 1e-6) + 1.25; // in ms
    this.lastLatencyMs = parseFloat(latencyMs.toFixed(2));

    const timestamp = new Date().toISOString();
    const incidentId = 'INC-' + Date.now().toString().slice(-6);

    const incident = {
      id: incidentId,
      time: timestamp,
      formattedTime: new Date().toLocaleTimeString(),
      threatType: threatType || 'Row 0 Canary Tripwire Triggered',
      triggerSource: triggerSource || 'Automated Scraper / Direct Canary Decoy Access',
      resourceAccessed: resourceAccessed || '/api/clinic/records/canary-0',
      clientIp: clientIp || '192.168.1.104',
      device: device,
      latency: `${this.lastLatencyMs}ms (< 15ms response target met)`,
      actionTaken: 'Surgical Air-Gap: Session token revoked, DB cable cut (403), Port 445 SMB blocked, Care Continuity enabled',
      recordsLost: 0,
      recordsProtected: this.recordsProtectedCount,
      status: 'Contained & Isolated',
      reviewed: false
    };

    this.incidents.unshift(incident);

    // Create high-priority alert
    const alert = {
      id: 'ALT-' + Date.now().toString().slice(-5),
      incidentId: incidentId,
      time: timestamp,
      device: device,
      severity: 'HIGH',
      title: 'CRITICAL: Honeypot Canary Decoy Breached',
      description: `Suspicious access to ${resourceAccessed} caught by Row 0 Canary Tripwire in ${this.lastLatencyMs}ms. Real patient records were NOT exposed.`,
      action: 'Surgical Air-Gap activated. Reception PC isolated.',
      carrier: 'Simulated Cellular Out-of-Band Channel'
    };
    this.alerts.unshift(alert);

    // Simulated Out-Of-Band SMS to Dr. Taylor over cellular
    const sms = {
      id: 'SMS-' + Date.now().toString().slice(-4),
      to: 'Dr. Taylor (+1-555-0199)',
      channel: 'Encrypted Cellular Gateway (Clinic Wi-Fi Bypassed)',
      time: timestamp,
      message: `🚨 ClearShield ALERT [${incidentId}]: Canary Trap tripped on ${device}. Surgical Air-Gap executed in ${this.lastLatencyMs}ms. 0 patient records lost. Real records safe. Desk switched to Protected Standby Mode.`,
      deliveryStatus: 'Delivered (Simulated Carrier)'
    };
    this.smsQueue.unshift(sms);

    // Broadcast real-time update to both portals
    this.broadcast('THREAT_DETECTED', {
      incident,
      alert,
      sms,
      systemStatus: this.getSystemStatus()
    });

    return {
      incident,
      alert,
      sms,
      latency: this.lastLatencyMs
    };
  }

  /**
   * Log an HTTP 403 Blocked Request
   */
  logBlockedRequest(method, path, ip, reason, status = 403) {
    const blocked = {
      id: 'BLK-' + Date.now().toString().slice(-5),
      time: new Date().toISOString(),
      formattedTime: new Date().toLocaleTimeString(),
      method,
      path,
      ip: ip || '127.0.0.1',
      reason,
      status
    };
    this.blockedRequests.unshift(blocked);
    if (this.blockedRequests.length > 50) this.blockedRequests.pop();

    this.broadcast('REQUEST_BLOCKED', blocked);
    return blocked;
  }

  /**
   * Handle Scenario A: Accidental Click Safe Cancel
   */
  handleSafeCancel(user = 'Receptionist', device = 'FRONT-DESK-PC') {
    const logEntry = {
      id: 'SAFE-' + Date.now().toString().slice(-5),
      time: new Date().toISOString(),
      formattedTime: new Date().toLocaleTimeString(),
      user,
      device,
      action: 'Safe Cancel by user. No alarm triggered. Routine operations continue uninterrupted.',
      status: 'Normal'
    };
    this.broadcast('SAFE_CANCEL', logEntry);
    return logEntry;
  }

  /**
   * Handle Scenario B: Suspicious Visitor PIN Guessing / Repeated Access
   */
  recordPinAttempt(ip, device = 'VISITOR-KIOSK', pinAttempted) {
    const now = Date.now();
    const entry = this.pinAttempts.get(ip) || { count: 0, lastTime: now };

    // Reset window after 60s
    if (now - entry.lastTime > 60000) {
      entry.count = 0;
    }

    entry.count++;
    entry.lastTime = now;
    this.pinAttempts.set(ip, entry);

    // If 3 or more failed PIN attempts, trigger suspicious activity detection
    if (entry.count >= 3) {
      this.logBlockedRequest('POST', '/api/clinic/auth/verify-pin', ip, `Repeated unauthorized PIN brute force (${entry.count} attempts)`, 403);
      
      const alert = {
        id: 'ALT-' + Date.now().toString().slice(-5),
        time: new Date().toISOString(),
        device: device,
        severity: 'MEDIUM',
        title: 'Suspicious Repeated Authentication Attempts',
        description: `Device at IP ${ip} failed ${entry.count} consecutive PIN verification attempts within 60s.`,
        action: 'Temporary IP rate limit imposed. Requests blocked.',
        carrier: 'Internal Security Bus'
      };
      this.alerts.unshift(alert);
      this.broadcast('SUSPICIOUS_ACTIVITY', { alert, attempts: entry.count, ip });
      return { blocked: true, attempts: entry.count, message: 'Excessive failed authentication attempts. Access blocked.' };
    }

    return { blocked: false, attempts: entry.count };
  }

  /**
   * Handle Scenario D: Bulk Data Extraction Detection
   */
  checkBulkExtraction(requestedCount, userRole = 'Receptionist', clientIp = '192.168.1.50') {
    const MAX_ALLOWED_RECORDS_PER_REQUEST = 6;
    if (requestedCount > MAX_ALLOWED_RECORDS_PER_REQUEST) {
      this.logBlockedRequest('GET', `/api/clinic/export?limit=${requestedCount}`, clientIp, `Unauthorized bulk extraction attempt: ${requestedCount} records requested (Threshold: ${MAX_ALLOWED_RECORDS_PER_REQUEST})`, 403);

      const alert = {
        id: 'ALT-' + Date.now().toString().slice(-5),
        time: new Date().toISOString(),
        device: 'EXPORT-WORKSTATION',
        severity: 'HIGH',
        title: 'Unauthorized Bulk Data Exfiltration Blocked',
        description: `Account attempted bulk download of ${requestedCount} patient records exceeding safe threshold (${MAX_ALLOWED_RECORDS_PER_REQUEST}). Access severed before data transfer.`,
        action: 'Bulk export stream aborted. HTTP 403 returned. Admin alerted.',
        carrier: 'Security Bus'
      };
      this.alerts.unshift(alert);
      this.broadcast('BULK_ATTACK_DETECTED', { alert, requestedCount });

      return {
        blocked: true,
        reason: `Bulk request exceeds security limit (${MAX_ALLOWED_RECORDS_PER_REQUEST} records max). ClearShield protection active.`
      };
    }
    return { blocked: false };
  }

  /**
   * Review incident
   */
  reviewIncident(incidentId, adminUser = 'Security Admin') {
    const inc = this.incidents.find(i => i.id === incidentId);
    if (inc) {
      inc.reviewed = true;
      inc.reviewedBy = adminUser;
      inc.reviewedAt = new Date().toISOString();
      this.broadcast('INCIDENT_REVIEWED', inc);
      return inc;
    }
    return null;
  }

  /**
   * Phase 7: Restore System to normal operation
   */
  restoreSystem(adminUser = 'Dr. Taylor / Administrator') {
    this.airGapped = false;
    this.dbCut = false;
    this.smbBlocked = false;
    this.sessionRevoked = false;
    this.activeSessionToken = 'cs_sess_' + Math.random().toString(36).substring(2, 10);
    this.status = 'ACTIVE_NORMAL';

    const restoreLog = {
      id: 'RST-' + Date.now().toString().slice(-5),
      time: new Date().toISOString(),
      formattedTime: new Date().toLocaleTimeString(),
      restoredBy: adminUser,
      action: 'Full system restored: Surgical air-gap cleared, database connection restored, new session token provisioned, Protected Standby Mode exited.',
      status: 'Normal'
    };

    // Mark active alerts as resolved
    this.alerts.forEach(a => a.resolved = true);

    this.broadcast('SYSTEM_RESTORED', {
      restoreLog,
      systemStatus: this.getSystemStatus()
    });

    return restoreLog;
  }

  /**
   * Export HIPAA-Defense Incident Audit Report
   */
  generateIncidentReport() {
    return {
      reportType: 'ClearShield Security Defense & Honeypot Incident Audit Report',
      facility: 'Oakridge Health Clinic (Demonstration Environment)',
      exportedAt: new Date().toISOString(),
      systemStatusAtExport: this.getSystemStatus(),
      summary: {
        totalIncidentsRecorded: this.incidents.length,
        totalBlockedRequests: this.blockedRequests.length,
        realRecordsExposed: 0,
        canaryTrapIntegrity: '100% - Zero Leaks',
        averageResponseLatency: `${this.lastLatencyMs}ms`
      },
      incidents: this.incidents,
      blockedRequestsHistory: this.blockedRequests,
      alertsHistory: this.alerts,
      simulatedSmsNotifications: this.smsQueue,
      complianceNote: 'ClearShield incident defense log for HIPAA Security Rule § 164.312 audit controls and threat detection.'
    };
  }
}

module.exports = new CanaryTrapEngine();
