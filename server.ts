import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';

// Load environmental parameters
dotenv.config();

// Initialize the GoogleGenAI instance if key is present
let ai: GoogleGenAI | null = null;
const API_KEY = process.env.GEMINI_API_KEY;

if (API_KEY && API_KEY !== 'MY_GEMINI_API_KEY' && API_KEY.trim() !== '') {
  try {
    ai = new GoogleGenAI({
      apiKey: API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
    console.log('Gemini AI Client successfully initialized server-side.');
  } catch (err) {
    console.warn('Failed to initialize Gemini AI client:', err);
  }
} else {
  console.log('No valid GEMINI_API_KEY environment variable detected. Running in Offline Assist mode.');
}

// In-Memory Database store
import { mockIncidents, mockAuditLogs, mockNetworkNodes } from './src/data';
let incidents = [...mockIncidents];
let networkNodes = [...mockNetworkNodes];
let auditLogs = [...mockAuditLogs];

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Middleware
  app.use(express.json());

  // API Route - Get all incidents
  app.get('/api/incidents', (req, res) => {
    res.json(incidents);
  });

  // API Route - Update/Toggle a remediation step
  app.post('/api/incidents/:id/remediation/:stepNum/toggle', (req, res) => {
    const { id, stepNum } = req.params;
    const incidentIndex = incidents.findIndex(inc => inc.id === id);
    if (incidentIndex !== -1) {
      const stepIndex = incidents[incidentIndex].remediation.findIndex(step => step.stepNum === parseInt(stepNum));
      if (stepIndex !== -1) {
        const currentStatus = incidents[incidentIndex].remediation[stepIndex].status;
        incidents[incidentIndex].remediation[stepIndex].status = currentStatus === 'completed' ? 'pending' : 'completed';
        
        // Calculate status of overall incident
        const allCompleted = incidents[incidentIndex].remediation.every(step => step.status === 'completed');
        const someCompleted = incidents[incidentIndex].remediation.some(step => step.status === 'completed');
        if (allCompleted) {
          incidents[incidentIndex].status = 'mitigated';
        } else if (someCompleted) {
          incidents[incidentIndex].status = 'investigating';
        } else {
          incidents[incidentIndex].status = incidents[incidentIndex].id === 'INC-2026-001' ? 'quarantined' : 'active';
        }
        
        return res.json({ success: true, incident: incidents[incidentIndex] });
      }
    }
    res.status(404).json({ error: 'Incident or remediation step not found.' });
  });

  // API Route - Execute all Remediation Tasks for an Incident
  app.post('/api/incidents/:id/remediation/execute-all', (req, res) => {
    const { id } = req.params;
    const incidentIndex = incidents.findIndex(inc => inc.id === id);
    if (incidentIndex !== -1) {
      incidents[incidentIndex].remediation = incidents[incidentIndex].remediation.map(step => ({
        ...step,
        status: 'completed'
      }));
      incidents[incidentIndex].status = 'mitigated';
      
      // Update affected asset nodes in network as 'secure'
      const assetNames = incidents[incidentIndex].affectedAssets.map(asset => asset.name);
      networkNodes = networkNodes.map(node => {
        if (assetNames.includes(node.label)) {
          return { ...node, status: 'secure' };
        }
        return node;
      });

      return res.json({ success: true, incident: incidents[incidentIndex] });
    }
    res.status(404).json({ error: 'Incident not found.' });
  });

  // API Route - Get logs
  app.get('/api/logs', (req, res) => {
    res.json(auditLogs);
  });

  // API Route - Create log entry
  app.post('/api/logs', (req, res) => {
    const newLog = {
      id: `LOG-${Date.now()}`,
      timestamp: new Date().toISOString(),
      level: req.body.level || 'medium',
      host: req.body.host || 'UNKNOWN-WKSTN',
      service: req.body.service || 'generic-monitor',
      message: req.body.message || 'Custom manual log record registered.',
      status: req.body.status || 'alerted'
    };
    auditLogs = [newLog, ...auditLogs];
    res.json(newLog);
  });

  // API Route - Get Network Nodes
  app.get('/api/network', (req, res) => {
    res.json(networkNodes);
  });

  // API Route - Simulate dynamic network threat scan
  app.post('/api/hunt/scan', (req, res) => {
    const { targetRange } = req.body;
    
    // Simulate target scan report
    const targets = targetRange || '10.0.0.0/16';
    const infectedIPs = networkNodes.filter(n => n.status === 'infected' || n.status === 'warning').map(n => n.ip);
    
    const detectedThreatCount = Math.floor(Math.random() * 2) + 1;
    const compromisedHosts = networkNodes.filter(n => n.status === 'infected' || n.status === 'warning');

    // Add a log entry dynamically
    const newAlertLog = {
      id: `LOG-${Date.now()}`,
      timestamp: new Date().toISOString(),
      level: 'high' as const,
      host: compromisedHosts[0]?.label || 'ROUT-EXT-GW',
      service: 'snort-ids',
      message: `Heuristics matching signatures found on path scanning targeting ${targets}. Possible persistent backdoor.`,
      status: 'alerted' as const
    };
    auditLogs = [newAlertLog, ...auditLogs];

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      scannedRange: targets,
      status: 'Completed with warnings',
      nodesScanned: networkNodes.length,
      threatsDetected: detectedThreatCount,
      criticalFindings: compromisedHosts.map(h => ({
        host: h.label,
        ip: h.ip,
        threat: h.status === 'infected' ? 'Active Backdoor Exploitation' : 'Unusual Latency / Lateral Probe Flags'
      }))
    });
  });

  // API Route - Gemini AI forensic threat investigation
  app.post('/api/ai/investigate', async (req, res) => {
    const { id } = req.body;
    const incidentIndex = incidents.findIndex(inc => inc.id === id);
    if (incidentIndex === -1) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    const currentIncident = incidents[incidentIndex];
    const contextLogs = auditLogs.filter(log => log.host.includes(currentIncident.affectedAssets[0]?.name) || log.message.includes(currentIncident.cve || ''));

    const promptMessage = `Analyze the following cybersecurity incident report and telemetry:
Incident Title: ${currentIncident.title}
CVE Context: ${currentIncident.cve || 'N/A'}
Risk Score: ${currentIncident.riskScore}/10 (Category: ${currentIncident.category})
Summary: ${currentIncident.summary}
Affected Assets: ${JSON.stringify(currentIncident.affectedAssets)}
Event Log Context: ${JSON.stringify(contextLogs)}

Please produce a comprehensive security investigation including:
1. **Executive Forensic Reconstruction**: Detail how the attacker penetrated, escalated, and exfiltrated, based on these indicators.
2. **Impact Assessment**: What database assets, sensitive client profiles or root credentials were at risk.
3. **Advanced Strategic Remediation & Hardening**: Specific, hardened rules, configurations (e.g. firewall, IAM settings) to secure the node against future regressions.
4. **MITRE ATT&CK Mapping Analysis**: Map these actions to standard categories.

Format your output beautifully in standard Markdown. Be brief, authoritative, highly technical, and direct. Use appropriate bolding, bullet points, and codeblocks if you suggest concrete config snippets. Do not mention API keys, AI Studio, or internal ports.`;

    if (ai) {
      try {
        console.log(`Querying Gemini (gemini-3.5-flash) for incident forensic reconstruction...`);
        const response = await ai.models.generateContent({
          model: 'gemini-3.5-flash',
          contents: promptMessage,
          config: {
            systemInstruction: 'You are the Chief AI Forensic Incident Responder at AI Threat Hunter. You write crisp, highly-detailed, executive cybersecurity reports containing explicit and deep forensic guidance.',
            temperature: 0.3,
          }
        });

        const generatedMarkdown = response.text;
        return res.json({
          offline: false,
          mitigationNotes: generatedMarkdown
        });
      } catch (geminiErr: any) {
        console.error('Gemini query failure:', geminiErr);
        // Fallback to beautiful local offline generator in case of quotas or API issues
        return res.json({
          offline: true,
          error: geminiErr.message || 'Gemini API Error',
          mitigationNotes: getOfflineReport(currentIncident)
        });
      }
    } else {
      // Return beautiful offline mock report when API Key is not set or not configured
      return res.json({
        offline: true,
        mitigationNotes: getOfflineReport(currentIncident)
      });
    }
  });

  // Handle Vite middleware inside server for Dev, compile output assets in Production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AI Threat Hunter Backend ready on http://localhost:${PORT}`);
  });
}

// Helper offline forensic markdown reports matching the incident
function getOfflineReport(incident: any): string {
  if (incident.id === 'INC-2026-001') {
    return `### 🛡️ AI Forensic Analysis Report: MOVEit (CVE-2023-34362)

#### 1. Executive Forensic Reconstruction
An extensive exfiltration protocol was triggered on workstation \`FIN-X92-WKSTN\` at **04:12 UTC**. The infection vector is validated as a spearphishing payload disguised as a Payroll Form. Double-clicking executed a remote DLL download that injected code into local service processes. 
Upon gaining secondary active credentials, the controller conducted horizontal sweeps using SQL queries to mapping the tables in \`DB-PROD-01\`.

*   **Attacker Core IP Range**: \`185.220.101.5\` (C2 Hub)
*   **Method**: High-volume, nested SQL Injection commands passing base64 indicators.

#### 2. Impact Assessment
*   **Database Host**: \`DB-PROD-01\` was target of query dumping keys containing active client banking numbers and financial directories.
*   **Remediation Urgency**: **CRITICAL**. A delay of 4 minutes would have compromised 85,000 corporate ledger files.

#### 3. Strategic Hardening Recommendations
1.  **Block Port egress**: Add egress rules on AWS Security groups restricting database node \`DB-PROD-01\` from opening non-standard outbound channels on Port \`8088\`.
    \`\`\`bash
    # Deny non-production outgoing traffic
    iptables -A OUTPUT -p tcp --dport 8088 -j DROP
    \`\`\`
2.  **Zero-Trust Client Isolator**: Automatically quarantine any endpoint that performs DNS queries matching TOR domain signatures.
3.  **Active Host Sanitization**: Reinstate pristine host OS images on workstation \`FIN-X92\` immediately.`;
  } else if (incident.id === 'INC-2024-002') {
    return `### 🛡️ AI Forensic Analysis Report: XZ Utils Supply-Chain Backdoor (CVE-2024-3094)

#### 1. Executive Forensic Reconstruction
During continuous building procedures, the compiler integrated backdoored assemblies in the liblzma package context (linked dynamically with SSH daemons). This allowed root control by executing custom cryptographic prefixes via standard SSH queries.

*   **Signature Origin**: Upstream builder user \`JiaT75\`
*   **Exploitation Pattern**: SSH pre-auth payload siphoning internal memory allocations.

#### 2. Impact Assessment
*   **Critical Host**: \`PROD-SSH-GATE\` (Our primary bastion ingress point). Unchecked access could distribute root tokens seamlessly through all inner VPC rings.

#### 3. Strategic Hardening Recommendations
1.  **Force Lockout**: Revoke developer credential certificates from build machine \`CI-CD-BUILDER-4\`.
2.  **Compiler Sandhousing**:
    \`\`\`yaml
    # Secure CI build manifest
    build_environment:
      dependencies_verification: strict-hash
      allow_unsigned_tarballs: false
    \`\`\`
3.  **Static Binaries**: Compile critical gateways statically to restrict load-order dynamic overrides.`;
  } else {
    return `### 🛡️ AI Forensic Analysis Report: Information Disclosure (CVE-2023-49103)

#### 1. Detailed Investigation
Hacker scanning tools located a debug exposure path in ownCloud templates allowing standard variables dumped outside memory containers ($ENV records).

#### 2. Impact Rating
*   High Impact. The AWS Secrets were read in raw format.

#### 3. Remediation Actions
*   Immediately rotate master security keys. Disable Apache debug outputs globally.`;
  }
}

startServer();
