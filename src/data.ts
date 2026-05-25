import { Incident, NetworkNode, SystemAuditLog } from './types';

export const mockIncidents: Incident[] = [
  {
    id: 'INC-2026-001',
    cve: 'CVE-2023-34362',
    title: 'Exploitation of CVE-2023-34362',
    summary: 'A sophisticated data exfiltration attempt was detected originating from an external IP cluster. Our NLP engine has reconstructed the attack narrative below.',
    riskScore: 9.2,
    category: 'SQL Injection / Exfiltration',
    status: 'quarantined',
    affectedAssets: [
      { name: 'FIN-X92-WKSTN', ip: '10.0.4.112', type: 'workstation' },
      { name: 'DB-PROD-01', ip: '10.0.8.22', type: 'database' }
    ],
    timeline: [
      {
        time: '04:12 UTC',
        title: 'Initial Access via Phishing',
        text: 'The attacker entered via Phishing targeting the finance department\'s payroll portal. A malicious attachment was opened on workstation FIN-X92 at 04:12 UTC.',
        type: 'phishing'
      },
      {
        time: '04:14 UTC',
        title: 'Privilege Escalation Attempt',
        text: 'They attempted to escalate privileges by exploiting a known vulnerability in the local credential manager. Scripts were observed scanning for active domain admin sessions.',
        type: 'escalation'
      },
      {
        time: '04:16 UTC',
        title: 'Internal Reconnaissance',
        text: 'Internal Reconnaissance began as the malware pinged the SQL production cluster, attempting to map table structures for sensitive client PII.',
        type: 'recon'
      },
      {
        time: '04:18 UTC',
        title: 'Automated AI Isolation',
        text: 'Our AI blocked the connection at 04:18 UTC after detecting anomalous outbound traffic patterns to a non-standard port (8088). The workstation was automatically quarantined.',
        type: 'blocked'
      }
    ],
    techniques: [
      { code: 'T1566.001', name: 'Phishing: Spearphishing Attachment', url: 'https://attack.mitre.org/techniques/T1566/001' },
      { code: 'T1078.002', name: 'Valid Accounts: Domain Accounts', url: 'https://attack.mitre.org/techniques/T1078/002' },
      { code: 'T1041', name: 'Exfiltration Over C2 Channel', url: 'https://attack.mitre.org/techniques/T1041' }
    ],
    remediation: [
      {
        stepNum: 1,
        title: 'Isolate FIN-X92',
        description: 'Host already disconnected by AI. Verify physical air-gap status.',
        status: 'completed'
      },
      {
        stepNum: 2,
        title: 'Reset Domain Admin Credentials',
        description: 'Recommended due to lateral movement attempts observed.',
        status: 'pending'
      },
      {
        stepNum: 3,
        title: 'Audit SQL Server Access Logs',
        description: 'Scan for any unauthorized queries between 04:10 and 04:20 UTC.',
        status: 'pending'
      }
    ],
    trafficData: [
      { time: '04:00', rate: 0.15 },
      { time: '04:02', rate: 0.18 },
      { time: '04:04', rate: 0.12 },
      { time: '04:06', rate: 0.08 },
      { time: '04:08', rate: 0.05 },
      { time: '04:10', rate: 0.11 },
      { time: '04:12', rate: 0.22 },
      { time: '04:14', rate: 0.15 },
      { time: '04:16', rate: 0.19 },
      { time: '04:18', rate: 4.22, isAnomaly: true },
      { time: '04:20', rate: 0.21 },
      { time: '04:22', rate: 0.14 },
      { time: '04:24', rate: 0.08 },
      { time: '04:26', rate: 0.11 },
      { time: '04:28', rate: 0.05 }
    ]
  },
  {
    id: 'INC-2026-002',
    cve: 'CVE-2024-3094',
    title: 'Backdoor Insertion in XZ Utils',
    summary: 'An unauthorized modification targeting liblzma was identified during automated byte-signature comparisons. This backdoor would allow remote attackers to bypass SSH authentication.',
    riskScore: 10.0,
    category: 'Supply Chain Compromise',
    status: 'active',
    affectedAssets: [
      { name: 'PROD-SSH-GATE', ip: '10.120.1.10', type: 'server' },
      { name: 'CI-CD-BUILDER-4', ip: '10.120.3.50', type: 'server' }
    ],
    timeline: [
      {
        time: '18:30 UTC',
        title: 'Malicious Commits Pushed',
        text: 'Rogue upstream edits were injected into the release stream, masquerading as compiler optimization overrides.',
        type: 'phishing'
      },
      {
        time: '19:15 UTC',
        title: 'Backdoored Library Linking',
        text: 'The server-side build linked the modified package structure, preparing an unauthenticated gateway payload.',
        type: 'escalation'
      },
      {
        time: '20:01 UTC',
        title: 'Abnormal CPU Thresholds',
        text: 'A high-load SSH connection triggered memory alignment scan flags on the host validator daemon.',
        type: 'recon'
      },
      {
        time: '20:04 UTC',
        title: 'Process Tree Suspended',
        text: 'Our heuristic core detected backdoored sshd process spawning child sub-shells and instantly quarantined the virtual machine.',
        type: 'blocked'
      }
    ],
    techniques: [
      { code: 'T1195.002', name: 'Supply Chain Compromise: Compromise Software Dependencies', url: 'https://attack.mitre.org/techniques/T1195/002' },
      { code: 'T1542.001', name: 'Pre-OS Boot: System Firmware', url: 'https://attack.mitre.org/techniques/T1542/001' }
    ],
    remediation: [
      {
        stepNum: 1,
        title: 'Rollback Package Version',
        description: 'Force-demote xz-utils library to native version 5.6.0 on all active build pipelines.',
        status: 'pending'
      },
      {
        stepNum: 2,
        title: 'Revoke Build Keys',
        description: 'Invalidate repository signing keys matching developer profile "JiaT75".',
        status: 'completed'
      },
      {
        stepNum: 3,
        title: 'Reprovision Linux Golden Images',
        description: 'Perform bare-metal rebuild of Gateways to strip lingering compiled build caches.',
        status: 'pending'
      }
    ],
    trafficData: [
      { time: '19:40', rate: 0.05 },
      { time: '19:45', rate: 0.08 },
      { time: '19:50', rate: 0.06 },
      { time: '19:55', rate: 0.12 },
      { time: '20:00', rate: 0.09 },
      { time: '20:05', rate: 3.85, isAnomaly: true },
      { time: '20:10', rate: 0.15 },
      { time: '20:15', rate: 0.05 }
    ]
  },
  {
    id: 'INC-2026-003',
    cve: 'CVE-2023-49103',
    title: 'Leak of Environment Secrets',
    summary: 'A public endpoint expose flaw on ownCloud deployments allowed external scanning of the server execution environment. Critical cloud variables were found on hacker pastebin nodes.',
    riskScore: 7.8,
    category: 'Information Disclosure',
    status: 'mitigated',
    affectedAssets: [
      { name: 'CLOUD-STORAGE-01', ip: '10.50.80.12', type: 'server' }
    ],
    timeline: [
      {
        time: '01:05 UTC',
        title: 'Endpoint Request (phpinfo)',
        text: 'External scraper originating from TOR exit nodes pinged `/apps/graphapi/vendor/.../phpinfo.php`.',
        type: 'recon'
      },
      {
        time: '01:08 UTC',
        title: 'Cloud Master Keys Read',
        text: 'The attacker dumped AWS root access credentials and SQL database root passwords.',
        type: 'escalation'
      },
      {
        time: '01:10 UTC',
        title: 'Data Access Alert',
        text: 'AWS GuardDuty signaled a root key sign-in attempt from high-risk IP geographic sectors.',
        type: 'other'
      },
      {
        time: '01:15 UTC',
        title: 'Key Revocation',
        text: 'Cloud provider deactivated the compromise keys under emergency response automated procedures.',
        type: 'blocked'
      }
    ],
    techniques: [
      { code: 'T1552', name: 'Unsecured Credentials', url: 'https://attack.mitre.org/techniques/T1552' },
      { code: 'T1580', name: 'Cloud Infrastructure Discovery', url: 'https://attack.mitre.org/techniques/T1580' }
    ],
    remediation: [
      {
        stepNum: 1,
        title: 'Revoke Compromised AWS IAM Keys',
        description: 'Terminate all active access credentials assigned to compromised cloud controller profiles.',
        status: 'completed'
      },
      {
        stepNum: 2,
        title: 'Update Docker configurations',
        description: 'Rebuild internal images with the hotpatched version of GraphAPI library.',
        status: 'completed'
      },
      {
        stepNum: 3,
        title: 'Rotate DB Credentials',
        description: 'Cycle database connection strings and storage master cipher codes.',
        status: 'completed'
      }
    ],
    trafficData: [
      { time: '01:00', rate: 0.12 },
      { time: '01:02', rate: 0.15 },
      { time: '01:04', rate: 0.18 },
      { time: '01:06', rate: 1.95, isAnomaly: true },
      { time: '01:08', rate: 0.22 },
      { time: '01:10', rate: 0.11 }
    ]
  }
];

export const mockNetworkNodes: NetworkNode[] = [
  { id: '1', label: 'Internet Gateway', type: 'internet', ip: '0.0.0.0', status: 'secure', connections: ['2', '10'] },
  { id: '2', label: 'Inbound Router', type: 'router', ip: '10.0.1.1', status: 'secure', connections: ['1', '3', '4'] },
  { id: '3', label: 'Staff Mail Server', type: 'server', ip: '10.0.2.10', status: 'warning', connections: ['2', '5', '6'] },
  { id: '4', label: 'CI/CD VM Node', type: 'server', ip: '10.0.3.50', status: 'secure', connections: ['2', '11'] },
  { id: '5', label: 'FIN-X92 Workstation', type: 'workstation', ip: '10.0.4.112', status: 'quarantined', connections: ['3', '7'] },
  { id: '6', label: 'HR-Laptop-03', type: 'workstation', ip: '10.0.4.150', status: 'secure', connections: ['3'] },
  { id: '7', label: 'DB-PROD-01', type: 'database', ip: '10.0.8.22', status: 'warning', connections: ['5', '8'] },
  { id: '8', label: 'Backup Vault Host', type: 'database', ip: '10.0.8.99', status: 'secure', connections: ['7'] },
  { id: '10', label: 'IP CLUSTER (C2)', type: 'attacker', ip: '185.220.101.5', status: 'infected', connections: ['1'] },
  { id: '11', label: 'PROD-SSH-GATE', type: 'server', ip: '10.120.1.10', status: 'infected', connections: ['4'] }
];

export const mockAuditLogs: SystemAuditLog[] = [
  {
    id: 'LOG-001',
    timestamp: '2026-05-25T20:21:05Z',
    level: 'critical',
    host: 'FIN-X92-WKSTN',
    service: 'ssshd-auth',
    message: 'Repeated authorization fails from domain master account: Admin-09',
    status: 'alerted'
  },
  {
    id: 'LOG-002',
    timestamp: '2026-05-25T20:18:55Z',
    level: 'critical',
    host: 'DB-PROD-01',
    service: 'postgres-engine',
    message: 'Anomalous outbound socket bind request spotted on port 8088 to external cluster 185.220.101.5',
    status: 'blocked'
  },
  {
    id: 'LOG-003',
    timestamp: '2026-05-25T20:12:44Z',
    level: 'medium',
    host: 'MAIL-SRV-02',
    service: 'postfix-relay',
    message: 'Attachment payroll_form_v2.pdf.js flagged with high heuristical rating signature',
    status: 'quarantined'
  },
  {
    id: 'LOG-004',
    timestamp: '2026-05-25T20:05:12Z',
    level: 'high',
    host: 'PROD-SSH-GATE',
    service: 'ssshd',
    message: 'Compromised dependencies load: custom wrapper loaded inside liblzma dynamic linker path',
    status: 'alerted'
  },
  {
    id: 'LOG-005',
    timestamp: '2026-05-25T19:55:00Z',
    level: 'low',
    host: 'HR-Laptop-03',
    service: 'windows-defender',
    message: 'Automatic definitions signature scan report: 0 threats resolved, status clean.',
    status: 'allowed'
  },
  {
    id: 'LOG-006',
    timestamp: '2026-05-25T19:40:11Z',
    level: 'medium',
    host: 'CLOUD-STORAGE-01',
    service: 'apache-docker',
    message: 'Forbidden path inquiry: app/graphapi/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php executed',
    status: 'blocked'
  },
  {
    id: 'LOG-007',
    timestamp: '2026-05-25T19:22:00Z',
    level: 'high',
    host: 'FIN-X92-WKSTN',
    service: 'win-kernel-driver',
    message: 'LSASS.exe access permission handles queried by unverified system daemon process id: 4880',
    status: 'alerted'
  }
];
