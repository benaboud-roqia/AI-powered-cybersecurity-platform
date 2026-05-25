export type SecurityLevel = 'critical' | 'high' | 'medium' | 'low';

export interface AffectedAsset {
  name: string;
  ip: string;
  type: 'workstation' | 'database' | 'server' | 'router';
}

export interface TimelineEvent {
  time: string;
  title: string;
  text: string;
  type: 'phishing' | 'escalation' | 'recon' | 'blocked' | 'other';
}

export interface MitreTechnique {
  code: string;
  name: string;
  url: string;
}

export interface RemediationStep {
  stepNum: number;
  title: string;
  description: string;
  status: 'pending' | 'completed';
}

export interface TrafficDataPoint {
  time: string;
  rate: number; // in GB/s
  isAnomaly?: boolean;
}

export interface Incident {
  id: string;
  cve?: string;
  title: string;
  summary: string;
  riskScore: number;
  category: string;
  status: 'active' | 'quarantined' | 'mitigated' | 'investigating';
  affectedAssets: AffectedAsset[];
  timeline: TimelineEvent[];
  techniques: MitreTechnique[];
  remediation: RemediationStep[];
  trafficData: TrafficDataPoint[];
}

export interface NetworkNode {
  id: string;
  label: string;
  type: 'user' | 'workstation' | 'server' | 'database' | 'internet' | 'attacker' | 'router';
  ip: string;
  status: 'infected' | 'secure' | 'quarantined' | 'warning';
  connections: string[]; // ids of connected nodes
}

export interface SystemAuditLog {
  id: string;
  timestamp: string;
  level: SecurityLevel;
  host: string;
  service: string;
  message: string;
  status: 'blocked' | 'allowed' | 'alerted' | 'quarantined';
}
