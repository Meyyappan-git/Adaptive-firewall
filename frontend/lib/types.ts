export interface TrafficEvent {
  id: number;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  packet_count: number;
  byte_count: number;
  timestamp: string;
  threat_score: number | null;
  action: string;
}

export interface Threat {
  id: number;
  source_ip: string;
  severity: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  score: number;
  reasons: string;
  timestamp: string;
  status: string;
}

export interface FirewallRule {
  id: number;
  source: string;
  destination: string | null;
  protocol: string | null;
  port: number | null;
  action: string;
  reason: string;
  threat_score: number;
  created_at: string;
  expires_at: string | null;
  status: string;
  severity?: string;
  enforced_at_os?: boolean;
}

export interface Alert {
  id: number;
  severity: string;
  title: string;
  description: string;
  source: string;
  timestamp: string;
  threat_score: number;
  status: string;
}

export interface DashboardSummary {
  total_traffic: number;
  threats_detected: number;
  active_rules: number;
  critical_alerts: number;
}

export interface SimulationStatus {
  scenario: string;
}

export interface FirewallStatus {
  backend: string;
  platform: string;
  is_elevated: boolean;
  os_enforcement_supported: boolean;
  os_enforcement_active: boolean;
  active_rules_count: number;
  last_error?: string | null;
  message: string;
}

export interface SystemStatus {
  status: string;
  mode: string;
  ml_model_ready?: boolean;
  scenario?: string;
  monitoring?: boolean;
  firewall_status?: FirewallStatus;
}
