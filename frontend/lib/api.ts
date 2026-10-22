import {
  DashboardSummary,
  TrafficEvent,
  Threat,
  FirewallRule,
  Alert,
  SimulationStatus,
  SystemStatus,
  FirewallStatus
} from './types';

const API_BASE = 'http://localhost:8000/api';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  if (!res.ok) {
    let msg = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const data = await res.json();
      if (data?.message) msg = data.message;
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

export const api = {
  async getHealth(): Promise<SystemStatus> {
    return fetchJson<SystemStatus>(`${API_BASE}/health`);
  },

  async getSystemStatus(): Promise<SystemStatus> {
    return fetchJson<SystemStatus>(`${API_BASE}/system/status`);
  },

  async getDashboardSummary(): Promise<DashboardSummary> {
    return fetchJson<DashboardSummary>(`${API_BASE}/dashboard/summary`);
  },

  async getRecentTraffic(): Promise<TrafficEvent[]> {
    return fetchJson<TrafficEvent[]>(`${API_BASE}/traffic/recent`);
  },

  async getThreats(): Promise<Threat[]> {
    return fetchJson<Threat[]>(`${API_BASE}/threats`);
  },

  async getRules(): Promise<FirewallRule[]> {
    return fetchJson<FirewallRule[]>(`${API_BASE}/rules`);
  },

  async deleteRule(id: number): Promise<{ status: string }> {
    return fetchJson<{ status: string }>(`${API_BASE}/rules/${id}`, { method: 'DELETE' });
  },

  async getAlerts(): Promise<Alert[]> {
    return fetchJson<Alert[]>(`${API_BASE}/alerts`);
  },

  async acknowledgeAlert(id: number): Promise<{ status: string }> {
    return fetchJson<{ status: string }>(`${API_BASE}/alerts/${id}/acknowledge`, { method: 'POST' });
  },

  async getSimulationStatus(): Promise<SimulationStatus> {
    return fetchJson<SimulationStatus>(`${API_BASE}/simulation/status`);
  },

  async setSimulationScenario(scenario: string): Promise<{ status: string; scenario: string }> {
    return fetchJson<{ status: string; scenario: string }>(`${API_BASE}/simulation/scenario`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    });
  },

  async getFirewallMode(): Promise<{ mode: string; firewall_status: FirewallStatus }> {
    return fetchJson<{ mode: string; firewall_status: FirewallStatus }>(`${API_BASE}/firewall/mode`);
  },

  async setFirewallMode(mode: 'live' | 'simulation'): Promise<{ status: string; mode: string; firewall_status: FirewallStatus }> {
    return fetchJson<{ status: string; mode: string; firewall_status: FirewallStatus }>(`${API_BASE}/firewall/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    });
  },

  async resetFirewall(): Promise<{ status: string }> {
    return fetchJson<{ status: string }>(`${API_BASE}/firewall/reset`, { method: 'POST' });
  },
};
