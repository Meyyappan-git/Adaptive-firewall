import {
  DashboardSummary,
  TrafficEvent,
  Threat,
  FirewallRule,
  Alert,
  SimulationStatus,
  SystemStatus
} from './types';

const API_BASE = 'http://localhost:8000/api';

export const api = {
  async getHealth(): Promise<SystemStatus> {
    const res = await fetch(`${API_BASE}/health`);
    return res.json();
  },

  async getDashboardSummary(): Promise<DashboardSummary> {
    const res = await fetch(`${API_BASE}/dashboard/summary`);
    return res.json();
  },

  async getRecentTraffic(): Promise<TrafficEvent[]> {
    const res = await fetch(`${API_BASE}/traffic/recent`);
    return res.json();
  },

  async getThreats(): Promise<Threat[]> {
    const res = await fetch(`${API_BASE}/threats`);
    return res.json();
  },

  async getRules(): Promise<FirewallRule[]> {
    const res = await fetch(`${API_BASE}/rules`);
    return res.json();
  },

  async deleteRule(id: number): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/rules/${id}`, { method: 'DELETE' });
    return res.json();
  },

  async getAlerts(): Promise<Alert[]> {
    const res = await fetch(`${API_BASE}/alerts`);
    return res.json();
  },

  async acknowledgeAlert(id: number): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/alerts/${id}/acknowledge`, { method: 'POST' });
    return res.json();
  },

  async getSimulationStatus(): Promise<SimulationStatus> {
    const res = await fetch(`${API_BASE}/simulation/status`);
    return res.json();
  },

  async setSimulationScenario(scenario: string): Promise<{ status: string, scenario: string }> {
    const res = await fetch(`${API_BASE}/simulation/scenario`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    });
    return res.json();
  },

  async resetFirewall(): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/firewall/reset`, { method: 'POST' });
    return res.json();
  },
};
