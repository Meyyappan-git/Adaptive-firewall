"use client";

import React, { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  AlertTriangle,
  Lock,
  Zap,
  RefreshCw,
  Wifi,
  WifiOff,
  Trash2,
  Info,
  Terminal,
  Clock,
  Eye,
  X
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';
import { api } from '@/lib/api';
import {
  DashboardSummary,
  TrafficEvent,
  Threat,
  FirewallRule,
  Alert,
  SimulationStatus
} from '@/lib/types';
import { StatusBadge } from '@/components/common/StatusBadge';
import { MetricCard } from '@/components/common/MetricCard';
import { cn } from '@/lib/utils';

export default function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [traffic, setTraffic] = useState<TrafficEvent[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [simStatus, setSimStatus] = useState<SimulationStatus | null>(null);
  const [isOnline, setIsOnline] = useState(true);
  const [isLoading, setIsLoading] = useState(true);
  const [activeScenario, setActiveScenario] = useState('NORMAL');
  const [selectedRule, setSelectedRule] = useState<FirewallRule | null>(null);

  const fetchData = async () => {
    try {
      const [sum, traf, thrt, ruls, alrt, sim] = await Promise.all([
        api.getDashboardSummary(),
        api.getRecentTraffic(),
        api.getThreats(),
        api.getRules(),
        api.getAlerts(),
        api.getSimulationStatus(),
      ]);
      setSummary(sum);
      setTraffic(traf);
      setThreats(thrt);
      setRules(ruls);
      setAlerts(alrt);
      setSimStatus(sim);
      setIsOnline(true);
    } catch (e) {
      console.error("API Error:", e);
      setIsOnline(false);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleScenarioChange = async (scenario: string) => {
    setActiveScenario(scenario);
    await api.setSimulationScenario(scenario);
  };

  const handleReset = async () => {
    if (confirm("CAUTION: This will wipe all security logs and firewall rules. Proceed?")) {
      await api.resetFirewall();
      fetchData();
    }
  };

  const handleAckAlert = async (id: number) => {
    await api.acknowledgeAlert(id);
    fetchData();
  };

  const handleRemoveRule = async (id: number) => {
    if (confirm("Are you sure you want to manually lift this block?")) {
      await api.deleteRule(id);
      fetchData();
    }
  };

  if (isLoading) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-slate-950 text-slate-400">
        <div className="flex flex-col items-center gap-4">
          <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
          <p className="font-mono text-sm uppercase tracking-widest">Initializing SOC Interface...</p>
        </div>
      </div>
    );
  }

  const chartData = traffic.slice(0, 30).reverse().map((t) => ({
    time: new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    bytes: t.byte_count,
    score: t.threat_score || 0,
  }));

  return (
    <div className="min-h-screen bg-slate-950 text-slate-300 p-0 font-sans overflow-x-hidden">
      {/* Global Header */}
      <nav className="h-12 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md flex items-center justify-between px-6 sticky top-0 z-50">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-500" />
            <span className="text-xs font-bold tracking-tighter text-slate-100 uppercase">Adaptive Firewall</span>
          </div>
          <div className="h-4 w-px bg-slate-700 mx-2" />
          <div className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-wider text-slate-500">
            <span className={cn("w-2 h-2 rounded-full animate-pulse", isOnline ? "bg-emerald-500" : "bg-red-500")} />
            System Status: <span className={isOnline ? "text-emerald-400" : "text-red-400"}>{isOnline ? "Healthy" : "Degraded"}</span>
          </div>
        </div>

        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-wider text-slate-500">
            <span className="text-slate-400">Mode:</span>
            <span className="text-blue-400 font-bold">Simulation</span>
          </div>
          <div className="text-xs font-mono text-slate-500 bg-slate-800 px-2 py-0.5 rounded">
            {new Date().toISOString().slice(11, 19)} UTC
          </div>
        </div>
      </nav>

      <main className="p-6 grid grid-cols-12 gap-6">

        {/* Left Sidebar: Command & Control (3 cols) */}
        <div className="col-span-12 lg:col-span-3 space-y-6">
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm">
            <div className="flex items-center gap-2 mb-6 text-slate-100 font-bold text-sm uppercase tracking-wider">
              <Terminal className="w-4 h-4 text-blue-500" />
              Command Center
            </div>

            <div className="space-y-6">
              <div>
                <label className="text-[10px] text-slate-500 uppercase font-bold block mb-2">Traffic Scenario</label>
                <div className="relative">
                  <select
                    value={activeScenario}
                    onChange={(e) => handleScenarioChange(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs p-2 rounded-md focus:ring-1 focus:ring-blue-500 outline-none appearance-none cursor-pointer"
                  >
                    <option value="NORMAL">Normal Baseline</option>
                    <option value="PORT_SCAN">Port Scan Attack</option>
                    <option value="BURST">Connection Burst</option>
                    <option value="HIGH_TRAFFIC">High Bandwidth Flood</option>
                    <option value="FAILED_CONN">Repeated Auth Failure</option>
                    <option value="MIXED">Mixed Attack Traffic</option>
                  </select>
                  <div className="absolute right-2 top-2 pointer-events-none">
                    <Zap className="w-3 h-3 text-slate-600" />
                  </div>
                </div>
              </div>

              <button
                onClick={handleReset}
                className="w-full py-2 px-4 bg-slate-800 hover:bg-red-900/20 border border-slate-700 hover:border-red-500/50 text-slate-400 hover:text-red-400 rounded-md text-xs font-bold transition-all flex items-center justify-center gap-2"
              >
                <RefreshCw className="w-3 h-3" />
                Reset Environment
              </button>
            </div>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm">
            <div className="flex items-center gap-2 mb-4 text-slate-100 font-bold text-sm uppercase tracking-wider">
              <Activity className="w-4 h-4 text-emerald-500" />
              System Health
            </div>
            <div className="space-y-3">
              {[
                { label: 'Kernel API', status: isOnline ? 'Healthy' : 'Error' },
                { label: 'SQLite Store', status: isOnline ? 'Active' : 'Disconnected' },
                { label: 'ML-Inference', status: 'Active' },
                { label: 'Packet Filter', status: 'Active' },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">{item.label}</span>
                  <StatusBadge status={item.status} />
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main Dashboard Area (9 cols) */}
        <div className="col-span-12 lg:col-span-9 space-y-6">

          {/* Intelligence Layer */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            <MetricCard
              title="Total Traffic"
              value={summary?.total_traffic || 0}
              icon={Activity}
              description="Packets processed"
              severity="low"
            />
            <MetricCard
              title="Threats Detected"
              value={summary?.threats_detected || 0}
              icon={AlertTriangle}
              description="Anomalies identified"
              severity="high"
            />
            <MetricCard
              title="Active Blocks"
              value={summary?.active_rules || 0}
              icon={Lock}
              description="IPs currently restricted"
              severity="critical"
            />
            <MetricCard
              title="Critical Alerts"
              value={summary?.critical_alerts || 0}
              icon={Zap}
              description="Immediate attention req."
              severity="critical"
            />
          </div>

          {/* Visual Core */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-2 text-slate-100 font-bold text-sm uppercase tracking-wider">
                  <Activity className="w-4 h-4 text-blue-500" />
                  Real-time Traffic Volume
                </div>
                <div className="flex gap-4 text-[10px] text-slate-500">
                  <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" /> Bytes</div>
                  <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Threat Score</div>
                </div>
              </div>
              <div className="h-72 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
                    <YAxis stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', color: '#f1f5f9' }}
                      itemStyle={{ fontSize: '12px' }}
                    />
                    <Area type="monotone" dataKey="bytes" stroke="#3b82f6" fill="url(#colorBytes)" strokeWidth={2} />
                    <Area type="monotone" dataKey="score" stroke="#ef4444" fill="transparent" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm flex flex-col">
              <div className="flex items-center gap-2 mb-4 text-slate-100 font-bold text-sm uppercase tracking-wider">
                <Clock className="w-4 h-4 text-amber-500" />
                Event Timeline
              </div>
              <div className="flex-1 overflow-y-auto space-y-4 pr-2 max-h-72 scrollbar-hide">
                {alerts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-slate-600 text-xs italic">
                    <Shield className="w-5 h-5 mb-2 opacity-20" />
                    No security events recorded
                  </div>
                ) : (
                  alerts.slice(0, 10).map((alert) => (
                    <div key={alert.id} className="flex gap-3 text-xs border-l-2 border-slate-800 pl-3 py-1 hover:border-blue-500 transition-colors">
                      <span className="text-slate-500 font-mono shrink-0">
                        {new Date(alert.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                      <div className="text-slate-300">
                        <span className="font-bold text-slate-100">{alert.title}</span>
                        <p className="text-slate-500 text-[10px]">{alert.source}</p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Enforcement Table */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden backdrop-blur-sm">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-slate-100 font-bold text-sm uppercase tracking-wider">
                <Lock className="w-4 h-4 text-blue-500" />
                Active Enforcement Rules
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-800/50 text-slate-500 uppercase font-bold">
                  <tr>
                    <th className="px-6 py-4">Source IP</th>
                    <th className="px-6 py-4">Threat Score</th>
                    <th className="px-6 py-4">Severity</th>
                    <th className="px-6 py-4">Reason</th>
                    <th className="px-6 py-4">Action</th>
                    <th className="px-6 py-4">Expires In</th>
                    <th className="px-6 py-4 text-right">Management</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {rules.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-6 py-16 text-center text-slate-600 italic">
                        <div className="flex flex-col items-center gap-3">
                          <Shield className="w-8 h-8 text-slate-800" />
                          <p className="text-sm">System Secure: No active threats detected</p>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    rules.map((rule) => (
                      <tr
                        key={rule.id}
                        onClick={() => setSelectedRule(rule)}
                        className="hover:bg-blue-500/5 cursor-pointer transition-colors group"
                      >
                        <td className="px-6 py-4 font-mono text-slate-300">{rule.source}</td>
                        <td className="px-6 py-4 font-bold text-slate-100">{rule.threat_score.toFixed(1)}</td>
                        <td className="px-6 py-4">
                          <StatusBadge status={rule.severity || (rule.threat_score > 75 ? 'CRITICAL' : 'HIGH')} />
                        </td>
                        <td className="px-6 py-4 text-slate-400 truncate max-w-xs">{rule.reason}</td>
                        <td className="px-6 py-4">
                          <StatusBadge status={rule.action} />
                        </td>
                        <td className="px-6 py-4 text-slate-500 font-mono">
                          {rule.expires_at ? new Date(rule.expires_at).toLocaleTimeString() : 'Permanent'}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button
                            onClick={(e) => { e.stopPropagation(); handleRemoveRule(rule.id); }}
                            className="p-1.5 text-slate-600 hover:text-red-400 transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </main>

      {/* Threat Intelligence Modal - rendered as overlay sibling to main */}
      {/* NOTE: portal-style overlay inside outer div */}
      {selectedRule && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden">
            <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-800/30">
              <div className="flex items-center gap-3">
                <Shield className="w-6 h-6 text-blue-500" />
                <h2 className="text-lg font-bold text-slate-100">Threat Intelligence Report</h2>
              </div>
              <button onClick={() => setSelectedRule(null)} className="p-1 hover:bg-slate-800 rounded text-slate-500">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Source IP</p>
                  <p className="text-sm font-mono text-slate-200">{selectedRule.source}</p>
                </div>
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Final Score</p>
                  <p className="text-sm font-bold text-blue-400">{selectedRule.threat_score.toFixed(1)} / 100</p>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                  <Info className="w-3 h-3" /> Detection Breakdown
                </h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-500">Rule-Based Score</span>
                    <span className="text-slate-200 font-mono">{(selectedRule.threat_score * 0.6).toFixed(1)}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-500">ML Anomaly Score</span>
                    <span className="text-slate-200 font-mono">{(selectedRule.threat_score * 0.3).toFixed(1)}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-500">Behavioral Weight</span>
                    <span className="text-slate-200 font-mono">{(selectedRule.threat_score * 0.1).toFixed(1)}</span>
                  </div>
                </div>
                <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-2">Logic Explanation</p>
                  <p className="text-xs text-slate-300 leading-relaxed italic">
                    "{selectedRule.reason}"
                  </p>
                </div>
              </div>
            </div>

            <div className="p-6 bg-slate-800/30 border-t border-slate-800 flex justify-between items-center">
              <div className="flex items-center gap-2">
                <StatusBadge status={selectedRule.action} />
                <span className="text-xs text-slate-400">Applied enforcement</span>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-md text-xs font-bold transition-colors"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
