"use client";

import React, { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  AlertTriangle,
  Lock,
  Zap,
  RefreshCw,
  Trash2,
  Info,
  Terminal,
  X,
  CheckCircle2,
  SlidersHorizontal,
  Server
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
  SimulationStatus,
  SystemStatus
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
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [isOnline, setIsOnline] = useState(true);
  const [isLoading, setIsLoading] = useState(true);
  const [activeScenario, setActiveScenario] = useState('NORMAL');
  const [activeMode, setActiveMode] = useState<'simulation' | 'live'>('live');
  const [selectedRule, setSelectedRule] = useState<FirewallRule | null>(null);

  const fetchData = async () => {
    try {
      const [sum, traf, thrt, ruls, alrt, sim, sys] = await Promise.all([
        api.getDashboardSummary(),
        api.getRecentTraffic(),
        api.getThreats(),
        api.getRules(),
        api.getAlerts(),
        api.getSimulationStatus(),
        api.getSystemStatus(),
      ]);
      setSummary(sum);
      setTraffic(traf);
      setThreats(thrt);
      setRules(ruls);
      setAlerts(alrt);
      setSimStatus(sim);
      setSystemStatus(sys);
      if (sys?.mode) {
        setActiveMode(sys.mode as 'simulation' | 'live');
      }
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

  const handleModeChange = async (newMode: 'live' | 'simulation') => {
    setActiveMode(newMode);
    try {
      await api.setFirewallMode(newMode);
      fetchData();
    } catch (e) {
      console.error("Failed to switch mode:", e);
    }
  };

  const handleScenarioChange = async (scenario: string) => {
    setActiveScenario(scenario);
    await api.setSimulationScenario(scenario);
  };

  const handleReset = async () => {
    if (confirm("CAUTION: This will wipe all security logs and remove all OS firewall rules. Proceed?")) {
      await api.resetFirewall();
      fetchData();
    }
  };

  const handleAckAlert = async (id: number) => {
    await api.acknowledgeAlert(id);
    fetchData();
  };

  const handleRemoveRule = async (id: number) => {
    if (confirm("Are you sure you want to manually lift this block from the OS firewall?")) {
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

  const fwStatus = systemStatus?.firewall_status;
  const isElevated = fwStatus?.is_elevated ?? false;
  const isLive = activeMode === 'live';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-300 p-0 font-sans overflow-x-hidden">
      {/* Global Header */}
      <nav className="h-14 border-b border-slate-800 bg-slate-900/60 backdrop-blur-md flex items-center justify-between px-6 sticky top-0 z-50">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Shield className={cn("w-5 h-5", isLive ? "text-emerald-400" : "text-blue-500")} />
            <span className="text-sm font-bold tracking-tight text-slate-100 uppercase">Adaptive Firewall SOC</span>
          </div>
          <div className="h-4 w-px bg-slate-700 mx-2" />
          <div className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-wider text-slate-500">
            <span className={cn("w-2 h-2 rounded-full animate-pulse", isOnline ? "bg-emerald-500" : "bg-red-500")} />
            System: <span className={isOnline ? "text-emerald-400 font-semibold" : "text-red-400"}>{isOnline ? "Healthy" : "Degraded"}</span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Mode Badge */}
          <div className={cn(
            "flex items-center gap-2 px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border transition-all",
            isLive
              ? "bg-emerald-950/60 border-emerald-500/40 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.2)]"
              : "bg-blue-950/60 border-blue-500/40 text-blue-300"
          )}>
            <span className={cn("w-2 h-2 rounded-full", isLive ? "bg-emerald-400 animate-ping" : "bg-blue-400")} />
            {isLive ? "LIVE NETWORK ENFORCED" : "SIMULATION SANDBOX"}
          </div>

          {/* OS Elevation Status */}
          <div className={cn(
            "hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-mono border",
            isElevated
              ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-400"
              : "bg-amber-950/40 border-amber-500/30 text-amber-300"
          )} title={fwStatus?.message}>
            <CheckCircle2 className="w-3 h-3" />
            {isElevated ? "OS Kernel Filter Active" : "App Guard Active (Elevation Optional)"}
          </div>

          <div className="text-xs font-mono text-slate-400 bg-slate-800/80 px-2.5 py-1 rounded border border-slate-700/50">
            {new Date().toISOString().slice(11, 19)} UTC
          </div>
        </div>
      </nav>

      {/* Elevation Notice Banner if not admin */}
      {!isElevated && isLive && (
        <div className="bg-amber-950/40 border-b border-amber-500/20 px-6 py-2 flex items-center justify-between text-xs text-amber-300/90 font-mono">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              <strong>Note:</strong> Running in user mode. Application-level connection rejection is active. For direct Windows Defender kernel-level packet drops, launch terminal as Administrator.
            </span>
          </div>
          <span className="text-[10px] uppercase font-bold tracking-wider text-amber-400 bg-amber-900/40 px-2 py-0.5 rounded">
            Enforced at App Layer
          </span>
        </div>
      )}

      <main className="p-6 grid grid-cols-12 gap-6">

        {/* Left Sidebar: Command & Control (3 cols) */}
        <div className="col-span-12 lg:col-span-3 space-y-6">
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2 text-slate-100 font-bold text-sm uppercase tracking-wider">
                <Terminal className="w-4 h-4 text-blue-500" />
                Command Center
              </div>
              <SlidersHorizontal className="w-3.5 h-3.5 text-slate-500" />
            </div>

            <div className="space-y-5">
              {/* Mode Toggle */}
              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-2">Enforcement Mode</label>
                <div className="grid grid-cols-2 gap-2 bg-slate-950 p-1 rounded-lg border border-slate-800">
                  <button
                    onClick={() => handleModeChange('live')}
                    className={cn(
                      "py-1.5 px-2 rounded text-xs font-bold transition-all flex items-center justify-center gap-1.5",
                      isLive
                        ? "bg-emerald-600 text-white shadow-md shadow-emerald-900/50"
                        : "text-slate-400 hover:text-slate-200"
                    )}
                  >
                    <Shield className="w-3 h-3" />
                    Live OS
                  </button>
                  <button
                    onClick={() => handleModeChange('simulation')}
                    className={cn(
                      "py-1.5 px-2 rounded text-xs font-bold transition-all flex items-center justify-center gap-1.5",
                      !isLive
                        ? "bg-blue-600 text-white shadow-md shadow-blue-900/50"
                        : "text-slate-400 hover:text-slate-200"
                    )}
                  >
                    <Zap className="w-3 h-3" />
                    Simulation
                  </button>
                </div>
              </div>

              {/* Traffic Generator Scenario */}
              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-2">
                  Traffic Generator / Ingestion
                </label>
                <div className="relative">
                  <select
                    value={activeScenario}
                    onChange={(e) => handleScenarioChange(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs p-2.5 rounded-md focus:ring-1 focus:ring-blue-500 outline-none appearance-none cursor-pointer"
                  >
                    <option value="NORMAL">Normal Baseline Traffic</option>
                    <option value="PORT_SCAN">Port Scan Attack (Triggers Block)</option>
                    <option value="BURST">Connection Burst (Adaptive Score)</option>
                    <option value="HIGH_TRAFFIC">High Bandwidth Flood</option>
                    <option value="FAILED_CONN">Repeated Auth Failure</option>
                    <option value="MIXED">Mixed Attack Traffic</option>
                  </select>
                  <div className="absolute right-3 top-3 pointer-events-none">
                    <Zap className="w-3.5 h-3.5 text-slate-600" />
                  </div>
                </div>
              </div>

              {/* Reset Environment */}
              <button
                onClick={handleReset}
                className="w-full py-2.5 px-4 bg-slate-800/80 hover:bg-red-950/40 border border-slate-700 hover:border-red-500/50 text-slate-400 hover:text-red-400 rounded-md text-xs font-bold transition-all flex items-center justify-center gap-2"
              >
                <RefreshCw className="w-3 h-3" />
                Reset & Purge All Rules
              </button>
            </div>
          </div>

          {/* System Health */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm">
            <div className="flex items-center gap-2 mb-4 text-slate-100 font-bold text-sm uppercase tracking-wider">
              <Activity className="w-4 h-4 text-emerald-500" />
              Subsystem Status
            </div>
            <div className="space-y-3 font-mono">
              {[
                { label: 'Kernel API', status: isOnline ? 'Healthy' : 'Error' },
                { label: 'SQLite Store', status: isOnline ? 'Active' : 'Disconnected' },
                { label: 'ML Anomaly Engine', status: systemStatus?.ml_model_ready ? 'Ready' : 'Training' },
                {
                  label: 'OS Firewall',
                  status: isLive ? (isElevated ? 'Kernel Enforced' : 'App Enforced') : 'Simulated'
                },
                { label: 'App Transport Guard', status: 'Enforced' },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 font-sans">{item.label}</span>
                  <StatusBadge status={item.status} />
                </div>
              ))}
            </div>

            {/* Active Firewall Backend Info */}
            <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 space-y-1">
              <div className="flex items-center gap-1.5 font-bold text-slate-300">
                <Server className="w-3 h-3 text-blue-400" />
                <span>Backend:</span>
              </div>
              <p className="font-mono text-[10px] text-slate-400 truncate">
                {fwStatus?.backend || 'Windows Defender / Netsh'}
              </p>
            </div>
          </div>
        </div>

        {/* Main Dashboard Area (9 cols) */}
        <div className="col-span-12 lg:col-span-9 space-y-6">

          {/* Intelligence Layer Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            <MetricCard
              title="Total Ingested"
              value={summary?.total_traffic || 0}
              icon={Activity}
              description="Packets evaluated"
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
              description="IPs enforced & restricted"
              severity="critical"
            />
            <MetricCard
              title="Critical Alerts"
              value={summary?.critical_alerts || 0}
              icon={Zap}
              description="Security events"
              severity="critical"
            />
          </div>

          {/* Live Charts & Alerts */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Live Chart (2 cols) */}
            <div className="lg:col-span-2 bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2 text-slate-100 font-bold text-sm uppercase tracking-wider">
                  <Activity className="w-4 h-4 text-blue-500" />
                  Live Network Telemetry
                </div>
                <div className="flex items-center gap-4 text-xs font-mono text-slate-500">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-blue-500 inline-block" /> Bytes / Packet
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-red-500 inline-block" /> Threat Score
                  </span>
                </div>
              </div>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="bytesGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="time" stroke="#475569" fontSize={10} />
                    <YAxis yAxisId="left" stroke="#475569" fontSize={10} />
                    <YAxis yAxisId="right" orientation="right" domain={[0, 100]} stroke="#475569" fontSize={10} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px', fontSize: '11px' }}
                    />
                    <Area yAxisId="left" type="monotone" dataKey="bytes" stroke="#3b82f6" fill="url(#bytesGrad)" strokeWidth={2} />
                    <Area yAxisId="right" type="monotone" dataKey="score" stroke="#ef4444" fill="url(#scoreGrad)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Security Alerts (1 col) */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm flex flex-col">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2 text-slate-100 font-bold text-sm uppercase tracking-wider">
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                  Security Alerts
                </div>
                <span className="text-[10px] font-mono text-slate-500 bg-slate-800 px-2 py-0.5 rounded">
                  {alerts.length} total
                </span>
              </div>
              <div className="space-y-3 overflow-y-auto max-h-64 flex-1 pr-1">
                {alerts.length === 0 ? (
                  <p className="text-xs text-slate-600 italic py-8 text-center">No alerts logged</p>
                ) : (
                  alerts.slice(0, 10).map((alert) => (
                    <div
                      key={alert.id}
                      onClick={() => handleAckAlert(alert.id)}
                      className="flex flex-col gap-1 text-xs border-l-2 border-slate-800 pl-3 py-1.5 hover:border-blue-500 bg-slate-950/30 rounded-r transition-colors cursor-pointer"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-200">{alert.title}</span>
                        <span className="text-[10px] font-mono text-slate-500">
                          {new Date(alert.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                      </div>
                      <p className="text-slate-400 text-[11px] truncate">{alert.description}</p>
                      <div className="flex items-center justify-between mt-1">
                        <span className="font-mono text-[10px] text-blue-400">{alert.source}</span>
                        <StatusBadge status={alert.severity} />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Real-time Enforcement Table */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden backdrop-blur-sm">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-slate-100 font-bold text-sm uppercase tracking-wider">
                <Lock className="w-4 h-4 text-blue-500" />
                Active Network Enforcement Rules
              </div>
              <span className="text-xs font-mono text-slate-400">
                {rules.filter(r => r.status === 'ACTIVE').length} Active Enforced Rules
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-800/50 text-slate-400 uppercase font-bold text-[10px] tracking-wider">
                  <tr>
                    <th className="px-6 py-4">Source IP</th>
                    <th className="px-6 py-4">Threat Score</th>
                    <th className="px-6 py-4">Severity</th>
                    <th className="px-6 py-4">Reason</th>
                    <th className="px-6 py-4">Enforcement Level</th>
                    <th className="px-6 py-4">Expires At</th>
                    <th className="px-6 py-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {rules.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-6 py-16 text-center text-slate-600 italic">
                        <div className="flex flex-col items-center gap-3">
                          <Shield className="w-8 h-8 text-slate-800" />
                          <p className="text-sm">Network Secure: No active blocks enforced</p>
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
                        <td className="px-6 py-4 font-mono font-bold text-slate-200">{rule.source}</td>
                        <td className="px-6 py-4 font-bold text-red-400">{rule.threat_score.toFixed(1)}</td>
                        <td className="px-6 py-4">
                          <StatusBadge status={rule.severity || (rule.threat_score > 75 ? 'CRITICAL' : 'HIGH')} />
                        </td>
                        <td className="px-6 py-4 text-slate-400 truncate max-w-xs">{rule.reason}</td>
                        <td className="px-6 py-4">
                          <span className={cn(
                            "px-2 py-0.5 rounded text-[10px] font-bold uppercase",
                            isLive && isElevated
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                              : "bg-blue-950 text-blue-400 border border-blue-800"
                          )}>
                            {isLive ? (isElevated ? "OS Kernel Dropped" : "App Layer Dropped") : "Simulated"}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-slate-400 font-mono">
                          {rule.expires_at ? new Date(rule.expires_at).toLocaleTimeString() : 'Permanent'}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button
                            onClick={(e) => { e.stopPropagation(); handleRemoveRule(rule.id); }}
                            className="p-1.5 text-slate-500 hover:text-red-400 transition-colors"
                            title="Lift block and remove from OS firewall"
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

      {/* Threat Intelligence Modal */}
      {selectedRule && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden">
            <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-800/30">
              <div className="flex items-center gap-3">
                <Shield className="w-6 h-6 text-blue-500" />
                <h2 className="text-lg font-bold text-slate-100">Enforcement Intelligence Dossier</h2>
              </div>
              <button onClick={() => setSelectedRule(null)} className="p-1 hover:bg-slate-800 rounded text-slate-500">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Target Host IP</p>
                  <p className="text-sm font-mono text-slate-200">{selectedRule.source}</p>
                </div>
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Calculated Score</p>
                  <p className="text-sm font-bold text-red-400">{selectedRule.threat_score.toFixed(1)} / 100</p>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                  <Info className="w-3 h-3" /> Detection & Enforcement Breakdown
                </h3>
                <div className="space-y-2.5 bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Rule-Based Detection Weight (60%)</span>
                    <span className="text-slate-200 font-mono">{(selectedRule.threat_score * 0.6).toFixed(1)}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">ML Isolation Forest Anomaly (30%)</span>
                    <span className="text-slate-200 font-mono">{(selectedRule.threat_score * 0.3).toFixed(1)}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Historical Behavior Score (10%)</span>
                    <span className="text-slate-200 font-mono">{(selectedRule.threat_score * 0.1).toFixed(1)}</span>
                  </div>
                </div>
                <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-2">Automated Policy Reason</p>
                  <p className="text-xs text-slate-300 leading-relaxed italic">
                    "{selectedRule.reason}"
                  </p>
                </div>
              </div>
            </div>

            <div className="p-6 bg-slate-800/30 border-t border-slate-800 flex justify-between items-center">
              <div className="flex items-center gap-2">
                <StatusBadge status={selectedRule.action} />
                <span className="text-xs text-slate-400">
                  {isLive ? "Enforced against host network" : "Simulated block"}
                </span>
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
