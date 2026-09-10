/**
 * src/pages/Dashboard.tsx — Main SOC dashboard
 */
import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield, TrendingUp, AlertTriangle, Server, Zap, Activity,
  ArrowUpRight, Clock, Radio,
} from 'lucide-react';
import { dashboardApi, analyticsApi } from '../services/api';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import { formatRelativeTime, formatNumber } from '../lib/utils';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';
import { format } from 'date-fns';

// Threat level config
const THREAT_LEVEL_CONFIG = {
  NORMAL: { label: 'NORMAL', color: 'text-threat-info', bg: 'bg-threat-info/10 border-threat-info/30' },
  ELEVATED: { label: 'ELEVATED', color: 'text-threat-medium', bg: 'bg-threat-medium/10 border-threat-medium/30' },
  HIGH: { label: 'HIGH', color: 'text-threat-high', bg: 'bg-threat-high/10 border-threat-high/30' },
  CRITICAL: { label: 'CRITICAL', color: 'text-threat-critical', bg: 'bg-threat-critical/10 border-threat-critical/30' },
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#10b981',
};

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: string;
  severity?: 'normal' | 'warning' | 'critical' | 'success';
}

function MetricCard({ title, value, icon, trend, severity = 'normal' }: MetricCardProps) {
  const colorClass = {
    normal: 'text-sentinel-accent',
    warning: 'text-threat-medium',
    critical: 'text-threat-critical',
    success: 'text-threat-info',
  }[severity];

  return (
    <div className="card p-6 hover:border-sentinel-muted transition-colors">
      <div className="flex items-center justify-between mb-4">
        <span className="text-sentinel-subtle text-sm font-medium">{title}</span>
        <div className={`${colorClass} opacity-70`}>{icon}</div>
      </div>
      <div className={`text-3xl font-bold ${colorClass} mb-1`}>{value}</div>
      {trend && <div className="text-xs text-sentinel-subtle">{trend}</div>}
    </div>
  );
}

export function Dashboard() {
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: dashboardApi.getSummary,
    refetchInterval: 15000,
  });

  const { data: timeline } = useQuery({
    queryKey: ['dashboard-timeline', 24],
    queryFn: () => dashboardApi.getTimeline(24, 60),
    refetchInterval: 60000,
  });

  const { data: attackDist } = useQuery({
    queryKey: ['attack-dist', 24],
    queryFn: () => analyticsApi.attackDistribution(24),
    refetchInterval: 60000,
  });

  const { data: severityDist } = useQuery({
    queryKey: ['severity-dist', 24],
    queryFn: () => analyticsApi.severityDistribution(24),
    refetchInterval: 60000,
  });

  if (summaryLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <LoadingSpinner size="lg" className="text-sentinel-accent" />
      </div>
    );
  }

  const threatConfig = THREAT_LEVEL_CONFIG[summary?.threat_level || 'NORMAL'];

  const timelineData = (timeline || []).map(p => ({
    time: format(new Date(p.timestamp), 'HH:mm'),
    threats: p.threats,
    benign: p.benign,
  }));

  const attackData = (attackDist || []).filter(d => d.class !== 'BENIGN').slice(0, 8);
  const severityData = (severityDist || []).map(d => ({
    name: d.severity,
    value: d.count,
    color: SEVERITY_COLORS[d.severity] || '#94a3b8',
  }));

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-sentinel-text">Security Dashboard</h1>
          <p className="text-sentinel-subtle text-sm mt-1">Real-time network threat monitoring</p>
        </div>
        <div className={`flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-semibold ${threatConfig.bg} ${threatConfig.color}`}>
          <span className={`w-2 h-2 rounded-full animate-pulse ${
            summary?.threat_level === 'NORMAL' ? 'bg-threat-info' :
            summary?.threat_level === 'ELEVATED' ? 'bg-threat-medium' :
            summary?.threat_level === 'HIGH' ? 'bg-threat-high' : 'bg-threat-critical'
          }`} />
          Threat Level: {threatConfig.label}
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <MetricCard
          title="Total Detections"
          value={formatNumber(summary?.total_detections || 0)}
          icon={<Activity size={20} />}
          trend="All time"
        />
        <MetricCard
          title="Threats Detected"
          value={formatNumber(summary?.threats_detected || 0)}
          icon={<AlertTriangle size={20} />}
          severity={summary?.threats_detected ? 'warning' : 'success'}
          trend="Non-BENIGN classifications"
        />
        <MetricCard
          title="Open Alerts"
          value={summary?.open_alerts || 0}
          icon={<Zap size={20} />}
          severity={summary?.critical_alerts ? 'critical' : summary?.open_alerts ? 'warning' : 'success'}
          trend={`${summary?.critical_alerts || 0} critical`}
        />
        <MetricCard
          title="Active Agents"
          value={summary?.active_agents || 0}
          icon={<Server size={20} />}
          severity={summary?.active_agents ? 'success' : 'warning'}
          trend="Sending heartbeats"
        />
      </div>

      {/* Secondary metrics */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <MetricCard
          title="Events Last Hour"
          value={formatNumber(summary?.events_last_hour || 0)}
          icon={<Clock size={20} />}
          trend="Network flows analyzed"
        />
        <MetricCard
          title="Events/Min Rate"
          value={`${summary?.events_last_minute_rate || 0}`}
          icon={<Radio size={20} />}
          trend="Last minute"
        />
        <MetricCard
          title="Model Status"
          value={summary?.model_status || '—'}
          icon={<Shield size={20} />}
          severity={summary?.model_status === 'READY' ? 'success' : 'critical'}
          trend="XGBoost inference engine"
        />
        <MetricCard
          title="Critical Alerts"
          value={summary?.critical_alerts || 0}
          icon={<TrendingUp size={20} />}
          severity={summary?.critical_alerts ? 'critical' : 'success'}
          trend="Requires immediate action"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Timeline chart */}
        <div className="xl:col-span-2 card p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="font-semibold text-sentinel-text">Detection Timeline</h2>
              <p className="text-xs text-sentinel-subtle mt-1">Last 24 hours, hourly buckets</p>
            </div>
          </div>
          {timelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={timelineData} margin={{ top: 5, right: 5, bottom: 5, left: 0 }}>
                <defs>
                  <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="benignGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 11 }} />
                <YAxis stroke="#475569" tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: '#0f1629', border: '1px solid #1e2d4a', borderRadius: 8 }}
                  labelStyle={{ color: '#e2e8f0' }}
                />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threatGrad)" name="Threats" />
                <Area type="monotone" dataKey="benign" stroke="#10b981" fill="url(#benignGrad)" name="Benign" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-sentinel-subtle text-sm">
              No detection data in the last 24 hours
            </div>
          )}
        </div>

        {/* Severity pie */}
        <div className="card p-6">
          <h2 className="font-semibold text-sentinel-text mb-1">Severity Distribution</h2>
          <p className="text-xs text-sentinel-subtle mb-6">Last 24 hours</p>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={85}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#0f1629', border: '1px solid #1e2d4a', borderRadius: 8 }}
                />
                <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-sentinel-subtle text-sm">
              No data
            </div>
          )}
        </div>
      </div>

      {/* Top attacks */}
      {attackData.length > 0 && (
        <div className="card p-6">
          <h2 className="font-semibold text-sentinel-text mb-6">Top Attack Classes (Last 24h)</h2>
          <div className="space-y-3">
            {attackData.map((d, i) => {
              const total = attackData.reduce((s, x) => s + x.count, 0);
              const pct = total > 0 ? ((d.count / total) * 100).toFixed(1) : '0';
              return (
                <div key={d.class} className="flex items-center gap-3">
                  <span className="text-xs text-sentinel-subtle w-5 text-right">{i + 1}</span>
                  <span className="text-sm text-sentinel-text flex-1 truncate">{d.class}</span>
                  <div className="flex-1 max-w-48 bg-sentinel-panel rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full bg-sentinel-accent"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs text-sentinel-subtle w-12 text-right">{formatNumber(d.count)}</span>
                  <span className="text-xs text-sentinel-subtle/60 w-12 text-right">{pct}%</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
