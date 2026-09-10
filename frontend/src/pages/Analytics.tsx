/**
 * src/pages/Analytics.tsx — Analytics dashboard with real charts
 */
import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { BarChart3 } from 'lucide-react';
import { analyticsApi } from '../services/api';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  LineChart, Line, CartesianGrid,
} from 'recharts';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#10b981',
};

const CLASS_COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#f97316', '#eab308', '#10b981', '#ef4444', '#06b6d4'];

export function Analytics() {
  const [hours, setHours] = useState(24);

  const { data: attacks, isLoading: a1 } = useQuery({
    queryKey: ['analytics-attacks', hours],
    queryFn: () => analyticsApi.attackDistribution(hours),
  });

  const { data: severity } = useQuery({
    queryKey: ['analytics-severity', hours],
    queryFn: () => analyticsApi.severityDistribution(hours),
  });

  const { data: sources } = useQuery({
    queryKey: ['analytics-sources', hours],
    queryFn: () => analyticsApi.topSources(hours),
  });

  const { data: trends } = useQuery({
    queryKey: ['analytics-trends'],
    queryFn: () => analyticsApi.trends(168),
  });

  const attackData = (attacks || []).filter(d => d.class !== 'BENIGN');
  const severityData = (severity || []).map(d => ({
    name: d.severity, value: d.count, color: SEVERITY_COLORS[d.severity] || '#94a3b8',
  }));

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-sentinel-text flex items-center gap-3">
            <BarChart3 size={22} />
            Analytics
          </h1>
          <p className="text-sentinel-subtle text-sm mt-1">Network threat intelligence</p>
        </div>
        <select
          value={hours}
          onChange={e => setHours(Number(e.target.value))}
          className="input text-sm"
        >
          <option value={6}>Last 6 hours</option>
          <option value={24}>Last 24 hours</option>
          <option value={168}>Last 7 days</option>
          <option value={720}>Last 30 days</option>
        </select>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Attack class bar chart */}
        <div className="card p-6">
          <h2 className="font-semibold text-sentinel-text mb-1">Attack Class Distribution</h2>
          <p className="text-xs text-sentinel-subtle mb-6">Excluding BENIGN traffic</p>
          {attackData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={attackData} layout="vertical" margin={{ left: 10, right: 10 }}>
                <XAxis type="number" stroke="#475569" tick={{ fontSize: 11 }} />
                <YAxis
                  type="category"
                  dataKey="class"
                  stroke="#475569"
                  tick={{ fontSize: 10 }}
                  width={140}
                />
                <Tooltip
                  contentStyle={{ background: '#0f1629', border: '1px solid #1e2d4a', borderRadius: 8 }}
                />
                {attackData.map((_, i) => null)}
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {attackData.map((_, idx) => (
                    <Cell key={idx} fill={CLASS_COLORS[idx % CLASS_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-72 flex items-center justify-center text-sentinel-subtle text-sm">
              {a1 ? <LoadingSpinner /> : 'No threat data'}
            </div>
          )}
        </div>

        {/* Severity pie */}
        <div className="card p-6">
          <h2 className="font-semibold text-sentinel-text mb-1">Severity Distribution</h2>
          <p className="text-xs text-sentinel-subtle mb-6">All detections</p>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={70} outerRadius={100} paddingAngle={2} dataKey="value">
                  {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#0f1629', border: '1px solid #1e2d4a', borderRadius: 8 }} />
                <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-72 flex items-center justify-center text-sentinel-subtle text-sm">No data</div>
          )}
        </div>

        {/* Top sources */}
        <div className="card p-6">
          <h2 className="font-semibold text-sentinel-text mb-1">Top Threat Sources</h2>
          <p className="text-xs text-sentinel-subtle mb-6">IP addresses by detection count</p>
          {(sources || []).length > 0 ? (
            <div className="space-y-3">
              {sources!.map((s, i) => {
                const max = sources![0].count;
                return (
                  <div key={s.ip} className="flex items-center gap-3">
                    <span className="text-xs text-sentinel-subtle w-5 text-right">{i + 1}</span>
                    <span className="ip-address text-sm text-sentinel-text flex-1">{s.ip}</span>
                    <div className="flex-1 max-w-36 bg-sentinel-panel rounded-full h-1.5">
                      <div
                        className="h-1.5 rounded-full bg-threat-high"
                        style={{ width: `${(s.count / max) * 100}%` }}
                      />
                    </div>
                    <span className="text-xs font-mono text-sentinel-subtle w-16 text-right">{s.count} events</span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="h-40 flex items-center justify-center text-sentinel-subtle text-sm">No threat traffic</div>
          )}
        </div>

        {/* 7-day trend */}
        <div className="card p-6">
          <h2 className="font-semibold text-sentinel-text mb-1">7-Day Detection Trend</h2>
          <p className="text-xs text-sentinel-subtle mb-6">Daily threat counts</p>
          {(trends || []).length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={trends} margin={{ top: 5, right: 10, bottom: 5, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
                <XAxis dataKey="date" stroke="#475569" tick={{ fontSize: 10 }}
                  tickFormatter={v => v ? new Date(v).toLocaleDateString('en', { month: 'short', day: 'numeric' }) : ''} />
                <YAxis stroke="#475569" tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#0f1629', border: '1px solid #1e2d4a', borderRadius: 8 }} />
                <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} dot={false} name="Threats" />
                <Line type="monotone" dataKey="total" stroke="#3b82f6" strokeWidth={2} dot={false} name="Total" />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-60 flex items-center justify-center text-sentinel-subtle text-sm">No trend data</div>
          )}
        </div>
      </div>
    </div>
  );
}
