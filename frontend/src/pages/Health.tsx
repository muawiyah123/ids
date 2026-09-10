/**
 * src/pages/Health.tsx — System health status page
 */
import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { healthApi } from '../services/api';

function StatusIcon({ value }: { value: string | number }) {
  if (value === 'ok') return <CheckCircle size={16} className="text-threat-info" />;
  if (value === 'unavailable') return <XCircle size={16} className="text-threat-critical" />;
  if (value === 'disabled') return <AlertTriangle size={16} className="text-threat-medium" />;
  return null;
}

export function Health() {
  const { data, isLoading, dataUpdatedAt } = useQuery({
    queryKey: ['health'],
    queryFn: healthApi.check,
    refetchInterval: 10000,
    // Don't throw on 503 — we want to show the failed state
    retry: false,
  });

  const checks = data?.checks || {};
  const isReady = data?.status === 'ready';

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-sentinel-text flex items-center gap-3">
            <Activity size={22} />
            System Health
          </h1>
          <p className="text-sentinel-subtle text-sm mt-1">
            Last checked: {dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString() : '—'}
          </p>
        </div>
        <div className={`flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-semibold ${
          isReady
            ? 'bg-threat-info/10 border-threat-info/30 text-threat-info'
            : 'bg-threat-critical/10 border-threat-critical/30 text-threat-critical'
        }`}>
          <span className={`w-2 h-2 rounded-full ${isReady ? 'bg-threat-info animate-pulse' : 'bg-threat-critical'}`} />
          {isReady ? 'System Ready' : isLoading ? 'Checking…' : 'Not Ready'}
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {Object.entries(checks).map(([key, value]) => {
          if (key === 'websocket_connections') {
            return (
              <div key={key} className="card p-5 flex items-center gap-4">
                <div className="flex-1">
                  <div className="font-medium text-sentinel-text capitalize">{key.replace(/_/g, ' ')}</div>
                  <div className="text-xs text-sentinel-subtle mt-1">Active WebSocket clients</div>
                </div>
                <div className="text-2xl font-bold text-sentinel-accent">{value as number}</div>
              </div>
            );
          }
          const strVal = String(value);
          return (
            <div key={key} className="card p-5 flex items-center gap-4">
              <StatusIcon value={strVal} />
              <div className="flex-1">
                <div className="font-medium text-sentinel-text capitalize">{key.replace(/_/g, ' ')}</div>
                {key === 'model_error' && Boolean(value) && (
                  <div className="text-xs text-threat-critical mt-1 font-mono">{strVal}</div>
                )}
              </div>
              <div className={`text-sm font-medium capitalize ${
                strVal === 'ok' ? 'text-threat-info' :
                strVal === 'unavailable' ? 'text-threat-critical' :
                strVal === 'disabled' ? 'text-threat-medium' : 'text-sentinel-subtle'
              }`}>
                {strVal}
              </div>
            </div>
          );
        })}
        {isLoading && (
          <div className="col-span-2 card p-12 flex items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <svg className="animate-spin w-8 h-8 text-sentinel-accent" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              <span className="text-sm text-sentinel-subtle">Checking system health…</span>
            </div>
          </div>
        )}
      </div>

      <div className="card p-4 border-sentinel-muted/50">
        <p className="text-xs text-sentinel-subtle">
          <strong className="text-sentinel-text">Health endpoints:</strong>{' '}
          <code className="font-mono bg-sentinel-panel px-1 rounded">GET /health</code> (liveness — always 200) and{' '}
          <code className="font-mono bg-sentinel-panel px-1 rounded">GET /ready</code> (readiness — 503 when DB or model unavailable).
          These endpoints are unauthenticated for Docker/k8s health checks.
        </p>
      </div>
    </div>
  );
}
