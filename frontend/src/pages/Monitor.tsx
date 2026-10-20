/**
 * src/pages/Monitor.tsx — Live event monitor with real WebSocket feed and initial history
 */
import React, { useState, useMemo } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Radio, Filter } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import type { RealtimeState } from '../hooks/useRealtimeEvents';
import { detectionsApi } from '../services/api';
import { SeverityBadge } from '../components/shared/SeverityBadge';
import { formatRelativeTime } from '../lib/utils';
import { formatConfidence } from '../lib/severity';
import type { WsEvent, Detection } from '../types';

interface MonitorItem {
  id: string;
  timestamp: string;
  predicted_class: string;
  severity: string;
  confidence: number;
  source_ip?: string | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  inference_ms?: number | null;
  isLive?: boolean;
}

export function Monitor() {
  const { isConnected, events } = useOutletContext<RealtimeState>();
  const [filterClass, setFilterClass] = useState('');
  const [showBenign, setShowBenign] = useState(true);

  // Load existing detections from DB on mount
  const { data: initialData } = useQuery({
    queryKey: ['monitor-initial-detections'],
    queryFn: () => detectionsApi.list({ page: 1, page_size: 50, sort_by: 'created_at', sort_dir: 'desc' }),
    staleTime: 60_000,
  });

  // Merge live WS events with DB detections
  const allItems = useMemo<MonitorItem[]>(() => {
    const liveItems: MonitorItem[] = events
      .filter((e: WsEvent) => e.type === 'detection.created')
      .map((e: WsEvent) => {
        const d = e.data as any;
        return {
          id: d.id,
          timestamp: d.flow_timestamp || e.timestamp,
          predicted_class: d.predicted_class,
          severity: d.severity,
          confidence: d.confidence,
          source_ip: d.source_ip,
          destination_ip: d.destination_ip,
          destination_port: d.destination_port,
          inference_ms: d.inference_ms,
          isLive: true,
        };
      });

    const dbItems: MonitorItem[] = (initialData?.items || []).map((d: Detection) => ({
      id: d.id,
      timestamp: d.flow_timestamp || d.created_at,
      predicted_class: d.predicted_class,
      severity: d.severity,
      confidence: d.confidence,
      source_ip: d.source_ip,
      destination_ip: d.destination_ip,
      destination_port: d.destination_port,
      inference_ms: d.inference_ms,
      isLive: false,
    }));

    const seen = new Set<string>();
    const result: MonitorItem[] = [];
    for (const item of [...liveItems, ...dbItems]) {
      if (item.id && !seen.has(item.id)) {
        seen.add(item.id);
        result.push(item);
      }
    }
    return result;
  }, [events, initialData]);

  const filtered = allItems.filter((d) => {
    if (!showBenign && d.predicted_class === 'BENIGN') return false;
    if (filterClass && !d.predicted_class?.toLowerCase().includes(filterClass.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-sentinel-text flex items-center gap-3">
            <Radio size={24} className={isConnected ? 'text-threat-info animate-pulse' : 'text-sentinel-subtle'} />
            Live Monitor
          </h1>
          <p className="text-sentinel-subtle text-sm mt-1">
            {isConnected ? 'Streaming real-time detections' : 'Connecting to event stream…'}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-sentinel-subtle cursor-pointer">
            <input
              type="checkbox"
              checked={showBenign}
              onChange={e => setShowBenign(e.target.checked)}
              className="rounded border-sentinel-border"
            />
            Show BENIGN
          </label>
          <div className="relative">
            <Filter size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-sentinel-subtle" />
            <input
              type="text"
              placeholder="Filter by class…"
              className="input pl-8 w-44"
              value={filterClass}
              onChange={e => setFilterClass(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Connection status */}
      <div className={`flex items-center gap-2 text-sm px-4 py-3 rounded-lg border ${
        isConnected
          ? 'bg-threat-info/10 border-threat-info/30 text-threat-info'
          : 'bg-sentinel-muted border-sentinel-border text-sentinel-subtle'
      }`}>
        <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-threat-info animate-pulse' : 'bg-sentinel-subtle'}`} />
        {isConnected ? `Connected — ${allItems.length} events loaded (${events.length} live this session)` : 'Connecting to WebSocket…'}
      </div>

      {/* Events table */}
      <div className="card overflow-hidden">
        <div className="px-6 py-4 border-b border-sentinel-border flex items-center justify-between">
          <span className="text-sm font-medium text-sentinel-text">Recent Detections</span>
          <span className="text-xs text-sentinel-subtle">{filtered.length} events shown</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-sentinel-border">
              <tr className="text-xs text-sentinel-subtle uppercase tracking-wider">
                <th className="px-4 py-3 text-left">Time</th>
                <th className="px-4 py-3 text-left">Class</th>
                <th className="px-4 py-3 text-left">Severity</th>
                <th className="px-4 py-3 text-left">Confidence</th>
                <th className="px-4 py-3 text-left font-mono">Source IP</th>
                <th className="px-4 py-3 text-left font-mono">Dest IP</th>
                <th className="px-4 py-3 text-left">Port</th>
                <th className="px-4 py-3 text-left">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border/50">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-sentinel-subtle text-sm">
                    {isConnected ? 'Waiting for events…' : 'No events — connecting'}
                  </td>
                </tr>
              ) : (
                filtered.map((d, idx) => {
                  const isThreat = d.predicted_class !== 'BENIGN';
                  return (
                    <tr
                      key={`${d.id}-${idx}`}
                      className={`hover:bg-sentinel-panel/50 transition-colors ${d.isLive && idx === 0 ? 'row-new' : ''}`}
                    >
                      <td className="px-4 py-3 text-xs text-sentinel-subtle whitespace-nowrap">
                        {formatRelativeTime(d.timestamp)}
                      </td>
                      <td className="px-4 py-3 font-medium">
                        <span className={isThreat ? 'text-threat-high' : 'text-sentinel-subtle'}>
                          {d.predicted_class}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={d.severity as any} size="sm" />
                      </td>
                      <td className="px-4 py-3 text-xs font-mono">
                        {formatConfidence(d.confidence)}
                      </td>
                      <td className="px-4 py-3 ip-address text-sentinel-subtle font-mono text-xs">
                        {d.source_ip || '—'}
                      </td>
                      <td className="px-4 py-3 ip-address text-sentinel-subtle font-mono text-xs">
                        {d.destination_ip || '—'}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-sentinel-subtle">
                        {d.destination_port || '—'}
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-sentinel-subtle">
                        {d.inference_ms ? `${d.inference_ms.toFixed(1)}ms` : '—'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
