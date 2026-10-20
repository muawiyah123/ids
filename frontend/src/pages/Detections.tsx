/**
 * src/pages/Detections.tsx — Detection history with filtering, sorting, and export
 */
import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Search, Download } from 'lucide-react';
import { detectionsApi } from '../services/api';
import { SeverityBadge } from '../components/shared/SeverityBadge';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import { formatRelativeTime } from '../lib/utils';
import { formatConfidence } from '../lib/severity';
import type { Detection } from '../types';

const CLASSES = [
  'BENIGN', 'Bot', 'DDoS', 'DoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
  'DoS slowloris', 'FTP-Patator', 'Heartbleed', 'Infiltration', 'PortScan',
  'SSH-Patator', 'Web Attack - Brute Force', 'Web Attack - Sql Injection', 'Web Attack - XSS',
];

export function Detections() {
  const [page, setPage] = useState(1);
  const [severityFilter, setSeverityFilter] = useState('');
  const [classFilter, setClassFilter] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortDir, setSortDir] = useState('desc');

  const { data, isLoading } = useQuery({
    queryKey: ['detections', page, severityFilter, classFilter, sourceIp, sortBy, sortDir],
    queryFn: () => detectionsApi.list({
      page,
      page_size: 25,
      ...(severityFilter && { severity: severityFilter }),
      ...(classFilter && { predicted_class: classFilter }),
      ...(sourceIp && { source_ip: sourceIp }),
      sort_by: sortBy,
      sort_dir: sortDir,
    }),
    refetchInterval: 15000,
  });

  const handleExport = () => {
    const params = new URLSearchParams();
    if (severityFilter) params.set('severity', severityFilter);
    window.open(`/api/v1/detections/export/csv?${params}`, '_blank');
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-sentinel-text flex items-center gap-3">
            <Search size={22} />
            Detections
          </h1>
          <p className="text-sentinel-subtle text-sm mt-1">{data?.total || 0} total detections</p>
        </div>
        <button onClick={handleExport} className="btn-secondary flex items-center gap-2">
          <Download size={14} />
          Export CSV
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          value={severityFilter}
          onChange={e => { setSeverityFilter(e.target.value); setPage(1); }}
          className="input text-sm"
        >
          <option value="">All Severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={classFilter}
          onChange={e => { setClassFilter(e.target.value); setPage(1); }}
          className="input text-sm"
        >
          <option value="">All Classes</option>
          {CLASSES.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <input
          type="text"
          placeholder="Source IP filter…"
          className="input text-sm w-44"
          value={sourceIp}
          onChange={e => { setSourceIp(e.target.value); setPage(1); }}
        />
        <select
          value={`${sortBy}:${sortDir}`}
          onChange={e => {
            const [field, dir] = e.target.value.split(':');
            setSortBy(field);
            setSortDir(dir);
          }}
          className="input text-sm"
        >
          <option value="created_at:desc">Newest first</option>
          <option value="created_at:asc">Oldest first</option>
          <option value="confidence:desc">Highest confidence</option>
          <option value="severity:desc">Highest severity</option>
        </select>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <LoadingSpinner size="md" className="text-sentinel-accent" />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-sentinel-border">
                <tr className="text-xs text-sentinel-subtle uppercase tracking-wider">
                  <th className="px-4 py-3 text-left">Timestamp</th>
                  <th className="px-4 py-3 text-left">Class</th>
                  <th className="px-4 py-3 text-left">Severity</th>
                  <th className="px-4 py-3 text-left">Confidence</th>
                  <th className="px-4 py-3 text-left">Source IP</th>
                  <th className="px-4 py-3 text-left">Dest IP</th>
                  <th className="px-4 py-3 text-left">Port</th>
                  <th className="px-4 py-3 text-left">Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/50">
                {(data?.items || []).map((d: Detection) => (
                  <tr key={d.id} className="hover:bg-sentinel-panel/50 transition-colors">
                    <td className="px-4 py-3 text-xs text-sentinel-subtle whitespace-nowrap">
                      {formatRelativeTime(d.flow_timestamp)}
                    </td>
                    <td className="px-4 py-3 font-medium">
                      <span className={d.predicted_class === 'BENIGN' ? 'text-sentinel-subtle' : 'text-sentinel-text'}>
                        {d.predicted_class}
                      </span>
                    </td>
                    <td className="px-4 py-3"><SeverityBadge severity={d.severity} size="sm" /></td>
                    <td className="px-4 py-3 font-mono text-xs">{formatConfidence(d.confidence)}</td>
                    <td className="px-4 py-3 font-mono text-xs text-sentinel-subtle">{d.source_ip || '—'}</td>
                    <td className="px-4 py-3 font-mono text-xs text-sentinel-subtle">{d.destination_ip || '—'}</td>
                    <td className="px-4 py-3 font-mono text-xs text-sentinel-subtle">{d.destination_port || '—'}</td>
                    <td className="px-4 py-3 font-mono text-xs text-sentinel-subtle">
                      {d.inference_ms ? `${d.inference_ms}ms` : '—'}
                    </td>
                  </tr>
                ))}
                {(data?.items || []).length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center text-sentinel-subtle text-sm">
                      No detections found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {data && data.total_pages > 1 && (
          <div className="px-6 py-4 border-t border-sentinel-border flex items-center justify-between">
            <span className="text-xs text-sentinel-subtle">
              Page {data.page} of {data.total_pages} ({data.total} total)
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="btn-secondary px-3 py-1.5 text-xs disabled:opacity-40"
              >
                Previous
              </button>
              <button
                onClick={() => setPage(p => p + 1)}
                disabled={page >= data.total_pages}
                className="btn-secondary px-3 py-1.5 text-xs disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
