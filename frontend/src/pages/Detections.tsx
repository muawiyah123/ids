/**
 * src/pages/Detections.tsx — Detection history with filtering, sorting, and export
 */
import React, { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Search, Download, ShieldCheck, X, Sparkles, CircleAlert, Check, ArrowUpRight } from 'lucide-react';
import { detectionsApi, type AttackExplanation } from '../services/api';
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
  const [selected, setSelected] = useState<Detection | null>(null);
  const explanation = useMutation({ mutationFn: detectionsApi.explain });
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
                  <th className="px-4 py-3 text-right">Investigation</th>
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
                    <td className="px-4 py-2 text-right">
                      {d.predicted_class !== 'BENIGN' ? (
                        <button onClick={() => { setSelected(d); explanation.mutate(d.id); }} className="btn-secondary inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs">
                          <Sparkles size={13} /> Explain
                        </button>
                      ) : <span className="text-xs text-sentinel-subtle">—</span>}
                    </td>
                  </tr>
                ))}
                {(data?.items || []).length === 0 && (
                  <tr>
                    <td colSpan={9} className="px-4 py-12 text-center text-sentinel-subtle text-sm">
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

      {selected && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60" onMouseDown={e => { if (e.target === e.currentTarget) setSelected(null); }}>
          <section role="dialog" aria-modal="true" aria-labelledby="explanation-title" className="h-full w-full max-w-xl overflow-y-auto border-l border-sentinel-border bg-sentinel-bg shadow-2xl">
            <div className="sticky top-0 z-10 flex items-center justify-between border-b border-sentinel-border bg-sentinel-surface/95 px-6 py-5 backdrop-blur">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-sentinel-accent/15 p-2 text-sentinel-accent"><ShieldCheck size={19} /></div>
                <div><h2 id="explanation-title" className="font-semibold">Attack investigation</h2><p className="text-xs text-sentinel-subtle">Detection context and response guidance</p></div>
              </div>
              <button onClick={() => setSelected(null)} aria-label="Close investigation" className="rounded-lg p-2 text-sentinel-subtle hover:bg-sentinel-panel hover:text-sentinel-text"><X size={18} /></button>
            </div>
            <div className="space-y-5 p-6">
              <div className="card p-5">
                <div className="flex items-start justify-between gap-4">
                  <div><p className="text-xs uppercase tracking-wider text-sentinel-subtle">Detected threat</p><h3 className="mt-1 text-xl font-semibold">{selected.predicted_class}</h3></div>
                  <SeverityBadge severity={selected.severity} size="sm" />
                </div>
                <div className="mt-4 grid grid-cols-2 gap-3 border-t border-sentinel-border pt-4 text-xs">
                  <div><span className="text-sentinel-subtle">Confidence</span><p className="mt-1 font-mono text-sentinel-text">{formatConfidence(selected.confidence)}</p></div>
                  <div><span className="text-sentinel-subtle">Protocol / port</span><p className="mt-1 font-mono text-sentinel-text">{selected.protocol || '—'} / {selected.destination_port || '—'}</p></div>
                  <div><span className="text-sentinel-subtle">Source</span><p className="mt-1 break-all font-mono text-sentinel-text">{selected.source_ip || '—'}{selected.source_port ? `:${selected.source_port}` : ''}</p></div>
                  <div><span className="text-sentinel-subtle">Destination</span><p className="mt-1 break-all font-mono text-sentinel-text">{selected.destination_ip || '—'}{selected.destination_port ? `:${selected.destination_port}` : ''}</p></div>
                </div>
              </div>
              {explanation.isPending && explanation.variables === selected.id ? (
                <div className="card flex items-center gap-3 p-5"><LoadingSpinner size="sm" className="text-sentinel-accent" /><span className="text-sm text-sentinel-subtle">Preparing attack analysis…</span></div>
              ) : explanation.isError && explanation.variables === selected.id ? (
                <div className="card flex gap-3 p-5 text-sm text-threat-high"><CircleAlert size={18} className="mt-0.5 shrink-0" /><div><p className="font-medium">Could not load the explanation</p><p className="mt-1 text-xs text-sentinel-subtle">Please retry. Your detection is still available in the detections list.</p><button className="btn-secondary mt-3 text-xs" onClick={() => explanation.mutate(selected.id)}>Retry</button></div></div>
              ) : explanation.data && explanation.variables === selected.id ? (
                <ExplanationContent explanation={explanation.data} />
              ) : null}
              <p className="flex gap-2 px-1 text-xs leading-relaxed text-sentinel-subtle"><CircleAlert size={14} className="mt-0.5 shrink-0" />Treat classifier output as a triage signal. Confirm the activity with network, endpoint, and service logs before taking disruptive action.</p>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function ExplanationContent({ explanation }: { explanation: AttackExplanation }) {
  return <>
    <div className="card p-5"><div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-sentinel-accent"><Sparkles size={14} />What this means</div><p className="mt-3 text-sm leading-relaxed text-sentinel-text">{explanation.summary}</p><div className="mt-4 rounded-lg border border-threat-high/20 bg-threat-high/5 p-3"><p className="flex items-center gap-2 text-xs font-semibold text-threat-high"><CircleAlert size={14} />Potential risk</p><p className="mt-1.5 text-sm leading-relaxed text-sentinel-subtle">{explanation.risk}</p></div></div>
    <div className="card p-5"><div className="flex items-center justify-between"><h3 className="font-semibold">Recommended response</h3><span className="rounded-full bg-sentinel-panel px-2.5 py-1 text-[10px] text-sentinel-subtle">{explanation.source}</span></div><ol className="mt-4 space-y-3">{explanation.actions.map((action, i) => <li key={`${i}-${action}`} className="flex gap-3 text-sm leading-relaxed"><span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-sentinel-accent/15 text-xs font-semibold text-sentinel-accent">{i + 1}</span><span className="pt-0.5 text-sentinel-text">{action}</span></li>)}</ol></div>
    <a href="/alerts" className="btn-secondary flex items-center justify-between px-4 py-3 text-sm"><span className="flex items-center gap-2"><Check size={15} />Open alert queue to track response</span><ArrowUpRight size={15} /></a>
  </>;
}
