/**
 * src/pages/Alerts.tsx — Alert management with filtering and status transitions
 */
import React, { Fragment, useState } from 'react';
import { useQuery, useQueries, useMutation, useQueryClient } from '@tanstack/react-query';
import { Bell, CheckCircle, Eye, X, Sparkles, CircleAlert } from 'lucide-react';
import { alertsApi } from '../services/api';
import type { AttackExplanation } from '../services/api';
import { SeverityBadge } from '../components/shared/SeverityBadge';
import { AlertStatusBadge } from '../components/shared/StatusBadge';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import { formatRelativeTime, formatDateTime } from '../lib/utils';
import { formatConfidence } from '../lib/severity';
import toast from 'react-hot-toast';
import type { Alert, AlertStatus } from '../types';

const STATUSES: AlertStatus[] = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function Alerts() {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ['alerts', page, statusFilter, severityFilter],
    queryFn: () => alertsApi.list({
      page,
      page_size: 20,
      ...(statusFilter && { status: statusFilter }),
      ...(severityFilter && { severity: severityFilter }),
    }),
    refetchInterval: 15000,
  });
  const alertItems = data?.items ?? [];
  const guidanceQueries = useQueries({
    queries: alertItems.map(alert => ({
      queryKey: ['alert-guidance', alert.id],
      queryFn: () => alertsApi.explain(alert.id),
      staleTime: 10 * 60 * 1000,
      retry: 1,
    })),
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (id: string) => alertsApi.acknowledge(id, 'Acknowledged via dashboard'),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); toast.success('Alert acknowledged'); },
  });

  const resolveMutation = useMutation({
    mutationFn: (id: string) => alertsApi.resolve(id, 'Resolved via dashboard'),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); toast.success('Alert resolved'); },
  });

  const fpMutation = useMutation({
    mutationFn: (id: string) => alertsApi.markFalsePositive(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); toast.success('Marked as false positive'); },
  });

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-sentinel-text flex items-center gap-3">
            <Bell size={22} />
            Alerts
          </h1>
          <p className="text-sentinel-subtle text-sm mt-1">
            {data?.total || 0} total alerts
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          value={statusFilter}
          onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
          className="input text-sm"
        >
          <option value="">All Statuses</option>
          {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          value={severityFilter}
          onChange={e => { setSeverityFilter(e.target.value); setPage(1); }}
          className="input text-sm"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
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
                  <th className="px-4 py-3 text-left">Title</th>
                  <th className="px-4 py-3 text-left">Severity</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Confidence</th>
                  <th className="px-4 py-3 text-left">Events</th>
                  <th className="px-4 py-3 text-left">Last Seen</th>
                  <th className="px-4 py-3 text-left">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/50">
                {alertItems.map((alert: Alert, index: number) => {
                  const guidance = guidanceQueries[index];
                  return (
                    <Fragment key={alert.id}>
                      <tr className="hover:bg-sentinel-panel/50 transition-colors">
                        <td className="px-4 py-3">
                          <div className="font-medium text-sentinel-text truncate max-w-xs">{alert.title}</div>
                          <div className="text-xs text-sentinel-subtle mt-0.5 font-mono">
                            {alert.source_ip || '—'} → {alert.destination_ip || '—'}
                          </div>
                        </td>
                        <td className="px-4 py-3"><SeverityBadge severity={alert.severity} size="sm" /></td>
                        <td className="px-4 py-3"><AlertStatusBadge status={alert.status} /></td>
                        <td className="px-4 py-3 font-mono text-xs">{formatConfidence(alert.confidence)}</td>
                        <td className="px-4 py-3 text-xs text-sentinel-subtle">{alert.event_count}</td>
                        <td className="px-4 py-3 text-xs text-sentinel-subtle">{formatRelativeTime(alert.last_seen_at)}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            {alert.status === 'NEW' && (
                              <button
                                onClick={() => acknowledgeMutation.mutate(alert.id)}
                                className="p-1.5 rounded text-sentinel-subtle hover:text-threat-info hover:bg-threat-info/10 transition-colors"
                                title="Acknowledge"
                              >
                                <CheckCircle size={14} />
                              </button>
                            )}
                            {['NEW', 'ACKNOWLEDGED', 'INVESTIGATING'].includes(alert.status) && (
                              <>
                                <button
                                  onClick={() => resolveMutation.mutate(alert.id)}
                                  className="p-1.5 rounded text-sentinel-subtle hover:text-threat-info hover:bg-threat-info/10 transition-colors"
                                  title="Resolve"
                                >
                                  <Eye size={14} />
                                </button>
                                <button
                                  onClick={() => fpMutation.mutate(alert.id)}
                                  className="p-1.5 rounded text-sentinel-subtle hover:text-threat-critical hover:bg-threat-critical/10 transition-colors"
                                  title="False Positive"
                                >
                                  <X size={14} />
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                      <tr className="bg-sentinel-panel/20">
                        <td colSpan={7} className="px-5 pb-5 pt-3">
                          {guidance.isPending ? (
                            <div className="flex items-center gap-2 text-xs text-sentinel-subtle"><LoadingSpinner size="sm" className="text-sentinel-accent" />Preparing attack analysis and prevention guidance…</div>
                          ) : guidance.isError ? (
                            <div className="flex flex-wrap items-center gap-3 text-xs text-threat-high">
                              <span>Guidance could not be loaded. Check backend connectivity and the configured AI provider.</span>
                              <button onClick={() => guidance.refetch()} className="btn-secondary px-2.5 py-1 text-xs">Retry</button>
                            </div>
                          ) : guidance.data ? (
                            <AlertExplanationContent explanation={guidance.data} />
                          ) : null}
                        </td>
                      </tr>
                    </Fragment>
                  );
                })}
                {(data?.items || []).length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-sentinel-subtle text-sm">
                      No alerts found
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

function AlertExplanationContent({ explanation }: { explanation: AttackExplanation }) {
  return <>
    <div className="card p-5"><div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-sentinel-accent"><Sparkles size={14} />Attack overview</div><p className="mt-3 text-sm leading-relaxed text-sentinel-text">{explanation.summary}</p><div className="mt-4 rounded-lg border border-threat-high/20 bg-threat-high/5 p-3"><p className="flex items-center gap-2 text-xs font-semibold text-threat-high"><CircleAlert size={14} />Potential risk</p><p className="mt-1.5 text-sm leading-relaxed text-sentinel-subtle">{explanation.risk}</p></div>
      <div className="mt-4 border-t border-sentinel-border pt-4"><h3 className="font-semibold">Prevention and response guidance</h3><ol className="mt-3 space-y-3">{explanation.actions.map((action, i) => <li key={`${i}-${action}`} className="flex gap-3 text-sm leading-relaxed"><span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-sentinel-accent/15 text-xs font-semibold text-sentinel-accent">{i + 1}</span><span className="pt-0.5 text-sentinel-text">{action}</span></li>)}</ol></div>
      <p className="mt-4 border-t border-sentinel-border pt-3 text-xs leading-relaxed text-sentinel-subtle">Treat this classification as a triage signal. Verify the activity using network and host logs before taking disruptive action.</p>
    </div>
  </>;
}
