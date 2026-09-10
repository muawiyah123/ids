/**
 * src/pages/Alerts.tsx — Alert management with filtering and status transitions
 */
import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Bell, CheckCircle, Eye, X } from 'lucide-react';
import { alertsApi } from '../services/api';
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
                {(data?.items || []).map((alert: Alert) => (
                  <tr key={alert.id} className="hover:bg-sentinel-panel/50 transition-colors">
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
                ))}
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
