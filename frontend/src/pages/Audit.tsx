/**
 * src/pages/Audit.tsx — Audit log viewer
 */
import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ClipboardList } from 'lucide-react';
import { auditApi } from '../services/api';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import { formatDateTime } from '../lib/utils';
import type { AuditLog } from '../types';

export function Audit() {
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ['audit', page],
    queryFn: () => auditApi.list({ page, page_size: 50 }),
    refetchInterval: 30000,
  });

  const getActionColor = (action: string) => {
    if (action.includes('LOGIN') || action.includes('REGISTER')) return 'text-threat-info';
    if (action.includes('ALERT') || action.includes('RESOLVED') || action.includes('ACKNOWLEDGED')) return 'text-sentinel-accent';
    if (action.includes('FAILED') || action.includes('ERROR') || action.includes('DELETED')) return 'text-threat-critical';
    if (action.includes('CREATED') || action.includes('UPDATED')) return 'text-threat-medium';
    return 'text-sentinel-subtle';
  };

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-sentinel-text flex items-center gap-3">
          <ClipboardList size={22} />
          Audit Log
        </h1>
        <p className="text-sentinel-subtle text-sm mt-1">
          Immutable record of all security-relevant actions • {data?.total || 0} total entries
        </p>
      </div>

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
                  <th className="px-4 py-3 text-left">Action</th>
                  <th className="px-4 py-3 text-left">Actor</th>
                  <th className="px-4 py-3 text-left">Role</th>
                  <th className="px-4 py-3 text-left">Result</th>
                  <th className="px-4 py-3 text-left">Resource</th>
                  <th className="px-4 py-3 text-left">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/50">
                {(data?.items || []).map((log: AuditLog) => (
                  <tr key={log.id} className="hover:bg-sentinel-panel/50 transition-colors">
                    <td className="px-4 py-3 text-xs text-sentinel-subtle whitespace-nowrap font-mono">
                      {formatDateTime(log.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-mono font-medium ${getActionColor(log.action)}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-sentinel-subtle truncate max-w-32">
                      {log.actor_email || '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-sentinel-subtle">
                      {log.actor_role || '—'}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-mono ${log.result === 'SUCCESS' ? 'text-threat-info' : 'text-threat-critical'}`}>
                        {log.result}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-sentinel-subtle">
                      {log.resource_type ? `${log.resource_type}` : '—'}
                      {log.resource_id && <span className="font-mono ml-1 opacity-60">{log.resource_id.slice(0, 8)}</span>}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-sentinel-subtle">{log.ip_address || '—'}</td>
                  </tr>
                ))}
                {(data?.items || []).length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-sentinel-subtle text-sm">
                      No audit log entries found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {data && data.total_pages > 1 && (
          <div className="px-6 py-4 border-t border-sentinel-border flex items-center justify-between">
            <span className="text-xs text-sentinel-subtle">
              Page {data.page} of {data.total_pages}
            </span>
            <div className="flex gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1} className="btn-secondary px-3 py-1.5 text-xs disabled:opacity-40">Previous</button>
              <button onClick={() => setPage(p => p + 1)} disabled={page >= data.total_pages} className="btn-secondary px-3 py-1.5 text-xs disabled:opacity-40">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
