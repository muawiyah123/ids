/**
 * src/pages/Agents.tsx — Agent management page
 */
import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Server, Plus, Copy, CheckCircle, AlertTriangle } from 'lucide-react';
import { agentsApi } from '../services/api';
import { AgentStatusBadge } from '../components/shared/StatusBadge';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import { formatRelativeTime, formatNumber } from '../lib/utils';
import { useAuthStore } from '../stores/authStore';
import toast from 'react-hot-toast';
import type { Agent, AgentRegisterResponse } from '../types';

export function Agents() {
  const { user } = useAuthStore();
  const qc = useQueryClient();
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN';

  const [showRegister, setShowRegister] = useState(false);
  const [newAgent, setNewAgent] = useState({ name: '', hostname: '', description: '', environment: '' });
  const [registeredToken, setRegisteredToken] = useState<AgentRegisterResponse | null>(null);
  const [copied, setCopied] = useState(false);

  const { data: agents, isLoading } = useQuery({
    queryKey: ['agents'],
    queryFn: agentsApi.list,
    refetchInterval: 15000,
  });

  const registerMutation = useMutation({
    mutationFn: agentsApi.register,
    onSuccess: (data) => {
      setRegisteredToken(data);
      setShowRegister(false);
      setNewAgent({ name: '', hostname: '', description: '', environment: '' });
      qc.invalidateQueries({ queryKey: ['agents'] });
    },
    onError: () => toast.error('Failed to register agent'),
  });

  const disableMutation = useMutation({
    mutationFn: agentsApi.disable,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['agents'] }); toast.success('Agent disabled'); },
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success('Copied to clipboard');
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-sentinel-text flex items-center gap-3">
            <Server size={22} />
            Network Agents
          </h1>
          <p className="text-sentinel-subtle text-sm mt-1">{(agents || []).length} registered agents</p>
        </div>
        {isAdmin && (
          <button onClick={() => setShowRegister(true)} className="btn-primary flex items-center gap-2">
            <Plus size={14} />
            Register Agent
          </button>
        )}
      </div>

      {/* New token display — shown once */}
      {registeredToken && (
        <div className="card p-6 border-threat-info/30 bg-threat-info/5">
          <div className="flex items-start gap-3">
            <CheckCircle size={20} className="text-threat-info flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="font-semibold text-sentinel-text mb-1">Agent registered successfully</h3>
              <p className="text-sm text-sentinel-subtle mb-4">
                Copy the token below — it will <strong className="text-threat-critical">never be shown again</strong>.
              </p>
              <div className="bg-sentinel-bg border border-sentinel-border rounded-lg p-4 font-mono text-xs text-sentinel-text break-all mb-3">
                {registeredToken.token}
              </div>
              <div className="flex gap-3">
                <button onClick={() => handleCopy(registeredToken.token)} className="btn-secondary flex items-center gap-2 text-xs">
                  {copied ? <CheckCircle size={12} /> : <Copy size={12} />}
                  {copied ? 'Copied!' : 'Copy Token'}
                </button>
                <button onClick={() => handleCopy(
                  `python ids_agent.py --server-url ${registeredToken.server_url} --agent-id ${registeredToken.id} --token ${registeredToken.token}`
                )} className="btn-secondary flex items-center gap-2 text-xs">
                  <Copy size={12} />
                  Copy Start Command
                </button>
                <button onClick={() => setRegisteredToken(null)} className="btn-secondary text-xs ml-auto">
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Register form */}
      {showRegister && (
        <div className="card p-6">
          <h3 className="font-semibold text-sentinel-text mb-4">Register New Agent</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-sentinel-subtle mb-1">Agent Name *</label>
              <input className="input w-full" placeholder="prod-server-01" value={newAgent.name} onChange={e => setNewAgent(p => ({ ...p, name: e.target.value }))} />
            </div>
            <div>
              <label className="block text-xs font-medium text-sentinel-subtle mb-1">Hostname</label>
              <input className="input w-full" placeholder="server-01.company.com" value={newAgent.hostname} onChange={e => setNewAgent(p => ({ ...p, hostname: e.target.value }))} />
            </div>
            <div>
              <label className="block text-xs font-medium text-sentinel-subtle mb-1">Environment</label>
              <input className="input w-full" placeholder="production / staging" value={newAgent.environment} onChange={e => setNewAgent(p => ({ ...p, environment: e.target.value }))} />
            </div>
            <div>
              <label className="block text-xs font-medium text-sentinel-subtle mb-1">Description</label>
              <input className="input w-full" placeholder="Optional description" value={newAgent.description} onChange={e => setNewAgent(p => ({ ...p, description: e.target.value }))} />
            </div>
          </div>
          <div className="flex gap-3 mt-4">
            <button
              onClick={() => registerMutation.mutate(newAgent)}
              disabled={!newAgent.name || registerMutation.isPending}
              className="btn-primary disabled:opacity-50"
            >
              {registerMutation.isPending ? 'Registering…' : 'Register Agent'}
            </button>
            <button onClick={() => setShowRegister(false)} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      {/* Agent cards */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <LoadingSpinner size="md" className="text-sentinel-accent" />
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {(agents || []).map((agent: Agent) => (
            <div key={agent.id} className="card p-6 hover:border-sentinel-muted transition-colors">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="font-semibold text-sentinel-text">{agent.name}</div>
                  <div className="text-xs text-sentinel-subtle mt-0.5 font-mono">{agent.hostname || 'No hostname'}</div>
                </div>
                <AgentStatusBadge status={agent.status} />
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs mb-4">
                <div>
                  <span className="text-sentinel-subtle">IP Address</span>
                  <div className="font-mono text-sentinel-text mt-0.5">{agent.ip_address || '—'}</div>
                </div>
                <div>
                  <span className="text-sentinel-subtle">Version</span>
                  <div className="font-mono text-sentinel-text mt-0.5">{agent.version || '—'}</div>
                </div>
                <div>
                  <span className="text-sentinel-subtle">Events Sent</span>
                  <div className="text-sentinel-text mt-0.5 font-medium">{formatNumber(agent.events_sent)}</div>
                </div>
                <div>
                  <span className="text-sentinel-subtle">Environment</span>
                  <div className="text-sentinel-text mt-0.5">{agent.environment || '—'}</div>
                </div>
              </div>
              <div className="flex items-center justify-between pt-3 border-t border-sentinel-border">
                <span className="text-xs text-sentinel-subtle">
                  Last seen: {agent.last_heartbeat_at ? formatRelativeTime(agent.last_heartbeat_at) : 'Never'}
                </span>
                {isAdmin && agent.is_active && (
                  <button
                    onClick={() => { if (confirm(`Disable agent "${agent.name}"?`)) disableMutation.mutate(agent.id); }}
                    className="text-xs text-sentinel-subtle hover:text-threat-critical transition-colors"
                  >
                    Disable
                  </button>
                )}
              </div>
            </div>
          ))}
          {(agents || []).length === 0 && (
            <div className="col-span-2 card p-12 flex flex-col items-center gap-3 text-center">
              <Server size={36} className="text-sentinel-muted" />
              <p className="text-sentinel-subtle">No agents registered yet</p>
              {isAdmin && (
                <button onClick={() => setShowRegister(true)} className="btn-primary text-sm">
                  Register your first agent
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
