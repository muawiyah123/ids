/**
 * src/pages/Agents.tsx — Agent management page
 */
import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Server, Plus, Copy, CheckCircle } from 'lucide-react';
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
  const [newAgentName, setNewAgentName] = useState('');
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
      setNewAgentName('');
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
              <h3 className="font-semibold text-sentinel-text mb-1">Agent ready to start</h3>
              <p className="text-sm text-sentinel-subtle mb-4">
                Open PowerShell as Administrator in the project folder, then paste the one-step command at the PS prompt.
                It sets up the agent and selects capture adapters automatically. Keep that window open while monitoring.
              </p>
              <div className="text-xs text-sentinel-subtle mb-1">Agent ID</div>
              <div className="bg-sentinel-bg border border-sentinel-border rounded-lg p-3 font-mono text-xs text-sentinel-text break-all mb-3">
                {registeredToken.id}
              </div>
              <p className="text-sm text-sentinel-subtle mb-2">
                Save the token now. It is shown once and must be kept private.
              </p>
              <div className="bg-sentinel-bg border border-sentinel-border rounded-lg p-4 font-mono text-xs text-sentinel-text break-all mb-3">
                {registeredToken.token}
              </div>
              <div className="flex gap-3">
                <button onClick={() => handleCopy(registeredToken.id)} className="btn-secondary flex items-center gap-2 text-xs">
                  <Copy size={12} />
                  Copy Agent ID
                </button>
                <button onClick={() => handleCopy(registeredToken.token)} className="btn-secondary flex items-center gap-2 text-xs">
                  <Copy size={12} />
                  Copy Token
                </button>
                <button onClick={() => {
                  const endpoint = `${registeredToken.server_url.replace(/\/+$/, '')}/api/v1/events`;
                  const quote = (value: string) => `'${value.replace(/'/g, "''")}'`;
                  handleCopy(`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\agent\\start_agent.ps1 -AgentId ${quote(registeredToken.id)} -Token ${quote(registeredToken.token)} -ServerUrl ${quote(endpoint)}`);
                }} className="btn-primary flex items-center gap-2 text-xs">
                  <Copy size={12} />
                  {copied ? 'Copied!' : 'Copy One-Step Start Command'}
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
          <p className="text-sm text-sentinel-subtle mb-3">Give this computer a simple name. The other details are filled in automatically when it starts.</p>
          <div className="max-w-xl">
            <label className="block text-xs font-medium text-sentinel-subtle mb-1">Agent Name *</label>
            <input className="input w-full" placeholder="My computer" value={newAgentName} onChange={e => setNewAgentName(e.target.value)} />
          </div>
          <div className="flex gap-3 mt-4">
            <button
              onClick={() => registerMutation.mutate({ name: newAgentName.trim() })}
              disabled={!newAgentName.trim() || registerMutation.isPending}
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
