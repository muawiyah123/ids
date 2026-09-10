/**
 * src/components/shared/StatusBadge.tsx
 */
import React from 'react';
import { STATUS_CONFIG, AGENT_STATUS_CONFIG } from '../../lib/severity';
import type { AlertStatus, AgentStatus } from '../../types';

interface AlertStatusBadgeProps {
  status: AlertStatus;
}

export function AlertStatusBadge({ status }: AlertStatusBadgeProps) {
  const config = STATUS_CONFIG[status] || { label: status, className: '' };
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${config.className}`}>
      {config.label}
    </span>
  );
}

interface AgentStatusBadgeProps {
  status: AgentStatus;
}

export function AgentStatusBadge({ status }: AgentStatusBadgeProps) {
  const config = AGENT_STATUS_CONFIG[status] || { label: status, dot: '', text: '' };
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${config.text}`}>
      <span className={`status-dot ${config.dot}`} />
      {config.label}
    </span>
  );
}
