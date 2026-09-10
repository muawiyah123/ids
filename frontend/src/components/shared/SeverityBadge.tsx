/**
 * src/components/shared/SeverityBadge.tsx
 */
import React from 'react';
import { getSeverityConfig } from '../../lib/severity';

interface Props {
  severity: string;
  size?: 'sm' | 'md';
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const config = getSeverityConfig(severity);
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-mono font-semibold uppercase tracking-wider
        ${size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs'}
        ${config.className}`}
    >
      <span className={`status-dot ${config.dot}`} />
      {config.label}
    </span>
  );
}
