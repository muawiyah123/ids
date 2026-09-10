/**
 * src/lib/severity.ts — Severity display utilities
 */
import type { Severity, AlertStatus, AgentStatus } from '../types';

export const SEVERITY_CONFIG: Record<Severity, {
  label: string;
  className: string;
  dot: string;
  textColor: string;
}> = {
  CRITICAL: {
    label: 'CRITICAL',
    className: 'severity-CRITICAL',
    dot: 'bg-threat-critical',
    textColor: 'text-threat-critical',
  },
  HIGH: {
    label: 'HIGH',
    className: 'severity-HIGH',
    dot: 'bg-threat-high',
    textColor: 'text-threat-high',
  },
  MEDIUM: {
    label: 'MEDIUM',
    className: 'severity-MEDIUM',
    dot: 'bg-threat-medium',
    textColor: 'text-threat-medium',
  },
  LOW: {
    label: 'LOW',
    className: 'severity-LOW',
    dot: 'bg-threat-low',
    textColor: 'text-threat-low',
  },
  INFO: {
    label: 'INFO',
    className: 'severity-INFO',
    dot: 'bg-threat-info',
    textColor: 'text-threat-info',
  },
};

export const STATUS_CONFIG: Record<AlertStatus, { label: string; className: string }> = {
  NEW: { label: 'New', className: 'bg-threat-critical/20 text-threat-critical border border-threat-critical/30' },
  ACKNOWLEDGED: { label: 'Acknowledged', className: 'bg-threat-medium/20 text-threat-medium border border-threat-medium/30' },
  INVESTIGATING: { label: 'Investigating', className: 'bg-sentinel-accent/20 text-sentinel-accent border border-sentinel-accent/30' },
  RESOLVED: { label: 'Resolved', className: 'bg-threat-info/20 text-threat-info border border-threat-info/30' },
  FALSE_POSITIVE: { label: 'False Positive', className: 'bg-sentinel-muted text-sentinel-subtle border border-sentinel-border' },
};

export const AGENT_STATUS_CONFIG: Record<AgentStatus, { label: string; dot: string; text: string }> = {
  ONLINE: { label: 'Online', dot: 'bg-threat-info animate-pulse', text: 'text-threat-info' },
  DEGRADED: { label: 'Degraded', dot: 'bg-threat-medium animate-pulse', text: 'text-threat-medium' },
  OFFLINE: { label: 'Offline', dot: 'bg-sentinel-subtle', text: 'text-sentinel-subtle' },
  DISABLED: { label: 'Disabled', dot: 'bg-threat-critical/50', text: 'text-threat-critical/50' },
};

export function getSeverityConfig(severity: string) {
  return SEVERITY_CONFIG[severity as Severity] || SEVERITY_CONFIG.INFO;
}

export function formatConfidence(confidence: number): string {
  return `${(confidence * 100).toFixed(1)}%`;
}

export function formatInferenceMs(ms: number | null): string {
  if (ms === null) return '—';
  return `${ms.toFixed(1)}ms`;
}
