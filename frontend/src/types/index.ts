/**
 * src/types/index.ts — Central TypeScript type definitions
 */

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: 'SUPER_ADMIN' | 'ADMIN' | 'SOC_ANALYST' | 'VIEWER';
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type AgentStatus = 'ONLINE' | 'OFFLINE' | 'DEGRADED' | 'DISABLED';

export interface Detection {
  id: string;
  event_id: string | null;
  flow_timestamp: string;
  created_at: string;
  agent_id: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  predicted_class: string;
  confidence: number;
  severity: Severity;
  model_version: string | null;
  inference_ms: number | null;
  probabilities: Record<string, number> | null;
}

export interface Alert {
  id: string;
  detection_id: string | null;
  title: string;
  attack_class: string;
  severity: Severity;
  status: AlertStatus;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  agent_id: string | null;
  confidence: number;
  event_count: number;
  first_seen_at: string;
  last_seen_at: string;
  assigned_to_id: string | null;
  notes: string | null;
  created_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
}

export interface Agent {
  id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  os_info: string | null;
  description: string | null;
  environment: string | null;
  version: string | null;
  status: AgentStatus;
  last_heartbeat_at: string | null;
  connected_since: string | null;
  events_sent: number;
  is_active: boolean;
  created_at: string;
}

export interface AgentRegisterResponse extends Agent {
  token: string;
  server_url: string;
}

export interface DashboardSummary {
  total_detections: number;
  threats_detected: number;
  critical_alerts: number;
  open_alerts: number;
  active_agents: number;
  events_last_hour: number;
  events_last_minute_rate: number;
  model_status: string;
  threat_level: 'NORMAL' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
}

export interface TimelinePoint {
  timestamp: string;
  total: number;
  benign: number;
  threats: number;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface ModelStatus {
  ready: boolean;
  version: string;
  model_type: string;
  feature_count: number;
  class_count: number;
  classes: string[];
  artifact_hash: string | null;
  load_error: string | null;
  loaded_at: number | null;
  metrics: {
    macro_f1_test: number | null;
    weighted_f1_test: number | null;
    accuracy_test: number | null;
  };
}

export interface AuditLog {
  id: string;
  actor_email: string | null;
  actor_role: string | null;
  action: string;
  result: string;
  resource_type: string | null;
  resource_id: string | null;
  ip_address: string | null;
  created_at: string;
}

// WebSocket event types
export interface WsEvent {
  type: string;
  timestamp: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any;
}

export interface WsDetectionEvent extends WsEvent {
  type: 'detection.created';
  data: Detection;
}

export interface WsAlertEvent extends WsEvent {
  type: 'alert.created' | 'alert.updated';
  data: Partial<Alert>;
}
