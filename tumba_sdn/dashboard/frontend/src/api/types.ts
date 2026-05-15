export type JsonValue = string | number | boolean | null | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export type ServiceStatus = {
  url?: string;
  online?: boolean;
  http_ok?: boolean;
  error?: string;
  payload?: Record<string, unknown>;
};

export type HealthResponse = {
  ok?: boolean;
  ts?: number;
  switches?: number;
  has_metrics?: boolean;
  services?: Record<string, ServiceStatus>;
  logs?: Record<string, string>;
};

export type Metrics = Record<string, unknown> & {
  zone_metrics?: Record<string, ZoneMetric>;
  connected_switches?: unknown[];
  switches?: unknown[];
  hosts?: unknown[];
  top_flows?: FlowRow[];
  security_events?: unknown[];
  security_blocked?: number;
  ml_action?: string;
};

export type ZoneMetric = {
  throughput_mbps?: number;
  max_utilization_pct?: number;
  latency_ms?: number;
  queue_depth?: number;
  packet_drops?: number;
  congested?: boolean;
  threshold_state?: string;
};

export type PcInfo = {
  id?: string;
  label?: string;
  ip?: string;
  mac?: string;
  zone?: string;
  zone_key?: string;
  zone_label?: string;
  vlan?: number | string;
  switch?: string;
  activity?: string;
  activity_label?: string;
  traffic_type?: string;
  priority_level?: string;
  priority_label?: string;
  dscp?: number | string;
  qos_queue?: number | string;
  current_mbps?: number;
  traffic_mbps?: number;
  link_capacity_mbps?: number;
  utilization_percent?: number;
  congestion_state?: string;
  controller_action?: string;
  current_status?: string;
  browser_url?: string;
  browser_status?: string;
  security_state?: string;
  last_alert?: string;
  dst_ip?: string;
  dst_port?: number | string;
  dst_service_name?: string;
  proto?: string;
};

export type PcActivities = {
  ts?: number;
  pcs?: Record<string, PcInfo>;
  profiles?: Record<string, Record<string, unknown>>;
};

export type FlowRow = {
  source_pc?: string;
  src_label?: string;
  src_ip?: string;
  src_zone?: string;
  src_vlan?: number | string;
  src_switch?: string;
  dst_ip?: string;
  dst_port?: number | string;
  dst_service_name?: string;
  proto?: string;
  activity?: string;
  mbps?: number;
  priority?: string;
  dscp?: number | string;
  controller_action?: string;
  status?: string;
  security_state?: string;
};

export type ProactiveState = Record<string, unknown> & {
  zones?: Record<string, Record<string, unknown>>;
  links?: Record<string, Record<string, unknown>[]>;
  link_index?: Record<string, Record<string, unknown>>;
  per_device_links?: Record<string, unknown>[];
  access_uplinks?: Record<string, Record<string, unknown>>;
  distribution_uplinks?: Record<string, Record<string, unknown>>;
  core_links?: Record<string, Record<string, unknown>>;
  network_aggregation?: Record<string, unknown>;
  summary?: Record<string, number>;
  recent_alerts?: AlertItem[];
};

export type AlertItem = {
  title?: string;
  detail?: string;
  severity?: string;
  device?: string;
  utilization_percent?: number;
  action_taken?: string;
  timestamp?: number | string;
};

export type DashboardSnapshot = {
  health: HealthResponse;
  metrics: Metrics;
  topology: Record<string, unknown>;
  pcActivities: PcActivities;
  flows: { flows?: FlowRow[]; count?: number };
  alerts: { alerts?: AlertItem[]; count?: number };
  proactive: ProactiveState;
  security: Record<string, unknown>;
  threats: { threats?: Record<string, unknown>[]; count?: number };
  mlAction: Record<string, unknown>;
  marlSecurity: Record<string, unknown>;
  ibn: Record<string, unknown>;
  timetable: Record<string, unknown>;
};

export type DatasetStatus = {
  ok?: boolean;
  running?: boolean;
  last_collection_time?: string;
  traffic_rows?: number;
  congestion_rows?: number;
  security_rows?: number;
  qos_rows?: number;
  ml_rows?: number;
  events_rows?: number;
  files?: Record<string, string>;
  message?: string;
  warning?: string;
};
