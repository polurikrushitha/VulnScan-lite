// VulnScan Lite — TypeScript Type Definitions

export interface User {
  id: string;
  email: string;
  name?: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user?: User;
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export type Grade = 'A' | 'B+' | 'B' | 'C' | 'D' | 'F';

export type CheckStatus = 'passed' | 'failed' | 'warning' | 'info';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RiskLevel = 'Excellent' | 'Good' | 'Moderate' | 'Needs Improvement' | 'Poor';

export type AuthorizationType = 'user_owned' | 'organization_approved' | 'explicit_permission';

export interface ConsentAudit {
  consent_version: string;
  authorization_state: string;
  scan_status: string;
  confirmed_at?: string;
}

export interface ScanCreatePayload {
  url: string;
  authorization_type: AuthorizationType;
  target_confirmed: boolean;
  consent_version?: string;
  confirmed_ownership: boolean;
  confirmed_requests_acknowledged: boolean;
  confirmed_authorized_testing_only: boolean;
  confirmed_passive_analysis_understood: boolean;
  confirmed_responsibility_accepted: boolean;
}

export interface ScanCreateResponse {
  scan_id: string;
  status: ScanStatus;
  stage?: string;
  authorization_type?: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: ScanStatus;
  stage?: string;
  message?: string;
  score?: number;
  grade?: Grade;
  risk_level?: RiskLevel | string;
  authorization_type?: string;
  error?: string;
}

export interface SecurityCheck {
  id: string;
  check_name: string;
  category: string;
  status: CheckStatus;
  points: number;
  description?: string;
}

export interface Finding {
  id: string;
  check_name: string;
  severity: FindingSeverity;
  category?: string;
  description: string;
  impact?: string;
  remediation?: string;
  affected_url?: string;
  evidence?: string;
  confidence?: string;
}

export interface SSLData {
  is_https: boolean;
  connection_successful: boolean;
  certificate_valid: boolean;
  certificate_expired: boolean;
  status?: string;
  subject?: string;
  issuer?: string;
  tls_version?: string;
  cipher?: string;
  not_before?: string;
  not_after?: string;
  days_until_expiry?: number;
  error?: string;
  points: number;
  description: string;
}

export interface HeaderCheck {
  header_name: string;
  present: boolean;
  value?: string;
  points: number;
  status: CheckStatus;
  description: string;
  remediation: string;
  category: string;
}

export interface HeaderData {
  checks: HeaderCheck[];
  raw_headers?: Record<string, string>;
  server?: string;
  x_powered_by?: string;
}

export interface CMSData {
  detected: boolean;
  cms_name?: string;
  version?: string;
  detection_source?: string;
  confidence: string;
  version_exposed: boolean;
  outdated_status?: string;
  description?: string;
}

export interface HTMLData {
  generator?: string;
  title?: string;
  description_meta?: string;
  technology_indicators: string[];
  form_count?: number;
  external_scripts?: number;
  has_https_links?: boolean;
  insecure_http_links?: string[];
  is_html?: boolean;
}

export interface ScanResult {
  scan_id: string;
  target_url: string;
  status: ScanStatus;
  stage?: string;
  authorization_type?: string;
  consent_audit?: ConsentAudit;
  score?: number;
  grade?: Grade;
  risk_level?: RiskLevel | string;
  duration_seconds?: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  ssl_data?: SSLData;
  header_data?: HeaderData;
  cms_data?: CMSData;
  html_data?: HTMLData;
  security_checks: SecurityCheck[];
  findings: Finding[];
  error?: string;
}

export interface ScanHistoryItem {
  scan_id: string;
  target_url: string;
  status: ScanStatus;
  stage?: string;
  authorization_type?: string;
  score?: number;
  grade?: Grade;
  risk_level?: RiskLevel | string;
  findings_count?: number;
  created_at: string;
  completed_at?: string;
}


