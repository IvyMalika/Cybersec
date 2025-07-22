export interface User {
  user_id: number;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'user';
  is_active: boolean;
  created_at: string;
  last_login: string;
  mfa_enabled: boolean;
  is_admin?: boolean;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: User;
}

export interface MFASetupResponse {
  message: string;
  mfa_enabled: boolean;
  mfa_secret: string;
}

export interface Target {
  target_id: number;
  target_value: string;
  target_type: 'ip' | 'domain' | 'url' | 'network';
  authorization_status: 'approved' | 'pending' | 'rejected';
  created_at: string;
}

export interface Tool {
  tool_id: number;
  name: string;
  description: string;
  category: string;
  is_active: boolean;
}

export interface Job {
  job_id: number;
  user_id: number;
  tool_id: number;
  target_id: number;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  parameters: Record<string, any>;
  created_at: string;
  completed_at: string | null;
  username?: string;
  tool_name?: string;
  target_value?: string;
}

export interface JobResult {
  result_id: number;
  job_id: number;
  output_type: string;
  content: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  created_at: string;
}

export interface Vulnerability {
  vulnerability_id: number;
  job_id: number;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  proof: string;
  cve?: string;
  cvss_score?: number;
  created_at: string;
}

export interface Credential {
  credential_id: number;
  job_id: number;
  username?: string;
  password?: string;
  hash?: string;
  origin: string;
  hash_type?: string;
  created_at: string;
}

export interface MITRETechnique {
  technique_id: string;
  technique_name: string;
  url: string;
  description: string;
}

export interface AuditLog {
  log_id: number;
  user_id: number;
  username: string;
  action: string;
  entity_type?: string;
  entity_id?: number;
  ip_address: string;
  user_agent: string;
  timestamp: string;
}

export interface NmapScanRequest {
  target: string;
  scan_type: 'quick' | 'full' | 'vuln';
}

export interface NmapScanResponse {
  message: string;
  job_id: number;
  open_ports: Array<{
    port: number;
    state: string;
    service: string;
    version: string;
  }>;
}

export interface VulnerabilityRequest {
  target: string;
  scan_type: 'full' | 'web' | 'network';
}

export interface VulnerabilityResponse {
  message: string;
  job_id: number;
  vulnerabilities_found: number;
  vulnerabilities: Array<{
    type: string;
    severity: string;
    proofs?: string[];
    proof?: string;
  }>;
}

export interface HealthStatus {
  status: 'healthy' | 'unhealthy';
  services: {
    database: boolean;
    shodan: boolean;
    virustotal: boolean;
    alienvault_otx: boolean;
  };
  timestamp: string;
}

export interface ApiError {
  error: string;
  description?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  pages: number;
}

export interface JobDetailsResponse {
  job: Job;
  results: JobResult[];
  vulnerabilities: Vulnerability[];
  mitre_mappings: MITRETechnique[];
}

/**
 * OSINTRequest: Used to request OSINT gathering.
 * - target: domain or IP (required)
 * - email: optional email address for EmailRep.io and Socialscan
 */
export interface OSINTRequest {
  target: string;
  email?: string;
}

/**
 * OSINTResponse: Response from OSINT gather endpoint.
 * - osint_data: includes whois, dns, recon, and optionally emailrep and socialscan results
 */
export interface OSINTResponse {
  message: string;
  job_id: number;
  osint_data: {
    whois: any;
    dns: any;
    recon: any;
    emailrep?: any;
    socialscan?: any;
    whois_error?: string;
    emailrep_error?: string;
    socialscan_error?: string;
  };
}

export interface ThreatIntelRequest {
  indicator: string;
  type: 'ip' | 'domain' | 'hash' | 'url';
}

export interface ThreatIntelResponse {
  message: string;
  job_id: number;
  malicious: boolean;
  intel_data: {
    virustotal: any;
    alienvault_otx: any;
    mitre_attack: MITRETechnique[];
  };
}

export interface PasswordCrackRequest {
  hash: string;
  hash_type: string;
  wordlist_id: number;
}

export interface PasswordCrackResponse {
  message: string;
  job_id: number;
  cracked: boolean;
  password?: string;
}

export interface NetworkMonitorRequest {
  interface: string;
  timeout: number;
}

export interface NetworkMonitorResponse {
  message: string;
  job_id: number;
  results: {
    total_packets: number;
    anomalies: Array<{
      type: string;
      source: string;
      destination: string;
      port?: number;
      payload?: string;
      size?: number;
    }>;
    sample_packets: Array<{
      source: string;
      destination: string;
      protocol: number;
      size: number;
    }>;
  };
}