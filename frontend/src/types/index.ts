// ════════════════════════════════════════════════════════════════════════
//  Enums
// ════════════════════════════════════════════════════════════════════════

export type SampleStatus = 'pending' | 'running' | 'completed' | 'failed' | 'stopped';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type IOCType =
  | 'ip'
  | 'domain'
  | 'url'
  | 'hash'
  | 'email'
  | 'filepath'
  | 'registry'
  | 'mutex'
  | 'other';

export type ExportFormat = 'json' | 'markdown' | 'html' | 'pdf';

export type MaxTokensPreset = '128k' | '200k';

// ════════════════════════════════════════════════════════════════════════
//  Projects
// ════════════════════════════════════════════════════════════════════════

export interface Project {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface ProjectCreate {
  name: string;
  description?: string | null;
}

// ════════════════════════════════════════════════════════════════════════
//  Samples
// ════════════════════════════════════════════════════════════════════════

export interface Sample {
  id: string;
  project_id: string;
  filename: string;
  language: string | null;
  status: SampleStatus;
  created_at: string;
  updated_at: string;
}

export interface SampleDetail {
  id: string;
  project_id: string;
  filename: string;
  original_text: string;
  recovered_text: string | null;
  language: string | null;
  status: SampleStatus;
  analyst_notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface SampleCreate {
  project_id: string;
  filename?: string;
  original_text: string;
  language?: string | null;
}

// ════════════════════════════════════════════════════════════════════════
//  Analysis internals
// ════════════════════════════════════════════════════════════════════════

export interface StringEntry {
  value: string;
  encoding: string | null;
  offset: number | null;
  context: string | null;
  decoded: string | null;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  evidence: string | null;
  confidence: number;
}

export interface IOC {
  type: IOCType;
  value: string;
  context: string | null;
  confidence: number;
}

export interface TransformRecord {
  iteration: number;
  action: string;
  reason: string;
  inputs: Record<string, unknown>;
  outputs: Record<string, unknown>;
  confidence_before: number;
  confidence_after: number;
  readability_before: number;
  readability_after: number;
  success: boolean;
  retry_revert: boolean;
}

export interface AnalysisState {
  language: string | null;
  parse_status: string | null;
  symbols: string[];
  strings: StringEntry[];
  imports: string[];
  functions: string[];
  suspicious_apis: string[];
  detected_techniques: string[];
  recovered_literals: string[];
  transform_history: TransformRecord[];
  evidence_references: string[];
  workspace_context?: {
    archive_name?: string;
    included_files?: number;
    omitted_files?: number;
    entry_points?: string[];
    suspicious_files?: string[];
    manifest_files?: string[];
    root_dirs?: string[];
    files_preview?: Array<{
      path: string;
      language: string;
      priority: string[];
      size_bytes: number;
    }>;
  };
  confidence: {
    overall: number;
    naming: number;
    structure: number;
    strings: number;
  };
  analysis_summary: string;
  llm_suggestions: string[];
  iteration_state: {
    current_iteration: number;
    stall_counter: number;
    last_confidence: number;
    stopped: boolean;
  };
}

// ════════════════════════════════════════════════════════════════════════
//  Provider settings
// ════════════════════════════════════════════════════════════════════════

export interface ProviderSettings {
  id: string;
  name: string;
  base_url: string;
  model_name: string;
  api_key_masked: string;
  cert_bundle_path: string | null;
  use_system_trust: boolean;
  max_tokens_preset: MaxTokensPreset;
  is_active: boolean;
  created_at: string;
}

export interface ProviderSettingsCreate {
  name: string;
  base_url: string;
  model_name: string;
  api_key: string;
  cert_bundle_path?: string | null;
  use_system_trust?: boolean;
  max_tokens_preset?: MaxTokensPreset;
}

// ════════════════════════════════════════════════════════════════════════
//  Analysis status
// ════════════════════════════════════════════════════════════════════════

export interface AnalysisStatus {
  sample_id: string;
  status: SampleStatus;
  current_iteration: number;
  total_iterations: number;
  current_action: string;
  progress_pct: number;
}

// ════════════════════════════════════════════════════════════════════════
//  Export / Notes
// ════════════════════════════════════════════════════════════════════════

export interface ExportRequest {
  sample_id: string;
  format: ExportFormat;
  include_transforms?: boolean;
  include_findings?: boolean;
  include_iocs?: boolean;
  include_strings?: boolean;
}

export interface NotesSave {
  sample_id: string;
  notes: string;
}
