// ════════════════════════════════════════════════════════════════════════
//  Enums
// ════════════════════════════════════════════════════════════════════════

export type SampleStatus = 'ready' | 'pending' | 'running' | 'completed' | 'failed' | 'stopped';

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
  saved_analysis_at: string | null;
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
  saved_analysis: SavedAnalysisSnapshot | null;
  saved_analysis_at: string | null;
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

export interface WorkspaceGraphSummary {
  local_edges?: number;
  external_edges?: number;
  cross_file_calls?: number;
  execution_paths?: number;
  hotspots?: string[];
}

export interface WorkspaceCallEdge {
  source: string;
  target: string;
  symbol: string;
  count: number;
  call_style: string;
}

export interface WorkspacePrioritizedFile {
  path: string;
  language: string;
  score: number;
  reasons: string[];
  priority_tags: string[];
  inbound_edges: number;
  outbound_edges: number;
  cross_file_call_in: number;
  cross_file_call_out: number;
  suspicious_api_hits: number;
  obfuscation_signal_hits: number;
  function_count: number;
  exported_symbol_count: number;
}

export interface WorkspaceFilePreview {
  path: string;
  language: string;
  priority: string[];
  size_bytes: number;
}

export interface WorkspaceSymbolIndex {
  path: string;
  symbols: string[];
}

export interface WorkspaceContext {
  archive_name?: string;
  included_files?: number;
  omitted_files?: number;
  languages?: string;
  entry_points?: string[];
  suspicious_files?: string[];
  manifest_files?: string[];
  root_dirs?: string[];
  prioritized_paths?: string[];
  dependency_hotspots?: string[];
  symbol_hotspots?: string[];
  execution_paths?: string[];
  local_dependency_count?: number;
  external_dependency_count?: number;
  cross_file_call_count?: number;
  graph_summary?: WorkspaceGraphSummary;
  cross_file_call_edges?: WorkspaceCallEdge[];
  prioritized_files?: WorkspacePrioritizedFile[];
  files_preview?: WorkspaceFilePreview[];
  recovered_files_preview?: WorkspaceFilePreview[];
  bundle_note?: string;
  imports_count?: number;
  functions_count?: number;
  languages_by_file?: Record<string, number>;
  indexed_file_count?: number;
  bundled_file_count?: number;
  bundle_file_count?: number;
  indexed_from_archive?: boolean;
  analysis_frontier?: string[];
  bundle_expansion_paths?: string[];
  remaining_frontier_paths?: string[];
  llm_focus_paths?: string[];
  targeted_files?: string[];
  deobfuscated_files?: string[];
  added_files_to_bundle?: string[];
  targeted_file_count?: number;
  deobfuscated_file_count?: number;
  file_transform_summary?: Array<Record<string, unknown>>;
  symbol_literal_files?: WorkspaceSymbolIndex[];
  defined_symbols?: WorkspaceSymbolIndex[];
  exported_symbols?: WorkspaceSymbolIndex[];
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
  workspace_context?: WorkspaceContext;
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
    llm_classification?: {
      obfuscation_type?: string;
      tools_identified?: string[];
      layers?: string[];
      recommended_strategy?: string;
      priority_transforms?: string[];
      confidence?: number;
    };
    planner_analysis?: string;
    [key: string]: unknown;
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

export interface AISummarySections {
  deobfuscation_analysis: string;
  inferred_original_intent: string;
  actual_behavior: string;
  confidence_assessment: string;
}

export interface AISummaryReport {
  summary: string;
  sections: AISummarySections;
  confidence_score: number | null;
}

export interface AnalystChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export type AnalystChatRetrievedFileSource =
  | 'recovered_bundle'
  | 'original_bundle'
  | 'archive_scan';

export interface AnalystChatRetrievedFile {
  path: string;
  language: string | null;
  source: AnalystChatRetrievedFileSource;
  matched_terms: string[];
  line_ranges: string[];
  excerpt_truncated: boolean;
}

export interface AnalystChatResponse {
  answer: string;
  provider_name: string;
  model_name: string;
  context_truncated: boolean;
  workspace_search_enabled: boolean;
  workspace_file_count: number;
  retrieved_files: AnalystChatRetrievedFile[];
}

export interface SavedAnalysisSnapshot {
  saved_at: string | null;
  sample_status: SampleStatus | null;
  transform_count: number;
  finding_count: number;
  ioc_count: number;
  string_count: number;
  recovered_text_length: number;
  confidence_score: number | null;
  analysis_summary: string;
  workspace_context: WorkspaceContext;
  ai_summary: AISummaryReport | null;
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
