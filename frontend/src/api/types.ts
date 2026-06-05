// Evidence types (from src/evidence.rs)
export type Confidence = 'Low' | 'Medium' | 'High';
export type FlowStepKind = 'source' | 'assignment' | 'call' | 'phi' | 'sink';

// Dynamic verification types (from src/evidence.rs VerifyStatus / VerifyResult)
export type VerifyStatus =
  | 'Confirmed'
  | 'PartiallyConfirmed'
  | 'NotConfirmed'
  | 'Inconclusive'
  | 'Unsupported';

export interface AttemptSummary {
  payload_label: string;
  exit_code?: number;
  timed_out: boolean;
  triggered: boolean;
  sink_hit?: boolean;
}

export interface VerifyResult {
  finding_id: string;
  status: VerifyStatus;
  triggered_payload?: string;
  /** Typed UnsupportedReason (PascalCase string) */
  reason?: string;
  /** Typed InconclusiveReason (PascalCase string) */
  inconclusive_reason?: string;
  detail?: string;
  attempts?: AttemptSummary[];
  toolchain_match?: string;
}

export interface DynamicVerificationSummary {
  total: number;
  confirmed: number;
  partially_confirmed: number;
  not_confirmed: number;
  inconclusive: number;
  unsupported: number;
}

export interface FlowStep {
  step: number;
  kind: FlowStepKind;
  file: string;
  line: number;
  col: number;
  snippet?: string;
  variable?: string;
  callee?: string;
  function?: string;
  is_cross_file?: boolean;
}

export interface SpanEvidence {
  path: string;
  line: number;
  col: number;
  kind: string;
  snippet?: string;
}

export interface StateEvidence {
  machine: string;
  subject?: string;
  from_state: string;
  to_state: string;
}

export interface Evidence {
  source?: SpanEvidence;
  sink?: SpanEvidence;
  guards: SpanEvidence[];
  sanitizers: SpanEvidence[];
  state?: StateEvidence;
  notes: string[];
  flow_steps: FlowStep[];
  explanation?: string;
  confidence_limiters: string[];
  /** Dynamic verification result; present only when --verify was active. */
  dynamic_verdict?: VerifyResult;
}

// Finding types
export interface CodeContextView {
  start_line: number;
  lines: string[];
  highlight_line: number;
}

export interface RelatedFindingView {
  index: number;
  rule_id: string;
  path: string;
  line: number;
  severity: string;
}

// Baseline / patch-validation types (M6.5)
export type VerdictTransition =
  | 'New'
  | 'Unchanged'
  | 'Resolved'
  | 'Regressed'
  | 'FlippedConfirmed'
  | 'FlippedNotConfirmed';

export interface VerdictDiffEntry {
  stable_hash: number;
  path: string;
  line: number;
  rule_id: string;
  baseline_status?: VerifyStatus;
  current_status?: VerifyStatus;
  transition: VerdictTransition;
}

export interface FindingView {
  index: number;
  fingerprint: string;
  portable_fingerprint?: string;
  /** Blake3-derived stable cross-commit identity (M6.5). */
  stable_hash?: number;
  path: string;
  line: number;
  col: number;
  severity: string;
  rule_id: string;
  category: string;
  confidence?: Confidence;
  rank_score?: number;
  message?: string;
  labels: [string, string][];
  path_validated: boolean;
  suppressed: boolean;
  language?: string;
  status: string;
  triage_state: string;
  triage_note?: string;
  code_context?: CodeContextView;
  evidence?: Evidence;
  dynamic_verdict?: VerifyResult;
  guard_kind?: string;
  rank_reason?: [string, string][];
  sanitizer_status?: string;
  related_findings: RelatedFindingView[];
}

export interface FindingSummary {
  total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_rule: Record<string, number>;
  by_file: Record<string, number>;
}

export interface FilterValues {
  severities: string[];
  categories: string[];
  confidences: string[];
  languages: string[];
  rules: string[];
  statuses: string[];
  verification_statuses: string[];
}

// Scan types
export interface TimingBreakdown {
  walk_ms: number;
  pass1_ms: number;
  call_graph_ms: number;
  pass2_ms: number;
  post_process_ms: number;
}

export interface ScanMetricsSnapshot {
  cfg_nodes: number;
  call_edges: number;
  functions_analyzed: number;
  summaries_reused: number;
  unresolved_calls: number;
}

export interface ScanView {
  id: string;
  status: string;
  scan_root: string;
  started_at?: string;
  finished_at?: string;
  duration_secs?: number;
  finding_count?: number;
  error?: string;
  engine_version?: string;
  languages?: string[];
  files_scanned?: number;
  timing?: TimingBreakdown;
  metrics?: ScanMetricsSnapshot;
}

export interface TargetView {
  id: string;
  name: string;
  path: string;
  db_path: string;
  last_seen_at: string;
  last_scan_at?: string;
  active: boolean;
  exists: boolean;
}

// Scan Comparison types
export interface CompareScanInfo {
  id: string;
  started_at?: string;
  finding_count: number;
}

export interface CompareSummary {
  new_count: number;
  fixed_count: number;
  changed_count: number;
  unchanged_count: number;
  severity_delta: Record<string, number>;
}

export interface ComparedFinding extends FindingView {
  fingerprint: string;
}

export interface FieldChange {
  field: string;
  old_value: string;
  new_value: string;
}

export interface ChangedFinding extends FindingView {
  fingerprint: string;
  changes: FieldChange[];
}

export interface CompareResponse {
  left_scan: CompareScanInfo;
  right_scan: CompareScanInfo;
  summary: CompareSummary;
  new_findings: ComparedFinding[];
  fixed_findings: ComparedFinding[];
  changed_findings: ChangedFinding[];
  unchanged_findings: ComparedFinding[];
  /** Verdict-level diff (M6.5). Present when findings carry stable_hash values. */
  verdict_diff?: VerdictDiffEntry[];
}

// Overview types
export interface OverviewCount {
  name: string;
  count: number;
}

export interface NoisyRule {
  rule_id: string;
  finding_count: number;
  suppression_rate: number;
}

export interface ScanSummary {
  id: string;
  status: string;
  started_at?: string;
  duration_secs?: number;
  finding_count?: number;
}

export interface Insight {
  kind: string;
  message: string;
  severity: string;
  action_url?: string;
}

export interface TrendPoint {
  scan_id: string;
  timestamp: string;
  total: number;
  by_severity: Record<string, number>;
}

export interface OverviewResponse {
  state: string;
  total_findings: number;
  new_since_last: number;
  fixed_since_last: number;
  high_confidence_rate: number;
  triage_coverage: number;
  latest_scan_duration_secs?: number;
  latest_scan_id?: string;
  latest_scan_at?: string;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_language: Record<string, number>;
  top_files: OverviewCount[];
  top_directories: OverviewCount[];
  top_rules: OverviewCount[];
  noisy_rules: NoisyRule[];
  recent_scans: ScanSummary[];
  insights: Insight[];

  // Tier 1
  health?: HealthScore;
  posture?: PostureSummary;
  backlog?: BacklogStats;
  weighted_top_files?: WeightedFile[];
  confidence_distribution?: ConfidenceDistribution;

  // Tier 2
  scanner_quality?: ScannerQuality;
  issue_categories?: IssueCategoryBucket[];
  hot_sinks?: HotSink[];
  owasp_buckets?: OwaspBucket[];
  cross_file_ratio?: number;

  // Tier 3
  baseline?: BaselineInfo;
  language_health?: LanguageHealth[];
  suppression_hygiene?: SuppressionHygiene;
}

export interface HealthComponent {
  label: string;
  score: number;
  weight: number;
  detail: string;
}

export interface HealthScore {
  score: number;
  grade: string;
  components: HealthComponent[];
}

export interface PostureSummary {
  trend: 'improving' | 'regressing' | 'stable' | 'unknown' | string;
  severity: 'success' | 'warning' | 'danger' | 'info' | string;
  message: string;
  reintroduced_count: number;
}

export interface BacklogStats {
  oldest_open_days?: number;
  median_age_days?: number;
  stale_count: number;
  age_buckets: OverviewCount[];
}

export interface WeightedFile {
  name: string;
  score: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface ConfidenceDistribution {
  high: number;
  medium: number;
  low: number;
  none: number;
}

export interface ScannerQuality {
  files_scanned: number;
  files_skipped: number;
  parse_success_rate: number;
  functions_analyzed: number;
  call_edges: number;
  unresolved_calls: number;
  call_resolution_rate: number;
  symex_verified_rate: number;
  symex_breakdown: Record<string, number>;
  dynamic_verification: DynamicVerificationSummary;
}

export interface IssueCategoryBucket {
  label: string;
  count: number;
}

export interface HotSink {
  callee: string;
  count: number;
}

export interface OwaspBucket {
  code: string;
  label: string;
  count: number;
}

export interface LanguageHealth {
  language: string;
  findings: number;
  high: number;
  medium: number;
  low: number;
}

export interface SuppressionHygiene {
  fingerprint_level: number;
  rule_level: number;
  file_level: number;
  rule_in_file_level: number;
  blanket_rate: number;
}

export interface BaselineInfo {
  scan_id: string;
  started_at?: string;
  baseline_total: number;
  drift_new: number;
  drift_fixed: number;
}

// Rules types
export interface RuleListItem {
  id: string;
  title: string;
  language: string;
  kind: string;
  cap: string;
  matchers: string[];
  enabled: boolean;
  is_custom: boolean;
  is_gated: boolean;
  is_class: boolean;
  case_sensitive: boolean;
  finding_count: number;
  suppression_rate: number;
}

export interface RuleDetailView extends RuleListItem {
  example_findings: RelatedFindingView[];
}

// Config types
export interface RuleView {
  lang: string;
  matchers: string[];
  kind: string;
  cap: string;
}

export interface TerminatorView {
  lang: string;
  name: string;
}

export interface LabelEntryView {
  lang: string;
  matchers: string[];
  cap: string;
  case_sensitive: boolean;
  is_builtin: boolean;
}

export interface ProfileView {
  name: string;
  is_builtin: boolean;
  settings: Record<string, unknown>;
}

// Health
export interface HealthResponse {
  status: string;
  version: string;
  scan_root: string;
}

// Paginated response wrappers
export interface PaginatedFindings {
  findings: FindingView[];
  total: number;
  page: number;
  per_page: number;
}

// Triage types
export interface TriageEntry {
  fingerprint: string;
  state: string;
  note: string;
  updated_at: string;
  finding?: FindingView;
}

export interface PaginatedTriage {
  entries: TriageEntry[];
  total: number;
  page: number;
  per_page: number;
}

export interface AuditEntry {
  id: number;
  fingerprint: string;
  action: string;
  previous_state: string;
  new_state: string;
  note: string;
  timestamp: string;
}

export interface PaginatedAudit {
  entries: AuditEntry[];
  total: number;
  page: number;
  per_page: number;
}

export interface SuppressionRule {
  id: number;
  suppress_by: string;
  match_value: string;
  state: string;
  note: string;
  created_at: string;
}

export interface SyncStatus {
  file_path: string;
  file_exists: boolean;
  sync_enabled: boolean;
  decisions: number;
  suppression_rules: number;
}

// File viewer
export interface FileResponse {
  path: string;
  lines: { number: number; content: string }[];
  total_lines: number;
}

// Explorer types
export interface TreeEntry {
  name: string;
  entry_type: 'file' | 'dir';
  path: string;
  language?: string;
  finding_count: number;
  severity_max?: string;
}

export interface SymbolEntry {
  name: string;
  /// Legacy display kind (`"function"` | `"method"`) used by existing
  /// CSS classes.  Prefer `func_kind` for new logic.
  kind: string;
  /// Structural FuncKind slug: `"fn"` | `"method"` | `"closure"` |
  /// `"ctor"` | `"getter"` | `"setter"` | `"toplevel"`.
  func_kind: string;
  /// Enclosing container (class / impl / module / outer function).
  /// Empty for free top-level functions.
  container: string;
  line?: number;
  finding_count: number;
  namespace?: string;
  arity?: number;
}

export interface ExplorerFinding {
  index: number;
  line: number;
  col: number;
  severity: string;
  rule_id: string;
  category: string;
  message?: string;
  confidence?: string;
}

// Scan log entry
export interface ScanLogEntry {
  timestamp: string;
  level: string;
  message: string;
  file_path?: string;
  detail?: string;
}

// ── Debug view types ─────────────────────────────────────────────────────────

export interface FunctionInfo {
  name: string;
  namespace: string;
  /// Enclosing container (class / impl / module / outer function).
  container: string;
  /// Structural FuncKind slug: `"fn"` | `"method"` | `"closure"` | etc.
  func_kind: string;
  param_count: number;
  line: number;
  source_caps: string[];
  sanitizer_caps: string[];
  sink_caps: string[];
}

// CFG
export interface CfgNodeView {
  id: number;
  kind: string;
  span: [number, number];
  line: number;
  defines?: string;
  uses: string[];
  callee?: string;
  labels: string[];
  condition_text?: string;
  enclosing_func?: string;
}

export interface CfgEdgeView {
  source: number;
  target: number;
  kind: string;
}

export interface CfgGraphView {
  nodes: CfgNodeView[];
  edges: CfgEdgeView[];
  entry: number;
}

// SSA
export interface SsaInstView {
  value: number;
  op: string;
  operands: string[];
  var_name?: string;
  span: [number, number];
  line: number;
}

export interface SsaBlockView {
  id: number;
  phis: SsaInstView[];
  body: SsaInstView[];
  terminator: string;
  preds: number[];
  succs: number[];
}

export interface SsaBodyView {
  blocks: SsaBlockView[];
  entry: number;
  num_values: number;
}

// Taint
export interface TaintValueView {
  ssa_value: number;
  var_name?: string;
  caps: string[];
  uses_summary: boolean;
}

export interface TaintBlockStateView {
  block_id: number;
  values: TaintValueView[];
  validated_must: number;
  validated_may: number;
}

export interface TaintEventView {
  sink_node: number;
  sink_caps: string[];
  tainted_values: TaintValueView[];
  all_validated: boolean;
  uses_summary: boolean;
}

export interface TaintAnalysisView {
  block_states: TaintBlockStateView[];
  events: TaintEventView[];
}

// Abstract Interpretation
export interface AbstractValueView {
  ssa_value: number;
  var_name?: string;
  interval_lo?: number;
  interval_hi?: number;
  string_prefix?: string;
  string_suffix?: string;
  known_zero: number;
  known_one: number;
}

export interface AbstractBlockView {
  block_id: number;
  values: AbstractValueView[];
}

export interface TypeFactView {
  ssa_value: number;
  var_name?: string;
  type_kind: string;
  nullable: boolean;
}

export interface ConstValueViewEntry {
  ssa_value: number;
  var_name?: string;
  value: string;
}

export interface AbstractInterpView {
  blocks: AbstractBlockView[];
  type_facts: TypeFactView[];
  const_values: ConstValueViewEntry[];
}

// Symbolic Execution
export interface SymexValueView {
  ssa_value: number;
  var_name?: string;
  expression: string;
}

export interface PathConstraintView {
  block: number;
  condition: string;
  polarity: boolean;
}

export interface SymexView {
  values: SymexValueView[];
  path_constraints: PathConstraintView[];
  tainted_roots: number[];
}

// Call Graph
export interface CallGraphNodeView {
  id: number;
  name: string;
  file: string;
  lang: string;
  namespace: string;
  arity?: number;
}

export interface CallGraphEdgeView {
  source: number;
  target: number;
  call_site: string;
}

export interface CallGraphView {
  nodes: CallGraphNodeView[];
  edges: CallGraphEdgeView[];
  sccs: number[][];
  unresolved_count: number;
  ambiguous_count: number;
}

// Summaries
export interface ParamReturnView {
  param_index: number;
  transform: string;
}

export interface ParamSinkView {
  param_index: number;
  sink_caps: string[];
}

export interface SsaSummaryView {
  param_to_return: ParamReturnView[];
  param_to_sink: ParamSinkView[];
  source_caps: string[];
}

export interface FuncSummaryView {
  name: string;
  file_path: string;
  lang: string;
  namespace: string;
  /// Enclosing container (class / impl / module / outer function).
  container: string;
  /// Structural FuncKind slug: `"fn"` | `"method"` | `"closure"` | etc.
  func_kind: string;
  arity?: number;
  param_count: number;
  source_caps: string[];
  sanitizer_caps: string[];
  sink_caps: string[];
  propagates_taint: boolean;
  propagating_params: number[];
  tainted_sink_params: number[];
  callees: string[];
  ssa_summary?: SsaSummaryView;
}

// ── Pointer (field-sensitive Steensgaard) ─────────────────────────────────
export interface PointerLocationView {
  id: number;
  kind: 'Top' | 'Alloc' | 'Param' | 'SelfParam' | 'Field';
  display: string;
  parent?: number;
  field?: string;
}

export interface PointerValueView {
  ssa_value: number;
  var_name?: string;
  points_to: number[];
  is_top: boolean;
}

export interface PointerFieldEntryView {
  /// `null` means the implicit receiver.
  param_index: number | null;
  field: string;
}

export interface PointerView {
  locations: PointerLocationView[];
  values: PointerValueView[];
  field_reads: PointerFieldEntryView[];
  field_writes: PointerFieldEntryView[];
  location_count: number;
}

// ── Type Facts (standalone) ────────────────────────────────────────────────
export interface DtoFieldView {
  name: string;
  kind: string;
}

export interface DtoFactView {
  class_name: string;
  fields: DtoFieldView[];
}

export interface TypeFactDetailView {
  ssa_value: number;
  var_name?: string;
  line: number;
  kind: string;
  nullable: boolean;
  container?: string;
  dto?: DtoFactView;
}

export interface TypeFactsView {
  facts: TypeFactDetailView[];
  total_values: number;
  unknown_count: number;
}

// ── Auth Analysis ──────────────────────────────────────────────────────────
export interface AuthValueRefView {
  source_kind: string;
  name: string;
  base?: string;
  field?: string;
  index?: string;
  line: number;
}

export interface AuthCheckView {
  kind: string;
  callee: string;
  line: number;
  subjects: AuthValueRefView[];
  args: string[];
  condition_text?: string;
}

export interface AuthOperationView {
  kind: string;
  sink_class?: string;
  callee: string;
  line: number;
  text: string;
  subjects: AuthValueRefView[];
}

export interface AuthCallSiteView {
  name: string;
  line: number;
  args: string[];
}

export interface AuthUnitView {
  kind: string;
  name?: string;
  line: number;
  params: string[];
  auth_checks: AuthCheckView[];
  operations: AuthOperationView[];
  call_sites: AuthCallSiteView[];
  self_actor_vars: string[];
  typed_bounded_vars: string[];
  authorized_sql_vars: string[];
  const_bound_vars: string[];
}

export interface AuthRouteView {
  framework: string;
  method: string;
  path: string;
  middleware: string[];
  handler_params: string[];
  line: number;
  unit_idx: number;
}

export interface AuthAnalysisView {
  routes: AuthRouteView[];
  units: AuthUnitView[];
  enabled: boolean;
}

// ── Surface map (Phase 21–23) ───────────────────────────────────────

export interface SurfaceSourceLocation {
  file: string;
  line: number;
  col: number;
}

export type SurfaceFramework =
  | 'flask'
  | 'fast_api'
  | 'django'
  | 'express'
  | 'koa'
  | 'spring'
  | 'jax_rs'
  | 'quarkus'
  | 'rails'
  | 'sinatra'
  | 'laravel'
  | 'slim'
  | 'axum'
  | 'actix'
  | 'rocket'
  | 'net_http'
  | 'gin'
  | 'next_app_router'
  | 'next_server_action';

export type SurfaceHttpMethod =
  | 'GET'
  | 'HEAD'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'DELETE'
  | 'OPTIONS';

export type SurfaceDataStoreKind =
  | 'sql'
  | 'key_value'
  | 'document'
  | 'blob_store'
  | 'filesystem'
  | 'unknown';

export type SurfaceExternalKind =
  | 'http_api'
  | 'message_broker'
  | 'search_index'
  | 'auth_provider'
  | 'unknown';

export type SurfaceEdgeKind =
  | 'calls'
  | 'reads_from'
  | 'writes_to'
  | 'talks_to'
  | 'reaches'
  | 'triggers'
  | 'auth_required_on';

export type SurfaceNode =
  | {
      node: 'entry_point';
      location: SurfaceSourceLocation;
      framework: SurfaceFramework;
      method: SurfaceHttpMethod;
      route: string;
      handler_name: string;
      handler_location: SurfaceSourceLocation;
      auth_required: boolean;
    }
  | {
      node: 'data_store';
      location: SurfaceSourceLocation;
      kind: SurfaceDataStoreKind;
      label: string;
    }
  | {
      node: 'external_service';
      location: SurfaceSourceLocation;
      kind: SurfaceExternalKind;
      label: string;
    }
  | {
      node: 'dangerous_local';
      location: SurfaceSourceLocation;
      function_name: string;
      cap_bits: number;
    };

export interface SurfaceEdge {
  from: number;
  to: number;
  kind: SurfaceEdgeKind;
}

export interface SurfaceMap {
  nodes: SurfaceNode[];
  edges: SurfaceEdge[];
}
