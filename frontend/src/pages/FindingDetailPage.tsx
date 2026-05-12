import { useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useFinding } from '../api/queries/findings';
import { useBulkTriage } from '../api/mutations/triage';
import { usePageTitle } from '../hooks/usePageTitle';
import { truncPath } from '../utils/truncPath';
import { escapeHtml, highlightSyntax } from '../utils/syntaxHighlight';
import { parseNoteText } from '../utils/parseNote';
import { findingToMarkdown } from '../utils/findingMarkdown';
import { CopyMarkdownButton } from '../components/CopyMarkdownButton';
import { VerdictBadge } from '../components/VerdictBadge';
import { Dropdown, DropdownItem } from '../components/ui/Dropdown';
import { CodeViewerModal } from '../modals/CodeViewerModal';
import type {
  FindingView,
  Evidence,
  FlowStep,
  SpanEvidence,
  RelatedFindingView,
  VerifyResult,
} from '../api/types';

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatTriageState(state: string): string {
  return (state || 'open').replace(/_/g, ' ');
}

interface StatusOption {
  value: string;
  label: string;
}

const STATUS_GROUPS: { heading: string; options: StatusOption[] }[] = [
  {
    heading: 'Active',
    options: [
      { value: 'open', label: 'Open' },
      { value: 'investigating', label: 'Investigating' },
    ],
  },
  {
    heading: 'Resolved',
    options: [
      { value: 'fixed', label: 'Fixed' },
      { value: 'false_positive', label: 'False Positive' },
      { value: 'accepted_risk', label: 'Accepted Risk' },
      { value: 'suppressed', label: 'Suppressed' },
    ],
  },
];

function isStateFinding(f: FindingView): boolean {
  return f.rule_id.startsWith('state-');
}

const STATE_REMEDIATION_HINTS: Record<string, string[]> = {
  'state-use-after-close': [
    'Do not access the resource after calling close/free.',
    'Restructure so every use happens before release.',
    'Consider a language-native cleanup pattern (defer, with, try-with-resources, RAII).',
  ],
  'state-double-close': [
    'Remove the duplicate close call, or guard with a null/closed check.',
    'Centralize cleanup in a single code path to avoid repeats.',
  ],
  'state-resource-leak': [
    'Add a close/free call before every function exit.',
    'Prefer a language-native cleanup pattern (defer, with, try-with-resources, RAII).',
  ],
  'state-resource-leak-possible': [
    'Ensure the resource is closed on all code paths, including error and early-return paths.',
    'Put cleanup in a finally/defer block rather than after the happy path.',
  ],
  'state-unauthed-access': [
    'Add an authentication check before the sensitive operation.',
    'Move this handler behind an auth middleware or guard.',
  ],
};

const STATE_RULE_DESCRIPTIONS: Record<string, string> = {
  'state-use-after-close': 'Variable used after its resource handle was closed',
  'state-double-close': 'Resource handle closed more than once',
  'state-resource-leak': 'Resource acquired but never closed',
  'state-resource-leak-possible': 'Resource may not be closed on all paths',
  'state-unauthed-access': 'Sensitive operation reached without authentication',
};

// ── Collapsible Section ─────────────────────────────────────────────────────

interface CollapsibleSectionProps {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

function CollapsibleSection({
  title,
  defaultOpen = true,
  children,
}: CollapsibleSectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="detail-section">
      <div className="section-toggle" onClick={() => setOpen((v) => !v)}>
        <span className={`toggle-arrow${!open ? ' collapsed' : ''}`}>
          &#9660;
        </span>{' '}
        {title}
      </div>
      <div className={`section-body${!open ? ' collapsed' : ''}`}>
        {children}
      </div>
    </div>
  );
}

// ── Evidence Cards ──────────────────────────────────────────────────────────

function EvidenceCard({
  kind,
  color,
  span,
}: {
  kind: string;
  color: string;
  span: SpanEvidence;
}) {
  return (
    <div className="evidence-card">
      <div className="evidence-kind" style={{ color }}>
        {kind}
      </div>
      <div>
        {span.path}:{span.line}:{span.col}
      </div>
      {span.snippet && <div className="evidence-snippet">{span.snippet}</div>}
    </div>
  );
}

function StateTransitionCard({
  evidence,
  ruleId,
}: {
  evidence: Evidence;
  ruleId: string;
}) {
  const st = evidence.state;
  if (!st) return null;

  const isAuth = st.machine === 'auth';
  const machineLabel = isAuth ? 'Authentication State' : 'Resource Lifecycle';
  const acquireLocation =
    ruleId.includes('leak') && evidence.sink
      ? `${evidence.sink.path}:${evidence.sink.line}:${evidence.sink.col}`
      : null;

  return (
    <div className="state-transition-card">
      <div className="state-machine-label">{machineLabel}</div>
      {st.subject && (
        <div className="state-subject">
          <span className="state-subject-label">Variable:</span>
          <code className="state-subject-name">{st.subject}</code>
        </div>
      )}
      <div className="state-transition-visual">
        <span className="state-from">{st.from_state}</span>
        <span className="state-arrow">&rarr;</span>
        <span className="state-to">{st.to_state}</span>
      </div>
      {acquireLocation && (
        <div className="state-acquire-location">
          Acquired at: {acquireLocation}
        </div>
      )}
    </div>
  );
}

function EvidenceSection({
  evidence,
  skipStateCard,
}: {
  evidence: Evidence;
  skipStateCard?: boolean;
}) {
  const cards: React.ReactNode[] = [];

  if (evidence.source) {
    cards.push(
      <EvidenceCard
        key="source"
        kind="Source"
        color="var(--success)"
        span={evidence.source}
      />,
    );
  }

  if (evidence.sink) {
    cards.push(
      <EvidenceCard
        key="sink"
        kind="Sink"
        color="var(--sev-high)"
        span={evidence.sink}
      />,
    );
  }

  for (let i = 0; i < (evidence.guards?.length ?? 0); i++) {
    cards.push(
      <EvidenceCard
        key={`guard-${i}`}
        kind="Guard"
        color="var(--accent)"
        span={evidence.guards[i]}
      />,
    );
  }

  for (let i = 0; i < (evidence.sanitizers?.length ?? 0); i++) {
    cards.push(
      <EvidenceCard
        key={`sanitizer-${i}`}
        kind="Sanitizer"
        color="var(--sev-medium)"
        span={evidence.sanitizers[i]}
      />,
    );
  }

  if (evidence.state && !skipStateCard) {
    const st = evidence.state;
    cards.push(
      <div className="evidence-card" key="state">
        <div className="evidence-kind">State: {st.machine}</div>
        <div>
          {st.subject ? `${st.subject}: ` : ''}
          {st.from_state} &rarr; {st.to_state}
        </div>
      </div>,
    );
  }

  if (cards.length === 0) return null;
  return <>{cards}</>;
}

// ── Notes Section ───────────────────────────────────────────────────────────

function NotesSection({ evidence }: { evidence: Evidence }) {
  if (!evidence.notes || evidence.notes.length === 0) return null;

  return (
    <ul style={{ listStyle: 'disc', paddingLeft: 20, margin: 0 }}>
      {evidence.notes.map((note, i) => (
        <li key={i} className="evidence-note">
          {parseNoteText(note)}
        </li>
      ))}
    </ul>
  );
}

// ── Confidence Section ──────────────────────────────────────────────────────

function ConfidenceSection({ finding }: { finding: FindingView }) {
  if (!finding.confidence) return null;

  const limiters = finding.evidence?.confidence_limiters;
  const showLimiters =
    limiters && limiters.length > 0 && finding.confidence !== 'High';

  return (
    <>
      <span className={`badge badge-conf-${finding.confidence.toLowerCase()}`}>
        {finding.confidence}
      </span>
      {finding.rank_score != null && (
        <span
          style={{
            marginLeft: 'var(--space-2)',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)',
          }}
        >
          Score: {finding.rank_score.toFixed(1)}
        </span>
      )}
      {finding.rank_reason && finding.rank_reason.length > 0 && (
        <div style={{ marginTop: 'var(--space-2)' }}>
          {finding.rank_reason.map(([k, v], i) => (
            <div key={i} className="evidence-note">
              <strong>{k}:</strong> {v}
            </div>
          ))}
        </div>
      )}
      {showLimiters && (
        <div style={{ marginTop: 'var(--space-3)' }}>
          <strong
            style={{
              fontSize: 'var(--text-sm)',
              color: 'var(--text-secondary)',
            }}
          >
            Why not higher confidence?
          </strong>
          <ul className="confidence-limiters">
            {limiters!.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

// ── Structured Explanation ──────────────────────────────────────────────────

function describeSpan(span: SpanEvidence): string {
  const name =
    span.snippet?.trim() ||
    span.kind ||
    span.path.split('/').pop() ||
    span.path;
  return `${name} (line ${span.line})`;
}

function StructuredExplanation({
  finding,
  evidence,
}: {
  finding: FindingView;
  evidence: Evidence;
}) {
  const rows: { label: string; value: React.ReactNode }[] = [];

  if (evidence.source) {
    rows.push({
      label: 'From',
      value: (
        <code className="struct-expl-code">
          {describeSpan(evidence.source)}
        </code>
      ),
    });
  }

  if (evidence.sink) {
    rows.push({
      label: 'Into',
      value: (
        <code className="struct-expl-code">{describeSpan(evidence.sink)}</code>
      ),
    });
  }

  rows.push({
    label: 'Risk',
    value: riskSummary(finding, evidence),
  });

  const contextNote = buildContextNote(finding, evidence);
  if (contextNote) {
    rows.push({ label: 'Notes', value: contextNote });
  }

  if (rows.length === 0) return null;

  return (
    <dl className="struct-expl">
      {rows.map((r, i) => (
        <div className="struct-expl-row" key={i}>
          <dt>{r.label}</dt>
          <dd>{r.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function riskSummary(finding: FindingView, evidence: Evidence): string {
  if (evidence.explanation) return evidence.explanation;
  if (finding.message) return finding.message;
  const category = finding.category?.toLowerCase() || '';
  if (category.includes('security')) {
    return 'Potential injection or unsafe-operation vulnerability.';
  }
  return `${finding.category} issue.`;
}

function buildContextNote(
  finding: FindingView,
  evidence: Evidence,
): React.ReactNode {
  const parts: string[] = [];
  const hasCrossFile = evidence.flow_steps?.some((s) => s.is_cross_file);
  if (hasCrossFile) {
    parts.push('Crosses function boundaries via summary resolution.');
  }
  if (finding.sanitizer_status === 'none') {
    parts.push('No sanitizer was applied to this flow.');
  } else if (finding.sanitizer_status === 'bypassed') {
    parts.push('A sanitizer was present but was bypassed.');
  }
  if (finding.guard_kind) {
    parts.push(`Guard: ${finding.guard_kind}.`);
  }
  return parts.length ? parts.join(' ') : null;
}

// ── Taint Flow Timeline ─────────────────────────────────────────────────────

const FLOW_KIND_COLORS: Record<string, string> = {
  source: 'var(--success)',
  assignment: 'var(--accent)',
  call: 'var(--sev-medium)',
  phi: 'var(--text-tertiary)',
  sink: 'var(--sev-high)',
};

const FLOW_KIND_LABELS: Record<string, string> = {
  source: 'Source',
  assignment: 'Assign',
  call: 'Call',
  phi: 'Phi',
  sink: 'Sink',
};

const FLOW_COLLAPSE_THRESHOLD = 5;

function FlowTimeline({ steps }: { steps: FlowStep[] }) {
  const [expanded, setExpanded] = useState(
    steps.length <= FLOW_COLLAPSE_THRESHOLD,
  );

  if (steps.length === 0) return null;

  const isLong = steps.length > FLOW_COLLAPSE_THRESHOLD;
  const visibleSteps: FlowStep[] = (() => {
    if (!isLong || expanded) return steps;
    const firstIdx = steps.findIndex((s) => s.kind === 'source');
    const lastSinkIdx = [...steps]
      .map((s, i) => ({ s, i }))
      .reverse()
      .find(({ s }) => s.kind === 'sink')?.i;
    const picked = new Set<number>();
    if (firstIdx >= 0) picked.add(firstIdx);
    if (lastSinkIdx != null) picked.add(lastSinkIdx);
    picked.add(0);
    picked.add(steps.length - 1);
    return [...picked].sort((a, b) => a - b).map((i) => steps[i]);
  })();

  return (
    <div className="flow-timeline">
      {visibleSteps.map((s, i) => {
        const color = FLOW_KIND_COLORS[s.kind] || 'var(--text-secondary)';
        const label = FLOW_KIND_LABELS[s.kind] || s.kind;
        const isLast = i === visibleSteps.length - 1;
        const isEndpoint = s.kind === 'source' || s.kind === 'sink';

        return (
          <div
            key={`${s.step}-${i}`}
            className={[
              'flow-step',
              s.is_cross_file ? 'flow-step-cross-file' : '',
              isEndpoint ? `flow-step-endpoint flow-step-${s.kind}` : '',
            ]
              .filter(Boolean)
              .join(' ')}
          >
            <div className="flow-step-connector">
              <div className="flow-step-dot" style={{ background: color }} />
              {!isLast && <div className="flow-step-line" />}
            </div>
            <div className="flow-step-card">
              <div className="flow-step-header">
                <span className="flow-step-badge" style={{ color }}>
                  {label}
                </span>
                <span className="flow-step-num">#{s.step}</span>
                {s.variable && (
                  <span className="flow-step-var">{s.variable}</span>
                )}
                {s.callee && (
                  <span className="flow-step-callee">{s.callee}</span>
                )}
              </div>
              <div className="flow-step-loc">
                {s.file}:{s.line}:{s.col}
                {s.function ? ` in ${s.function}` : ''}
              </div>
              {s.snippet && (
                <div className="flow-step-snippet">{s.snippet}</div>
              )}
            </div>
          </div>
        );
      })}
      {isLong && (
        <button
          type="button"
          className="flow-expand-toggle"
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded
            ? `Collapse (${steps.length} steps)`
            : `Show all ${steps.length} steps`}
        </button>
      )}
    </div>
  );
}

// ── Related Findings ────────────────────────────────────────────────────────

function RelatedFindings({ findings }: { findings: RelatedFindingView[] }) {
  const navigate = useNavigate();

  if (findings.length === 0) return null;

  return (
    <>
      {findings.map((r) => (
        <div
          key={r.index}
          className="related-row"
          onClick={() => navigate(`/findings/${r.index}`)}
        >
          <span className={`badge badge-${r.severity.toLowerCase()}`}>
            {r.severity.charAt(0)}
          </span>
          <span style={{ fontSize: 'var(--text-xs)' }}>{r.rule_id}</span>
          <span
            className="cell-path"
            style={{ fontSize: 'var(--text-xs)', maxWidth: 200 }}
          >
            {truncPath(r.path, 30)}:{r.line}
          </span>
        </div>
      ))}
    </>
  );
}

// ── Code Preview ────────────────────────────────────────────────────────────

function CodePreview({
  lines,
  startLine,
  highlightLine,
  language,
}: {
  lines: string[];
  startLine: number;
  highlightLine: number;
  language?: string;
}) {
  const lang = (language || '').toLowerCase();

  return (
    <div className="code-block">
      {lines.map((line, i) => {
        const lineNum = startLine + i;
        const isHighlight = lineNum === highlightLine;
        return (
          <div
            key={lineNum}
            className={`code-line${isHighlight ? ' highlight' : ''}`}
          >
            <span className="line-number">{lineNum}</span>
            <span
              className="line-content"
              dangerouslySetInnerHTML={{
                __html: highlightSyntax(escapeHtml(line), lang),
              }}
            />
          </div>
        );
      })}
    </div>
  );
}

// ── How to Fix ──────────────────────────────────────────────────────────────

function sinkCapKey(finding: FindingView): string | null {
  const snippet = (finding.evidence?.sink?.snippet || '').toLowerCase();
  const rule = finding.rule_id.toLowerCase();

  if (rule.includes('data-exfiltration') || rule.includes('exfil'))
    return 'data-exfil';

  if (
    /innerhtml|outerhtml|document\.write|dangerouslysetinnerhtml/.test(snippet)
  )
    return 'xss';
  if (/\beval\b|new function|settimeout\s*\(\s*["'`]/.test(snippet))
    return 'code-exec';
  if (
    /\bexec\b|\bspawn\b|\bsystem\b|\bpopen\b|shell_exec|subprocess/.test(
      snippet,
    )
  )
    return 'cmd-inject';
  if (
    /query|execute|raw|prepare.*%|select\s|insert\s|update\s|delete\s/i.test(
      snippet,
    )
  )
    return 'sql';
  if (/readfile|fs\.|open\s*\(|path\.join/.test(snippet)) return 'path';
  if (/\bfetch\b|\baxios\b|http\.|request\.|urlopen|curl/.test(snippet))
    return 'ssrf';
  if (rule.includes('xss')) return 'xss';
  if (rule.includes('sql')) return 'sql';
  if (rule.includes('cmd') || rule.includes('command')) return 'cmd-inject';
  if (rule.includes('ssrf')) return 'ssrf';
  if (rule.includes('path') || rule.includes('traversal')) return 'path';
  if (rule.includes('deserial')) return 'deserialize';
  if (rule.includes('eval') || rule.includes('codeexec')) return 'code-exec';

  return null;
}

const TAINT_REMEDIATION: Record<string, string[]> = {
  xss: [
    'Avoid writing user input into innerHTML / outerHTML / document.write.',
    'Use textContent, or framework-native binding (React props, Vue {{ }}, etc.).',
    'If HTML is unavoidable, run input through a well-maintained sanitizer (DOMPurify, Bleach).',
  ],
  sql: [
    'Use parameterized queries or a prepared statement. Never concatenate user input into SQL.',
    'Prefer an ORM or query builder that escapes parameters automatically.',
    'Validate input type (integer, enum, allowlist) before the query.',
  ],
  'cmd-inject': [
    'Avoid passing user input to shell/exec APIs.',
    'Use the argv-array form of exec (no shell interpretation).',
    'Validate against a strict allowlist of commands and arguments.',
  ],
  ssrf: [
    'Validate and allowlist outbound hostnames before making the request.',
    'Resolve and check the target IP is not internal / metadata (169.254.169.254, 127.0.0.0/8, 10.0.0.0/8, RFC1918).',
    'Use a dedicated HTTP client that disables redirects to private addresses.',
  ],
  path: [
    'Normalize the path and verify it stays within an expected root directory.',
    'Reject inputs containing "..", null bytes, or absolute paths.',
    'Use a safe-join helper rather than string concatenation.',
  ],
  deserialize: [
    'Do not deserialize untrusted input with dangerous formats (pickle, ObjectInputStream).',
    'Use a schema-constrained format (JSON with a validator, Protobuf).',
    'If unavoidable, run deserialization in a locked-down process and validate types post-hoc.',
  ],
  'code-exec': [
    'Do not pass user input to eval / new Function / exec.',
    'Replace dynamic code generation with a parser over an allowlisted grammar.',
    'If scripting is required, sandbox it (VM / Web Worker with no DOM, seccomp).',
  ],
  'data-exfil': [
    'Do not put cookies, session tokens, or env secrets into outbound request bodies.',
    'If the forward is intentional, allowlist the destination under `detectors.data_exfil.trusted_destinations` or route through a named wrapper the engine treats as a data-exfil sanitizer.',
    'Use dedicated server-to-server credentials for the upstream call instead of forwarding the user session.',
  ],
};

const DEFAULT_TAINT_REMEDIATION: string[] = [
  'Validate user input against an allowlist (length, character set, format).',
  'Encode or escape data appropriately for the target sink.',
  'Prefer parameterized / structured APIs over string concatenation.',
];

function HowToFix({ finding }: { finding: FindingView }) {
  const isState = isStateFinding(finding);

  const bullets: string[] = (() => {
    if (isState) {
      return STATE_REMEDIATION_HINTS[finding.rule_id] || [];
    }
    const key = sinkCapKey(finding);
    if (key && TAINT_REMEDIATION[key]) return TAINT_REMEDIATION[key];
    return DEFAULT_TAINT_REMEDIATION;
  })();

  if (bullets.length === 0) return null;

  return (
    <ul className="how-to-fix-list">
      {bullets.map((b, i) => (
        <li key={i}>{b}</li>
      ))}
    </ul>
  );
}

// ── Dynamic Verification Panel ──────────────────────────────────────────────

function DynamicVerdictSection({ verdict }: { verdict: VerifyResult }) {
  const [copied, setCopied] = useState(false);
  const reproPath = `~/.cache/nyx/dynamic/repro/${verdict.finding_id}/`;
  const reproCmd = './reproduce.sh';

  const copyCmd = () => {
    navigator.clipboard.writeText(reproCmd).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="dynamic-verdict-section">
      <div className="dynamic-verdict-badge-row">
        <VerdictBadge verdict={verdict} />
        {verdict.toolchain_match && (
          <span
            className="dynamic-toolchain-match"
            title={`Toolchain match: ${verdict.toolchain_match}`}
          >
            {verdict.toolchain_match === 'exact' ? 'exact toolchain' : 'approximate toolchain'}
          </span>
        )}
      </div>

      {verdict.status === 'Confirmed' && (
        <div className="repro-panel" data-testid="repro-panel">
          <div className="repro-path-row">
            <span className="repro-label">Repro artifact:</span>
            <code className="repro-path">{reproPath}</code>
          </div>
          <div className="repro-cmd-row">
            <code className="repro-cmd">{reproCmd}</code>
            <button
              type="button"
              className="btn btn-sm repro-copy-btn"
              onClick={copyCmd}
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      {(verdict.reason || verdict.inconclusive_reason || verdict.detail) && (
        <div className="dynamic-verdict-detail">
          {verdict.reason && (
            <div>
              <strong>Reason:</strong> {verdict.reason}
            </div>
          )}
          {verdict.inconclusive_reason && (
            <div>
              <strong>Inconclusive reason:</strong> {verdict.inconclusive_reason}
            </div>
          )}
          {verdict.detail && (
            <div className="dynamic-verdict-detail-text">{verdict.detail}</div>
          )}
        </div>
      )}

      {verdict.attempts.length > 0 && (
        <div className="dynamic-attempts">
          <strong>Payload attempts:</strong>
          <ul className="dynamic-attempt-list">
            {verdict.attempts.map((a, i) => (
              <li key={i} className={`attempt-row ${a.triggered ? 'triggered' : ''}`}>
                <code>{a.payload_label}</code>
                <span className="attempt-outcome">
                  {a.triggered
                    ? 'triggered'
                    : a.timed_out
                      ? 'timeout'
                      : 'no hit'}
                </span>
                {a.exit_code != null && (
                  <span className="attempt-exit-code">exit {a.exit_code}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ── Status Control ──────────────────────────────────────────────────────────

function StatusControl({
  finding,
  onTriage,
  isPending,
}: {
  finding: FindingView;
  onTriage: (state: string, note: string) => void;
  isPending: boolean;
}) {
  const [noteDraft, setNoteDraft] = useState('');
  const [noteOpen, setNoteOpen] = useState(false);

  const currentState = finding.triage_state || 'open';

  const chooseStatus = (state: string, close: () => void) => {
    if (state === currentState) {
      close();
      return;
    }
    onTriage(state, noteDraft.trim());
    setNoteDraft('');
    setNoteOpen(false);
    close();
  };

  return (
    <div className="status-control" data-fingerprint={finding.fingerprint}>
      <div className="status-control-row">
        <label className="status-label">Status</label>
        <Dropdown
          trigger={({ open }) => (
            <button
              type="button"
              className={`status-trigger status-trigger-${currentState}`}
              disabled={isPending}
            >
              <span className={`status-dot status-dot-${currentState}`} />
              <span className="status-value">
                {formatTriageState(currentState)}
              </span>
              <span className={`status-caret${open ? ' open' : ''}`}>▾</span>
            </button>
          )}
        >
          {({ close }) => (
            <>
              {STATUS_GROUPS.map((group) => (
                <div className="status-group" key={group.heading}>
                  <div className="status-group-heading">{group.heading}</div>
                  {group.options.map((opt) => (
                    <DropdownItem
                      key={opt.value}
                      checked={opt.value === currentState}
                      onClick={() => chooseStatus(opt.value, close)}
                    >
                      {opt.label}
                    </DropdownItem>
                  ))}
                </div>
              ))}
            </>
          )}
        </Dropdown>
        {!noteOpen && (
          <button
            type="button"
            className="status-note-toggle"
            onClick={() => setNoteOpen(true)}
          >
            {finding.triage_note ? 'Edit note' : 'Add note'}
          </button>
        )}
      </div>
      {finding.triage_note && !noteOpen && (
        <div className="status-current-note">
          <strong>Note:</strong> {finding.triage_note}
        </div>
      )}
      {noteOpen && (
        <div className="status-note-input">
          <textarea
            placeholder="Context for the next person reading this…"
            rows={2}
            value={noteDraft || finding.triage_note || ''}
            onChange={(e) => setNoteDraft(e.target.value)}
            autoFocus
          />
          <div className="status-note-actions">
            <button
              className="btn btn-sm btn-primary"
              disabled={isPending}
              onClick={() => {
                onTriage(currentState, noteDraft.trim());
                setNoteOpen(false);
              }}
            >
              Save note
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setNoteOpen(false);
                setNoteDraft('');
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────────────

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();

  const { data: finding, isLoading, isError, error } = useFinding(id ?? '');
  usePageTitle(
    finding
      ? `${finding.rule_id} · ${finding.path}:${finding.line}`
      : 'Finding',
  );

  const bulkTriage = useBulkTriage();
  const [codeModalOpen, setCodeModalOpen] = useState(false);

  const handleTriage = useCallback(
    (state: string, note: string) => {
      if (!finding) return;
      bulkTriage.mutate({
        fingerprints: [finding.fingerprint],
        state,
        note,
      });
    },
    [finding, bulkTriage],
  );

  if (isLoading) {
    return <div className="loading">Loading finding...</div>;
  }

  if (isError || !finding) {
    const msg = error instanceof Error ? error.message : 'Unknown error';
    return (
      <div className="error-state">
        <h3>Finding not found</h3>
        <p>{msg}</p>
      </div>
    );
  }

  const f = finding;
  const evidence = f.evidence;
  const isState = isStateFinding(f);
  const hasWhySection =
    f.message ||
    (evidence && (evidence.source || evidence.sink || evidence.state));
  const hasEvidence =
    evidence &&
    (evidence.source ||
      evidence.sink ||
      (evidence.guards && evidence.guards.length > 0) ||
      (evidence.sanitizers && evidence.sanitizers.length > 0) ||
      evidence.state);
  const hasNotes = evidence && evidence.notes && evidence.notes.length > 0;
  const hasFlow =
    evidence && evidence.flow_steps && evidence.flow_steps.length > 0;
  const hasRelated = f.related_findings && f.related_findings.length > 0;
  const hasLabels = f.labels && f.labels.length > 0;
  const hasCode = !!f.code_context;
  const sourcePath = evidence?.source
    ? `${evidence.source.path}:${evidence.source.line}:${evidence.source.col}`
    : null;
  const sinkPath = evidence?.sink
    ? `${evidence.sink.path}:${evidence.sink.line}:${evidence.sink.col}`
    : null;

  const metaParts: string[] = [];
  if (f.category) metaParts.push(f.category);
  if (f.language) metaParts.push(f.language);
  metaParts.push(formatTriageState(f.triage_state || 'open'));
  if (f.sanitizer_status && !isState) {
    metaParts.push(
      f.sanitizer_status === 'none'
        ? 'No sanitizers'
        : f.sanitizer_status === 'bypassed'
          ? 'Sanitizer bypassed'
          : 'Sanitized',
    );
  }

  return (
    <div className="detail-panel finding-detail page-shell">
      <div className="detail-title-row">
        <h2 className="finding-heading">
          <span
            className={`severity-pill severity-pill-${f.severity.toLowerCase()}`}
          >
            {f.severity}
          </span>
          <span className="finding-rule-id">{f.rule_id}</span>
        </h2>
        <CopyMarkdownButton
          iconOnly
          title="Copy as markdown"
          getMarkdown={() => findingToMarkdown(f)}
        />
      </div>

      <a
        href="#"
        className="file-location"
        onClick={(e) => {
          e.preventDefault();
          setCodeModalOpen(true);
        }}
      >
        {f.path}:{f.line}:{f.col}
      </a>

      <div className="finding-meta">
        {metaParts.map((p, i) => (
          <span key={i}>
            {i > 0 && <span className="finding-meta-sep">•</span>}
            <span className="finding-meta-item">{p}</span>
          </span>
        ))}
      </div>

      {(sourcePath || sinkPath) && (
        <div className="path-trace" aria-label="Source to sink path">
          <div className="path-trace-card">
            <span className="path-trace-label">Source</span>
            <code className="path-trace-path">{sourcePath || 'Unknown'}</code>
          </div>
          <div className="path-trace-arrow" aria-hidden>
            &rarr;
          </div>
          <div className="path-trace-card">
            <span className="path-trace-label">Sink</span>
            <code className="path-trace-path">{sinkPath || 'Unknown'}</code>
          </div>
        </div>
      )}

      <StatusControl
        finding={f}
        onTriage={handleTriage}
        isPending={bulkTriage.isPending}
      />

      {/* Why Nyx Reported This */}
      {hasWhySection && (
        <CollapsibleSection title="Why Nyx Reported This">
          {isState ? (
            <>
              {STATE_RULE_DESCRIPTIONS[f.rule_id] && (
                <p style={{ marginBottom: 'var(--space-3)', lineHeight: 1.5 }}>
                  {STATE_RULE_DESCRIPTIONS[f.rule_id]}
                </p>
              )}
              {f.message && (
                <p style={{ marginBottom: 'var(--space-3)' }}>{f.message}</p>
              )}
              {evidence && (
                <StateTransitionCard evidence={evidence} ruleId={f.rule_id} />
              )}
            </>
          ) : (
            evidence && (
              <StructuredExplanation finding={f} evidence={evidence} />
            )
          )}
        </CollapsibleSection>
      )}

      {/* Taint Flow */}
      {hasFlow && (
        <CollapsibleSection title="Taint Flow">
          <FlowTimeline steps={evidence!.flow_steps} />
        </CollapsibleSection>
      )}

      {/* How to Fix */}
      <CollapsibleSection title="How to fix">
        <HowToFix finding={f} />
      </CollapsibleSection>

      {/* Analysis Notes */}
      {hasNotes && (
        <CollapsibleSection title="Analysis Notes" defaultOpen={false}>
          <NotesSection evidence={evidence!} />
        </CollapsibleSection>
      )}

      {/* Confidence Reasoning */}
      {f.confidence && (
        <CollapsibleSection title="Confidence Reasoning" defaultOpen={false}>
          <ConfidenceSection finding={f} />
        </CollapsibleSection>
      )}

      {/* Related Findings */}
      {hasRelated && (
        <CollapsibleSection title="Related Findings">
          <RelatedFindings findings={f.related_findings} />
        </CollapsibleSection>
      )}

      {/* Dynamic Verification */}
      {evidence?.dynamic_verdict && (
        <CollapsibleSection title="Dynamic Verification">
          <DynamicVerdictSection verdict={evidence.dynamic_verdict} />
        </CollapsibleSection>
      )}

      {/* Code Preview */}
      {hasCode && (
        <CollapsibleSection title="Code Preview" defaultOpen={false}>
          <CodePreview
            lines={f.code_context!.lines}
            startLine={f.code_context!.start_line}
            highlightLine={f.code_context!.highlight_line}
            language={f.language}
          />
        </CollapsibleSection>
      )}
      <CodeViewerModal
        open={codeModalOpen}
        onClose={() => setCodeModalOpen(false)}
        finding={f}
      />
    </div>
  );
}
