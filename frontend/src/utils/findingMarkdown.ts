import type {
  FindingView,
  Evidence,
  FlowStep,
  SpanEvidence,
  CodeContextView,
  RelatedFindingView,
} from '../api/types';
import { parseNoteText } from './parseNote';

function firstLine(s: string): string {
  const nl = s.indexOf('\n');
  return nl === -1 ? s : s.slice(0, nl);
}

function fence(lang: string | undefined, body: string): string {
  const hint = (lang || '').toLowerCase();
  return `\`\`\`${hint}\n${body}\n\`\`\``;
}

function formatSpan(s: SpanEvidence, lang: string | undefined): string {
  const header = `\`${s.path}:${s.line}:${s.col}\` (kind: ${s.kind})`;
  if (!s.snippet) return header;
  return `${header}\n${fence(lang, s.snippet)}`;
}

function formatEvidence(ev: Evidence, lang: string | undefined): string {
  const parts: string[] = [];

  if (ev.explanation) {
    parts.push(`### Explanation\n${ev.explanation}`);
  }

  const hasSpans =
    ev.source ||
    ev.sink ||
    (ev.guards && ev.guards.length > 0) ||
    (ev.sanitizers && ev.sanitizers.length > 0) ||
    ev.state;

  if (hasSpans) {
    const lines: string[] = ['### Evidence'];
    if (ev.source) {
      lines.push(`**Source**: ${formatSpan(ev.source, lang)}`);
    }
    if (ev.sink) {
      lines.push(`**Sink**: ${formatSpan(ev.sink, lang)}`);
    }
    if (ev.source || ev.sink) {
      if (!ev.guards || ev.guards.length === 0) {
        lines.push(`**Guards**: none`);
      } else {
        lines.push(`**Guards**:`);
        for (const g of ev.guards) {
          lines.push(`- ${formatSpan(g, lang)}`);
        }
      }
      if (!ev.sanitizers || ev.sanitizers.length === 0) {
        lines.push(`**Sanitizers**: none`);
      } else {
        lines.push(`**Sanitizers**:`);
        for (const s of ev.sanitizers) {
          lines.push(`- ${formatSpan(s, lang)}`);
        }
      }
    }
    if (ev.state) {
      const st = ev.state;
      const subj = st.subject ? ` ${st.subject}:` : '';
      lines.push(
        `**State**: ${st.machine} -${subj} ${st.from_state} -> ${st.to_state}`,
      );
    }
    parts.push(lines.join('\n'));
  }

  if (ev.confidence_limiters && ev.confidence_limiters.length > 0) {
    const lines: string[] = ['**Confidence limiters**:'];
    for (const l of ev.confidence_limiters) lines.push(`- ${l}`);
    parts.push(lines.join('\n'));
  }

  return parts.join('\n\n');
}

function formatFlow(steps: FlowStep[]): string {
  const lines: string[] = [`### Flow (${steps.length} steps)`];
  for (const s of steps) {
    const segs: string[] = [`${s.step}. **${s.kind}** \`${s.file}:${s.line}\``];
    if (s.snippet) segs.push(`- \`${s.snippet}\``);
    if (s.variable) segs.push(`(var \`${s.variable}\`)`);
    if (s.callee) segs.push(`(callee \`${s.callee}\`)`);
    if (s.is_cross_file) segs.push(`[cross-file]`);
    lines.push(segs.join(' '));
  }
  return lines.join('\n');
}

function formatCodeContext(
  cc: CodeContextView,
  lang: string | undefined,
): string {
  const width = String(cc.start_line + cc.lines.length - 1).length;
  const body = cc.lines
    .map((line, i) => {
      const ln = cc.start_line + i;
      const marker = ln === cc.highlight_line ? '>' : ' ';
      return `${String(ln).padStart(width, ' ')}${marker} ${line}`;
    })
    .join('\n');
  return `### Code context (lines ${cc.start_line}–${
    cc.start_line + cc.lines.length - 1
  }, highlight line ${cc.highlight_line})\n${fence(lang, body)}`;
}

function formatRelated(related: RelatedFindingView[]): string {
  const lines: string[] = ['### Related findings'];
  for (const r of related) {
    lines.push(
      `- \`#${r.index}\` \`${r.rule_id}\` - \`${r.path}:${r.line}\` (${r.severity})`,
    );
  }
  return lines.join('\n');
}

export function findingToMarkdown(f: FindingView): string {
  const lang = f.language;
  const heading = firstLine(f.message || '').trim() || f.category;
  const parts: string[] = [];

  parts.push(`## ${f.rule_id} - ${heading}`);

  const meta: string[] = [];
  meta.push(`- **Rule**: \`${f.rule_id}\` (category: \`${f.category}\`)`);
  meta.push(
    `- **Severity**: ${f.severity} | **Confidence**: ${f.confidence ?? 'unknown'}`,
  );
  meta.push(`- **Location**: \`${f.path}:${f.line}:${f.col}\``);
  meta.push(`- **Language**: ${f.language ?? 'unknown'}`);
  meta.push(
    `- **Status**: ${f.status} | **Triage**: ${f.triage_state || 'open'}`,
  );
  meta.push(`- **Fingerprint**: \`${f.fingerprint}\``);
  if (f.sanitizer_status) {
    meta.push(`- **Sanitizer status**: ${f.sanitizer_status}`);
  }
  parts.push(meta.join('\n'));

  if (f.message) {
    parts.push(`### Message\n${f.message}`);
  }

  if (f.evidence) {
    const ev = formatEvidence(f.evidence, lang);
    if (ev) parts.push(ev);

    if (f.evidence.flow_steps && f.evidence.flow_steps.length > 0) {
      parts.push(formatFlow(f.evidence.flow_steps));
    }
  }

  if (f.code_context) {
    parts.push(formatCodeContext(f.code_context, lang));
  }

  if (f.labels && f.labels.length > 0) {
    const lines: string[] = ['### Labels'];
    for (const [k, v] of f.labels) lines.push(`- \`${k}\`: \`${v}\``);
    parts.push(lines.join('\n'));
  }

  if (f.evidence?.notes && f.evidence.notes.length > 0) {
    const lines: string[] = ['### Notes'];
    for (const n of f.evidence.notes) lines.push(`- ${parseNoteText(n)}`);
    parts.push(lines.join('\n'));
  }

  if (f.triage_note) {
    parts.push(`### Triage note\n${f.triage_note}`);
  }

  if (
    f.confidence &&
    (f.rank_score != null || (f.rank_reason && f.rank_reason.length > 0))
  ) {
    const lines: string[] = ['### Confidence reasoning'];
    if (f.rank_score != null) lines.push(`Score: ${f.rank_score.toFixed(1)}`);
    if (f.rank_reason && f.rank_reason.length > 0) {
      for (const [k, v] of f.rank_reason) lines.push(`- **${k}**: ${v}`);
    }
    parts.push(lines.join('\n'));
  }

  if (f.related_findings && f.related_findings.length > 0) {
    parts.push(formatRelated(f.related_findings));
  }

  return parts.join('\n\n');
}

export function findingsToMarkdown(fs: FindingView[]): string {
  const header = `# Nyx findings (${fs.length})`;
  if (fs.length === 0) return `${header}\n\n(none)`;
  return [header, ...fs.map(findingToMarkdown)].join('\n\n---\n\n');
}
