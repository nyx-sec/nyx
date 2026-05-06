import { describe, it, expect } from 'vitest';
import {
  findingToMarkdown,
  findingsToMarkdown,
} from '../../utils/findingMarkdown';
import type { FindingView } from '../../api/types';

const lean: FindingView = {
  index: 0,
  fingerprint: 'fp-lean',
  path: 'src/a.js',
  line: 10,
  col: 2,
  severity: 'High',
  rule_id: 'js-xss',
  category: 'xss',
  labels: [],
  path_validated: false,
  suppressed: false,
  language: 'javascript',
  status: 'new',
  triage_state: 'open',
  related_findings: [],
};

const full: FindingView = {
  index: 42,
  fingerprint: 'fp-full-abc',
  path: 'src/handlers/login.py',
  line: 141,
  col: 10,
  severity: 'High',
  rule_id: 'py-sqli',
  category: 'sqli',
  confidence: 'High',
  rank_score: 8.7,
  message: 'User input flows into SQL query.\nReview the construction.',
  labels: [
    ['source', 'request'],
    ['sink', 'cursor.execute'],
  ],
  path_validated: false,
  suppressed: false,
  language: 'python',
  status: 'new',
  triage_state: 'investigating',
  triage_note: 'Looks real - assigned to alice.',
  code_context: {
    start_line: 138,
    highlight_line: 141,
    lines: [
      'name = request.args.get("name")',
      '',
      'query_name = name.strip()',
      'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
    ],
  },
  evidence: {
    source: {
      path: 'src/handlers/login.py',
      line: 138,
      col: 7,
      kind: 'UserInput',
      snippet: 'request.args.get("name")',
    },
    sink: {
      path: 'src/handlers/login.py',
      line: 141,
      col: 10,
      kind: 'SqlQuery',
      snippet: 'cursor.execute(...)',
    },
    guards: [],
    sanitizers: [],
    notes: ['source_kind:UserInput', 'hop_count:3'],
    flow_steps: [
      {
        step: 1,
        kind: 'source',
        file: 'src/handlers/login.py',
        line: 138,
        col: 7,
        snippet: 'request.args.get("name")',
        variable: 'name',
      },
      {
        step: 2,
        kind: 'assignment',
        file: 'src/handlers/login.py',
        line: 140,
        col: 4,
        variable: 'query_name',
      },
      {
        step: 3,
        kind: 'sink',
        file: 'src/handlers/login.py',
        line: 141,
        col: 10,
        callee: 'cursor.execute',
        is_cross_file: true,
      },
    ],
    explanation: 'Untrusted input reaches a SQL sink without sanitization.',
    confidence_limiters: [],
  },
  rank_reason: [['source_kind', 'direct user input']],
  sanitizer_status: 'none',
  related_findings: [
    {
      index: 99,
      rule_id: 'py-xss',
      path: 'src/handlers/login.py',
      line: 160,
      severity: 'Medium',
    },
  ],
};

describe('findingToMarkdown', () => {
  it('renders the full finding with all sections', () => {
    const md = findingToMarkdown(full);
    expect(md).toContain('## py-sqli - User input flows into SQL query.');
    expect(md).toContain('- **Rule**: `py-sqli` (category: `sqli`)');
    expect(md).toContain('- **Severity**: High | **Confidence**: High');
    expect(md).toContain('- **Location**: `src/handlers/login.py:141:10`');
    expect(md).toContain('- **Fingerprint**: `fp-full-abc`');
    expect(md).toContain('- **Sanitizer status**: none');
    expect(md).toContain('### Message\nUser input flows into SQL query.');
    expect(md).toContain('### Explanation\nUntrusted input reaches');
    expect(md).toContain('### Evidence');
    expect(md).toContain(
      '**Source**: `src/handlers/login.py:138:7` (kind: UserInput)',
    );
    expect(md).toContain('```python\nrequest.args.get("name")\n```');
    expect(md).toContain('**Guards**: none');
    expect(md).toContain('**Sanitizers**: none');
    expect(md).toContain('### Flow (3 steps)');
    expect(md).toContain('[cross-file]');
    expect(md).toContain(
      '### Code context (lines 138–141, highlight line 141)',
    );
    expect(md).toContain('141> ');
    expect(md).toContain('### Labels');
    expect(md).toContain('- `source`: `request`');
    expect(md).toContain('### Notes');
    expect(md).toContain('- Source type: User Input');
    expect(md).toContain('- Path length: 3 blocks');
    expect(md).toContain('### Triage note\nLooks real - assigned to alice.');
    expect(md).toContain('### Confidence reasoning');
    expect(md).toContain('Score: 8.7');
    expect(md).toContain('- **source_kind**: direct user input');
    expect(md).toContain('### Related findings');
    expect(md).toContain(
      '- `#99` `py-xss` - `src/handlers/login.py:160` (Medium)',
    );
  });

  it('skips optional sections for a lean finding', () => {
    const md = findingToMarkdown(lean);
    expect(md).toContain('## js-xss - xss');
    expect(md).toContain('**Confidence**: unknown');
    expect(md).not.toContain('### Message');
    expect(md).not.toContain('### Evidence');
    expect(md).not.toContain('### Flow');
    expect(md).not.toContain('### Code context');
    expect(md).not.toContain('### Labels');
    expect(md).not.toContain('### Notes');
    expect(md).not.toContain('### Related findings');
    expect(md).not.toContain('### Triage note');
    expect(md).not.toContain('### Confidence reasoning');
  });
});

describe('findingsToMarkdown', () => {
  it('bundles multiple findings with a count header and separator', () => {
    const md = findingsToMarkdown([full, lean]);
    expect(md.startsWith('# Nyx findings (2)')).toBe(true);
    expect(md).toContain('\n\n---\n\n');
    expect(md).toContain('## py-sqli');
    expect(md).toContain('## js-xss');
  });

  it('handles empty selection gracefully', () => {
    const md = findingsToMarkdown([]);
    expect(md).toBe('# Nyx findings (0)\n\n(none)');
  });
});
