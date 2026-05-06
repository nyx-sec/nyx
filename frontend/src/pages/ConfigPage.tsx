import { useState, useCallback, useEffect, useMemo } from 'react';
import {
  useConfig,
  useRawConfig,
  useSources,
  useSinks,
  useSanitizers,
  useTerminators,
  useProfiles,
} from '../api/queries/config';
import {
  useAddSource,
  useDeleteSource,
  useAddSink,
  useDeleteSink,
  useAddSanitizer,
  useDeleteSanitizer,
  useAddTerminator,
  useDeleteTerminator,
  useAddProfile,
  useDeleteProfile,
  useActivateProfile,
  useToggleTriageSync,
  useSaveRawConfig,
} from '../api/mutations/config';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { usePageTitle } from '../hooks/usePageTitle';
import { useToast } from '../contexts/ToastContext';
import { useTheme, type ThemePreference } from '../contexts/ThemeContext';
import type { LabelEntryView, TerminatorView, ProfileView } from '../api/types';

const THEME_OPTIONS: Array<{ value: ThemePreference; label: string }> = [
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
  { value: 'system', label: 'System' },
  { value: 'hc-light', label: 'High-contrast light' },
  { value: 'hc-dark', label: 'High-contrast dark' },
];

const LANG_OPTIONS = [
  'javascript',
  'typescript',
  'python',
  'go',
  'java',
  'c',
  'cpp',
  'php',
  'ruby',
  'rust',
];

const CAP_OPTIONS = [
  'all',
  'env_var',
  'html_escape',
  'shell_escape',
  'url_encode',
  'json_parse',
  'file_io',
  'sql_query',
  'deserialize',
  'ssrf',
  'code_exec',
  'crypto',
];

type Tab = 'overview' | 'rules' | 'profiles' | 'raw';

// ── Collapsible Config Section ───────────────────────────────────────────────

function ConfigSection({
  title,
  id,
  defaultCollapsed = false,
  children,
}: {
  title: string;
  id?: string;
  defaultCollapsed?: boolean;
  children: React.ReactNode;
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);

  return (
    <div className="config-section" id={id}>
      <div
        className={`config-section-header${collapsed ? ' collapsed' : ''}`}
        onClick={() => setCollapsed(!collapsed)}
      >
        <span
          className={`config-collapse-arrow${collapsed ? ' collapsed' : ''}`}
        >
          &#9660;
        </span>{' '}
        <strong>{title}</strong>
      </div>
      <div className={`config-section-body${collapsed ? ' collapsed' : ''}`}>
        {children}
      </div>
    </div>
  );
}

// ── Top-of-page settings panel (theme + triage sync) ────────────────────────

function SettingsSection({
  triageSyncOn,
  onToggleTriageSync,
}: {
  triageSyncOn: boolean;
  onToggleTriageSync: (enabled: boolean) => void;
}) {
  const { preference, setPreference } = useTheme();

  return (
    <div className="config-section" id="config-settings">
      <div className="config-section-header config-section-header-static">
        <strong>Settings</strong>
      </div>
      <div className="config-section-body">
        <div className="settings-row">
          <label htmlFor="theme-select" className="settings-row-label">
            Theme
          </label>
          <select
            id="theme-select"
            className="settings-row-control"
            value={preference}
            onChange={(e) => setPreference(e.target.value as ThemePreference)}
          >
            {THEME_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
        <div className="toggle-inline settings-row-toggle">
          <input
            type="checkbox"
            id="triage-sync-toggle"
            checked={triageSyncOn}
            onChange={(e) => onToggleTriageSync(e.target.checked)}
          />
          <label htmlFor="triage-sync-toggle">
            Auto-sync triage decisions to <code>.nyx/triage.json</code> for
            git-based team sharing
          </label>
        </div>
      </div>
    </div>
  );
}

// ── Read-only key/value grid for effective config display ───────────────────

function KvGrid({ entries }: { entries: Array<[string, React.ReactNode]> }) {
  return (
    <div className="config-kv-grid">
      {entries.map(([k, v]) => (
        <div className="config-kv-row" key={k}>
          <div className="config-kv-key">{k}</div>
          <div className="config-kv-val">{v}</div>
        </div>
      ))}
    </div>
  );
}

function fmt(v: unknown): React.ReactNode {
  if (v === null || v === undefined) return <span className="muted">-</span>;
  if (typeof v === 'boolean')
    return (
      <span className={v ? 'pill pill-on' : 'pill pill-off'}>
        {v ? 'on' : 'off'}
      </span>
    );
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="muted">[]</span>;
    return (
      <span className="config-list-inline">
        {v.map(String).map((s, i) => (
          <span key={i} className="config-tag">
            {s}
          </span>
        ))}
      </span>
    );
  }
  if (typeof v === 'object')
    return <code className="config-mono">{JSON.stringify(v)}</code>;
  return <span className="config-mono">{String(v)}</span>;
}

// ── Custom rules table (no built-ins; built-ins live on /rules) ─────────────

function CustomLabelSection({
  title,
  id,
  kind,
  entries,
  onAdd,
  onDelete,
}: {
  title: string;
  id: string;
  kind: 'source' | 'sink' | 'sanitizer';
  entries: LabelEntryView[];
  onAdd: (body: { lang: string; matchers: string[]; cap: string }) => void;
  onDelete: (entry: LabelEntryView) => void;
}) {
  const [lang, setLang] = useState('');
  const [matcher, setMatcher] = useState('');
  const [cap, setCap] = useState('all');

  const handleAdd = useCallback(() => {
    if (!lang || !matcher) return;
    onAdd({ lang, matchers: [matcher], cap });
    setMatcher('');
  }, [lang, matcher, cap, onAdd]);

  return (
    <ConfigSection title={title} id={id}>
      <p className="config-help">
        Custom {kind} rules from your <code>nyx.local</code>. Built-in rules are
        listed on the <strong>Rules</strong> page.
      </p>
      <div className="config-form-row">
        <div className="form-group">
          <label>Language</label>
          <select value={lang} onChange={(e) => setLang(e.target.value)}>
            <option value="">Select…</option>
            {LANG_OPTIONS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group form-group-grow">
          <label>Matcher</label>
          <input
            type="text"
            placeholder="functionName"
            value={matcher}
            onChange={(e) => setMatcher(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleAdd();
            }}
          />
        </div>
        <div className="form-group">
          <label>Capability</label>
          <select value={cap} onChange={(e) => setCap(e.target.value)}>
            {CAP_OPTIONS.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <button
          className="btn btn-primary"
          onClick={handleAdd}
          disabled={!lang || !matcher}
        >
          Add
        </button>
      </div>
      <div className="table-wrap" style={{ marginTop: 12 }}>
        {entries.length === 0 ? (
          <div className="empty-state" style={{ padding: 12 }}>
            <p>No custom {kind} rules yet</p>
          </div>
        ) : (
          <table className="label-table">
            <thead>
              <tr>
                <th>Language</th>
                <th>Matchers</th>
                <th>Cap</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={`c-${i}`}>
                  <td>{e.lang}</td>
                  <td className="config-mono">{e.matchers.join(', ')}</td>
                  <td>{e.cap}</td>
                  <td>
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => onDelete(e)}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </ConfigSection>
  );
}

// ── Raw TOML editor ─────────────────────────────────────────────────────────

function RawEditor() {
  const { data, isLoading, error, refetch } = useRawConfig();
  const save = useSaveRawConfig();
  const [draft, setDraft] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  // Seed the editor whenever we load fresh data and have no in-flight edit.
  useEffect(() => {
    if (data && draft === null) {
      setDraft(data.content);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  if (isLoading) return <LoadingState message="Loading nyx.local…" />;
  if (error) return <ErrorState message={error.message} />;
  if (!data) return null;

  const dirty = draft !== null && draft !== data.content;

  const handleSave = async () => {
    if (draft === null) return;
    setSaveError(null);
    try {
      await save.mutateAsync(draft);
      setSavedAt(Date.now());
      // refresh disk view so {data.content} reflects what's on disk
      await refetch();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
    }
  };

  const handleDiscard = () => {
    setDraft(data.content);
    setSaveError(null);
  };

  return (
    <div className="raw-editor">
      <div className="raw-editor-header">
        <div>
          <strong>nyx.local</strong>
          <div className="raw-editor-path">
            {data.exists ? data.path : `${data.path} (will be created on save)`}
          </div>
        </div>
        <div className="raw-editor-actions">
          {dirty && <span className="raw-editor-dirty">Unsaved changes</span>}
          {savedAt && !dirty && <span className="raw-editor-saved">Saved</span>}
          <button
            className="btn btn-sm"
            onClick={handleDiscard}
            disabled={!dirty || save.isPending}
          >
            Discard
          </button>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleSave}
            disabled={!dirty || save.isPending}
          >
            {save.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
      {saveError && (
        <div className="raw-editor-error">
          <strong>Save failed:</strong> {saveError}
        </div>
      )}
      <textarea
        className="raw-editor-textarea"
        value={draft ?? ''}
        spellCheck={false}
        onChange={(e) => setDraft(e.target.value)}
        placeholder="# nyx.local - overrides for the default config.&#10;# Anything you set here wins over nyx.conf."
      />
      <p className="config-help">
        Edits are validated against the full config schema before being written.
        Saved files take effect immediately for new scans.
      </p>
    </div>
  );
}

// ── Effective config overview (read-only) ───────────────────────────────────

function EffectiveOverview({
  cfg,
}: {
  cfg: Record<string, Record<string, unknown>> | undefined;
}) {
  const sections = useMemo(
    () => [
      {
        key: 'scanner',
        title: 'Scanner',
        keys: [
          'mode',
          'min_severity',
          'max_file_size_mb',
          'excluded_directories',
          'excluded_extensions',
          'read_global_ignore',
          'read_vcsignore',
          'follow_symlinks',
          'scan_hidden_files',
          'include_nonprod',
          'enable_state_analysis',
          'enable_auth_analysis',
          'enable_auth_as_taint',
          'enable_panic_recovery',
        ],
      },
      {
        key: 'output',
        title: 'Output',
        keys: [
          'default_format',
          'quiet',
          'max_results',
          'attack_surface_ranking',
          'min_score',
          'min_confidence',
          'require_converged',
          'include_quality',
          'show_all',
          'max_low',
          'max_low_per_file',
          'max_low_per_rule',
        ],
      },
      {
        key: 'performance',
        title: 'Performance',
        keys: [
          'max_depth',
          'min_depth',
          'worker_threads',
          'batch_size',
          'channel_multiplier',
          'rayon_thread_stack_size',
          'scan_timeout_secs',
          'memory_limit_mb',
        ],
      },
      {
        key: 'database',
        title: 'Database',
        keys: [
          'path',
          'auto_cleanup_days',
          'max_db_size_mb',
          'vacuum_on_startup',
        ],
      },
      {
        key: 'server',
        title: 'Server',
        keys: [
          'host',
          'port',
          'auto_open_browser',
          'persist_runs',
          'max_saved_runs',
          'triage_sync',
        ],
      },
      {
        key: 'runs',
        title: 'Runs',
        keys: [
          'persist',
          'max_runs',
          'save_logs',
          'save_stdout',
          'save_code_snippets',
        ],
      },
    ],
    [],
  );

  return (
    <>
      <p className="config-help">
        The merged result of <code>nyx.conf</code> defaults plus your
        <code> nyx.local</code> overrides. To change anything, edit fields below
        or use the <strong>Raw</strong> tab.
      </p>
      {sections.map((s) => {
        const sec = cfg?.[s.key] as Record<string, unknown> | undefined;
        const entries: Array<[string, React.ReactNode]> = s.keys.map((k) => [
          k,
          fmt(sec?.[k]),
        ]);
        return (
          <ConfigSection
            key={s.key}
            title={s.title}
            id={`config-${s.key}`}
            defaultCollapsed={s.key !== 'scanner' && s.key !== 'output'}
          >
            <KvGrid entries={entries} />
          </ConfigSection>
        );
      })}
    </>
  );
}

// ── Page ────────────────────────────────────────────────────────────────────

export function ConfigPage() {
  usePageTitle('Config');
  const {
    data: config,
    isLoading: configLoading,
    error: configError,
  } = useConfig();
  const { data: sources } = useSources();
  const { data: sinks } = useSinks();
  const { data: sanitizers } = useSanitizers();
  const { data: terminators } = useTerminators();
  const { data: profiles } = useProfiles();

  const addSource = useAddSource();
  const deleteSource = useDeleteSource();
  const addSink = useAddSink();
  const deleteSink = useDeleteSink();
  const addSanitizer = useAddSanitizer();
  const deleteSanitizer = useDeleteSanitizer();
  const addTerminator = useAddTerminator();
  const deleteTerminator = useDeleteTerminator();
  const addProfile = useAddProfile();
  const deleteProfile = useDeleteProfile();
  const activateProfile = useActivateProfile();
  const toggleTriageSync = useToggleTriageSync();
  const toast = useToast();

  const ruleSummary = (b: { lang: string; matchers: string[]; cap: string }) =>
    `${b.lang} · ${b.matchers.join(', ')} → ${b.cap}`;
  const errMsg = (e: unknown) =>
    e instanceof Error ? e.message : String(e ?? 'Unknown error');

  const addRuleHandlers = (kind: 'source' | 'sink' | 'sanitizer') => ({
    onSuccess: (
      _d: unknown,
      b: { lang: string; matchers: string[]; cap: string },
    ) =>
      toast.success(
        ruleSummary(b),
        `${kind[0].toUpperCase()}${kind.slice(1)} added`,
      ),
    onError: (e: unknown) => toast.error(errMsg(e), `Could not add ${kind}`),
  });
  const deleteRuleHandlers = (kind: 'source' | 'sink' | 'sanitizer') => ({
    onSuccess: (
      _d: unknown,
      b: { lang: string; matchers: string[]; cap: string },
    ) =>
      toast.success(
        ruleSummary(b),
        `${kind[0].toUpperCase()}${kind.slice(1)} removed`,
      ),
    onError: (e: unknown) => toast.error(errMsg(e), `Could not remove ${kind}`),
  });

  const [tab, setTab] = useState<Tab>('overview');
  const [termLang, setTermLang] = useState('');
  const [termName, setTermName] = useState('');
  const [profileName, setProfileName] = useState('');

  const handleAddTerminator = useCallback(() => {
    if (!termLang || !termName) return;
    addTerminator.mutate(
      { lang: termLang, name: termName },
      {
        onSuccess: (_d, b) =>
          toast.success(`${b.lang} · ${b.name}`, 'Terminator added'),
        onError: (e) =>
          toast.error(
            e instanceof Error ? e.message : String(e ?? 'Unknown error'),
            'Could not add terminator',
          ),
      },
    );
    setTermName('');
  }, [termLang, termName, addTerminator, toast]);

  const handleSaveProfile = useCallback(() => {
    if (!profileName) return;
    addProfile.mutate({ name: profileName, settings: {} });
    setProfileName('');
  }, [profileName, addProfile]);

  if (configLoading) return <LoadingState message="Loading configuration..." />;
  if (configError) return <ErrorState message={configError.message} />;

  const cfg = config as Record<string, Record<string, unknown>> | undefined;
  const server = cfg?.server as Record<string, unknown> | undefined;
  const triageSyncOn = !!server?.triage_sync;

  return (
    <div className="config-page page-shell">
      <div className="config-tabs">
        {(
          [
            ['overview', 'Overview'],
            ['rules', 'Custom Rules'],
            ['profiles', 'Profiles'],
            ['raw', 'Raw nyx.local'],
          ] as Array<[Tab, string]>
        ).map(([id, label]) => (
          <button
            key={id}
            className={`config-tab${tab === id ? ' active' : ''}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <>
          <SettingsSection
            triageSyncOn={triageSyncOn}
            onToggleTriageSync={(enabled) =>
              toggleTriageSync.mutate({ enabled })
            }
          />
          <EffectiveOverview cfg={cfg} />
        </>
      )}

      {tab === 'rules' && (
        <>
          <CustomLabelSection
            title="Sources"
            id="config-sources"
            kind="source"
            entries={sources || []}
            onAdd={(body) => addSource.mutate(body, addRuleHandlers('source'))}
            onDelete={(e) =>
              deleteSource.mutate(
                { lang: e.lang, matchers: e.matchers, cap: e.cap },
                deleteRuleHandlers('source'),
              )
            }
          />
          <CustomLabelSection
            title="Sinks"
            id="config-sinks"
            kind="sink"
            entries={sinks || []}
            onAdd={(body) => addSink.mutate(body, addRuleHandlers('sink'))}
            onDelete={(e) =>
              deleteSink.mutate(
                { lang: e.lang, matchers: e.matchers, cap: e.cap },
                deleteRuleHandlers('sink'),
              )
            }
          />
          <CustomLabelSection
            title="Sanitizers"
            id="config-sanitizers"
            kind="sanitizer"
            entries={sanitizers || []}
            onAdd={(body) =>
              addSanitizer.mutate(body, addRuleHandlers('sanitizer'))
            }
            onDelete={(e) =>
              deleteSanitizer.mutate(
                { lang: e.lang, matchers: e.matchers, cap: e.cap },
                deleteRuleHandlers('sanitizer'),
              )
            }
          />

          <ConfigSection title="Terminators" id="config-terminators">
            <p className="config-help">
              Function calls that abort control flow (e.g.{' '}
              <code>process.exit</code>,<code> sys.exit</code>) so the analyzer
              doesn't continue past them.
            </p>
            <div className="config-form-row">
              <div className="form-group">
                <label>Language</label>
                <select
                  value={termLang}
                  onChange={(e) => setTermLang(e.target.value)}
                >
                  <option value="">Select…</option>
                  {LANG_OPTIONS.map((l) => (
                    <option key={l} value={l}>
                      {l}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-group form-group-grow">
                <label>Function Name</label>
                <input
                  type="text"
                  placeholder="process.exit"
                  value={termName}
                  onChange={(e) => setTermName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleAddTerminator();
                  }}
                />
              </div>
              <button
                className="btn btn-primary"
                onClick={handleAddTerminator}
                disabled={!termLang || !termName}
              >
                Add
              </button>
            </div>
            <div className="table-wrap" style={{ marginTop: 12 }}>
              {!terminators || terminators.length === 0 ? (
                <div className="empty-state" style={{ padding: 12 }}>
                  <p>No terminators configured</p>
                </div>
              ) : (
                <table className="label-table">
                  <thead>
                    <tr>
                      <th>Language</th>
                      <th>Name</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {(terminators as TerminatorView[]).map((t, i) => (
                      <tr key={i}>
                        <td>{t.lang}</td>
                        <td className="config-mono">{t.name}</td>
                        <td>
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => deleteTerminator.mutate(t)}
                          >
                            Remove
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </ConfigSection>
        </>
      )}

      {tab === 'profiles' && (
        <ConfigSection title="Profiles" id="config-profiles">
          <p className="config-help">
            Profiles bundle scanner + output settings. Activate one to apply its
            settings to the current session.
          </p>
          <div className="table-wrap">
            {!profiles || profiles.length === 0 ? (
              <div className="empty-state" style={{ padding: 12 }}>
                <p>No profiles configured</p>
              </div>
            ) : (
              <table className="label-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Settings</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {(profiles as ProfileView[]).map((p) => (
                    <tr key={p.name}>
                      <td>
                        <strong>{p.name}</strong>
                      </td>
                      <td>
                        {p.is_builtin ? (
                          <span className="badge-builtin">built-in</span>
                        ) : (
                          <span className="badge-custom">custom</span>
                        )}
                      </td>
                      <td className="config-profile-settings">
                        {JSON.stringify(p.settings)}
                      </td>
                      <td>
                        <button
                          className="btn btn-sm"
                          onClick={() => activateProfile.mutate(p.name)}
                        >
                          Activate
                        </button>
                        {!p.is_builtin && (
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => deleteProfile.mutate(p.name)}
                            style={{ marginLeft: 6 }}
                          >
                            Delete
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          <div
            className="config-form-row config-form-row-2col"
            style={{ marginTop: 12 }}
          >
            <div className="form-group">
              <label>Profile Name</label>
              <input
                type="text"
                placeholder="my_profile"
                value={profileName}
                onChange={(e) => setProfileName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleSaveProfile();
                }}
              />
            </div>
            <button
              className="btn btn-primary"
              onClick={handleSaveProfile}
              disabled={!profileName}
            >
              Save Current as Profile
            </button>
          </div>
        </ConfigSection>
      )}

      {tab === 'raw' && <RawEditor />}
    </div>
  );
}
