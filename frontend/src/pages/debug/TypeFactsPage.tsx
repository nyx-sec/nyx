import { useDebugTypeFacts } from '../../api/queries/debug';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';
import type { TypeFactDetailView, DtoFactView } from '../../api/types';

interface TypeFactsAnalysisPanelProps {
  file: string;
  functionName: string;
}

const SECURITY_TYPES = new Set([
  'HttpClient',
  'HttpResponse',
  'DatabaseConnection',
  'FileHandle',
  'Url',
  'LocalCollection',
]);

export function TypeFactsAnalysisPanel({
  file,
  functionName,
}: TypeFactsAnalysisPanelProps) {
  const { data, isLoading, error } = useDebugTypeFacts(file, functionName);

  if (isLoading) {
    return <LoadingState message="Loading type facts..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState message="Type facts are not available for the selected function." />
      );
    }
    return <ErrorState message="Failed to load type facts." />;
  }
  if (!data || data.facts.length === 0) {
    return (
      <EmptyState message="No type facts were inferred for this function. Type analysis fires when constructors, framework extractors, or constant literals reveal a value's type." />
    );
  }

  const securityFacts = data.facts.filter((f) => SECURITY_TYPES.has(f.kind));
  const dtoFacts = data.facts.filter((f) => f.kind === 'Dto');
  const scalarFacts = data.facts.filter(
    (f) => !SECURITY_TYPES.has(f.kind) && f.kind !== 'Dto',
  );

  return (
    <div className="abstract-interp-viewer">
      <div className="abstract-block">
        <div className="abstract-block-header">
          <h3 style={{ margin: 0 }}>Inferred Types</h3>
          <span className="text-secondary">
            {data.facts.length} of {data.total_values} SSA values typed ·{' '}
            {data.unknown_count} unknown
          </span>
        </div>
      </div>

      {securityFacts.length > 0 && (
        <TypeFactGroup
          title="Security-Relevant Types"
          subtitle="HttpClient, DatabaseConnection, Url, and related types drive type-qualified callee resolution and sink suppression"
          facts={securityFacts}
          highlight
        />
      )}

      {dtoFacts.length > 0 && (
        <DtoFactGroup
          title="DTO Types"
          subtitle="Framework-injected DTO bodies with known field shapes (Phase 6)"
          facts={dtoFacts}
        />
      )}

      {scalarFacts.length > 0 && (
        <TypeFactGroup
          title="Scalar Types"
          subtitle="String / Int / Bool / Object / Array / Null inferences"
          facts={scalarFacts}
        />
      )}
    </div>
  );
}

function TypeFactGroup({
  title,
  subtitle,
  facts,
  highlight,
}: {
  title: string;
  subtitle?: string;
  facts: TypeFactDetailView[];
  highlight?: boolean;
}) {
  return (
    <div className="abstract-block">
      <div className="abstract-block-header">
        <h3 style={{ margin: 0 }}>{title}</h3>
        <span className="text-secondary">
          {facts.length} value{facts.length === 1 ? '' : 's'}
        </span>
      </div>
      {subtitle && <p className="abstract-subtitle">{subtitle}</p>}
      <table className="abstract-table">
        <thead>
          <tr>
            <th>Value</th>
            <th>Name</th>
            <th>Type</th>
            <th>Container</th>
            <th>Nullable</th>
            <th>Line</th>
          </tr>
        </thead>
        <tbody>
          {facts.map((f) => (
            <tr key={f.ssa_value}>
              <td className="mono">v{f.ssa_value}</td>
              <td className="mono">{f.var_name ?? '-'}</td>
              <td>
                <span
                  className={`cap-badge ${
                    highlight ? 'cap-badge-sink' : 'cap-badge-source'
                  }`}
                >
                  {f.kind}
                </span>
              </td>
              <td className="mono">{f.container ?? '-'}</td>
              <td>{f.nullable ? 'Yes' : 'No'}</td>
              <td className="mono">{f.line > 0 ? `L${f.line}` : '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DtoFactGroup({
  title,
  subtitle,
  facts,
}: {
  title: string;
  subtitle?: string;
  facts: TypeFactDetailView[];
}) {
  return (
    <div className="abstract-block">
      <div className="abstract-block-header">
        <h3 style={{ margin: 0 }}>{title}</h3>
        <span className="text-secondary">
          {facts.length} DTO{facts.length === 1 ? '' : 's'}
        </span>
      </div>
      {subtitle && <p className="abstract-subtitle">{subtitle}</p>}
      {facts.map((f) => (
        <div key={f.ssa_value} style={{ padding: '8px 12px' }}>
          <div className="debug-detail-row">
            <span className="debug-detail-label">DTO</span>
            <span className="debug-detail-value mono">
              v{f.ssa_value} {f.var_name ? `(${f.var_name}) ` : ''}:{' '}
              {f.dto?.class_name ?? '?'}
            </span>
          </div>
          {f.dto && f.dto.fields.length > 0 && <DtoFieldTable dto={f.dto} />}
        </div>
      ))}
    </div>
  );
}

function DtoFieldTable({ dto }: { dto: DtoFactView }) {
  return (
    <table className="abstract-table">
      <thead>
        <tr>
          <th>Field</th>
          <th>Kind</th>
        </tr>
      </thead>
      <tbody>
        {dto.fields.map((f) => (
          <tr key={f.name}>
            <td className="mono">{f.name}</td>
            <td>
              <span className="cap-badge cap-badge-source">{f.kind}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
