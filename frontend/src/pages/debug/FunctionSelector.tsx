import { useMemo, useState } from 'react';
import { useDebugFunctions } from '../../api/queries/debug';
import type { FunctionInfo } from '../../api/types';

interface Props {
  file: string;
  selectedFunction: string | null;
  onFunctionChange: (fn_name: string | null) => void;
  showFilePath?: boolean;
}

export function FunctionSelector({
  file,
  selectedFunction,
  onFunctionChange,
  showFilePath = true,
}: Props) {
  const { data: functions, isLoading } = useDebugFunctions(file || null);
  const [showClosures, setShowClosures] = useState(false);

  const closureCount = useMemo(
    () => functions?.filter((fn) => fn.func_kind === 'closure').length ?? 0,
    [functions],
  );

  const visible = useMemo(() => {
    if (!functions) return functions;
    return showClosures
      ? functions
      : functions.filter((fn) => fn.func_kind !== 'closure');
  }, [functions, showClosures]);

  return (
    <div
      className={`function-selector${showFilePath ? '' : ' function-selector-flat'}`}
    >
      {showFilePath && (
        <div className="function-selector-path">
          <span className="function-selector-path-label">File:</span>
          <code className="function-selector-path-value">
            {file || 'No file selected'}
          </code>
        </div>
      )}
      <div className="function-selector-field">
        <label>Function</label>
        <select
          value={selectedFunction ?? ''}
          onChange={(e) => onFunctionChange(e.target.value || null)}
          disabled={!visible || visible.length === 0}
          className="function-selector-select"
        >
          <option value="">
            {isLoading
              ? 'Loading...'
              : !visible || visible.length === 0
                ? 'No functions found'
                : 'Select function'}
          </option>
          {visible?.map((fn: FunctionInfo) => (
            <option key={fn.name} value={fn.name}>
              {formatFunctionLabel(fn)}
              {fn.source_caps.length > 0 &&
                ` [src: ${fn.source_caps.join(',')}]`}
              {fn.sink_caps.length > 0 && ` [sink: ${fn.sink_caps.join(',')}]`}
            </option>
          ))}
        </select>
      </div>
      {closureCount > 0 && (
        <label className="function-selector-toggle">
          <input
            type="checkbox"
            checked={showClosures}
            onChange={(e) => setShowClosures(e.target.checked)}
          />
          <span>
            Show {closureCount} anonymous closure
            {closureCount === 1 ? '' : 's'}
          </span>
        </label>
      )}
    </div>
  );
}

function formatFunctionLabel(fn: FunctionInfo): string {
  const sig = `(${fn.param_count} params), L${fn.line}`;
  if (fn.func_kind === 'closure' && fn.container) {
    return `${fn.name} [closure in ${fn.container}] ${sig}`;
  }
  if (fn.func_kind === 'closure') {
    return `${fn.name} [closure] ${sig}`;
  }
  return `${fn.name}${sig}`;
}
