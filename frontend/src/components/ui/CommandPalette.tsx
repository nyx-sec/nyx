import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useNavigate } from 'react-router-dom';

export interface PaletteCommand {
  id: string;
  /** Visible label. */
  label: string;
  /** Optional secondary line such as section, hint, or shortcut. */
  hint?: string;
  /** Group label for visual separation. */
  group?: string;
  /** Search aliases beyond the label. */
  keywords?: string[];
  /** Optional leading icon. */
  icon?: ReactNode;
  /** Optional trailing keyboard hint. */
  shortcut?: string;
  /** Either a route to navigate to, or an action callback. One must be set. */
  to?: string;
  action?: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  commands: PaletteCommand[];
  placeholder?: string;
}

function rank(query: string, cmd: PaletteCommand): number {
  if (!query) return 0;
  const q = query.toLowerCase();
  const haystacks = [cmd.label, cmd.hint ?? '', ...(cmd.keywords ?? [])].map(
    (s) => s.toLowerCase(),
  );
  let best = -1;
  for (const h of haystacks) {
    if (h.startsWith(q)) return 100;
    const idx = h.indexOf(q);
    if (idx >= 0 && (best < 0 || idx < best)) best = idx;
  }
  if (best < 0) return -1;
  return 50 - best;
}

export function CommandPalette({
  open,
  onClose,
  commands,
  placeholder = 'Type a command or page...',
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [highlight, setHighlight] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const navigate = useNavigate();

  // Reset state on each open so the palette feels fresh and the highlight
  // doesn't stick to a now-filtered-out item.
  useEffect(() => {
    if (open) {
      setQuery('');
      setHighlight(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const filtered = useMemo(() => {
    if (!query) return commands;
    return commands
      .map((cmd) => [cmd, rank(query, cmd)] as const)
      .filter(([, r]) => r >= 0)
      .sort((a, b) => b[1] - a[1])
      .map(([cmd]) => cmd);
  }, [commands, query]);

  // Keep highlight inside the filtered range.
  useEffect(() => {
    if (highlight >= filtered.length) setHighlight(0);
  }, [filtered.length, highlight]);

  const run = useCallback(
    (cmd: PaletteCommand) => {
      onClose();
      if (cmd.action) cmd.action();
      else if (cmd.to) navigate(cmd.to);
    },
    [navigate, onClose],
  );

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLInputElement>) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
      } else if (event.key === 'ArrowDown') {
        event.preventDefault();
        setHighlight((h) => Math.min(h + 1, filtered.length - 1));
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        setHighlight((h) => Math.max(h - 1, 0));
      } else if (event.key === 'Enter') {
        event.preventDefault();
        const cmd = filtered[highlight];
        if (cmd) run(cmd);
      }
    },
    [filtered, highlight, onClose, run],
  );

  if (!open) return null;

  // Group while preserving filtered order.
  const groups = new Map<string, PaletteCommand[]>();
  for (const cmd of filtered) {
    const g = cmd.group ?? '';
    const arr = groups.get(g) ?? [];
    arr.push(cmd);
    groups.set(g, arr);
  }

  let runningIndex = 0;
  return (
    <div className="palette-overlay" role="dialog" aria-label="Command palette">
      <div className="palette-backdrop" onClick={onClose} />
      <div className="palette" role="combobox" aria-expanded="true">
        <input
          ref={inputRef}
          className="palette-input"
          placeholder={placeholder}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
          aria-label="Command search"
          aria-autocomplete="list"
        />
        <ul className="palette-list" role="listbox">
          {filtered.length === 0 && (
            <li className="palette-empty">No matches</li>
          )}
          {Array.from(groups.entries()).map(([group, items]) => (
            <li key={group || '_'} className="palette-group">
              {group && <div className="palette-group-label">{group}</div>}
              <ul>
                {items.map((cmd) => {
                  const idx = runningIndex++;
                  const active = idx === highlight;
                  return (
                    <li
                      key={cmd.id}
                      role="option"
                      aria-selected={active}
                      className={`palette-item${active ? ' active' : ''}`}
                      onMouseEnter={() => setHighlight(idx)}
                      onClick={() => run(cmd)}
                    >
                      {cmd.icon && (
                        <span className="palette-icon">{cmd.icon}</span>
                      )}
                      <span className="palette-label">{cmd.label}</span>
                      {cmd.hint && (
                        <span className="palette-hint">{cmd.hint}</span>
                      )}
                      {cmd.shortcut && (
                        <kbd className="palette-shortcut">{cmd.shortcut}</kbd>
                      )}
                    </li>
                  );
                })}
              </ul>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
