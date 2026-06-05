import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { CheckIcon } from '../icons/Icons';

interface DropdownProps {
  trigger: (opts: { open: boolean }) => ReactNode;
  children: (opts: { close: () => void }) => ReactNode;
  align?: 'left' | 'right';
  className?: string;
}

export function Dropdown({
  trigger,
  children,
  align = 'left',
  className,
}: DropdownProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  const close = useCallback(() => setOpen(false), []);

  useEffect(() => {
    if (!open) return;

    const handlePointer = (e: MouseEvent) => {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };

    document.addEventListener('mousedown', handlePointer);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handlePointer);
      document.removeEventListener('keydown', handleKey);
    };
  }, [open]);

  return (
    <div
      ref={rootRef}
      className={`dropdown${open ? ' dropdown--open' : ''}${className ? ` ${className}` : ''}`}
    >
      <div
        className="dropdown-trigger"
        onClick={() => setOpen((v) => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen((v) => !v);
          }
        }}
      >
        {trigger({ open })}
      </div>
      {open && (
        <div className={`dropdown-menu dropdown-menu--${align}`} role="menu">
          {children({ close })}
        </div>
      )}
    </div>
  );
}

interface DropdownItemProps {
  onClick: () => void;
  children: ReactNode;
  checked?: boolean;
  hint?: string;
  tone?: 'default' | 'warning';
}

export function DropdownItem({
  onClick,
  children,
  checked,
  hint,
  tone = 'default',
}: DropdownItemProps) {
  return (
    <button
      type="button"
      role="menuitem"
      className={`dropdown-item dropdown-item--${tone}`}
      onClick={onClick}
    >
      <span className="dropdown-item-check" aria-hidden>
        {checked && <CheckIcon size={14} />}
      </span>
      <span className="dropdown-item-label">{children}</span>
      {hint && <span className="dropdown-item-hint">{hint}</span>}
    </button>
  );
}
