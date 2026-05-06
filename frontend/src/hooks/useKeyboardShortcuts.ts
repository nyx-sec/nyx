import { useEffect } from 'react';

export interface Shortcut {
  /** Key string per `KeyboardEvent.key` (e.g. "k", "/", "Escape"). */
  key: string;
  /** Require Cmd/Ctrl (matches the same on each OS). */
  meta?: boolean;
  /** Require Shift. */
  shift?: boolean;
  /** Require Alt. */
  alt?: boolean;
  description: string;
  handler: (event: KeyboardEvent) => void;
  /**
   * If true, the shortcut still fires when focus is in an input/textarea/
   * contenteditable. Default is false, so shortcuts should not hijack typing.
   */
  allowInInput?: boolean;
}

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (target.isContentEditable) return true;
  return false;
}

function matches(event: KeyboardEvent, shortcut: Shortcut): boolean {
  if (event.key !== shortcut.key) return false;
  const wantMeta = !!shortcut.meta;
  const hasMeta = event.metaKey || event.ctrlKey;
  if (wantMeta !== hasMeta) return false;
  if (!!shortcut.shift !== event.shiftKey) return false;
  if (!!shortcut.alt !== event.altKey) return false;
  return true;
}

/**
 * Register a list of keyboard shortcuts at the document level.
 *
 * Pass a stable array (memoize or hoist outside the component) to avoid
 * unnecessary re-binding. Shortcuts with `meta: true` match either Cmd or
 * Ctrl so the same binding works on macOS and Linux/Windows.
 */
export function useKeyboardShortcuts(shortcuts: Shortcut[]) {
  useEffect(() => {
    if (shortcuts.length === 0) return;
    const onKeyDown = (event: KeyboardEvent) => {
      const typing = isTypingTarget(event.target);
      for (const sc of shortcuts) {
        if (typing && !sc.allowInInput) continue;
        if (matches(event, sc)) {
          event.preventDefault();
          sc.handler(event);
          return;
        }
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [shortcuts]);
}
