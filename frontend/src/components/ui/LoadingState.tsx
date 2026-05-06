interface LoadingStateProps {
  message?: string;
  /**
   * Suppresses the spinner for the first ~150ms so trivially-fast queries
   * don't flash a spinner on screen. The text shows instantly so there's
   * always something, but the visible spin only kicks in if work is
   * actually slow.
   */
  delaySpinnerMs?: number;
}

export function LoadingState({ message = 'Loading...' }: LoadingStateProps) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span className="loading-message">{message}</span>
    </div>
  );
}
