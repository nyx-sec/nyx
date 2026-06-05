import {
  createContext,
  useContext,
  useEffect,
  useState,
  useRef,
  useCallback,
  type ReactNode,
} from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { TimingBreakdown } from '../api/types';

export interface ScanProgress {
  job_id: string;
  stage: string;
  files_discovered: number;
  files_parsed: number;
  files_analyzed: number;
  files_skipped: number;
  batches_total: number;
  batches_completed: number;
  dynamic_enabled?: boolean;
  dynamic_total: number;
  dynamic_completed: number;
  current_file: string;
  elapsed_ms: number;
  timing: TimingBreakdown;
}

interface SSEState {
  scanProgress: ScanProgress | null;
  isScanRunning: boolean;
}

const SSEContext = createContext<SSEState>({
  scanProgress: null,
  isScanRunning: false,
});

export function useSSE() {
  return useContext(SSEContext);
}

export function SSEProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [isScanRunning, setIsScanRunning] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(
    undefined,
  );

  const connect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
    }

    const es = new EventSource('/api/events');
    esRef.current = es;

    es.addEventListener('scan_started', () => {
      setIsScanRunning(true);
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['targets'] });
    });

    es.addEventListener('scan_progress', (e) => {
      try {
        const data = JSON.parse(e.data);
        setScanProgress(data.data ?? data);
      } catch {
        /* ignore parse errors */
      }
    });

    es.addEventListener('scan_completed', () => {
      setScanProgress(null);
      setIsScanRunning(false);
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['overview'] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['targets'] });
    });

    es.addEventListener('scan_failed', () => {
      setScanProgress(null);
      setIsScanRunning(false);
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['targets'] });
    });

    es.addEventListener('config_changed', () => {
      queryClient.invalidateQueries({ queryKey: ['config'] });
      queryClient.invalidateQueries({ queryKey: ['rules'] });
    });

    es.onerror = () => {
      es.close();
      esRef.current = null;
      reconnectTimer.current = setTimeout(connect, 3000);
    };
  }, [queryClient]);

  useEffect(() => {
    connect();
    return () => {
      if (esRef.current) esRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [connect]);

  return (
    <SSEContext.Provider value={{ scanProgress, isScanRunning }}>
      {children}
    </SSEContext.Provider>
  );
}
