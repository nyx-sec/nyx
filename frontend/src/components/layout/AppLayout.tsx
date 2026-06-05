import { useCallback, useMemo, useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { HeaderBar } from './HeaderBar';
import { NewScanModal } from '../../modals/NewScanModal';
import { CommandPalette, type PaletteCommand } from '../ui/CommandPalette';
import { ShortcutsHelp } from '../ui/ShortcutsHelp';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';
import { useChordNavigation } from '../../hooks/useChordNavigation';
import { OverviewPage } from '../../pages/OverviewPage';
import { FindingsPage } from '../../pages/FindingsPage';
import { FindingDetailPage } from '../../pages/FindingDetailPage';
import { ScansPage } from '../../pages/ScansPage';
import { ScanDetailPage } from '../../pages/ScanDetailPage';
import { ScanComparePage } from '../../pages/ScanComparePage';
import { RulesPage } from '../../pages/RulesPage';
import { TriagePage } from '../../pages/TriagePage';
import { ConfigPage } from '../../pages/ConfigPage';
import { ExplorerPage } from '../../pages/ExplorerPage';
import { SurfacePage } from '../../pages/SurfacePage';
import { DebugLayout } from '../../pages/debug/DebugLayout';
import { CallGraphPage } from '../../pages/debug/CallGraphPage';
import { SummaryExplorerPage } from '../../pages/debug/SummaryExplorerPage';

export function AppLayout() {
  const [scanModalOpen, setScanModalOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  const handleStartScan = useCallback(() => {
    setScanModalOpen(true);
  }, []);

  const commands = useMemo<PaletteCommand[]>(
    () => [
      // Navigation
      { id: 'go-overview', group: 'Navigate', label: 'Overview', to: '/' },
      {
        id: 'go-findings',
        group: 'Navigate',
        label: 'Findings',
        to: '/findings',
      },
      { id: 'go-scans', group: 'Navigate', label: 'Scans', to: '/scans' },
      { id: 'go-rules', group: 'Navigate', label: 'Rules', to: '/rules' },
      { id: 'go-triage', group: 'Navigate', label: 'Triage', to: '/triage' },
      { id: 'go-config', group: 'Navigate', label: 'Config', to: '/config' },
      {
        id: 'go-explorer',
        group: 'Navigate',
        label: 'Explorer',
        to: '/explorer',
      },
      {
        id: 'go-surface',
        group: 'Navigate',
        label: 'Attack surface',
        to: '/surface',
      },
      {
        id: 'go-debug-cg',
        group: 'Navigate',
        label: 'Call Graph',
        hint: 'Debug',
        to: '/debug/call-graph',
      },
      {
        id: 'go-debug-summaries',
        group: 'Navigate',
        label: 'Summary Explorer',
        hint: 'Debug',
        to: '/debug/summaries',
      },
      // Actions
      {
        id: 'start-scan',
        group: 'Actions',
        label: 'Start new scan',
        keywords: ['scan', 'run'],
        action: () => setScanModalOpen(true),
      },
      {
        id: 'show-shortcuts',
        group: 'Actions',
        label: 'Show keyboard shortcuts',
        keywords: ['help', 'keys'],
        shortcut: '?',
        action: () => setHelpOpen(true),
      },
    ],
    [],
  );

  useChordNavigation();

  const shortcuts = useMemo(
    () => [
      {
        key: 'k',
        meta: true,
        description: 'Open command palette',
        handler: () => setPaletteOpen(true),
        allowInInput: true,
      },
      {
        key: '?',
        shift: true,
        description: 'Show keyboard shortcuts',
        handler: () => setHelpOpen(true),
      },
      {
        key: 'Escape',
        description: 'Close modal / palette',
        handler: () => {
          if (paletteOpen) setPaletteOpen(false);
          else if (helpOpen) setHelpOpen(false);
          else if (scanModalOpen) setScanModalOpen(false);
        },
        allowInInput: true,
      },
    ],
    [paletteOpen, helpOpen, scanModalOpen],
  );

  useKeyboardShortcuts(shortcuts);

  return (
    <div id="app">
      <Sidebar />
      <div className="main-panel">
        <HeaderBar
          onStartScan={handleStartScan}
          onOpenPalette={() => setPaletteOpen(true)}
        />
        <main className="content">
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/findings/:id" element={<FindingDetailPage />} />
            <Route path="/scans" element={<ScansPage />} />
            <Route
              path="/scans/compare/:left/:right"
              element={<ScanComparePage />}
            />
            <Route path="/scans/:id" element={<ScanDetailPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/rules/:id" element={<RulesPage />} />
            <Route path="/triage" element={<TriagePage />} />
            <Route path="/config" element={<ConfigPage />} />
            <Route path="/explorer" element={<ExplorerPage />} />
            <Route path="/surface" element={<SurfacePage />} />
            <Route path="/debug" element={<DebugLayout />}>
              <Route
                index
                element={<Navigate to="/debug/call-graph" replace />}
              />
              <Route path="call-graph" element={<CallGraphPage />} />
              <Route path="summaries" element={<SummaryExplorerPage />} />
              <Route
                path="auth"
                element={<Navigate to="/explorer?view=auth" replace />}
              />
            </Route>
          </Routes>
        </main>
      </div>
      <NewScanModal
        open={scanModalOpen}
        onClose={() => setScanModalOpen(false)}
      />
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        commands={commands}
      />
      <ShortcutsHelp open={helpOpen} onClose={() => setHelpOpen(false)} />
    </div>
  );
}
