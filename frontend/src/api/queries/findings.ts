import { useQuery, type QueryClient } from '@tanstack/react-query';
import { apiGet } from '../client';
import type { PaginatedFindings, FindingView, FilterValues } from '../types';

export interface FindingsParams {
  page?: number;
  per_page?: number;
  severity?: string;
  category?: string;
  confidence?: string;
  language?: string;
  rule_id?: string;
  status?: string;
  verification?: string;
  search?: string;
  sort_by?: string;
  sort_dir?: string;
}

function buildQuery(params: FindingsParams): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null && v !== '',
  );
  if (entries.length === 0) return '';
  const qs = new URLSearchParams(
    entries.map(([k, v]) => [k, String(v)]),
  ).toString();
  return `?${qs}`;
}

export function useFindings(params: FindingsParams = {}) {
  return useQuery({
    queryKey: ['findings', params],
    queryFn: ({ signal }) =>
      apiGet<PaginatedFindings>(`/findings${buildQuery(params)}`, signal),
  });
}

export function useFinding(id: number | string) {
  return useQuery({
    queryKey: ['findings', id],
    queryFn: ({ signal }) => apiGet<FindingView>(`/findings/${id}`, signal),
    enabled: id !== undefined && id !== null && id !== '',
  });
}

export function fetchFindingDetail(
  qc: QueryClient,
  index: number,
  signal?: AbortSignal,
): Promise<FindingView> {
  return qc.fetchQuery({
    queryKey: ['findings', String(index)],
    queryFn: ({ signal: s }) =>
      apiGet<FindingView>(`/findings/${index}`, s ?? signal),
  });
}

export function useFindingFilters() {
  return useQuery({
    queryKey: ['findings', 'filters'],
    queryFn: ({ signal }) => apiGet<FilterValues>('/findings/filters', signal),
  });
}
