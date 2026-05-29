import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiDelete, apiGet, apiPost } from '../client';
import type { TargetView } from '../types';

export function useTargets() {
  return useQuery({
    queryKey: ['targets'],
    queryFn: ({ signal }) => apiGet<TargetView[]>('/targets', signal),
  });
}

export function useAddTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { path: string }) => apiPost<TargetView>('/targets', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] });
    },
  });
}

export function useSelectTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { id?: string; path?: string }) =>
      apiPost<TargetView>('/targets/select', body),
    onSuccess: () => {
      qc.invalidateQueries();
    },
  });
}

export function useDeleteTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiDelete<void>(`/targets/${encodeURIComponent(id)}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] });
    },
  });
}
