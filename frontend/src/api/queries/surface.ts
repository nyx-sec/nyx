import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../client';
import type { SurfaceMap } from '../types';

export function useSurfaceMap() {
  return useQuery({
    queryKey: ['surface'],
    queryFn: ({ signal }) => apiGet<SurfaceMap>('/surface', signal),
    staleTime: 30_000,
  });
}
