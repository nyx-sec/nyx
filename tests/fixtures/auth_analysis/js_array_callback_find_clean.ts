// `find`, `findIndex` and `filter` with a function as the FIRST argument are
// the Array methods, not a data-layer read.  Pinned in `auth_analysis_tests`.
export function pickProvider(providers: Provider[], providerId: string) {
  return providers.find((p) => p.id === providerId);
}

export function indexOfDocument(documents: Doc[], documentId: string) {
  return documents.findIndex((d) => d.id === documentId);
}
