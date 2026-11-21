function go() {
  const id = new URLSearchParams(location.search).get('id');
  window.open('/reports/' + id);
  const next = new URLSearchParams(location.search).get('next');
  window.open(next);
}
go();
