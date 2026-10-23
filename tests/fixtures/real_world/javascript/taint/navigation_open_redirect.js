function go() {
  const u = new URLSearchParams(location.search).get('next');
  window.open(u);
  location.assign(u);
  location.replace(u);
}
go();
