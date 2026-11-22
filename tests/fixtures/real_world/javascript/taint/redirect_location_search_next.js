function go() {
  const next = new URLSearchParams(window.location.search).get('next');
  window.location.assign(next);
}
