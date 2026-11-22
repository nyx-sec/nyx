function reset() {
  window.location.assign(window.location.origin + '/login');
}

function support() {
  const home = window.location.protocol + '//' + window.location.host + '/support';
  window.location.replace(home + '?x=1');
}
