function g1() {
  const el = document.getElementById('a');
  el.innerHTML = location.search;
}
function g2() {
  document.getElementById('a').innerHTML = location.search;
}
function g5() {
  const el = document.getElementById('a');
  el.innerHTML = '<b>' + location.hash + '</b>';
}
function h5() {
  window.location.href = location.hash.substring(1);
}
function s1() {
  const el = document.getElementById('a');
  el.innerHTML = DOMPurify.sanitize(location.hash);
}
function s2() {
  const el = document.getElementById('a');
  el.textContent = location.hash;
}
g1(); g2(); g5(); h5(); s1(); s2();
