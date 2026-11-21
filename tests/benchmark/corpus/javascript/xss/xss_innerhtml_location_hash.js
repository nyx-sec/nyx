// DOM XSS: a member source written straight to an assignment sink.
function showGreeting() {
    const el = document.getElementById('greeting');
    el.innerHTML = '<b>' + location.hash.slice(1) + '</b>';
}

showGreeting();
