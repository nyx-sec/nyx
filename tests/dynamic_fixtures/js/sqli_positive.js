// SQL injection — positive fixture.
// Vulnerable: directly concatenates user input into SQL query string.
// Entry: login(username)  Cap: SQL_QUERY
// Expected verdict: Confirmed (UNION payload echoes NYX_SQL_CONFIRMED)

function login(username) {
    const query = "SELECT name FROM users WHERE name='" + username + "'";
    process.stdout.write('__NYX_SINK_HIT__\n');
    // Simulate error-based SQL execution: echo query on failure.
    process.stdout.write('DB query: ' + query + '\n');
}

module.exports = { login };
