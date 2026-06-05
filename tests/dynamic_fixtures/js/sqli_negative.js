// SQL injection — negative fixture.
// Safe: uses a parameterized query pattern; payload never concatenated.
// Entry: login(username)  Cap: SQL_QUERY
// Expected verdict: NotConfirmed

function login(username) {
    // Parameterized: the query template is fixed, payload is a bound param.
    const template = 'SELECT name FROM users WHERE name = ?';
    // Simulate param binding — payload is never embedded in the query string.
    const safeQuery = template; // template unchanged regardless of username
    process.stdout.write('Query executed with param: ' + safeQuery + '\n');
}

module.exports = { login };
