// SQL injection — positive fixture.
// Vulnerable: directly concatenates user input into SQL query string.
// Entry: Login(username string)  Cap: SQL_QUERY
// Expected verdict: Confirmed (UNION payload echoes NYX_SQL_CONFIRMED)

package entry

import "fmt"

func Login(username string) {
	query := "SELECT name FROM users WHERE name='" + username + "'"
	fmt.Print("__NYX_SINK_HIT__\n")
	// Error-based echo: output the query so UNION payload is visible.
	fmt.Print("DB query: " + query + "\n")
}
