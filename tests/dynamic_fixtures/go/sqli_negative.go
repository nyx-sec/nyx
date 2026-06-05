// SQL injection — negative fixture.
// Safe: uses a parameterized query; payload is a bound argument, not concatenated.
// Entry: Login(username string)  Cap: SQL_QUERY
// Expected verdict: NotConfirmed

package entry

import "fmt"

func Login(username string) {
	template := "SELECT name FROM users WHERE name = ?"
	// Simulate parameterized execution: template is fixed.
	fmt.Println("Executing:", template, "with param length:", len(username))
}
