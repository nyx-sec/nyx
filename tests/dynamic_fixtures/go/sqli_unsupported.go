// SQL injection — unsupported fixture.
// Entry is a method on a struct — entry kind unsupported (only Function supported).
// Test sets confidence = Low to get Unsupported(ConfidenceTooLow).
// Entry: UserRepo.FindUser  Cap: SQL_QUERY
// Expected verdict: Unsupported

package entry

import "fmt"

type UserRepo struct{}

func (r *UserRepo) FindUser(name string) {
	query := "SELECT * FROM users WHERE name='" + name + "'"
	fmt.Println(query)
}
