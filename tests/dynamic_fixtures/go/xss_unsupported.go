// XSS — unsupported fixture.
// Entry is a method on a struct; test sets confidence = Low.
// Expected verdict: Unsupported

package entry

import "fmt"

type Renderer struct{}

func (r *Renderer) Render(input string) {
	fmt.Print("<html><body>" + input + "</body></html>\n")
}
