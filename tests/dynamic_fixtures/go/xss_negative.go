// XSS — negative fixture.
// Safe: uses html.EscapeString before output.
// Entry: RenderPage(userInput string)  Cap: HTML_ESCAPE
// Expected verdict: NotConfirmed

package entry

import (
	"fmt"
	"html"
)

func RenderPage(userInput string) {
	safe := html.EscapeString(userInput)
	fmt.Print("<html><body>" + safe + "</body></html>\n")
}
