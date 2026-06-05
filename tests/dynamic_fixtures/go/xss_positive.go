// XSS — positive fixture.
// Vulnerable: echoes raw user input into HTML output without escaping.
// Entry: RenderPage(userInput string)  Cap: HTML_ESCAPE
// Expected verdict: Confirmed (<script>NYX_XSS_CONFIRMED</script> echoed)

package entry

import "fmt"

func RenderPage(userInput string) {
	fmt.Print("__NYX_SINK_HIT__\n")
	fmt.Print("<html><body>" + userInput + "</body></html>\n")
}
