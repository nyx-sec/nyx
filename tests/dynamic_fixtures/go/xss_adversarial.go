// XSS — adversarial collision fixture.
// Prints the XSS oracle marker unconditionally without rendering any template
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: RenderPage(userInput string)  Cap: HTML_ESCAPE

package entry

import "fmt"

func RenderPage(userInput string) {
	// Coincidental oracle match — not an HTML render sink.
	fmt.Println("<script>NYX_XSS_CONFIRMED</script>")
	_ = len(userInput)
}
