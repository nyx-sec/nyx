// go-vuln-realrepo-018 — recall guard for the inner-call-arg /
// member-LHS fixes.  Bare-identifier `f := os.OpenFile(...)` with no
// `f.Close()` anywhere must still fire the resource-leak rule.

package safe

import "os"

func vuln_open_no_close() error {
	f, err := os.OpenFile("/tmp/x", os.O_RDWR, 0o666)
	if err != nil {
		return err
	}
	_ = f
	return nil
}
