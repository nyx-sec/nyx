// go-safe-realrepo-016 — distilled from prometheus tsdb/block_test.go:185
// and 9+ other prometheus test files.  Pattern: a wrapper call takes
// the close call's RESULT as an argument, e.g.
//
//     require.NoError(t, f.Close())
//     errs = append(errs, f.Close())
//
// The CFG creates one Call node per statement keyed on the OUTER
// callee.  The inner-call release was invisible to the resource pass
// before the fix: direct-release loop matches `info.call.callee`
// (the outer callee), and the inner-call callee was carried in
// `info.arg_callees[i]` but unread.  Engine fix:
// src/state/transfer.rs::apply_call now walks `info.arg_callees`
// after the direct-release branch.

package safe

import (
	"errors"
	"os"
)

type tHelper struct{}

func (tHelper) NoError(args ...any) {}

var t tHelper

func close_in_require_noerror() error {
	f, err := os.OpenFile("/tmp/x", os.O_RDWR, 0o666)
	if err != nil {
		return err
	}
	t.NoError(f.Close())
	return nil
}

func close_in_append_arg() error {
	f, err := os.Create("/tmp/y")
	if err != nil {
		return err
	}
	var errs []error
	errs = append(errs, f.Close())
	return errors.Join(errs...)
}

func close_via_defer() error {
	f, err := os.Open("/tmp/z")
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}
