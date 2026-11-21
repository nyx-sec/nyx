// A helper whose formal is named `r` but is not a request.  The name alone
// is not user-input evidence.  Pinned in
// `auth_analysis_tests::go_non_request_param_named_r_does_not_flag`.
package api

import (
	"bufio"

	"example.com/store"
)

func purgeFromJournal(r *bufio.Reader) {
	docID, _ := r.ReadString('\n')
	store.DB.DeleteDocument(docID)
}
