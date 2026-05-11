// Phase 15 — Go GORM `userDb.Raw(sql)` SQLi positive with non-`db`
// receiver name.  Pre-fix: the CFG-side receiver extraction handled
// JS/TS `member_expression`, Python `attribute`, and Rust
// `field_expression` shapes but missed Go's `selector_expression`,
// so `userDb.Raw(...)` lowered to an `SsaOp::Call` with
// `receiver: None`.  Without a receiver SSA value, type-qualified
// resolution had no anchor and could not rewrite `userDb.Raw` →
// `GormDb.Raw`; the flat `db.Raw` matcher missed too because the
// callee text is literally `userDb.Raw`.  Post-fix, the CFG-side
// `Kind::CallFn` arm extracts the receiver from the
// `selector_expression.operand` field, so type-qualified resolution
// can lift the `gorm.Open(...)` → `GormDb` type tag and match the
// existing `GormDb.Raw` label rule.
package main

import (
	"fmt"
	"net/http"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func lookupNamedReceiver(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	userDb, _ := gorm.Open(postgres.Open("dbname=app"), &gorm.Config{})
	sqlStr := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	userDb.Raw(sqlStr)
}
