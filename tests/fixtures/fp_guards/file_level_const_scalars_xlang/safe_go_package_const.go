// Package-level scalar constant flows into a db.Exec sink. The argument
// resolves to a `const DriverName = "postgres"` declaration at file scope,
// so the SQL string is compile-time bounded and cfg-unguarded-sink must
// not fire.
package main

import (
	"database/sql"
)

const DriverName = "postgres"
const QueryLimit = 100

func setup(db *sql.DB) {
	db.Exec(DriverName)
}
