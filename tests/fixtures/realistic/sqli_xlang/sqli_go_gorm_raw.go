// Phase 15 — Go GORM `db.Raw(sql)` interpolation SQLi positive.
// `gorm.Open(...)` tags `db` as `TypeKind::GormDb`; type-qualified
// resolution rewrites `db.Raw(...)` → `GormDb.Raw`, which is a flat
// SQL_QUERY sink in `labels/go.rs`.  `fmt.Sprintf` interpolates the
// user-controlled value into the SQL string with no parameterisation.
package main

import (
	"fmt"
	"net/http"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func lookup(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db, _ := gorm.Open(postgres.Open("dbname=app"), &gorm.Config{})
	sqlStr := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	db.Raw(sqlStr)
}
