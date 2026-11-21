// A logged and ignored error followed by calls whose arguments are all
// literals.  Nothing from the failed call, or from anywhere else, reaches
// the sink, so `cfg-error-fallthrough` has nothing to report.
package main

import (
	"database/sql"
	"log"
	"os"
	"os/exec"
)

func initSchema(db *sql.DB) {
	_, err := os.Stat("/var/lib/app")
	if err != nil {
		log.Println("state dir:", err)
	}
	db.Exec("CREATE INDEX IF NOT EXISTS jobs_id ON jobs (id)")
}

func flush(path string) {
	if err := os.Remove(path); err != nil {
		log.Println(err)
	}
	exec.Command("sync").Run()
}
