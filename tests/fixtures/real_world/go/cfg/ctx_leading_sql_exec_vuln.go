package models

import (
	"context"
	"net/http"

	"example.com/db"
)

func del(ctx context.Context, r *http.Request) error {
	name := r.FormValue("n")
	_, err := db.Exec(ctx, "DELETE FROM t WHERE n = '"+name+"'")
	return err
}

func delBackground(r *http.Request) error {
	name := r.FormValue("n")
	_, err := db.Exec(context.Background(), "DELETE FROM t WHERE n = '"+name+"'")
	return err
}
