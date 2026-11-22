package models

import (
	"context"
	"net/http"

	"example.com/db"
)

func restore(ctx context.Context, reviewerID int64) error {
	if _, err := db.Exec(ctx, "UPDATE `review` SET official=? WHERE id=?", true, reviewerID); err != nil {
		return err
	}
	return nil
}

func clear(ctx context.Context, repoID int64) error {
	if _, err := db.Exec(ctx, "UPDATE `repository` SET num_watches = 0 WHERE id = ?", repoID); err != nil {
		return err
	}
	return nil
}

func fromRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.FormValue("id")
	_, _ = db.Exec(ctx, "DELETE FROM sessions WHERE id = ?", id)
}

func background(id string) error {
	_, err := db.Exec(context.Background(), "DELETE FROM sessions WHERE id = ?", id)
	return err
}
