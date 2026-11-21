package main

import (
	"errors"
	"net/http"
	"strings"
)

type adminHandler struct{ mux *http.ServeMux }

type AdminHandlerFunc func(http.ResponseWriter, *http.Request) error

func (f AdminHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type APIError struct {
	Err        error
	Message    string
	HTTPStatus int
}

func (e APIError) Error() string {
	if e.Err != nil {
		return "x"
	}
	return e.Message
}

var errInternalRedir = errors.New("redir")

func (h adminHandler) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Upgrade"), "websocket") {
		h.handleError(w, r, APIError{HTTPStatus: 400, Err: errors.New("ws"), Message: "no"})
	}
	h.mux.ServeHTTP(w, r)
}

func (h adminHandler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	if err == errInternalRedir {
		h.serveHTTP(w, r)
	}
	apiErr, ok := err.(APIError)
	if !ok {
		return
	}
	if apiErr.Message == "" && apiErr.Err != nil {
		apiErr.Message = apiErr.Err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
}
