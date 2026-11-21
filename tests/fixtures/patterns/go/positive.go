package main

import (
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/gob"
	"os"
	"os/exec"
	"golang.org/x/sys/execabs"
	"unsafe"
)

// go.cmdi.exec_command
func triggerExecCommand(cmd string) {
	exec.Command("bash", "-c", cmd)
}

// go.cmdi.exec_command through the hardened os/exec replacement
func triggerExecabsCommand(cmd string) {
	execabs.Command("bash", "-c", cmd)
}

// go.memory.unsafe_pointer
func triggerUnsafePointer() {
	x := 42
	p := unsafe.Pointer(&x)
	_ = p
}

// go.transport.insecure_skip_verify
func triggerInsecureSkipVerify() {
	_ = struct{ InsecureSkipVerify bool }{InsecureSkipVerify: true}
}

// go.crypto.md5
func triggerMD5(data []byte) {
	md5.Sum(data)
}

// go.crypto.sha1
func triggerSHA1(data []byte) {
	sha1.Sum(data)
}

// go.sqli.query_concat
func triggerSQLConcat(db *sql.DB, user string) {
	db.Query("SELECT * FROM users WHERE name = '" + user + "'")
}

// go.secrets.hardcoded_key
func triggerHardcodedSecret() {
	password := "super_secret_password_12345"
	_ = password
}

// go.deser.gob_decode
func triggerGobDecode(f *os.File) {
	dec := gob.NewDecoder(f)
	_ = dec
}
