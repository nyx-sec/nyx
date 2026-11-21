package ssh

import (
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	log "unknwon.dev/clog/v2"

	"gogs.io/gogs/internal/conf"
)

func handleServerConn(keyID string, chans <-chan ssh.NewChannel) {
	for newChan := range chans {
		ch, reqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go func(in <-chan *ssh.Request) {
			for req := range in {
				payload := string(req.Payload)
				switch req.Type {
				case "exec":
					cmdName := strings.TrimLeft(payload, "'()")
					args := []string{"serv", "key-" + keyID, "--config=" + conf.CustomConf}
					cmd := exec.Command(conf.AppPath(), args...)
					cmd.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+cmdName)
					stdout, err := cmd.StdoutPipe()
					if err != nil {
						return
					}
					input, err := cmd.StdinPipe()
					if err != nil {
						return
					}
					if err = cmd.Start(); err != nil {
						return
					}
					_ = req.Reply(true, nil)
					go func() {
						_, _ = io.Copy(input, ch)
						input.Close()
					}()
					_, _ = io.Copy(ch, stdout)
					if err = cmd.Wait(); err != nil {
						return
					}
					return
				default:
				}
			}
		}(reqs)
	}
}

func listen(config *ssh.ServerConfig, host string, port int) {
	listener, err := net.Listen("tcp", host+":"+strconv.Itoa(port))
	if err != nil {
		log.Fatal("Failed to start SSH server: %v", err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func() {
			sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			go handleServerConn(sConn.Permissions.Extensions["key-id"], chans)
		}()
	}
}

func Listen(opts conf.SSHOpts, appDataPath string) {
	config := &ssh.ServerConfig{}
	go listen(config, opts.ListenHost, opts.ListenPort)
}
