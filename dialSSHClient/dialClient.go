package connect

import (
	"fmt"
	"github.com/go-ping/ping"
	"golang.org/x/crypto/ssh"
	"log"
	"strings"
	"time"
)

var sshConnectTimeout = 2
var config *ssh.ClientConfig

// Set custom timeout value for an ssh connection. Default is 2 seconds.
func SetTimeout(seconds int) {
	sshConnectTimeout = seconds
}

// Sets up the config for an SSH connection. Default Timeout is 2 seconds.
// You can optionally provide a privatekey using "" double quotes for the unused variable.
func Init(username string, password string, privatekey string) {
	config = &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		//Might need to play with this. Default timeout is something insane like 10 seconds. I thought the program froze.
		Timeout: time.Duration(sshConnectTimeout) * time.Second,
		/*
			//not needed currently, but good code to keep
			Config: ssh.Config{
				Ciphers: []string{"aes128-ctr", "hmac-sha2-256"},
			},
		*/
	}
	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	if privatekey != "" {
		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey([]byte(privatekey))
		if err != nil {
			log.Printf("unable to parse private key: %v", err)
		}
		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	} else {
		config.Auth = []ssh.AuthMethod{
			ssh.Password(password),
		}
	}
}

// Uses ssh.Dial() to connect to hosts and sort through error responses. You must Init() the config before dialing.
func DialClient(host string) (*ssh.Client, error) {
	// Connect to the remote host
	// Requires defined port number
	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		if strings.Contains(err.Error(),
			`connectex: A connection attempt failed because the connected party did not properly respond after a period of time`) ||
			strings.Contains(err.Error(), `i/o timeout`) {
			return nil, fmt.Errorf("Unable to connect: SSH attempt Timed Out.")
		}
		//Confusing errors. If it's exhausted all authentication methods it's probably a bad password.
		//We don't want to gather the progress here, because this error gets reused in the return.
		if strings.Contains(err.Error(), "unable to authenticate, attempted methods [none password]") {
			return nil, fmt.Errorf("Unable to connect: Authentication Failed")
		} else {
			return nil, fmt.Errorf("Unable to connect: %s", err)
		}
	}

	return client, nil
}

func UpdateUser(username string) {
	config.User = username
}

func UpdatePass(password string) {
	config.Auth = []ssh.AuthMethod{
		ssh.Password(password),
	}
}

func UpdateKey(privatekey string) {
	signer, err := ssh.ParsePrivateKey([]byte(privatekey))
	if err != nil {
		log.Printf("unable to parse private key: %v", err)
	}
	config.Auth = []ssh.AuthMethod{
		ssh.PublicKeys(signer),
	}
}
func IsAlive(host string, count int, timeout int) (*ping.Statistics, error) {
	if host == "" {
		return nil, fmt.Errorf("IP Address cannot be empty")
	}
	pinger, err := ping.NewPinger(host)
	if err != nil {
		return nil, fmt.Errorf("Pings not working: %s", err)
	}
	pinger.Count = count
	pinger.SetPrivileged(true)
	pinger.Timeout = time.Duration(timeout) * time.Millisecond //times out after 500 milliseconds
	pinger.Run()                                               // blocks until finished
	return pinger.Statistics(), nil
}
