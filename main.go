package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type CMD struct {
	username   string
	password   string
	privatekey string
}

// encryption key used to decrypt helper.yml
// create 'helper.key' file to store appCode. Copy below code format for yml
// helper:
//
//	key: 'fasdfasdfasdfasdf'
var appCode string

// This function is used to pass encrypted credentials.
// Don't forget to update the appCode with a new 32 bit string per application.
func passBall(ct string) string {
	var plaintext []byte
	ciphertext, _ := hex.DecodeString(ct)
	c, err := aes.NewCipher([]byte(appCode))
	CheckError(err)

	gcm, err := cipher.NewGCM(c)
	CheckError(err)

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err = gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	CheckError(err)

	return string(plaintext)
}

// CheckError : default error checker. Built in if statement.
func CheckError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func StringPrompt(label string) string {
	var s string
	r := bufio.NewReader(os.Stdin)
	_, err := fmt.Fprint(os.Stderr, fmt.Sprintf("%s ", label))
	if err != nil {
		log.Fatal(err)
	}
	if label == "Password:" {
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
		s = string(bytePassword)
	} else {
		for {
			s, _ = r.ReadString('\n')
			if s != "" {
				break
			}
		}
	}
	return strings.TrimSpace(s)
}

func (cmd *CMD) GetCredentialsFromFiles() bool {
	viper.AddConfigPath(".")
	viper.SetConfigName("key") // Register config file name (no extension)
	viper.SetConfigType("yml") // Look for specific type
	var err = viper.ReadInConfig()
	CheckError(err)
	appCode = viper.GetString("helper.key")

	viper.SetConfigName("helper") // Change file and reread contents.
	err = viper.ReadInConfig()
	CheckError(err)

	cmd.username = passBall(viper.GetString("helper.username"))
	cmd.password = passBall(viper.GetString("helper.password"))
	return true
}

// SSHConnect : Run command against a host, using
func (cmd *CMD) SSHConnect(command string, host string) error {
	config := &ssh.ClientConfig{
		User:            cmd.username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	if cmd.privatekey != "" {
		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey([]byte(cmd.privatekey))
		if err != nil {
			return fmt.Errorf("unable to parse private key: %v", err)
		}
		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	} else {
		config.Auth = []ssh.AuthMethod{
			ssh.Password(cmd.password),
		}
	}

	// Connect to the remote host
	// Requires defined port number
	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		return fmt.Errorf("Failed to dial - unable to connect: %s", err)
	}
	defer client.Close()

	// Open a session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("Failed to create session: %s", err)
	}
	defer session.Close()
	out, err := session.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	err = session.Run(command)
	if err != nil {
		return err
	}
	value, err := ioutil.ReadAll(out)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(value))

	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var command CMD
	var deviceIP, userScript string
	command.GetCredentialsFromFiles()

	fmt.Print("Device IP to connect: ")
	fmt.Scan(&deviceIP)

	fmt.Print("Command to run: ")
	fmt.Scan(&userScript)
	err := command.SSHConnect(userScript, deviceIP)
	if err != nil {
		log.Println(err)
	}

}
