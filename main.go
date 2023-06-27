package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"log"
	"os"
	"strings"
	"syscall"
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

func (cmd CMD) GetCredentialsFromFiles() bool {
	viper.AddConfigPath(".")
	viper.SetConfigName("key") // Register config file name (no extension)
	viper.SetConfigType("yml") // Look for specific type
	var err = viper.ReadInConfig()
	//CheckError(err)
	if err != nil {
		return false
	}
	appCode = viper.GetString("helper.key")

	viper.SetConfigName("helper") // Change file and reread contents.
	err = viper.ReadInConfig()
	CheckError(err)

	cmd.username = passBall(viper.GetString("helper.username"))
	cmd.password = passBall(viper.GetString("helper.password"))
	//FSApplianceFQDN = viper.GetString("helper.url")
	return true
}

// SSHConnect : Run command against a host, using
func (cmd CMD) SSHConnect(command string, host string) error {
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
	client, err := ssh.Dial("tcp", host, config)
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
	err = session.Run(fmt.Sprintf(`%s`, command))
	if err != nil {
		return err
	}
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var command CMD
	if !command.GetCredentialsFromFiles() {
		fmt.Println("Unable to read credentials from file.")
		command.username = StringPrompt("Username:")
		command.password = StringPrompt("Password:")
	}
	err := command.SSHConnect("hostname && cat /etc/os-release", "10.9.0.10")
	if err != nil {
		log.Println(err)
	}

}
