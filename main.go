package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-ping/ping"
	"github.com/spf13/viper"
	"github.com/zenthangplus/goccm"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type CMD struct {
	username   string
	useralt    string
	password   string
	passalt    string
	privatekey string
}

// encryption key used to decrypt helper.yml
// create 'helper.key' file to store appCode. Copy below code format for yml
// helper:
//
//	key: 'fasdfasdfasdfasdf'
var appCode string

// passBall : This function is used to pass encrypted credentials.
// Don't forget to update the appCode with a new 32 bit string per application.
func passBall(ct string) string {
	var plaintext []byte
	ciphertext, _ := hex.DecodeString(ct)
	c, err := aes.NewCipher([]byte(appCode))
	if err != nil {
		log.Fatal("Failed to import decryption key.")
	}

	gcm, err := cipher.NewGCM(c)
	CheckError(err)

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err = gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		log.Fatal("Failed to decrypt text. Check encryption key or redo access encryption.")
	}

	return string(plaintext)
}

// CheckError : default error checker. Built in if statement.
func CheckError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// StringPrompt : Prompts for user input, and securely prompts for password if "Password:" is the given label.
// Required for passwords as it's grabbing the Stdin and processing. Can't use ReadPassword standalone
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

// promptList : Prompt for user input and return array of string. Each line is its own string.
func promptList(promptString string) []string {
	fmt.Println("\n" + promptString)
	scanner := bufio.NewScanner(os.Stdin)

	var lines []string
	for {
		scanner.Scan()
		line := scanner.Text()

		// break the loop if line is empty
		if len(line) == 0 {
			break
		}
		lines = append(lines, line)
	}

	err := scanner.Err()
	if err != nil {
		log.Fatal(err)
	}

	return lines
}

// GetCredentialsFromFiles : reads username and password from config files and defines them inside the CMD type.
func (cmd *CMD) GetCredentialsFromFiles() bool {
	viper.AddConfigPath(".")
	viper.SetConfigName("key") // Register config file name (no extension)
	viper.SetConfigType("yml") // Look for specific type
	var err = viper.ReadInConfig()
	if err != nil {
		return false
	}
	appCode = viper.GetString("helper.key")

	viper.SetConfigName("helper") // Change file and reread contents.
	err = viper.ReadInConfig()
	if err != nil {
		return false
	}
	cmd.username = passBall(viper.GetString("helper.username"))
	cmd.useralt = passBall(viper.GetString("helper.useralt"))
	cmd.password = passBall(viper.GetString("helper.password"))
	cmd.passalt = passBall(viper.GetString("helper.passalt"))
	return true
}

// SSHConnect : Run command against a host
func (cmd *CMD) SSHConnect(userScript []string, host string, config *ssh.ClientConfig) error {
	pinger, err := ping.NewPinger(host)
	if err != nil {
		fmt.Errorf("Pings not working: %s", err)
	}
	pinger.Count = viper.GetInt("blockTimer.pingCount")
	pinger.SetPrivileged(true)
	pinger.Timeout = time.Duration(viper.GetInt("blockTimer.pingTimeout")) * time.Millisecond //times out after 500 milliseconds
	pinger.Run()                                                                              // blocks until finished
	stats := pinger.Statistics()                                                              // get send/receive/rtt stats
	if stats.PacketsRecv == 0 {
		//Device Timed out. No need to make a list of available iPs. Exit function.
		return fmt.Errorf("%s - Unable to connect: Device Offline.", host)
	}
	var client *ssh.Client
	for i := 0; i < 2; i++ { //loops twice for credentials. Should probably be changed to if authenticated.
		// Connect to the remote host
		// Requires defined port number
		client, err = ssh.Dial("tcp", host+":22", config)
		if err != nil {
			client = nil
			if strings.Contains(err.Error(),
				`connectex: A connection attempt failed because the connected party did not properly respond after a period of time`) ||
				strings.Contains(err.Error(), `i/o timeout`) {
				return fmt.Errorf("%s - Unable to connect: SSH attempt Timed Out.", host)
			}
			//Confusing errors. If it's exhausted all authentication methods it's probably a bad password.
			if strings.Contains(err.Error(), "unable to authenticate, attempted methods [none password]") {
				if cmd.useralt != "" && i == 0 {
					log.Printf("%s - Unable to connect: Trying Alternate Credentials.", host)
					config = &ssh.ClientConfig{
						User:            cmd.useralt,
						HostKeyCallback: ssh.InsecureIgnoreHostKey(),
						Timeout:         1 * time.Second,
						Auth: []ssh.AuthMethod{
							ssh.Password(cmd.passalt),
						},
					}

				} else {
					return fmt.Errorf("%s - Unable to connect: Authentication Retries Exceeded.", host)
				}
			} else {
				return fmt.Errorf("%s - Unable to connect: %s\n", host, err)
			}
		} else {
			break
		}
	}
	defer client.Close()

	// Open a session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("Failed to create session: %s", err)
	}
	defer session.Close()

	err = session.RequestPty("xterm", 80, 40, ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	})
	if err != nil {
		return err
	}

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	stdinBuf, err := session.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	session.Shell()
	if err != nil {
		log.Fatal(err)
	}

	command := strings.Join(userScript, "\n")
	//can use multiple of these buffer writes in a row, but I just used 1 string.
	//stdinBuf.Write([]byte("config t \n"))
	// The command has been sent to the device, but you haven't gotten output back yet.
	// Not that you can't send more commands immediately.
	stdinBuf.Write([]byte("terminal length 0\n" + command + "\nterminal length 32\n"))
	// Then you'll want to wait for the response, and watch the stdout buffer for output.
	upperLimit := 30
	for i := 1; i <= upperLimit; i++ {
		if i > 10 {
			time.Sleep(time.Duration(100 * time.Millisecond))
		} else {
			time.Sleep(time.Duration(40 * time.Millisecond))
		}

		outputArray := strings.Split(strings.TrimSpace(stdoutBuf.String()), "\n")

		outputLastLine := strings.TrimSpace(outputArray[len(outputArray)-1])
		outputArray = removeBanner(outputArray)

		if len(outputArray) >= 3 && strings.HasSuffix(outputLastLine, "#") {
			outputArray[1] = ""
			fmt.Printf("\n#####################  %s  #####################\n \n\n %s\n",
				host, strings.TrimSpace(strings.Join(outputArray, "\n")))
			break
		}
		if i == upperLimit {
			log.Printf("%s - No output received. Timed Out.", host)
		}
	}
	return nil
}

// getLastLine : Fetch Last line of string
func getLastLine(input string) string {
	results := strings.Split(input, "\n")
	return results[len(results)-1]
}

// removes the banners from the output array to make the code easier to digest.
func removeBanner(input []string) []string { //TODO: Add this as a CLI flag to add banners back.
	for index, bannerString := range input {
		if strings.Contains(bannerString, "-------------------------------") {
			input[index-1] = ""
			input[index] = ""
			input[index+1] = ""
		}
		if strings.Contains(bannerString, "terminal length") {
			input[index] = ""
		}
	}
	return input

}

// SetupCloseHandler : Catch ^C and gracefully shutdown.
func SetupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n- Ctrl+C pressed in Terminal. Gracefully shutting down.")
		os.Exit(1)
	}()
	return
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// This sets certain flags for the "log" package, so when a log.Println
	// or other sub-function is run, makes a traceback. Similar to log.Panic, but does it for every log function.
	// The log package contains many of the same functions as fmt.
	SetupCloseHandler()
	var command CMD
	if !command.GetCredentialsFromFiles() {
		log.Println("Unable to read credentials from file.")
		command.username = StringPrompt("Username:")
		command.password = StringPrompt("Password:")
	}

	config := &ssh.ClientConfig{
		User:            command.username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		//Might need to play with this. Default timeout is something insane like 10 seconds. I thought the program froze.
		Timeout: 1 * time.Second,
		/*
			//not needed currently, but good code to keep
			Config: ssh.Config{
				Ciphers: []string{"aes128-ctr", "hmac-sha2-256"},
			},
		*/
	}
	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	if command.privatekey != "" {
		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey([]byte(command.privatekey))
		if err != nil {
			log.Printf("unable to parse private key: %v", err)
		}
		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	} else {
		config.Auth = []ssh.AuthMethod{
			ssh.Password(command.password),
		}
	}

	deviceList := promptList("Enter Device List, Press Enter when completed.")
	userScript := promptList("Enter commands to run, Press Enter when completed.")

	fmt.Println("Received input, processing...")
	waitGroup := goccm.New(200)
	for _, deviceIP := range deviceList {
		waitGroup.Wait()
		go func(deviceIP string) {
			defer waitGroup.Done()
			err := command.SSHConnect(userScript, deviceIP, config)
			if err != nil {
				log.Print(err)
			}
		}(deviceIP)
		//Keeps the output buffer from crossing streams in the go routine.
		time.Sleep(1 * time.Millisecond)
	}

	//blocks until ALL go routines are done.
	waitGroup.WaitAllDone()

}
