package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/go-ping/ping"
	"github.com/spf13/viper"
	"github.com/zenthangplus/goccm"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type CMD struct {
	username     string
	password     string
	fallbackUser string
	fallbackPass string
	privatekey   string
}

type Progress struct {
	offline         int
	offlineDevices  []string
	unauthed        int
	unauthedDevices []string
	online          int
	onlineDevices   []string
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
	if ct == "" { //basically a catch for not providing alternate credentials
		return ""
	}
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
		log.Println(err)
		return false
	}
	appCode = viper.GetString("helper.key")

	viper.SetConfigName("helper") // Change file and reread contents.
	err = viper.ReadInConfig()
	if err != nil {
		log.Println(err)
		return false
	}
	cmd.username = passBall(viper.GetString("helper.username"))
	cmd.password = passBall(viper.GetString("helper.password"))
	cmd.fallbackUser = passBall(viper.GetString("helper.fallbackUser"))
	cmd.fallbackPass = passBall(viper.GetString("helper.fallbackPass"))
	return true
}

// SSHConnect : Run command against a host
func (cmd *CMD) SSHConnect(userScript []string, host string) error {
	config := &ssh.ClientConfig{
		User:            cmd.username,
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
	if cmd.privatekey != "" {
		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey([]byte(cmd.privatekey))
		if err != nil {
			log.Printf("unable to parse private key: %v", err)
		}
		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	} else {
		config.Auth = []ssh.AuthMethod{
			ssh.Password(cmd.password),
		}
	}
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
		progress.offline++
		progress.offlineDevices = append(progress.offlineDevices, host)
		return fmt.Errorf("%s - Unable to connect: Device Offline.", host)
	}
	client, err := cmd.dialClient(host, config)
	if err != nil {
		if cmd.fallbackUser != "" || strings.Contains("Authentication Failed", err.Error()) {
			log.Printf("%s - Unable to connect: Trying Alternate Credentials.", host)
			config.User = cmd.fallbackUser
			config.Auth = []ssh.AuthMethod{
				ssh.Password(cmd.fallbackPass),
			}
			client, err = cmd.dialClient(host, config)
			if err != nil {
        progress.unauthed++
				progress.unauthedDevices = append(progress.unauthedDevices, host)
				return fmt.Errorf("%s - %s\n", host, err)
			}
		} else {
			return fmt.Errorf("%s - %s\n", host, err)
		}
	}
	defer client.Close()
	// Open a session
	session, err := client.NewSession()
	if err != nil {
		log.Fatal(fmt.Sprintf("%s - Failed to create session: %s", host, err))
	}
	defer session.Close()

	err = session.RequestPty("xterm", 80, 40, ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	})
	if err != nil {
		log.Fatal(fmt.Sprintf("%s - Unable to start session: %s", host, err))
	}

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	stdinBuf, err := session.StdinPipe()
	if err != nil {
		log.Fatal(fmt.Sprintf("%s - Unable to start session: %s", host, err))
	}
	session.Shell()
	if err != nil {
		log.Fatal(fmt.Sprintf("%s - Unable to start session: %s", host, err))
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
			time.Sleep(100 * time.Millisecond)
		} else {
			time.Sleep(40 * time.Millisecond)
		}
		outputArray := strings.Split(strings.TrimSpace(stdoutBuf.String()), "\n")
		outputLastLine := strings.TrimSpace(outputArray[len(outputArray)-1])

		if len(outputArray) >= 3 && strings.HasSuffix(outputLastLine, "#") {
			outputArray, failedCommand := processOutput(outputArray)
			fmt.Printf("\n#####################  %s  #####################\n \n\n %s\n",
				host, strings.TrimSpace(strings.Join(outputArray, "\n")))
			if failedCommand == true {
				log.Printf("%s - Command not applied to switch.", host)
			}
			break
		}
		if i == upperLimit {
			log.Printf("%s - No output received. Timed Out.", host)
		}
	}
	progress.online++
	progress.onlineDevices = append(progress.onlineDevices, host)
	return nil
}
func (cmd *CMD) dialClient(host string, config *ssh.ClientConfig) (*ssh.Client, error) {
	// Connect to the remote host
	// Requires defined port number
	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		if strings.Contains(err.Error(),
			`connectex: A connection attempt failed because the connected party did not properly respond after a period of time`) ||
			strings.Contains(err.Error(), `i/o timeout`) {
      progress.unauthed++
			progress.unauthedDevices = append(progress.unauthedDevices, host)
			return nil, fmt.Errorf("Unable to connect: SSH attempt Timed Out.")
		}
		//Confusing errors. If it's exhausted all authentication methods it's probably a bad password.
    //We don't want to gather the progress here, because this error gets reused in the return.
		if strings.Contains(err.Error(), "unable to authenticate, attempted methods [none password]") {
			return nil, fmt.Errorf("Unable to connect: Authentication Failed")
		} else {
      	progress.unauthed++
				progress.unauthedDevices = append(progress.unauthedDevices, host)
			return nil, fmt.Errorf("Unable to connect: %s", err)
		}
	}

	return client, nil
}

// Removes the banners from the output array to make the code easier to digest.
// Also looks for any errors in the execution.
func processOutput(input []string) ([]string, bool) {
	failedCommand := false
	for index, bannerString := range input {
		if *originalOutput == false {
			if strings.Contains(bannerString, "-------------------------------") {
				input[index-1] = ""
				input[index] = ""
				input[index+1] = ""
			}
			if strings.Contains(bannerString, "terminal length") {
				input[index] = ""
			}
		}
		if strings.Contains(bannerString, "% Invalid") {
			failedCommand = true
		}
	}
	return input, failedCommand

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

var originalOutput = flag.Bool("s", false, "Shows raw output from switches.")
var testRun = flag.Bool("t", false, "Run preloaded test case for development. Defined in helper file.")
var verboseOutput = flag.Bool("v", false, "Output all successfully connected devices.")
var progress Progress

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// This sets certain flags for the "log" package, so when a log.Println
	// or other sub-function is run, makes a traceback. Similar to log.Panic, but does it for every log function.
	// The log package contains many of the same functions as fmt.

	flag.Parse()
	SetupCloseHandler()
	var command CMD
	var deviceList []string
	var userScript []string
	if !command.GetCredentialsFromFiles() || command.username == "" {
		log.Println("Unable to read credentials from helper file.")
		command.username = StringPrompt("Username:")
		command.password = StringPrompt("Password:")
	}
	if *testRun == false {
		deviceList = promptList("Enter Device List, Press Enter when completed.")
		userScript = promptList("Enter commands to run, Press Enter when completed.")
	} else {
		deviceList = viper.GetStringSlice("tester.devices")
		userScript = []string{viper.GetString("tester.commands")}
	}
	fmt.Println("Received input, processing...")

	waitGroup := goccm.New(200)
	bar := pb.StartNew(len(deviceList)).SetTemplate(pb.Simple).SetRefreshRate(100 * time.Millisecond) //Default refresh rate is 200 Milliseconds.
	for _, deviceIP := range deviceList {
		waitGroup.Wait()
		go func(host string) {
			defer bar.Increment()
			defer waitGroup.Done()
			err := command.SSHConnect(userScript, host)
			if err != nil {
				log.Print(err)
			}
		}(deviceIP)
		//Keeps the output buffer from crossing streams in the go routine.
		time.Sleep(1 * time.Millisecond)
	}

	//blocks until ALL go routines are done.
	waitGroup.WaitAllDone()
	for i := 0; i >= 50; i++ {
		if bar.Current() == int64(len(deviceList)) {
			bar.Finish()
			break
		}
		time.Sleep(1 * time.Millisecond)
	}
	if *verboseOutput {
		fmt.Printf("\nStatus report: \n\tOffline devices (%d) : %s\n\tOnline but unable to authenticate with given credentials (%d) : %s\n\tSuccessfully able to connect and run commands (%d) : %s", progress.offline, strings.Join(progress.offlineDevices, ","), progress.unauthed, strings.Join(progress.unauthedDevices, ","), progress.online, strings.Join(progress.onlineDevices, ","))
	} else {
		fmt.Printf("\nStatus report: \n\tOffline devices (%d) : %s\n\tOnline but unable to authenticate with given credentials (%d) : %s\n\tSuccessfully able to connect and run commands (%d)", progress.offline, strings.Join(progress.offlineDevices, ","), progress.unauthed, strings.Join(progress.unauthedDevices, ","), progress.online)
	}
}
