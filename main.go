package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Rldeckard/aesGenerate256/authGen"
	"github.com/Rldeckard/sshRunCMD/closeHandler"
	"github.com/Rldeckard/sshRunCMD/dialSSHClient"
	"github.com/Rldeckard/sshRunCMD/processOutput"
	"github.com/Rldeckard/sshRunCMD/userPrompt"
	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/viper"
	"github.com/zenthangplus/goccm"
	"golang.org/x/crypto/ssh"
)

type CRED struct {
	username     string
	password     string
	fallbackUser string
	fallbackPass string
	privatekey   string
}

type Progress struct {
	offlineDevices        []string
	unauthedDevices       []string
	connectedDevices      []string
	failedCommandsDevices []string
	failedCommands        []string
}

// Reads username and password from config files and defines them inside the CMD type.
func GetCredentialsFromFiles(cred *CRED) bool {
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
	cred.username = aes256.Decrypt(appCode, viper.GetString("helper.username"))
	cred.password = aes256.Decrypt(appCode, viper.GetString("helper.password"))
	cred.fallbackUser = aes256.Decrypt(appCode, viper.GetString("helper.fallbackUser"))
	cred.fallbackPass = aes256.Decrypt(appCode, viper.GetString("helper.fallbackPass"))
	return true
}

// Run command against a host
func (cred *CRED) SSHConnect(userScript []string, host string) error {
	var m sync.Mutex
	connect.Init(cred.username, cred.password, "")
	altCreds := ""

	stats, err := connect.IsAlive(host, viper.GetInt("blockTimer.pingCount"), viper.GetInt("blockTimer.pingTimeout")) // get send/receive/rtt stats
	if err != nil {
		return err
	}
	if stats.PacketsRecv == 0 {
		//Device Timed out. No need to make a list of available iPs. Exit function.
		progress.offlineDevices = append(progress.offlineDevices, host)
		return fmt.Errorf("%s - Unable to connect: Device Offline.", host)
	}
	client, err := connect.DialClient(host)
	if err != nil {
		if cred.fallbackUser != "" || strings.Contains("Authentication Failed", err.Error()) {

			connect.UpdateUser(cred.fallbackUser)
			connect.UpdatePass(cred.fallbackPass)
			client, err = connect.DialClient(host)
			if err != nil {
				progress.unauthedDevices = append(progress.unauthedDevices, host)
				return fmt.Errorf("%s - %s\n", host, err)
			} else {
				altCreds = "Using Alternate Credentials"
			}
		} else {
			progress.unauthedDevices = append(progress.unauthedDevices, host)
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
	configT := false
	session.Stdout = &stdoutBuf

	stdinBuf, err := session.StdinPipe()
	if err != nil {
		log.Fatal(fmt.Sprintf("%s - Unable to start session: %s", host, err))
	}

	session.Shell()
	m.Lock()
	//can use multiple of these buffer writes in a row, but I just used 1 string.
	// The command has been sent to the device, but you haven't gotten output back yet.
	stdinBuf.Write([]byte("terminal length 0\n"))
	for _, command := range userScript {
		if strings.Contains(command, "config t") {
			configT = true
		}
		if command == "exit" {
			configT = false
		}
		stdinBuf.Write([]byte(command + "\n"))
		time.Sleep(5 * time.Millisecond) //TODO: Might not need, but this ensures commands are applied. Needs rigorous testing.
	}
	//makes sure you're at the lowest level before running terminal command or it won't work.
	if configT {
		stdinBuf.Write([]byte("end\n"))
	}
	stdinBuf.Write([]byte("terminal length 32\n"))
	// Not that you can't send more commands immediately.
	// Then you'll want to wait for the response, and watch the stdout buffer for output.
	upperLimit := 10
	for i := 1; i <= upperLimit; i++ {

		outputArray := strings.Split(strings.TrimSpace(stdoutBuf.String()), "\n")
		outputLastLine := strings.TrimSpace(outputArray[len(outputArray)-1])

		if len(outputArray) >= 3 && strings.HasSuffix(outputLastLine, "#") {
			outputArray, failedCommand := output.Process(outputArray, *originalOutput)
			outputString := fmt.Sprintf("\n#####################  %s  #####################\n%s", host, altCreds)
			if *fileOutput {
				f, err := os.OpenFile("output.txt",
					os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Fatal("Please close output.txt before running program")
				}
				defer f.Close()

				_, err = f.WriteString(fmt.Sprintf("%s\n\n%s\n", outputString, strings.TrimSpace(strings.Join(outputArray, ""))))
				if err != nil {
					log.Println("Issue writing to file.")
				}
			} else {
				fmt.Printf(fmt.Sprintf("%s\n\n%s\n", outputString, strings.TrimSpace(strings.Join(outputArray, "\n"))))
			}
			if failedCommand == true {
				progress.failedCommandsDevices = append(progress.failedCommandsDevices, host)
				progress.failedCommands = append(progress.failedCommands, strings.Join(userScript, ","))
				log.Printf("%s - Command not applied to switch.", host)
			} else {
				progress.connectedDevices = append(progress.connectedDevices, host)
			}
			break
		}
		if i == upperLimit {
			progress.offlineDevices = append(progress.offlineDevices, host)
			log.Printf("%s - No output received. Timed Out.", host)
		}
		if i > 5 {
			time.Sleep(500 * time.Millisecond)
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	m.Unlock()
	return nil
}

var originalOutput = flag.Bool("s", false, "Shows raw output from switches.")
var testRun = flag.Bool("t", false, "Run preloaded test case for development. Defined in helper file.")
var verboseOutput = flag.Bool("v", false, "Output all successfully connected devices.")
var dontVerifyCreds = flag.Bool("c", false, "Doesn't verify your credentials against a known device. Be careful to not lock out your account.")
var promptCreds = flag.Bool("p", false, "Bypasses all stored credentials and prompts for new credentials.")
var fileOutput = flag.Bool("f", false, "Sends output from switches to file. Good for show runs or cdp neighbor.")
var progress Progress

// encryption key used to decrypt helper.yml
// create 'helper.key' file to store appCode. Copy below code format for yml
// helper:
//
//	key: 'fasdfasdfasdfasdf'
var appCode string

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// This sets certain flags for the "log" package, so when a log.Println
	// or other sub-function is run, makes a traceback. Similar to log.Panic, but does it for every log function.
	// The log package contains many of the same functions as fmt.

	flag.Parse()
	closeHandler.Listener()
	os.Remove("output.txt")
	var cred CRED
	var deviceList []string
	var userScript []string
	if !GetCredentialsFromFiles(&cred) || cred.username == "" || *promptCreds {
		if !*promptCreds {
			log.Println("Unable to read credentials from helper file.")
		}
		cred.username = prompt.Credentials("Username:")
		cred.password = prompt.Credentials("Password:")
	}
	if !*dontVerifyCreds {
		//checks credentials against a default device so you don't lock yourself out
		connect.Init(cred.username, cred.password, "")
		_, err := connect.DialClient(viper.GetString("helper.core"))
		if err != nil {
			log.Fatalf("Supplied Credentials not working.")
		}
	}
	if *testRun == false {
		deviceList = prompt.List("Enter Device List, Press Enter when completed.")
		userScript = prompt.List("Enter commands to run, Press Enter when completed.")
	} else {
		deviceList = viper.GetStringSlice("tester.devices")
		userScript = []string{viper.GetString("tester.commands")} //only works for one command, but needs to be a slice to be processed. Possible conver to csv import if needed.
	}
	fmt.Println("Received input, processing...")

	waitGroup := goccm.New(40)
	bar := pb.StartNew(len(deviceList)).SetTemplate(pb.Simple).SetRefreshRate(25 * time.Millisecond) //Default refresh rate is 200 Milliseconds.
	checkList := strings.Split(deviceList[0], " ")
	if len(checkList) > 1 {
		deviceList = checkList
	}
	for _, deviceIP := range deviceList {
		waitGroup.Wait()
		go func(host string) {
			defer bar.Increment()
			defer waitGroup.Done()
			err := cred.SSHConnect(userScript, host)
			if err != nil {
				log.Print(err)
			}
		}(deviceIP)
		//Keeps the output buffer from crossing streams in the go routine.
	}

	//blocks until ALL go routines are done.
	waitGroup.WaitAllDone()
	for i := 0; i <= 50; i++ {
		if bar.Current() == int64(len(deviceList)) {
			bar.Finish()
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if *verboseOutput {
		fmt.Printf("\nStatus report: \n\tOffline devices (%d) : %s\n\tOnline but unable to authenticate with given credentials (%d) : %s\n\tSuccessfully connected, but unable to run commands: (%d) \"%s\" on (%d) devices : %s\n\tSuccessfully able to connect and run commands (%d) : %s", len(progress.offlineDevices), strings.Join(progress.offlineDevices, " "), len(progress.unauthedDevices), strings.Join(progress.unauthedDevices, " "), len(progress.failedCommands), strings.Join(progress.failedCommands, " "), len(progress.failedCommandsDevices), strings.Join(progress.failedCommandsDevices, " "), len(progress.connectedDevices), strings.Join(progress.connectedDevices, " "))
	} else {
		fmt.Printf("\nStatus report: \n\tOffline devices (%d) : %s\n\tOnline but unable to authenticate with given credentials (%d) : %s\n\tSuccessfully connected, but unable to run commands: (%d) on (%d) devices : %s\n\tSuccessfully able to connect and run commands (%d)", len(progress.offlineDevices), strings.Join(progress.offlineDevices, " "), len(progress.unauthedDevices), strings.Join(progress.unauthedDevices, " "), len(progress.failedCommands), len(progress.failedCommandsDevices), strings.Join(progress.failedCommandsDevices, " "), len(progress.connectedDevices))
	}

	prompt.Pause()
}
