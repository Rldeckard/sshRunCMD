package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"sync"

	"github.com/Rldeckard/sshRunCMD/closeHandler"
	"github.com/Rldeckard/sshRunCMD/userPrompt"
	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/viper"
	"github.com/zenthangplus/goccm"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

type CRED struct {
	username     string
	password     string
	fallbackUser string
	fallbackPass string
	privatekey   string
	core         string
	pingTimeout  int
	pingCount    int
	typeDropDown *widget.Select
	threads 	 int
}

type Progress struct {
	offlineDevices        []string
	unauthedDevices       []string
	connectedDevices      []string
	failedCommandsDevices []string
	failedCommands        []string
	step                  float64
}

var originalOutput = flag.Bool("s", false, "Shows raw output from switches.")
var testRun = flag.Bool("t", false, "Run preloaded test case for development. Defined in helper file.")
var verboseOutput = flag.Bool("v", false, "Output all successfully connected devices.")
var verifyCreds = flag.Bool("c", false, "Doesn't verify your credentials against a known device. Be careful to not lock out your account.")
var promptCreds = flag.Bool("p", false, "Bypasses all stored credentials and prompts for new credentials.")
var fileOutput = flag.Bool("f", false, "Sends output from switches to file. Good for show runs or cdp neighbor.")

// -g=false to call flag
var showGUI = flag.Bool("g", true, "Disables GUI. Ex. -g=false")
var helpCalled = flag.Bool("h", false, "Shows Usage Menu.")
var progress Progress
var outputCMD = widget.NewLabel("")
var progBar *widget.ProgressBar
var myWindow fyne.Window
var useCreds = false
var legacySSH = false

// encryption key used to decrypt helper.yml
// create 'helper.key' file to store appCode. Copy below code format for yml
// helper:
//
//	key: 'fasdfasdfasdfasdf'
var appCode string

// to build new fyne application: 'fyne package -target windows -icon .\sshRunCMD.png'
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
	if *helpCalled {
		flag.PrintDefaults()
		os.Exit(0)
	}
	go GetCredentialsFromFiles(&cred)
	if cred.username == "" || *promptCreds {
		if !*promptCreds {
			log.Println("Unable to read credentials from helper file. Credentials not preloaded")
		}
		if !*showGUI {
			cred.username = prompt.Credentials("Username:")
			cred.password = prompt.Credentials("Password:")
		}
	}
	if !*showGUI {
		if !*testRun {
			deviceList = prompt.List("Enter Device List, Press Enter when completed.")
			userScript = prompt.List("Enter commands to run, Press Enter when completed.")
		} else {
			deviceList = viper.GetStringSlice("tester.devices")
			userScript = strings.Split(viper.GetString("tester.commands"), ",") //only works for one command, but needs to be a slice to be processed. Possible convert to csv import if needed.
		}
		fmt.Println("Received input, processing...")
		waitGroup := goccm.New(10)
		checkList := strings.Split(deviceList[0], " ")
		if len(checkList) > 1 {
			deviceList = checkList
		}
		bar := pb.StartNew(len(deviceList)).SetTemplate(pb.Simple).SetRefreshRate(25 * time.Millisecond) //Default refresh rate is 200 Milliseconds.
		var m sync.Mutex
		user := cred.username
	pass := cred.password
	isLegacy := legacySSH
		for _, deviceIP := range deviceList {
			waitGroup.Wait()
			go func(host string) {
				defer bar.Increment()
				defer waitGroup.Done()
				err := cred.SSHConnect(user, pass, userScript, host, &m, isLegacy)
				if err != nil {
					log.Fatalf("issue with ssh: %v", err)
				}
			}(deviceIP)
		}

		//blocks until ALL go routines are done.
		waitGroup.WaitAllDone()
		for i := uint8(0); i <= 50; i++ {
			if bar.Current() == int64(len(deviceList)) {
				bar.Finish()
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		showResults()
		prompt.Pause()
	} else {
		cred.guiApp()
	}

}
