package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/Rldeckard/aesGenerate256/authGen"
	"github.com/Rldeckard/sshRunCMD/closeHandler"
	"github.com/Rldeckard/sshRunCMD/dialSSHClient"
	"github.com/Rldeckard/sshRunCMD/processOutput"
	"github.com/Rldeckard/sshRunCMD/userPrompt"
	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/viper"
	"github.com/zenthangplus/goccm"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
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
	var configT bool = false
	var outputFinished bool = false
	var outputArray []string
	session.Stdout = &stdoutBuf

	stdinBuf, err := session.StdinPipe()
	if err != nil {
		log.Fatal(fmt.Sprintf("%s - Unable to start session: %s", host, err))
	}

	session.Shell()
	m.Lock()
	// The command has been sent to the device, but you haven't gotten output back yet.
	stdinBuf.Write([]byte("terminal length 0\n"))
	for _, command := range userScript {
		if strings.Contains(command, "config t") {
			configT = true
		}
		if command == "exit" || command == "end" {
			configT = false
		}
		stdinBuf.Write([]byte(command + "\n"))
		time.Sleep(20 * time.Millisecond) //TODO: Might not need, but this ensures commands are applied. Needs rigorous testing.
	}
	//makes sure you're at the lowest level before running terminal command or it won't work.
	if configT {
		stdinBuf.Write([]byte("end\n"))
	}
	stdinBuf.Write([]byte("terminal length 32\n"))
	// Then you'll want to wait for the response, and watch the stdout buffer for output.
	const upperLimit uint8 = 30
	for i := uint8(1); i <= upperLimit; i++ {

		outputArray = strings.Split(strings.TrimSpace(stdoutBuf.String()), "\n")
		outputLastLine := strings.TrimSpace(outputArray[len(outputArray)-1])

		if len(outputArray) >= 3 && strings.HasSuffix(outputLastLine, "#") {
			outputFinished = true
			break
		}
		if i == upperLimit {
			outputFinished = false
		}
		if i > upperLimit/2 {
			time.Sleep(500 * time.Millisecond)
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}

	outputArray, failedCommand := output.Process(outputArray, *originalOutput)
	outputString := fmt.Sprintf("\n#####################  %s  #####################\n%s", host, altCreds)
	if outputFinished == false {
		outputString = outputString + "\nWARNING: Incomplete Output"
	}
	if *fileOutput {
		f, err := os.OpenFile("output.txt",
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal("Please close output.txt before running program")
		}
		defer f.Close()
		//file output automatically adds a new line. No new line needed when converting outputArray to string
		_, err = f.WriteString(fmt.Sprintf("%s\n\n%s\n", outputString, strings.TrimSpace(strings.Join(outputArray, ""))))
		if err != nil {
			log.Println("Issue writing to file.")
		}
	} else if *showGUI {
		outputCMD.Text = fmt.Sprintf("%s\n\n%s\n", outputString, strings.TrimSpace(strings.Join(outputArray, "\n"))) + outputCMD.Text
		outputCMD.Refresh()

	} else {
		//Newline needed when outputting to console for output array join.
		fmt.Printf(fmt.Sprintf("%s\n\n%s\n", outputString, strings.TrimSpace(strings.Join(outputArray, "\n"))))
	}
	if failedCommand == true {
		progress.failedCommandsDevices = append(progress.failedCommandsDevices, host)
		progress.failedCommands = append(progress.failedCommands, strings.Join(userScript, ","))
		log.Printf("%s - Command not applied to switch.", host)
	} else {
		progress.connectedDevices = append(progress.connectedDevices, host)
	}
	m.Unlock()
	return nil
}

func (cred *CRED) runProgram(deviceList *widget.Entry, userScript *widget.Entry) { // optional, handle form submission
	//clear output for subsequent runs
	if !*dontVerifyCreds {
		//checks credentials against a default device so you don't lock yourself out
		connect.Init(cred.username, cred.password, "")
		_, err := connect.DialClient(viper.GetString("helper.core"))
		if err != nil {
			var dialogError dialog.Dialog
			if strings.Contains(err.Error(), "SSH attempt Timed Out") {
				dialogError = dialog.NewCustom("Error", "Close", widget.NewLabel("Can't connect to Core Device."), myWindow)
			} else {
				dialogError = dialog.NewError(err, myWindow)
			}
			//"Supplied Credentials not working."
			dialogError.Show()
			return
		}
	}
	outputCMD.Text = ""
	waitGroup := goccm.New(40)
	deviceSlice := strings.Split(deviceList.Text, "\n")
	userScriptSlice := strings.Split(userScript.Text, "\n")
	outputCMD.Text = "\nApplication Started....\n"
	outputCMD.Refresh()
	for _, deviceIP := range deviceSlice {
		waitGroup.Wait()
		go func(host string) {
			defer waitGroup.Done()
			err := cred.SSHConnect(userScriptSlice, strings.TrimSpace(host))
			if err != nil {
				log.Print(err)
			}
		}(deviceIP)
	}
	waitGroup.WaitAllDone()
	showResults()

}

func (cred *CRED) guiApp() {
	myApp := app.New()
	myWindow = myApp.NewWindow("sshRunCMD")
	myWindow.Resize(fyne.NewSize(1050, 0))
	// Main menu
	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Quit", func() { myApp.Quit() }),
	)

	helpMenu := fyne.NewMenu("Help",
		fyne.NewMenuItem("About", func() {
			dialog.ShowCustom("About", "Close", container.NewVBox(
				widget.NewLabel("Welcome to sshRunCMD, a simple CLI application for managing switches."),
				widget.NewLabel("Version: v1.3"),
				widget.NewLabel("Author: Ryan Deckard"),
			), myWindow)
		}))
	mainMenu := fyne.NewMainMenu(
		fileMenu,
		helpMenu,
	)
	myWindow.SetMainMenu(mainMenu)
	outTitle := widget.NewLabel("Switch Output")
	outTitle.TextStyle.Bold = true
	outTitle.Alignment = fyne.TextAlignCenter

	outputScroll := container.NewVScroll(outputCMD)
	outputCMD.Wrapping = fyne.TextWrapWord //outputScroll.ScrollToBottom()

	deviceList := widget.NewMultiLineEntry()
	userScript := widget.NewMultiLineEntry()
	deviceList.SetMinRowsVisible(10)
	userScript.SetMinRowsVisible(10)

	submitButton := widget.NewButton(
		"Run CMD", func() { cred.runProgram(deviceList, userScript) },
	)
	submitButton.Importance = widget.HighImportance
	testButton := widget.NewButton(
		//premade test to run against network to verify applicaton functionality
		"Test Run", func() {
			surePopup := dialog.NewConfirm("Please confirm", "Run test script?", func(ok bool) {
				if ok {
					procDeviceList := viper.GetStringSlice("tester.devices")
					deviceList.Text = strings.Join(procDeviceList, "\n")
					procUserScript := viper.GetString("tester.commands")
					userScript.Text = procUserScript
					if len(procDeviceList) == 0 || len(procUserScript) == 0 {
						dialog.NewCustom("Error", "Close", widget.NewLabel("Test not found. Please add test case to helper file and restart."), myWindow).Show()
						deviceList.Text = ""
						userScript.Text = ""
						return
					}
					deviceList.Refresh()
					userScript.Refresh()
					cred.runProgram(deviceList, userScript)
				}
			}, myWindow)
			surePopup.Show()
		},
	)
	exportButton := widget.NewButton(
		"Export", func() {
			if outputCMD.Text == "" {
				dialog.NewCustom("Oops", "Close", widget.NewLabel("No results to export. Please run query before exporting."), myWindow).Show()
			} else {
				timeRaw := time.Now()
				userHome, _ := os.UserHomeDir()
				fileName := fmt.Sprintf("sshRunCMD-Export_%s.txt", timeRaw.Format("150405"))
				f, err := os.OpenFile(
					fmt.Sprintf(`%s\Downloads\%s`, userHome, fileName),
					os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644,
				)
				if err != nil {
					dialog.NewError(err, myWindow)
				}
				defer f.Close()
				//file output automatically adds a new line. No new line needed when converting outputArray to string
				_, err = f.WriteString(outputCMD.Text)
				if err != nil {
					log.Println("Issue writing to file.")
				}
				dialog.NewCustom("Export Complete", "Ok", widget.NewLabel("Export sent to Downloads Folder."), myWindow).Show()
			}
			return
		},
	)

	ipBox := container.New(
		layout.NewVBoxLayout(),
		widget.NewLabel("IP Addresses"),
		deviceList,
	)
	cmdBox := container.New(
		layout.NewVBoxLayout(),
		widget.NewLabel("Commands"),
		userScript,
		submitButton,
	)
	buttonBox := container.New(
		layout.NewHBoxLayout(),
		testButton,
		exportButton,
	)
	left := container.New(
		layout.NewVBoxLayout(),
		ipBox,
		buttonBox,
		cmdBox,
	)
	right := container.NewBorder(
		outTitle,
		nil,
		nil,
		nil,
		outputScroll,
	)
	right.Resize(fyne.NewSize(400, 400))
	content := container.New(
		layout.NewGridLayout(2),
		left,
		right,
	)
	// Display our content
	myWindow.SetContent(content)
	// Close the App when Escape key is pressed
	myWindow.Canvas().SetOnTypedKey(func(keyEvent *fyne.KeyEvent) {

		if keyEvent.Name == fyne.KeyEscape {
			myApp.Quit()
		}
	})

	// Show window and run app
	myWindow.ShowAndRun()
}

func showResults() {
	var deviceResults string
	if *verboseOutput {
		deviceResults = fmt.Sprintf("\nStatus report: "+
			"\n\tOffline devices (%d) : %s\n"+
			"\tOnline but unable to authenticate with given credentials (%d) : %s\n"+
			"\tSuccessfully connected, but unable to run commands: (%d) \"%s\" on (%d) devices : %s\n"+
			"\tSuccessfully able to connect and run commands (%d) : %s\n",
			len(progress.offlineDevices),
			strings.Join(progress.offlineDevices, " "),
			len(progress.unauthedDevices),
			strings.Join(progress.unauthedDevices, " "),
			len(progress.failedCommands),
			strings.Join(progress.failedCommands, " "),
			len(progress.failedCommandsDevices),
			strings.Join(progress.failedCommandsDevices, " "),
			len(progress.connectedDevices),
			strings.Join(progress.connectedDevices, " "),
		)
	} else {
		deviceResults = fmt.Sprintf("\nStatus report: \n"+
			"\tOffline devices (%v) : %v\n"+
			"\tOnline but unable to authenticate with given credentials (%v) : %v\n"+
			"\tSuccessfully connected, but unable to run commands: (%v) on (%v) devices : %v\n"+
			"\tSuccessfully able to connect and run commands (%v)\n",
			len(progress.offlineDevices),
			strings.Join(progress.offlineDevices, " "),
			len(progress.unauthedDevices),
			strings.Join(progress.unauthedDevices, " "),
			len(progress.failedCommands),
			len(progress.failedCommandsDevices),
			strings.Join(progress.failedCommandsDevices, " "),
			len(progress.connectedDevices),
		)
	}
	if *showGUI {
		outputCMD.Text = deviceResults + outputCMD.Text
		outputCMD.Refresh()
	} else {
		fmt.Println(deviceResults)
	}
}

var originalOutput = flag.Bool("s", false, "Shows raw output from switches.")
var testRun = flag.Bool("t", false, "Run preloaded test case for development. Defined in helper file.")
var verboseOutput = flag.Bool("v", false, "Output all successfully connected devices.")
var dontVerifyCreds = flag.Bool("c", false, "Doesn't verify your credentials against a known device. Be careful to not lock out your account.")
var promptCreds = flag.Bool("p", false, "Bypasses all stored credentials and prompts for new credentials.")
var fileOutput = flag.Bool("f", false, "Sends output from switches to file. Good for show runs or cdp neighbor.")

// -g=false to call flag
var showGUI = flag.Bool("g", true, "Disables GUI. Ex. -g=false")
var helpCalled = flag.Bool("h", false, "Shows Usage Menu.")
var progress Progress
var outputCMD = widget.NewLabel("")
var myWindow fyne.Window

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
	if *helpCalled {
		flag.PrintDefaults()
		os.Exit(0)
	}
	if !GetCredentialsFromFiles(&cred) || cred.username == "" || *promptCreds {
		if !*promptCreds {
			log.Println("Unable to read credentials from helper file.")
		}
		if *showGUI {
			dialog.NewCustom("Error", "Close", widget.NewLabel("Unable to read credentials from helper file.\nCheck Helper File."), myWindow)
		} else {
			cred.username = prompt.Credentials("Username:")
			cred.password = prompt.Credentials("Password:")
		}
	}
	if *showGUI {
		cred.guiApp()
	}

	if *showGUI == false {
		if *testRun == false {
			deviceList = prompt.List("Enter Device List, Press Enter when completed.")
			userScript = prompt.List("Enter commands to run, Press Enter when completed.")
		} else {
			deviceList = viper.GetStringSlice("tester.devices")
			userScript = strings.Split(viper.GetString("tester.commands"), ",") //only works for one command, but needs to be a slice to be processed. Possible convert to csv import if needed.
		}
		fmt.Println("Received input, processing...")
		waitGroup := goccm.New(40)
		checkList := strings.Split(deviceList[0], " ")
		if len(checkList) > 1 {
			deviceList = checkList
		}
		bar := pb.StartNew(len(deviceList)).SetTemplate(pb.Simple).SetRefreshRate(25 * time.Millisecond) //Default refresh rate is 200 Milliseconds.

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
	}

}
