package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gonutz/w32/v2"

	"github.com/Rldeckard/aesGenerate256/authGen"
	"github.com/Rldeckard/sshRunCMD/dialSSHClient"
	"github.com/spf13/viper"
	"github.com/zenthangplus/goccm"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// Windows doesn't allow console and Gui apps in one anymore.
// Dont specify the windowsgui flag and use this to maintain CLI functionality with Fyne
func hideConsole() {
	console := w32.GetConsoleWindow()
	if console == 0 {
		return // no console attached
	}
	// If this application is the process that created the console window, then
	// this program was not compiled with the -H=windowsgui flag and on start-up
	// it created a console along with the main application window. In this case
	// hide the console window.
	// See
	// http://stackoverflow.com/questions/9009333/how-to-check-if-the-program-is-run-from-a-console
	_, consoleProcID := w32.GetWindowThreadProcessId(console)
	if w32.GetCurrentProcessId() == consoleProcID {
		w32.ShowWindowAsync(console, w32.SW_HIDE)
	}
}
func (cred *CRED) guiApp() {
	// Windows doesn't allow console and Gui apps in one anymore.
	// Dont specify the windowsgui flag and use this to maintain CLI functionality with Fyne
	hideConsole()

	myApp := app.New()
	myWindow = myApp.NewWindow("sshRunCMD")
	myWindow.Resize(fyne.NewSize(1000, 500))

	// Main menu

	formUser := widget.NewEntry()
	formPass := widget.NewPasswordEntry()
	formDrop := widget.NewSelect([]string{"Active Directory", "Local Account"}, func(value string) {
		if value == "Active Directory" {
			formUser.Text = cred.username
		}
		if value == "Local Account" {
			formUser.Text = cred.fallbackUser
		}
		formUser.Refresh()
	})
	formDrop.SetSelectedIndex(0)
	loginFormItems := []*widget.FormItem{
		{Text: "", Widget: formDrop},
		{Text: "Username", Widget: formUser},
		{Text: "Password", Widget: formPass},
	}
	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Manage Credentials", func() {
			formUser.Text = cred.username
			formPopUp := dialog.NewForm("Manage", "Update", "Cancel", loginFormItems, func(ok bool) {
				if ok {
					if formDrop.Selected == "Active Directory" {
						cred.username = strings.Trim(formUser.Text, " ")
						cred.password = strings.Trim(formPass.Text, " ")
						//TODO: Generate appCode and save to file if not present.
						if appCode != "" {
							viper.Set("helper.username", aes256.Encrypt(appCode, cred.username))
							viper.Set("helper.password", aes256.Encrypt(appCode, cred.password))
						}

					} else {
						cred.fallbackUser = strings.Trim(formUser.Text, " ")
						cred.fallbackPass = strings.Trim(formPass.Text, " ")
						if appCode != "" {
							viper.Set("helper.fallbackUser", aes256.Encrypt(appCode, cred.fallbackUser))
							viper.Set("helper.fallbackPass", aes256.Encrypt(appCode, cred.fallbackPass))
						}
					}
					viper.WriteConfig()
					err := viper.WriteConfigAs("helper.yml")
					if err != nil {
					log.Fatalf("Error writing config file: %v", err)
					}
					formPass.Text = ""
				}
			}, myWindow)
			formPopUp.Resize(fyne.NewSize(300, 0))
			formPopUp.Show()
		}),
		fyne.NewMenuItem("Export Output", func() {
			if outputCMD.Text == "" {
				dialog.NewCustom("Oops", "Close", widget.NewLabel("No results to export. Please run query before exporting."), myWindow).Show()
			} else {
				timeRaw := time.Now()
				os.UserConfigDir()
				userHome, _ := os.UserHomeDir()
				fileName := fmt.Sprintf("sshRunCMD-Export_%s.txt", timeRaw.Format("150405"))
				fileLocation := fmt.Sprintf(`%s\Downloads\%s`, userHome, fileName)
				f, err := os.OpenFile(
					fileLocation,
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
				fileOpen := widget.Hyperlink{
					Text: "Open File",
					OnTapped: func() {
						cmd := exec.Command("cmd", "/C", "start "+fileLocation)
						err := cmd.Run()
						if err != nil {
							dialog.NewCustom("Error", "Close", widget.NewLabel("Issue with file, retry:\n"+err.Error()), myWindow).Show()
						}
					},
				}
				linkText := container.NewVBox(
					widget.NewLabel("File exported to Downloads folder"),
					container.NewCenter(
						container.NewHBox(&fileOpen),
					),
				)
				dialog.NewCustom("Export Complete", "Ok", linkText, myWindow).Show()
			}
		}),
		fyne.NewMenuItem("Quit", func() { myApp.Quit() }),
	)
	helpMenu := fyne.NewMenu("Help",
		fyne.NewMenuItem("About", func() {
			dialog.ShowCustom("About", "Close", container.NewVBox(
				widget.NewLabel("Welcome to sshRunCMD, a simple CLI application for managing switches."),
				widget.NewLabel("Version: v1.6.1"),
				widget.NewLabel("Author: Ryan Deckard"),
			), myWindow)
		}))

	pingCountEntry := widget.NewEntry()
	pingTimeoutEntry := widget.NewEntry()
	coreEntry := widget.NewEntry()

	settingsFormItems := []*widget.FormItem{
		{Text: "Core IP", Widget: coreEntry},
		{Text: "Ping Count", Widget: pingCountEntry},
		{Text: "Ping Timeout (ms)", Widget: pingTimeoutEntry},
	}
	editMenu := fyne.NewMenu("Edit",
		fyne.NewMenuItem("Options", func() {
			coreEntry.Text = cred.core
			pingCountEntry.Text = fmt.Sprint(cred.pingCount)
			pingTimeoutEntry.Text = fmt.Sprint(cred.pingTimeout)
			settingsPop := dialog.NewForm("Manage", "Update", "Cancel", settingsFormItems, func(ok bool) {
				if ok {
					cred.core = strings.Trim(coreEntry.Text, " ")
					cred.pingCount, _ = strconv.Atoi(strings.Trim(pingCountEntry.Text, " "))
					cred.pingTimeout, _ = strconv.Atoi(strings.Trim(pingTimeoutEntry.Text, " "))
					viper.Set("helper.core", cred.core)
					viper.Set("blockTimer.pingCount", cred.pingCount)
					viper.Set("blockTimer.pingTimeout", cred.pingTimeout)
					viper.WriteConfig()
					err := viper.WriteConfigAs("helper.yml")
					if err != nil {
						log.Fatalf("Error writing config file: %v", err)
					}

				}
			}, myWindow)
			settingsPop.Resize(fyne.NewSize(300, 0))
			settingsPop.Show()

		}),
	)
	mainMenu := fyne.NewMainMenu(
		fileMenu,
		editMenu,
		helpMenu,
	)
	myWindow.SetMainMenu(mainMenu)
	outTitle := widget.NewLabel("Switch Output")
	outTitle.TextStyle.Bold = true
	outTitle.Alignment = fyne.TextAlignCenter

	outputScroll := container.NewVScroll(outputCMD)
	outputCMD.Wrapping = fyne.TextWrapWord //outputScroll.ScrollToBottom()
	outputScroll.SetMinSize(fyne.NewSize(450, 0))

	progBar = widget.NewProgressBar()
	progBar.Hide()

	deviceList := widget.NewMultiLineEntry()
	userScript := widget.NewMultiLineEntry()

	submitButton := widget.NewButton(
		"Run CMD", func() { cred.runProgram(deviceList, userScript) },
	)
	submitButton.Importance = widget.HighImportance
	testButton := widget.NewButton(
		//premade test to run against network to verify applicaton functionality
		"Test Run", func() {
			var surePopup *dialog.ConfirmDialog

			surePopup = dialog.NewConfirm("Please confirm", "Run test script?", func(ok bool) {
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
					surePopup.Hide()
					cred.runProgram(deviceList, userScript)
				}
			}, myWindow)
			surePopup.Show()
		},
	)
	verifyCredsCheck := widget.NewCheck("Check Credentials", func(ok bool) {
		*verifyCreds = ok
	})

	legacySSHCheck := widget.NewCheck("Legacy SSH", func(ok bool) {
		legacySSH = ok
	})
	verifyCredsCheck.SetChecked(true)
	buttonBox := container.New(
		layout.NewHBoxLayout(),
		testButton,
		verifyCredsCheck,
		legacySSHCheck,
	)
	ipBox := container.NewBorder(
		widget.NewLabel("IP Addresses"),
		buttonBox,
		nil,
		nil,
		deviceList,
	)
	cmdBox := container.NewBorder(
		widget.NewLabel("Commands"),
		submitButton,
		nil,
		nil,
		userScript,
	)
	left := container.New(
		layout.NewGridLayout(1),
		ipBox,
		cmdBox,
	)
	right := container.NewBorder(
		outTitle,
		progBar,
		nil,
		nil,
		outputScroll,
	)
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

func (cred *CRED) runProgram(deviceList *widget.Entry, userScript *widget.Entry) { // optional, handle form submission
	deviceSlice := strings.Split(deviceList.Text, "\n")
	progress.step = 1 / float64(len(deviceSlice))
	progBar.Show()
	progBar.SetValue(progress.step)
	if *verifyCreds {
		if (cred.username == "" || cred.password == "") {
			if (cred.fallbackPass == "" || cred.fallbackUser == "") {
				dialog.NewCustom("Error", "Close", widget.NewLabel("Credentials not provided. \nPlease update helper.yml or manually add under File > Manage Credentials.\n"), myWindow).Show()
				return
			} 
		} else {
			//checks credentials against a default device so you don't lock yourself out. Only done for primary / AD creds. Doesn't check for local creds.
			connect.Init(cred.username, cred.password, "", legacySSH)
			if cred.core == "" {
				dialog.NewCustom("Error", "Close", widget.NewLabel("No core device specified in helper file. Please add to Edit > Options."), myWindow).Show()
				return
			} else {
				outputCMD.Text = "\nVerifying credentials\n"
				outputCMD.Refresh()
				_, err := connect.DialClient(cred.core)
				if err != nil {
					dialog.NewCustom("Error", "Close", widget.NewLabel("Can't connect to Core Device. Please check credentials.\n"+err.Error()), myWindow).Show()
					//"Supplied Credentials not working."
					return
				}
			}
		}
			

		

	}
	outputCMD.Text = ""
	userScriptSlice := strings.Split(userScript.Text, "\n")
	// recent updates in Fyne offloaded GUI Refresh() to its own thread. You can no longer block the main application for any length of time. 
	// For the below refresh to work as expected all addtional items below that had to be put into a Go Routine.
	outputCMD.Text = "\nApplication Started....\n"
	outputCMD.Refresh()
	outputCMD.Text = ""
	go func() {
		waitGroup := goccm.New(40)
		for _, deviceIP := range deviceSlice {
			waitGroup.Wait()
			go func(host string) {
				defer waitGroup.Done()
				if strings.TrimSpace(host) != "" {
					err := cred.SSHConnect(userScriptSlice, strings.TrimSpace(host))
					if err != nil {
						errOut := err.Error()
						//no idea why this error means authentication failed.....but it does
						if strings.Contains(errOut, "reason 2: Non-assigned port") {
							errOut = "unable to connect: ssh: authentication not provided"
						}
						outputCMD.Text = host + ": issue with ssh: " + errOut + "\n" + outputCMD.Text
					}
				}
			}(deviceIP)
		}
		waitGroup.WaitAllDone()
		showResults()
	}()

}
