package main

import (
	"fmt"
	"github.com/Rldeckard/aesGenerate256/authGen"
	"github.com/Rldeckard/sshRunCMD/dialSSHClient"
	"github.com/spf13/viper"
	"github.com/zenthangplus/goccm"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func (cred *CRED) guiApp() {
	myApp := app.New()
	myWindow = myApp.NewWindow("sshRunCMD")
	myWindow.Resize(fyne.NewSize(1050, 0))

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
			viper.AddConfigPath(".")
			viper.SetConfigName("key") // Register config file name (no extension)
			viper.SetConfigType("yml") // Look for specific type
			formUser.Text = cred.username
			formPopUp := dialog.NewForm("Manage", "Update", "Cancel", loginFormItems, func(ok bool) {
				if ok {
					if formDrop.Selected == "Active Directory" {
						cred.username = strings.Trim(formUser.Text, " ")
						cred.password = strings.Trim(formPass.Text, " ")
						viper.Set("helper.username", aes256.Encrypt(appCode, cred.username))
						viper.Set("helper.password", aes256.Encrypt(appCode, cred.password))

					} else {
						cred.fallbackUser = strings.Trim(formUser.Text, " ")
						cred.fallbackPass = strings.Trim(formPass.Text, " ")
						viper.Set("helper.fallbackUser", aes256.Encrypt(appCode, cred.fallbackUser))
						viper.Set("helper.fallbackPass", aes256.Encrypt(appCode, cred.fallbackPass))
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
		}),
		fyne.NewMenuItem("Quit", func() { myApp.Quit() }),
	)
	helpMenu := fyne.NewMenu("Help",
		fyne.NewMenuItem("About", func() {
			dialog.ShowCustom("About", "Close", container.NewVBox(
				widget.NewLabel("Welcome to sshRunCMD, a simple CLI application for managing switches."),
				widget.NewLabel("Version: v1.3.1"),
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
			viper.AddConfigPath(".")
			viper.SetConfigName("key") // Register config file name (no extension)
			viper.SetConfigType("yml") // Look for specific type
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

	deviceList := widget.NewMultiLineEntry()
	userScript := widget.NewMultiLineEntry()
	deviceList.SetMinRowsVisible(5)
	userScript.SetMinRowsVisible(5)
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
	verifyCredsCheck := widget.NewCheck("Check Credentials", func(ok bool) {
		if !ok {
			*dontVerifyCreds = true
		} else {
			*dontVerifyCreds = false
		}
	})
	verifyCredsCheck.SetChecked(true)

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
		verifyCredsCheck,
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

func (cred *CRED) runProgram(deviceList *widget.Entry, userScript *widget.Entry) { // optional, handle form submission
	//clear output for subsequent runs
	if !*dontVerifyCreds {
		if cred.username == "" || cred.password == "" {
			dialog.NewCustom("Error", "Close", widget.NewLabel("Credentials not provided. \nPlease update helper.yml or manually add under File > Manage Credentials.\n"), myWindow).Show()
			return
		}
		//checks credentials against a default device so you don't lock yourself out
		connect.Init(cred.username, cred.password, "")
		if cred.core == "" {
			dialog.NewCustom("Error", "Close", widget.NewLabel("No core device specified in helper file. Please add to Edit > Options."), myWindow).Show()
			return
		} else {
			_, err := connect.DialClient(cred.core)
			if err != nil {
				dialog.NewCustom("Error", "Close", widget.NewLabel("Can't connect to Core Device. Please check credentials.\n"+err.Error()), myWindow).Show()
				//"Supplied Credentials not working."
				return
			}
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
			if strings.TrimSpace(host) != "" {
				err := cred.SSHConnect(userScriptSlice, strings.TrimSpace(host))
				if err != nil {
					log.Print(err)
				}
			}
		}(deviceIP)
	}
	waitGroup.WaitAllDone()
	showResults()

}
