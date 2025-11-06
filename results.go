package main

import (
	"fmt"
	"strings"
	"fyne.io/fyne/v2"
)

func showResults() {
	var deviceResults string
	if *verboseOutput {
		deviceResults = fmt.Sprintf("\nStatus report: "+
			"\n\tOffline devices (%d) : %s\n"+
			"\tOnline but unable to authenticate with given credentials (%d) : %s\n"+
			"\tSuccessfully connected, but unable to run commands: (%d) \"%s\" on (%d) devices : %s\n"+
			"\tSuccessfully able to connect and run commands (%d) : %s\n\n",
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
			"\tSuccessfully able to connect and run commands (%v)\n\n",
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
		fyne.Do(func() {
			outputCMD.Text = deviceResults + outputCMD.Text
			outputCMD.Refresh()
		})
	} else {
		fmt.Println(deviceResults)
	}
	//clears results to prepare for next run
	progress = Progress{}
}
