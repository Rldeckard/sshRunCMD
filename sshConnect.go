package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"bufio"


	"github.com/Rldeckard/sshRunCMD/dialSSHClient"
	"github.com/Rldeckard/sshRunCMD/processOutput"
	"golang.org/x/crypto/ssh"
	"fyne.io/fyne/v2"

)

// Run command against a host
func (cred *CRED) SSHConnect(userScript []string, host string) error {
	var m sync.Mutex

	connect.Init(cred.username, cred.password, "", legacySSH)
	altCreds := ""

	stats, err := connect.IsAlive(host, cred.pingCount, cred.pingTimeout) // get send/receive/rtt stats
	if err != nil {
		return err
	}
	if stats.PacketsRecv == 0 {
		//Device Timed out. No need to make a list of available iPs. Exit function.
	fyne.Do(func() {
		progBar.SetValue(progBar.Value + progress.step)
	})		
	progress.offlineDevices = append(progress.offlineDevices, host)
		return fmt.Errorf("%s - Unable to connect: Device Offline", host)
	}
	client, err := connect.DialClient(host)
	if err != nil {
		if cred.fallbackUser != "" || strings.Contains("Authentication Failed", err.Error()) {

			connect.UpdateUser(cred.fallbackUser)
			connect.UpdatePass(cred.fallbackPass)
			client, err = connect.DialClient(host)
			if err != nil {
				progress.unauthedDevices = append(progress.unauthedDevices, host)
				fyne.Do(func() {
					progBar.SetValue(progBar.Value + progress.step)
				})				
				return fmt.Errorf("%s - %s", host, err)
			} else {
				altCreds = "Using Alternate Credentials"
			}
		} else {
			progress.unauthedDevices = append(progress.unauthedDevices, host)
			fyne.Do(func() {
					progBar.SetValue(progBar.Value + progress.step)
			})			
			return fmt.Errorf("%s - %s", host, err)
		}
	}
	defer client.Close()
	// Open a session
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("%s - Failed to create session: %s", host, err)
	}
	defer session.Close()

	err = session.RequestPty("xterm", 80, 40, ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	})
	if err != nil {
		log.Fatalf("%s - Unable to start session: %s", host, err)
		fyne.Do(func() {
			progBar.SetValue(progBar.Value + progress.step)
		})	
	}

	var configT bool = false
	var outputFinished bool = false
	var outputArray []string
	stdinBuf, err := session.StdinPipe()
	if err != nil {
		log.Fatalf("%s - Unable to start session: %s", host, err)
		fyne.Do(func() {
			progBar.SetValue(progBar.Value + progress.step)
		})
	}
	stdoutPipe, err := session.StdoutPipe()
    if err != nil {
        log.Fatalf("Error obtaining stdout pipe: %v", err)
    }
	session.Shell()
	m.Lock()

	scanner := bufio.NewScanner(stdoutPipe)
	// first round we're just making sure the device loads, no need to return. 
	// This should probably be cleaned up to have some handling if we don't get a device interface for some reason similar to below.
	time.Sleep(5 * time.Second)	
	// The command has been sent to the device, but you haven't gotten output back yet.
	stdinBuf.Write([]byte("terminal length 0\n"))
	time.Sleep(200 * time.Millisecond) //TODO: Might not need, but this ensures commands are applied. Needs rigorous testing.

	fmt.Println("Commands started")
	for _, command := range userScript {
		if strings.Contains(command, "config t") {
			configT = true
		}
		if command == "exit" || command == "end" {
			configT = false
		}
		stdinBuf.Write([]byte(command + "\n"))
		time.Sleep(200 * time.Millisecond) //TODO: Might not need, but this ensures commands are applied. Needs rigorous testing.
	}
	
	//makes sure you're at the lowest level before running terminal command or it won't work.
	if configT {
		stdinBuf.Write([]byte("end\n"))
	}		
	time.Sleep(200 * time.Millisecond) //TODO: Might not need, but this ensures commands are applied. Needs rigorous testing.
	stdinBuf.Write([]byte("terminal length 32\n\n"))
	outputFinished, outputArray = cred.WatchForOutput(outputArray, scanner)
	outputArray, failedCommand := output.Process(outputArray, *originalOutput)
	outputString := fmt.Sprintf("\n#####################  %s  #####################\n%s", host, altCreds)
	if !outputFinished {
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
		fyne.Do(func() {
			outputCMD.Text = fmt.Sprintf("%s\n\n%s\n", outputString, strings.TrimSpace(strings.Join(outputArray, "\n"))) + outputCMD.Text
			outputCMD.Refresh()
		})
	} else {
		//Newline needed when outputting to console for output array join.
		fmt.Printf("%s\n\n%s\n", outputString, strings.TrimSpace(strings.Join(outputArray, "\n")))
	}
	if failedCommand {
		progress.failedCommandsDevices = append(progress.failedCommandsDevices, host)
		progress.failedCommands = append(progress.failedCommands, strings.Join(userScript, ","))
		log.Printf("%s - Command not applied to switch.", host)
	} else {
		progress.connectedDevices = append(progress.connectedDevices, host)
	}
	fyne.Do(func() {
		progBar.SetValue(progBar.Value + progress.step)
		progBar.Hide()
	})
	m.Unlock()
	return nil
}

func (cred *CRED) WatchForOutput(outputArray []string, scanner *bufio.Scanner) (bool, []string) {
	// Then you'll want to wait for the response, and watch the stdout buffer for output.
	i := 0
	for scanner.Scan() {
        // Process line-by-line output here
		outputArray = append(outputArray, strings.TrimSpace(scanner.Text()))
		outputLastLine := strings.TrimSpace(outputArray[len(outputArray)-1])
		if len(outputArray) > 3 && strings.HasSuffix(outputLastLine, "#") {
			fmt.Println("Completed")
			break
		}
		i++
	}

	return true, outputArray
}
