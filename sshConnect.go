package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Rldeckard/sshRunCMD/dialSSHClient"
	"github.com/Rldeckard/sshRunCMD/processOutput"
	"golang.org/x/crypto/ssh"
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
		progBar.SetValue(progBar.Value + progress.step)
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
				progBar.SetValue(progBar.Value + progress.step)
				return fmt.Errorf("%s - %s", host, err)
			} else {
				altCreds = "Using Alternate Credentials"
			}
		} else {
			progress.unauthedDevices = append(progress.unauthedDevices, host)
			progBar.SetValue(progBar.Value + progress.step)
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
		progBar.SetValue(progBar.Value + progress.step)
	}

	var stdoutBuf bytes.Buffer
	var configT bool = false
	var outputFinished bool = false
	var outputArray []string
	session.Stdout = &stdoutBuf

	stdinBuf, err := session.StdinPipe()
	if err != nil {
		log.Fatalf("%s - Unable to start session: %s", host, err)
		progBar.SetValue(progBar.Value + progress.step)
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
		outputCMD.Text = fmt.Sprintf("%s\n\n%s\n", outputString, strings.TrimSpace(strings.Join(outputArray, "\n"))) + outputCMD.Text
		outputCMD.Refresh()

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
	progBar.SetValue(progBar.Value + progress.step)
	m.Unlock()
	return nil
}
