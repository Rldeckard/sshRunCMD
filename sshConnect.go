package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"bufio"
	"context"



	"github.com/Rldeckard/sshRunCMD/dialSSHClient"
	"github.com/Rldeckard/sshRunCMD/processOutput"
	"golang.org/x/crypto/ssh"
	"fyne.io/fyne/v2"
)

// Run command against a host
func (cred *CRED) SSHConnect(user string, pass string, userScript []string, host string, m *sync.Mutex, isLegacy bool) error {
	localCred := *cred
	config := connect.Init(user, pass, "", isLegacy)
	altCreds := ""

	stats, err := connect.IsAlive(host, localCred.pingCount, localCred.pingTimeout) // get send/receive/rtt stats
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
	client, err := connect.DialClient(host, config)
	if err != nil {
		if cred.fallbackUser != "" && strings.Contains(err.Error(), "Authentication Failed") {
			fmt.Println("Testing Fallback credentials")
			connect.UpdateUser(cred.fallbackUser, &config)
			connect.UpdatePass(cred.fallbackPass, &config)
			client, err = connect.DialClient(host, config)
			if err != nil {
				progress.unauthedDevices = append(progress.unauthedDevices, host)
				fyne.Do(func() {
					progBar.SetValue(progBar.Value + progress.step)
				})				
				return fmt.Errorf("%s - %w", host, err)
			} else {
				altCreds = "Using Alternate Credentials"
			}
		} else {
			progress.unauthedDevices = append(progress.unauthedDevices, host)
			fyne.Do(func() {
					progBar.SetValue(progBar.Value + progress.step)
			})	
			return fmt.Errorf("%s - %w", host, err)
		}
	}
	defer client.Close()
	// Open a session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("%s - Failed to create session: %s", host, err)
	}
	defer session.Close()
	var terminalType string
	if cred.typeDropDown.SelectedIndex() == 0 {
		terminalType = "vt100"

	} else {
		terminalType = "dumb"
	}

	err = session.RequestPty(terminalType, 80, 40, ssh.TerminalModes{
		ssh.ECHO:          1,     // enable echoing
		ssh.TTY_OP_ISPEED: 115200, 
		ssh.TTY_OP_OSPEED: 115200,
	})
	if err != nil {
		fyne.Do(func() {
			progBar.SetValue(progBar.Value + progress.step)
		})	
		return fmt.Errorf("%s - Unable to start session: %s", host, err)

	}
	defer func() {
    	log.Printf("host=%s: exiting SSHConnect, client will be closed", host)
	}()


	var configT bool = false
	var outputFinished bool = false
	var outputArray []string
	stdinBuf, err := session.StdinPipe()
	if err != nil {
		fyne.Do(func() {
			progBar.SetValue(progBar.Value + progress.step)
		})
		return fmt.Errorf("%s - Unable to start session: %s", host, err)

	}
	stdoutPipe, err := session.StdoutPipe()
    if err != nil {
        return fmt.Errorf("error obtaining stdout pipe: %v", err)
    }
	session.Shell()
	appCtx, endApplication := context.WithCancel(context.Background())
	defer endApplication()
	go func() {
		time.Sleep(30 * time.Second)
		select {
        case <-appCtx.Done():
            // main has finished or decided to cancel; exit goroutine
            return
        default:
            log.Printf("host=%s: Force closing ssh connnection", host)
			client.Close()
			session.Close()
        }
		
	}()
	scanner := bufio.NewScanner(stdoutPipe)
	// This should probably be cleaned up to have some handling if we don't get a device interface for some reason similar to below.
	time.Sleep(5 * time.Second)	
	// The command has been sent to the device, but you haven't gotten output back yet.
	// 0 = "Network Devices"
	// 1 = "Servers"
	if cred.typeDropDown.SelectedIndex() == 0 {
		stdinBuf.Write([]byte("terminal length 0\n"))
	}
	time.Sleep(200 * time.Millisecond) //TODO: Might not need, but this ensures commands are applied. Needs rigorous testing.
	for _, command := range userScript {
		if cred.typeDropDown.SelectedIndex() == 0 {
			if strings.Contains(command, "config t") {
				configT = true
			}
			if command == "exit" || command == "end" {
				configT = false
			}
		}
		stdinBuf.Write([]byte(command + "\n"))
		time.Sleep(200 * time.Millisecond) //TODO: Might not need, but this ensures commands are applied. Needs rigorous testing.
	}
	
	//makes sure you're at the lowest level before running terminal command or it won't work.
	if cred.typeDropDown.SelectedIndex() == 0 {
		if configT {
			stdinBuf.Write([]byte("end\n"))
		}
		time.Sleep(200 * time.Millisecond) //TODO: Might not need, but this ensures commands are applied. Needs rigorous testing.
		stdinBuf.Write([]byte("terminal length 32\n\n"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()
	outputFinished, outputArray = cred.WatchForOutput(ctx, outputArray, scanner)
	m.Lock()
	outputArray, failedCommand := output.Process(outputArray, *originalOutput)
	outputString := fmt.Sprintf("\n#####################  %s  #####################\n%s", host, altCreds)
	if !outputFinished {
		outputString = outputString + "\nWARNING: Incomplete Output"
	}
	if *fileOutput {
		f, err := os.OpenFile("output.txt",
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("please close output.txt before running program")
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
	
	m.Unlock()
	fyne.Do(func() {
		progBar.SetValue(progBar.Value + progress.step)
	})
	return nil
}

func (cred *CRED) WatchForOutput(ctx context.Context, outputArray []string, scanner *bufio.Scanner) (bool, []string) {
	// Then you'll want to wait for the response, and watch the stdout buffer for output.
	i := 0
	for scanner.Scan() {
        // Process line-by-line output here
		outputArray = append(outputArray, strings.TrimSpace(scanner.Text()))
		outputLastLine := strings.TrimSpace(outputArray[len(outputArray)-1])
		if len(outputArray) > 3 && (strings.HasSuffix(outputLastLine, "#") || strings.HasSuffix(outputLastLine, "$")) {
			break
		}
		select{
 		case <-ctx.Done():
			return false, outputArray
		default:
			i++
			continue
		}
	}

	return true, outputArray
}
