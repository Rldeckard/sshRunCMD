package prompt

import (
	"bufio"
	"fmt"
	"golang.org/x/term"
	"log"
	"os"
	"strings"
	"syscall"
)

// Prompts for user input, and securely prompts for password if "Password:" is the given label.
// Required for passwords as it's grabbing the Stdin and processing. Can't use ReadPassword standalone
func Credentials(label string) string {
	var s string
	fmt.Printf("%s ", label)
	if label == "Password:" {
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
		s = string(bytePassword)
	} else {
		fmt.Scan(&s)
	}
	return strings.TrimSpace(s)
}

// Prompt for user input and return an array of strings. Each line is its own string.
// To exit the function do an empty return (hit enter on a new line).
func List(label string) []string {
	var lines []string
	r := bufio.NewReader(os.Stdin)
	_, err := fmt.Fprint(os.Stderr, fmt.Sprintf("%s\n", label))
	test, _ := r.ReadString('\n') //discards any newlines that could force an exit before processing user input.
	if test != "\r\n" {           //collects legit enteries for when newReader is working properly
		lines = append(lines, strings.Trim(test, "\r\n"))
	}
	if err != nil {
		log.Fatal(err)
	}

	for {
		line, _ := r.ReadString('\n')
		if line == "\r\n" {
			break
		}
		lines = append(lines, strings.Trim(line, "\r\n"))
	}
	return lines
}

// Obligitory wrapper for fmt.Scan(). No need to use a weird pointer, the returned value is the user string.
func Scan(label string) string {
	var userInput string

	fmt.Print(label)

	fmt.Scan(&userInput)
	return userInput

}

// This functions whole job is to allow you to stop at the end of a program and digest the output before closing. Press Enter to continue...
func Pause() {
	r := bufio.NewReader(os.Stdin)
	_, _ = fmt.Fprint(os.Stderr, "\n\nPress Enter to continue...")
	_, _ = r.ReadString('\n')
}
