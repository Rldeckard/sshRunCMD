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
	r := bufio.NewReader(os.Stdin)
	_, err := fmt.Fprint(os.Stderr, fmt.Sprintf("%s ", label))
	if err != nil {
		log.Fatal(err)
	}
	if label == "Password:" {
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
		s = string(bytePassword)
	} else {
		for {
			s, _ = r.ReadString('\n')
			if s != "" {
				break
			}
		}
	}
	return strings.TrimSpace(s)
}

// Prompt for user input and return an array of strings. Each line is its own string.
// To exit the function do an empty return (hit enter on a new line).
func List(label string) []string {
	fmt.Println("\n" + label)
	scanner := bufio.NewScanner(os.Stdin)

	var lines []string
	for {
		scanner.Scan()
		line := scanner.Text()

		// break the loop if line is empty
		if len(line) == 0 {
			break
		}
		lines = append(lines, line)
	}

	err := scanner.Err()
	if err != nil {
		log.Fatal(err)
	}

	return lines
}

// Obligitory wrapper for fmt.Scan(). No need to use a weird pointer, the returned value is the user string.
func Scan(label string) string {
	var userInput string

	fmt.Println(label)

	fmt.Scan(&userInput)

	return userInput

}
