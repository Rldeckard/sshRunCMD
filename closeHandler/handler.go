package closeHandler

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Setup a listener thorugh a seperate Go Routine to Catch ^C and gracefully shutdown.
func Listener() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n- Ctrl+C pressed in Terminal. Gracefully shutting down.")
		os.Exit(1)
	}()
	return
}
