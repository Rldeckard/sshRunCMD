package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// SetupCloseHandler : Catch ^C and gracefully shutdown.
func SetupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n- Ctrl+C pressed in Terminal. Gracefully shutting down.")
		os.Exit(1)
	}()
	return
}
