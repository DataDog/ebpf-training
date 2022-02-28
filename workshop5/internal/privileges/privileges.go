package privileges

import (
	"log"
	"os/user"
	"runtime/debug"
)

// AbortIfNotRoot checks the current user permissions, if the permissions are not elevated, we abort.
func AbortIfNotRoot() {
	current, err := user.Current()
	if err != nil {
		log.Panic(err)
	}

	if current.Uid != "0" {
		log.Panic("sniffer must run under superuser privileges")
	}
}

// RecoverFromCrashes is a defer function that caches all panics being thrown from the application.
func RecoverFromCrashes() {
	if err := recover(); err != nil {
		log.Printf("Application crashed: %v\nstack: %s\n", err, string(debug.Stack()))
	}
}
