package main

// This is to ensure voting.

import (
	"github.com/gredinger/rfc/apps/Vote/app"
)

func main() {
	a := app.App{}
	a.Initialize("settings.ini")
	a.Run()
}
