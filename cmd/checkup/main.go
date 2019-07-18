package main

import (
	"log"
	"os"

	"github.com/sourcegraph/checkup/cmd"
)

var std = log.New(os.Stdout, "", log.LstdFlags)

func main() {
	log.SetOutput(os.Stdout)
	std.Println("health check start.")
	cmd.Execute()
}
