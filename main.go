package main

// Author: Valentin Kuznetsov <vkuznet [AT] gmain [DOT] com>

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

// version of the code
var gitVersion string

// Info function returns version string of the server
func info() string {
	goVersion := runtime.Version()
	tstamp := time.Now().Format("2006-02-01")
	return fmt.Sprintf("2fa-server git=%s go=%s date=%s", gitVersion, goVersion, tstamp)
}

func main() {
	var config string
	flag.StringVar(&config, "config", "", "config file")
	var version bool
	flag.BoolVar(&version, "version", false, "Show version")
	flag.Parse()
	if version {
		fmt.Println(info())
		os.Exit(0)

	}

	// read configuration
	parseConfig(config)

	log.Printf("Server configuration %+v", Config)

	if Config.Verbose > 0 {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// start HTTP server
	server()
}
