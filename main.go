package main

// Author: Valentin Kuznetsov <vkuznet [AT] gmain [DOT] com>

import (
	"flag"
	"log"
)

func main() {
	var config string
	flag.StringVar(&config, "config", "", "config file")
	flag.Parse()

	// read configuration
	parseConfig(config)

	log.Printf("Server configuration %+v", Config)

	if Config.Verbose > 0 {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// start HTTP server
	server()
}
