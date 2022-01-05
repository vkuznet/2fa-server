package main

// configuration module

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// Configuration stores dbs configuration parameters
type Configuration struct {
	Port      int    `json:"port"`      // port number
	StaticDir string `json:"staticdir"` // location of static directory
	Verbose   int    `json:"verbose"`   // verbosity level
	DBFile    string `json:"dbfile"`    // dbfile name
	Templates string `json:"templates"` // server templates
}

// Config represents global configuration object
var Config Configuration

// String returns string representation of dbs Config
func (c *Configuration) String() string {
	data, err := json.Marshal(c)
	if err != nil {
		log.Println("ERROR: fail to marshal configuration", err)
		return ""
	}
	return string(data)
}

// parseConfig parses given configuration file and initialize Config object
func parseConfig(configFile string) {
	// default values
	Config.Port = 12345
	Config.DBFile = "users.db"
	Config.Verbose = 0
	path, err := os.Getwd()
	if err != nil {
		log.Println("unable to get current directory", err)
		path = "."
	}
	Config.StaticDir = fmt.Sprintf("%s/static", path)
	Config.Templates = fmt.Sprintf("%s/static/tmpl", path)

	// read config file
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Println("unable to read file", err)
	}
	err = json.Unmarshal(data, &Config)
	if err != nil {
		log.Println("unable to unmarshal config data", err)
	}
}
