package main

import (
	"./models"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

var logger *log.Logger

type Configuration struct {
	Address      string
	ReadTimeout  int64
	WriteTimeout int64
	Static       string
}

var config Configuration

func init() {
	models.Dbinit()
	loadConfig()

}

func loadConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		fmt.Println("Cannot open config file", err)
	}
	decoder := json.NewDecoder(file)
	config = Configuration{}
	err = decoder.Decode(&config)
	if err != nil {
		fmt.Println("Cannot get configuration from file", err)
	}
}
func p(a ...interface{}) {
	fmt.Println(a)
}

func version() string {
	return "0.1"
}
func danger(args ...interface{}) {
	logger.SetPrefix("ERROR ")
	logger.Println(args...)
}
