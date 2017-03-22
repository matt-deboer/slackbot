package main

import (
	_ "github.com/matt-deboer/slackbot/importer"
	"github.com/matt-deboer/slackbot/robots"
	"github.com/matt-deboer/slackbot/server"
)

func main() {
	server.Main(robots.Robots)
}
