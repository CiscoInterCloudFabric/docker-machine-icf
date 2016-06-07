package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/joeswaminathan/docker-machine-icf/icf"
)

func main() {
	plugin.RegisterDriver(icf.NewDriver("", ""))
}
