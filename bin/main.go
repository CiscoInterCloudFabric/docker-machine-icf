package main

import (
	"github.com/CiscoInterCloudFabric/docker-machine-icf/icf"
	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(icf.NewDriver("", ""))
}
