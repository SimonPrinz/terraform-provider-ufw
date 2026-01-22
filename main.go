package main

import (
	"context"
	"flag"
	"log"

	"github.com/SimonPrinz/terraform-provider-ufw/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var (
	version string = "dev"
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "debug support")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/simonprinz/ufw",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
