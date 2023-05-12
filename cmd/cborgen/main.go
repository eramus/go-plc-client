package main

import (
	"github.com/eramus/go-plc-client"

	cbor "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbor.WriteMapEncodersToFile("../../cbor_gen.go", "plc",
		plc.Update{},
		plc.Create{},
		plc.Tombstone{},
		plc.Service{},
	); err != nil {
		panic(err)
	}
}
