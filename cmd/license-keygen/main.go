package main

import (
	"chameleon/internal/activation"
	"flag"
	"fmt"
	"log"
)

func main() {
	private := flag.String("private", "", "new protected PKCS8 file; never commit")
	public := flag.String("public", "", "public trust JSON file")
	kid := flag.String("kid", "", "public key id")
	flag.Parse()
	if *private == "" || *public == "" || *kid == "" {
		log.Fatal("required: -private -public -kid")
	}
	if e := activation.GenerateFiles(*private, *public, *kid); e != nil {
		log.Fatal(e)
	}
	fmt.Println("Created Ed25519 issuer and public trust set; private material was not printed.")
}
