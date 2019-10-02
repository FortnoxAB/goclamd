package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/fortnoxab/goclamd"
)

func main() {
	fmt.Println("vim-go")
	scanner := goclamd.NewStreamScanner("192.168.3.57:30028")

	err := scanner.Ping()
	log.Printf("Ping error: %v\n", err)

	data := bytes.NewBuffer(goclamd.EICAR)
	err = scanner.Scan(data)
	log.Println(err)

	okData := bytes.NewBufferString("clean")
	err = scanner.Scan(okData)
	log.Println(err)
}
