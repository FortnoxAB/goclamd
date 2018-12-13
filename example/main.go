package main

import (
	"bytes"
	"fmt"

	"github.com/fortnoxab/goclamd"
	"github.com/sirupsen/logrus"
)

func main() {
	fmt.Println("vim-go")
	scanner := goclamd.NewStreamScanner("192.168.3.57:30028")

	err := scanner.Ping()
	logrus.Info("Ping error: ", err)

	data := bytes.NewBuffer(goclamd.EICAR)
	err = scanner.Scan(data)
	logrus.Info(err)

	okData := bytes.NewBufferString("clean")
	err = scanner.Scan(okData)
	logrus.Info(err)

}
