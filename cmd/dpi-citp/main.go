// dpi-citp — клиент CITP для DPI-бенчмарка (dpi-bench/).
//
// Поднимает ОДИН сеанс CITP (рукопожатие + мультиплексор, как в приложении)
// и пробрасывает локальный TCP-порт на цель через ноду: workload.py ходит
// на 127.0.0.1:<port> и получает ровно тот же провод, что даёт приложение.
//
//	dpi-citp -genkey                     → приватный и публичный ключ устройства
//	dpi-citp -node 10.200.2.1:9443 -pub <ключ ноды> -key <ключ устройства> \
//	         -listen 127.0.0.1:18080 -target 10.200.2.1:8080 [-cbr 40ms -flavor auto]
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"chameleon/internal/chameleon"
)

func main() {
	genkey := flag.Bool("genkey", false, "сгенерировать ключ устройства и выйти")
	node := flag.String("node", "", "адрес ноды host:port")
	pub := flag.String("pub", "", "публичный ключ ноды (base64)")
	key := flag.String("key", "", "приватный ключ устройства (base64)")
	listen := flag.String("listen", "127.0.0.1:18080", "локальный порт проброса")
	target := flag.String("target", "", "цель host:port (открывается через ноду)")
	cbr := flag.Duration("cbr", 0, "клиентский CBR-шейпер (0 = выкл, как в приложении)")
	flavor := flag.String("flavor", "auto", "маска ритма шейпера")
	tlsrec := flag.Bool("tlsrec", false, "предварять hello заголовком TLS-записи (исключение FET)")
	flag.Parse()
	chameleon.ClientTLSRecord = *tlsrec
	if *genkey {
		priv, pubk, err := chameleon.GenerateNodeKey()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(priv, pubk)
		return
	}
	if *node == "" || *pub == "" || *key == "" || *target == "" {
		flag.Usage()
		os.Exit(2)
	}
	conn, err := chameleon.DialNode(*node, *pub, *key, 10*time.Second)
	if err != nil {
		log.Fatalf("рукопожатие: %v", err)
	}
	if *cbr > 0 {
		f := chameleon.FlavorByName(*flavor, nil)
		conn.StartShaper(f.Base, f.Jitter, f.MinPad, f.MaxPad, "c2s-cbr")
	}
	m := chameleon.NewMuxClient(conn)
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("dpi-citp: сеанс к %s готов, проброс %s → %s", *node, *listen, *target)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			s, err := m.Open(*target)
			if err != nil {
				log.Printf("open: %v", err)
				return
			}
			defer s.Close()
			go func() { _, _ = io.Copy(s, c) }()
			_, _ = io.Copy(c, s)
		}(c)
	}
}
