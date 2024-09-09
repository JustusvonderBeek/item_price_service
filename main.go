package main

import (
	"flag"
	"io"
	"log"
	"os"
)

func main() {
	config := createConfig()
	setupLogger(config.Logfile)

}

func createConfig() Config {
	addr := flag.String("a", "0.0.0.0", "Listen address")
	port := flag.String("p", "46155", "Listen port")
	logfile := flag.String("l", "server.log", "The logfile location")
	dbConfig := flag.String("c", "resources/db.json", "The database configuration file")
	tlscert := flag.String("cert", "resources/shoppinglist.crt", "The location of the TLS Certificate")
	tlskey := flag.String("key", "resources/shoppinglist.pem", "THe location of the TLS keyfile")
	flag.Parse()

	return Config{
		Logfile:        *logfile,
		ListenAddr:     *addr,
		ListenPort:     *port,
		TLSCertificate: *tlscert,
		TLSKeyfile:     *tlskey,
		DisableTLS:     false,

		DatabaseConfigFile: *dbConfig,
	}
}

func setupLogger(logfile string) {
	logFile, err := os.OpenFile(logfile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0640)
	if err != nil {
		panic(err)
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)
}
