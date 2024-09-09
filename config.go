package main

type Config struct {
	Logfile string

	ListenAddr string
	ListenPort string

	TLSCertificate string
	TLSKeyfile     string
	DisableTLS     bool

	DatabaseConfigFile string

	JWTSecretFile string
}
