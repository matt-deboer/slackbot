package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	//"strconv"
	"time"
)

type CertHandler struct {
	certMap map[string]tls.Certificate
}

type CertInfo struct {
	cert      *tls.Certificate
	touchedAt time.Time
}

func (m *CertHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Print debug info
	fmt.Println(r.Host)
	fmt.Println(r.Method)
	fmt.Println(r.RequestURI)
	fmt.Println(r.URL) // has many keys, such as Query
	for k, v := range r.Header {
		fmt.Println(k, v)
	}

	fmt.Println(r.Body)
	fmt.Println()
	fmt.Println()

	// End the request
	// TODO serve from hosting directory
	fmt.Fprintf(w, "Hi there, %s %q? Wow!\n\nWith Love,\n\t%s", r.Method, r.URL.Path[1:], r.Host)
}

func StartServerSSL() {

	port := os.Getenv("PORT")
	certsPath := os.Getenv("SLACK_SSL_CERT_PATH")
	defaultHost := os.Getenv("SLACK_SSL_HOST_NAME")

	host := strings.ToLower(defaultHost)
	// See https://groups.google.com/a/letsencrypt.org/forum/#!topic/ca-dev/l1Dd6jzWeu8
	/*
		if strings.HasPrefix("www.", host) {
			fmt.Println("TODO: 'www.' prefixed certs should be obtained for every 'example.com' domain.")
		}
		host = strings.TrimPrefix("www.", host)
	*/

	fmt.Printf("Loading Certificates %s/%s/{privkey.pem,fullchain.pem}\n", certsPath, defaultHost)
	privkeyPath := filepath.Join(certsPath, defaultHost, "privkey.pem")
	certPath := filepath.Join(certsPath, defaultHost, "fullchain.pem")
	defaultCert, err := tls.LoadX509KeyPair(certPath, privkeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't load default certificates: %s\n", err)
		os.Exit(1)
	}

	addr := ":" + port //strconv.Itoa(int(port))

	conn, err := net.Listen("tcp", addr)
	if nil != err {
		fmt.Fprintf(os.Stderr, "Couldn't bind to TCP socket %q: %s\n", addr, err)
		os.Exit(1)
	}

	certMap := make(map[string]CertInfo)
	tlsConfig := new(tls.Config)
	tlsConfig.Certificates = []tls.Certificate{defaultCert}
	tlsConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {

		// Load from memory
		// TODO unload untouched certificates every x minutes
		if CertInfo, ok := certMap[clientHello.ServerName]; ok {
			CertInfo.touchedAt = time.Now()
			return CertInfo.cert, nil
		}

		privkeyPath := filepath.Join(certsPath, clientHello.ServerName, "privkey.pem")
		certPath := filepath.Join(certsPath, clientHello.ServerName, "fullchain.pem")

		loadCert := func() *tls.Certificate {
			// TODO handle race condition (ask Matt)
			// the transaction is idempotent, however, so it shouldn't matter
			if _, err := os.Stat(privkeyPath); err == nil {
				fmt.Printf("Loading Certificates %s/%s/{privkey.pem,fullchain.pem}\n\n", certsPath, clientHello.ServerName)
				cert, err := tls.LoadX509KeyPair(certPath, privkeyPath)
				if nil != err {
					return &cert
				}
				return nil
			}

			return nil
		}

		if cert := loadCert(); nil != cert {
			certMap[clientHello.ServerName] = CertInfo{
				cert:      cert,
				touchedAt: time.Now(),
			}
			return cert, nil
		}

		// TODO try to get cert via letsencrypt python client
		// TODO check for a hosting directory before attempting this
		/*
			cmd := exec.Command(
				"./venv/bin/letsencrypt",
				"--text",
				"--agree-eula",
				"--email", "coolaj86@gmail.com",
				"--authenticator", "standalone",
				"--domains", "www.example.com",
				"--domains", "example.com",
				"--dvsni-port", "65443",
				"auth",
			)
			err := cmd.Run()
			if nil != err {
				if cert := loadCert(); nil != cert {
					return cert, nil
				}
			}
		*/

		fmt.Fprintf(os.Stderr, "Failed to load certificates for %q.\n", clientHello.ServerName)
		fmt.Fprintf(os.Stderr, "\tTried %s/{privkey.pem,fullchain.pem}\n", filepath.Join(certsPath, clientHello.ServerName))
		//fmt.Fprintf(os.Stderr, "\tand letsencrypt api\n")
		fmt.Fprintf(os.Stderr, "\n")
		// TODO how to prevent attack and still enable retry?
		// perhaps check DNS and hosting directory, wait 5 minutes?
		certMap[clientHello.ServerName] = CertInfo{
			cert:      &defaultCert,
			touchedAt: time.Now(),
		}
		return &defaultCert, nil
	}
	tlsListener := tls.NewListener(conn, tlsConfig)

	server := &http.Server{
		Addr:    addr,
		Handler: &CertHandler{},
	}
	fmt.Printf("Listening on https://%s:%d\n\n", host, port)
	server.Serve(tlsListener)
}
