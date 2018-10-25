# mitm - mitm is a SSL-capable man-in-the-middle proxy for use with golang net/http.

It is heavily inspired by the mitmproxy project (https://mitmproxy.org/). Forked from https://github.com/kr/mitm, the original authors.

## Install

	go get github.com/zapier/mitm

## Usage

Let's say you have `example.go` like this:

```go
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/zapier/mitm"
)

var (
	hostname, _ = os.Hostname()

	dir      = path.Join(os.Getenv("HOME"), ".mitm")
	keyFile  = path.Join(dir, "ca-key.pem")
	certFile = path.Join(dir, "ca-cert.pem")
)

func main() {
	ca, err := loadCA()
	if err != nil {
		log.Fatal(err)
	}
	p := &mitm.Proxy{
		CA: &ca,
		TLSServerConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			//CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
		Wrap: cloudToButt,
	}
	log.Fatal(http.ListenAndServe(":8080", p))
}

func loadCA() (cert tls.Certificate, err error) {
	// TODO(kr): check file permissions
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if os.IsNotExist(err) {
		cert, err = genCA()
	}
	if err == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	}
	return
}

func genCA() (cert tls.Certificate, err error) {
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return
	}
	certPEM, keyPEM, err := mitm.GenCA(hostname)
	if err != nil {
		return
	}
	cert, _ = tls.X509KeyPair(certPEM, keyPEM)
	err = ioutil.WriteFile(certFile, certPEM, 0400)
	if err == nil {
		err = ioutil.WriteFile(keyFile, keyPEM, 0400)
	}
	return cert, err
}

type cloudToButtResponse struct {
	http.ResponseWriter

	sub         bool
	wroteHeader bool
}

func (w *cloudToButtResponse) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	ctype := w.Header().Get("Content-Type")
	if strings.HasPrefix(ctype, "text/html") {
		w.sub = true
	}
	w.ResponseWriter.WriteHeader(code)
}

var (
	cloud = []byte("the cloud")
	butt  = []byte("my   butt")
)

func (w *cloudToButtResponse) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(200)
	}
	if w.sub {
		p = bytes.Replace(p, cloud, butt, -1)
	}
	return w.ResponseWriter.Write(p)
}

func cloudToButt(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Accept-Encoding", "")
		upstream.ServeHTTP(&cloudToButtResponse{ResponseWriter: w}, r)
	})
}
```

To see it in action, try this:

```bash
go run example.go

# in another tab
curl -Lv --proxy http://localhost:1080 --cacert ~/.mitm/ca-cert.pem https://techcrunch.com/2018/07/27/the-cloud-continues-to-grow-in-leaps-and-bounds-but-its-still-awss-world/
```

Now look at the content, there should be "my   butt" in a few places.
