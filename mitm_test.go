package mitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

var hostname, _ = os.Hostname()

func init() {
	flag.Parse()
}

func genTestCA() (cert tls.Certificate, err error) {
	certPEM, keyPEM, err := GenerateCertificateAuthority(hostname)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	return cert, err
}

type capsWriterResponse struct {
	http.ResponseWriter
}

var (
	before = []byte("illustrative")
	after  = []byte("ILLUSTRATIVE")
)

func (w *capsWriterResponse) Write(p []byte) (int, error) {
	// log.Printf(hex.Dump(p))
	// log.Printf(string(p))
	p = bytes.Replace(p, before, after, -1)
	return w.ResponseWriter.Write(p)
}

func capitalizer(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// very important, proxy would need to handle encoding otherwise
		r.Header.Set("Accept-Encoding", "")
		upstream.ServeHTTP(&capsWriterResponse{ResponseWriter: w}, r)
	})
}

func TestLiveNet(t *testing.T) {
	ca, err := genTestCA()
	if err != nil {
		log.Fatal(err)
	}

	p := &Proxy{
		CA: &ca,
		TLSServerConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		Wrap: capitalizer,
	}

	listenAddr := ":7997"
	go func() {
		log.Fatal(http.ListenAndServe(listenAddr, p))
	}()
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(r *http.Request) (*url.URL, error) {
				u := *r.URL
				u.Scheme = "http"
				u.Host = listenAddr
				log.Println("proxy through:", listenAddr)
				return &u, nil
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	log.Println("requesting:", req.URL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("Do:", err)
	}
	got, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("ReadAll:", err)
	}
	if code := resp.StatusCode; code != 200 {
		t.Errorf("want code 200, got %d", code)
	}
	if g := string(got); !strings.Contains(g, "Example Domain") {
		t.Errorf("want example domain, got %q", g)
	}
	if g := string(got); !strings.Contains(g, "ILLUSTRATIVE") {
		t.Errorf("want ILLUSTRATIVE, got %q", g)
	}
}
