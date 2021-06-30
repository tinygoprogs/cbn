package main

import (
	"bogo/cbn"
	"golang.org/x/net/proxy"
	"log"
	"net/http"
	"os"
)

func main() {
	// proxy for debugging: mitmproxy --mode socks5 -p 1080 -v
	socksproxy := "localhost:1080"
	socks5dial, err := proxy.SOCKS5("tcp", socksproxy, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("proxy.SOCKS5 @ '%v' failed: %v", socksproxy, err)
	}
	c := http.Client{
		Transport: &http.Transport{
			Dial:              socks5dial.Dial,
			DisableKeepAlives: false, // ???
		},
	}
	api := cbn.NewCBNAgent("http://192.168.0.1", &cbn.CBNConfig{
		HttpClient: &c,
		Username:   os.Getenv("CBN_USR"),
		Password:   os.Getenv("CBN_PW"),
	})
	err = api.Authenticate()
	if err != nil {
		log.Fatal(err)
	}
}
