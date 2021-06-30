package cbn

import (
	"log"
	"net/http"
	"net/url"
	"strings"
)

// url-encode vals
func EncodeVals(vals url.Values) string {
	var r string
	for k, v := range vals {
		r += k + "=" + strings.Join(v, ",") + "&"
	}
	r = r[:len(r)-1] // strip the last "&" ^
	return r
}

// handle for http-sessions
type Agent struct {
	Header       map[string][]string
	BaseUrl      string
	UserAgent    string
	Client       *http.Client
	ResponseHook func(*http.Response)
}

func (a *Agent) NewRequestV(method string, url string, vals url.Values) *http.Request {
	return a.NewRequest(method, url, EncodeVals(vals))
}

func (a *Agent) NewRequest(method string, url string, body string) *http.Request {
	req, err := http.NewRequest(method, a.BaseUrl+url, strings.NewReader(body))
	if err != nil {
		log.Fatalf("method=%v, url=%v, body=%v: %v", method, url, body, err)
	}
	req.Header.Set("User-Agent", a.UserAgent)
	for key, val := range a.Header {
		req.Header.Set(key, strings.Join(val, ";"))
	}
	return req
}

// log+terminate on error
func (a *Agent) Do(r *http.Request) *http.Response {
	rsp, err := a.Client.Do(r)
	if err != nil {
		log.Fatalf("Request[\n%v\n] --Response--> [\n%v\n]", r, err)
	}
	return rsp
}
