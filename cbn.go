package cbn

import (
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// used for all that ajax xml back and forth
var xmlHeaders = map[string][]string{
	"Referer":          {"http://192.168.0.1/common_page/login.html"},
	"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
	"X-Requested-With": {"XMLHttpRequest"},
	"Connection":       {"keep-alive"},
	"Accept":           {"application/xml, text/xml, */*; q=0.01"},
	"Accept-Language":  {"en-US,en;q=0.5"},
	"Accept-Encoding":  {"gzip, deflate"},
}

// unclear, why it is required, see header swtich below
var upgradeInsecureHeaders = map[string][]string{
	"Referer":                   {"http://192.168.0.1/"},
	"Connection":                {"keep-alive"},
	"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	"Accept-Language":           {"en-US,en;q=0.5"},
	"Accept-Encoding":           {"gzip, deflate"},
	"Upgrade-Insecure-Requests": {"1"},
	"If-Modified-Since":         {"Thu, 29 Mar 2018 02:17:52 GMT"},
}

type UserConfig struct {
	// if != "": save SessionID to this file
	SIDFile string
}

var DefaultUserConfig = UserConfig{
	SIDFile: ".cbn_sid",
}

type CBNConfig struct {
	Username   string
	Password   string
	HttpClient *http.Client
}

// cbn router api, can login + execute arbitrary ajax functions
type CBNAgent struct {
	Agent
	Config *CBNConfig
	User   *UserConfig
	Token  string
	SID    string
}

func NewCBNAgent(url string, c *CBNConfig, u ...*UserConfig) *CBNAgent {
	cbn := &CBNAgent{
		Config: c,
		User:   &DefaultUserConfig,
		Agent: Agent{
			BaseUrl: url,
			// required; cbn does not talk to golang/curl/..
			UserAgent: `Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0`,
			Header:    xmlHeaders,
			Client:    c.HttpClient,
		},
	}
	if len(u) == 1 {
		cbn.User = u[0]
	}
	return cbn
}

func (cbn *CBNAgent) updateCookies() {
	cookies := []string{"sessionToken=" + cbn.Token}
	if cbn.SID != "" {
		cookies = append(cookies, "SID="+cbn.SID)
	}
	cbn.Header["Cookie"] = cookies
}

// update sessionToken (and SID if available)
func (cbn *CBNAgent) updateSession(r *http.Response) []byte {
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("reading response body: %v", err)
	}
	cs := r.Cookies()
	if len(cs) == 0 {
		log.Println("[.] no cookies")
		return body
	}
	c := r.Cookies()[0]
	if c.Name != "sessionToken" {
		log.Fatalf("no sessionToken, response=%v, cookies=%v", r, r.Cookies())
	}
	cbn.Token = c.Value
	cbn.updateCookies()
	return body
}

// authenticate with the router
func (cbn *CBNAgent) Authenticate() error {
	_, err := os.Stat(cbn.User.SIDFile)
	if cbn.User.SIDFile == "" || os.IsNotExist(err) {
		return cbn.NewSID()
	} else {
		return cbn.AuthenticateWithSID()
	}
}

// authenticate with a known SID (read from config file)
func (cbn *CBNAgent) AuthenticateWithSID() error {
	data, err := ioutil.ReadFile(cbn.User.SIDFile)
	if err != nil {
		return errors.Wrap(err, "unable to read SIDFile")
	}
	sid := string(data)
	if len(sid) <= 4 {
		log.Printf("sid too short (likely wrong): %v", sid)
		return cbn.NewSID()
	}
	cbn.SID = sid
	cbn.Header["Cookie"] = []string{"SID=" + cbn.SID}
	rsp := cbn.Agent.Do(cbn.NewRequest("GET", "", ""))
	cbn.updateSession(rsp)
	return nil
}

// authenticate with username + password to receive a new SID
func (cbn *CBNAgent) NewSID() error {
	if cbn.Config.Username == "" || cbn.Config.Password == "" {
		return errors.New("missing environment variables: CBN_USR, CBN_PW")
	}

	// get an initial session token
	rsp := cbn.Agent.Do(cbn.NewRequest("GET", "", ""))
	cbn.updateSession(rsp)

	// setup (1/3)
	cbn.xmlGetter("24")

	// setup (2/3): seems like they wanted https redirects for logins, but gave
	// up half-way through
	cbn.Header = upgradeInsecureHeaders
	rsp = cbn.Agent.Do(cbn.NewRequest("POST", "/common_page/login.html", ""))
	cbn.Header = xmlHeaders
	cbn.updateSession(rsp)

	// setup (3/3)
	cbn.xmlGetter("3")

	// FIXME: sometimes the first setter.xml ajax command fails, because another
	// user is already logged in, might be avoidable by calling "N" again?

	// login
	data := cbn.xmlSetter(FLogin, url.Values{
		"Username": {cbn.Config.Username},
		"Password": {cbn.Config.Password},
	})
	// expecting: "successful;SID=987462656"
	s := string(data)
	if !strings.Contains(s, "successful") {
		// XXX: handle retries, in case the server disconnects us, because another
		// session was still open; maybe just 'retrun cbn.NewSID()' once?
		return errors.Errorf("login failed: %v", s)
	}
	cbn.SID = strings.Split(strings.Split(s, ";")[1], "=")[1]
	log.Println("login successful, SID: ", cbn.SID)
	cbn.updateSession(rsp)
	if cbn.User.SIDFile != "" {
		log.Printf("persisting SID: %v %v %v", cbn.User.SIDFile, []byte(cbn.SID), 0600)
		err := ioutil.WriteFile(cbn.User.SIDFile, []byte(cbn.SID), 0600)
		if err != nil {
			log.Printf("couldn't save SID: %v", err)
		}
	}

	return nil
}

// execute ajax function fn @ uri with optional opt[0], returns reponse body
func (cbn *CBNAgent) postFunction(fn, uri string, opt ...url.Values) []byte {
	values := url.Values{
		"token": {cbn.Token},
		"fun":   {fn},
	}
	if len(opt) == 1 {
		for k, v := range opt[0] {
			values[k] = v
		}
	}
	rsp := cbn.Agent.Do(cbn.NewRequestV("POST", uri, values))
	return cbn.updateSession(rsp)
}
func (cbn *CBNAgent) xmlSetter(fn Function, opt ...url.Values) []byte {
	return cbn.postFunction(string(fn), "/xml/setter.xml", opt...)
}
func (cbn *CBNAgent) xmlGetter(fn Function, opt ...url.Values) []byte {
	return cbn.postFunction(string(fn), "/xml/getter.xml", opt...)
}

type Function string

var (
	// perform login, requires username + password in the POST body
	FLogin Function = "15"
)
