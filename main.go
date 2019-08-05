package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sparrc/go-ping"
)

const responseType string = "ephemeral"

const errorURL string = "https://sysrant.com/oeps"

const succesURL string = "https://sysrant.com/thanks-for-installing"

const oauthURL string = "https://slack.com/api/oauth.access"

type jsonOauthResult struct {
	Ok bool `json:"ok"`
}

type jsonResult struct {
	Text        string        `json:"text"`
	ReponseType string        `json:"response_type"`
	Attachments []Attachments `json:"attachments"`
}

type Attachments struct {
	Text string `json:"text"`
}

type Result struct {
	Stats *ping.Statistics
	Error error
}

func main() {
	http.HandleFunc("/ping", Ping)
	http.HandleFunc("/oauth", Auth)
	http.ListenAndServe(":80", nil)
}

func Auth(w http.ResponseWriter, r *http.Request) {

	// We must check if the error field is set, in case user cancels his requests
	error := r.URL.Query().Get("error")
	if error != "" {
		redirectUrl := errorURL
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
	}

	// We require a code
	code := r.URL.Query().Get("code")
	if code == "" {
		redirectUrl := errorURL
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
	}

	// Preparing to send a POST to slack's Oauth access page.
	hc := http.Client{}
	routerURL := oauthURL

	// Create the form
	form := url.Values{}
	form.Add("code", code)
	form.Add("client_id", os.Getenv("CLIENTID"))
	form.Add("client_secret", os.Getenv("CLIENTSECRET"))

	req, err := http.NewRequest("POST", routerURL, strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Println(err)
		redirectUrl := errorURL
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		return
	}

	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// Do the request
	res, err := hc.Do(req)
	if err != nil {
		fmt.Println(err)
		redirectUrl := errorURL
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		return
	}

	// Get the response
	decoder := json.NewDecoder(res.Body)
	var oauthResult jsonOauthResult
	err = decoder.Decode(&oauthResult)
	if err != nil {
		fmt.Println(err)
		redirectUrl := errorURL
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		return
	}

	// If the response was not OK, redirect for an error
	if oauthResult.Ok != true {
		fmt.Println("Oauth response was not TRUE")
		redirectUrl := errorURL
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, succesURL, http.StatusSeeOther)
}

func Ping(w http.ResponseWriter, r *http.Request) {

	// Default headers always..
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// We need the raw body to create a signature
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bodyString := string(bodyBytes)

	// Return the bytes to the body for the FormParser, because using r.FormValue is easy.
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// Parse POST values
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Prepare the vars for our signing
	slackVersion := "v0:"
	slackTimestamp := r.Header.Get("X-Slack-Request-Timestamp")
	slackSignature := r.Header.Get("X-Slack-Signature")

	// Check if the request is within 5 minutes - replay attack
	now := time.Now()
	n, err := strconv.ParseInt(slackTimestamp, 10, 64)
	if err != nil {
		fmt.Printf("%d of type %T", n, n)
	}
	if (now.Unix() - n) > 60*5 {
		fmt.Println("replay attack")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create our hash and compare it with the slack Signature.
	sigBasestring := slackVersion + slackTimestamp + ":" + string(bodyString)
	secret := os.Getenv("SIGNINGSECRET")
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(sigBasestring))

	sha := hex.EncodeToString(h.Sum(nil))
	sha = "v0=" + sha

	if sha != slackSignature {
		fmt.Println("signature mismatch")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// We need SOME information, text is the value after the slash command
	host := r.FormValue("text")
	if host == "" {
		w.WriteHeader(http.StatusOK)
		data := jsonResult{Text: "I need something to ping... usage is either /ping hostname or /ping ip", ReponseType: responseType}
		json.NewEncoder(w).Encode(data)
		return
	}

	// Bit dodgy, but if the message is "help", lets help the user.
	if host == "help" {
		w.WriteHeader(http.StatusOK)
		data := jsonResult{Text: "The usage is either /ping hostname or /ping ip. For example /ping slack.com", ReponseType: responseType}
		json.NewEncoder(w).Encode(data)
		return
	}

	// And do the Ping
	stats, err := doPing(host)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		data := jsonResult{Text: err.Error(), ReponseType: responseType}
		json.NewEncoder(w).Encode(data)
		return
	}

	// Prepare the response with the actual ping data
	responseHeader := fmt.Sprintf("\n--- %s ping statistics on IP: %s ---\n", stats.Addr, stats.IPAddr)
	responseTransmit := fmt.Sprintf("%d packets transmitted, %d packets received, %v%% packet loss\n",
		stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
	responseRound := fmt.Sprintf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
		stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)

	// Concat the response
	response := responseHeader + responseTransmit + responseRound
	attachment := []Attachments{Attachments{Text: response}}

	// Write it and cya.
	w.WriteHeader(http.StatusOK)
	data := jsonResult{Text: "I've got your ping", ReponseType: responseType, Attachments: attachment}
	json.NewEncoder(w).Encode(data)
}

func doPing(host string) (*ping.Statistics, error) {

	// Resolve as IP first
	_, err := net.ResolveIPAddr("ip", host)
	if err != nil {

		// IP failed, so resolve as Domain, remove trailing parts
		host = strings.Replace(host, "http://", "", -1)
		host = strings.Replace(host, "https://", "", -1)

		errorDomain := checkDomain(host)
		if errorDomain != nil {
			return nil, errorDomain
		}
		// No error for the domain, we can use the host now.
	}

	// Initiate the pinger
	pinger, err := ping.NewPinger(host)
	if err != nil {
		// This could "leak" internal network data. Thefore we look for this string and create our own message
		if strings.Contains(err.Error(), "no such host") {
			return nil, fmt.Errorf("Lookup %s: no such host", host)
		} else {
			return nil, fmt.Errorf("Could not lookup host, unknown error")
		}
	}
	// This is required on Linux hosts, since ICMP blows on rights.
	pinger.SetPrivileged(true)
	// I would prefer a higher timeout, but Slack requires a response back within 3 seconds.
	pinger.Timeout = 2 * time.Second

	// Lets do 2 runs. This means a maximum of 2 seconds processing, which leaves a second to respond.
	pinger.Count = 4
	pinger.Run()                 // blocks until finished
	stats := pinger.Statistics() // get send/receive/rtt stats
	// And return the stats!
	return stats, nil
}

// Thanks https://gist.github.com/chmike
// I did however alter this to allow certain characters
func checkDomain(name string) error {

	switch {
	case len(name) == 0:
		return nil // an empty domain name will result in a cookie without a domain restriction
	case len(name) > 255:
		return fmt.Errorf("Domain name length is %d, can't exceed 255", len(name))
	}
	var l int
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			// check domain labels validity
			switch {
			case i == l:
				return fmt.Errorf("Domain invalid character '%c' at offset %d: label can't begin with a period", b, i)
			case i-l > 63:
				return fmt.Errorf("Domain byte length of label '%s' is %d, can't exceed 63", name[l:i], i-l)
			case name[l] == '-':
				return fmt.Errorf("Domain label '%s' at offset %d begins with a hyphen", name[l:i], l)
			case name[i-1] == '-':
				return fmt.Errorf("Domain label '%s' at offset %d ends with a hyphen", name[l:i], l)
			}
			l = i + 1
			continue
		}
	}

	var IsValidChars = regexp.MustCompile(`^[a-zA-Z0-9ßàÁáâãóôþüúðæåïçèõöÿýòäœêëìíøùîûñé.\-]+$`).MatchString

	// check top level domain validity
	switch {
	case IsValidChars(name) == false:
		return fmt.Errorf("Domain has a non valid character")
	case l == len(name):
		return fmt.Errorf("Domain is missing top level domain, domain can't end with a period")
	case len(name)-l > 63:
		return fmt.Errorf("Domain byte length of top level domain '%s' is %d, can't exceed 63", name[l:], len(name)-l)
	case name[l] == '-':
		return fmt.Errorf("Domain top level domain '%s' at offset %d begins with a hyphen", name[l:], l)
	case name[len(name)-1] == '-':
		return fmt.Errorf("Domain top level domain '%s' at offset %d ends with a hyphen", name[l:], l)
	case name[l] >= '0' && name[l] <= '9':
		return fmt.Errorf("Domain top level domain '%s' at offset %d begins with a digit", name[l:], l)
	}
	return nil
}
