package provider

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/containous/traefik/v2/pkg/log"
)

type Slack struct {
	ClientID         string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret     string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scope            string
	Prompt           string `long:"prompt" env:"PROMPT" default:"select_account" description:"Space separated list of OpenID prompt options"`
	SigningSecret    string `long:"signing-secret" env:"SIGINING_SECRET" description:"Secret used to verify reponses from Slack"`
	Workspace        string `long:"workspace-name" env:"WORKSPACE" description:"optional name of Slack workspace"`
	NameRegex        string `long:"name-regex" env:"NAME_REGEX" description:"regular expression for replacing characters in the username" default:"(?m)[^a-zA-Z0-9_.-]"`
	SubstitutionChar string `long:"substitution-char" env:"SUBSTITUTION_CHAR" description:"used to replace illegal characters" default:"-"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL

	CompiledNameRegex *regexp.Regexp
}

// Name returns the name of the provider
func (g *Slack) Name() string {
	return "slack"
}

// Setup performs validation and setup
func (s *Slack) Setup() error {
	if s.ClientID == "" || s.ClientSecret == "" {
		return errors.New("providers.slack.client-id, providers.slack.client-secret must be set")
	}

	// Set static values
	s.Scope = "identity.basic"
	s.LoginURL = &url.URL{
		Scheme: "https",
		Host:   "slack.com",
		Path:   "/oauth/v2/authorize",
	}
	s.TokenURL = &url.URL{
		Scheme: "https",
		Host:   "slack.com",
		Path:   "/api/oauth.v2.access",
	}
	s.UserURL = &url.URL{
		Scheme: "https",
		Host:   "slack.com",
		Path:   "/api/users.identity",
	}
	if s.Workspace != "" {
		s.LoginURL.Host = s.Workspace + "." + s.LoginURL.Host
		s.TokenURL.Host = s.Workspace + "." + s.TokenURL.Host
		s.UserURL.Host = s.Workspace + "." + s.UserURL.Host
	}
	log.Info("NameRegex=", s.NameRegex)
	s.CompiledNameRegex = regexp.MustCompile(s.NameRegex)
	log.Info("CompiledNameRegex=", s.CompiledNameRegex)
	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (g *Slack) GetLoginURL(redirectURI, state string) string {
	q := url.Values{}
	q.Set("client_id", g.ClientID)
	q.Set("response_type", "code")
	q.Set("user_scope", g.Scope)
	if g.Prompt != "" {
		q.Set("prompt", g.Prompt)
	}
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)

	var u url.URL
	u = *g.LoginURL
	u.RawQuery = q.Encode()

	return u.String()
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (g *Slack) ExchangeCode(redirectURI, code string) (string, error) {
	client := http.Client{}
	q := url.Values{}
	q.Set("client_id", g.ClientID)
	q.Set("client_secret", g.ClientSecret)
	q.Set("code", code)
	q.Set("redirect_uri", redirectURI)

	var u url.URL
	u = *g.TokenURL
	u.RawQuery = q.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		log.Error("[ExchangeCode] err=%s", err)
	}
	res, err := client.Do(req)
	if err != nil {
		log.Error("[ExchangeCode] err=", err)
		return "", err
	}
	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Error("[ExchangeCode] ioutil err=", err)
	}
	bodyString := string(bodyBytes)

	var oauth_access_response oauth_access_response
	defer res.Body.Close()
	err = json.NewDecoder(strings.NewReader(bodyString)).Decode(&oauth_access_response)
	if err != nil {
		log.Error("[ExchangeCode] json err=", err)
	}

	log.Info("[ExchangeCode] bodyString=", bodyString)
	log.Info("[ExchangeCode] oauth_access_response=", oauth_access_response)
	return oauth_access_response.AuthedUser.Token, err
}

func (g *Slack) GetUser(token string) (User, error) {
	var user User

	client := &http.Client{}
	reqString := g.UserURL.String() + "?token=" + token
	req, err := http.NewRequest("GET", reqString, nil)
	if err != nil {
		log.Error("[GetUser] err=", err)
		return user, err
	}

	res, err := client.Do(req)
	if err != nil {
		log.Error("[GetUser] err2=", err)
		return user, err
	}

	defer res.Body.Close()
	var identity_response identity_response

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Error("[GetUser] ioutil err=", err)
	}
	bodyString := string(bodyBytes)
	log.Info("[GetUser] bodyStrin=", bodyString)
	err = json.NewDecoder(strings.NewReader(bodyString)).Decode(&identity_response)
	log.Info("[GetUser] identity_response=", identity_response)
	user.Email = identity_response.User.Email
	user.Name = identity_response.User.Name
	// user.Email = g.CompiledNameRegex.ReplaceAllString(identity_response.User.Name, g.SubstitutionChar)
	user.ID = identity_response.User.ID
	user.Verified = true
	log.Info("[GetUser] user=", user)

	return user, err
}
