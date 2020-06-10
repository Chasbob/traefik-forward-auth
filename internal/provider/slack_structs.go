package provider

type identity_response struct {
	OK   bool          `json:"ok"`
	User identity_user `json:"user"`
	Team Team          `json:"team"`
}
type identity_user struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	Email string `json:"email"`
}
type authed_user struct {
	ID        string `json:"id"`
	Scope     string `json:"scope"`
	Token     string `json:"access_token"`
	TokenType string `json:"token_type"`
}

type Team struct {
	ID string `json:"id"`
}

type oauth_access_response struct {
	OK         bool        `json:"ok"`
	AppID      string      `json:"app_id"`
	AuthedUser authed_user `json:"authed_user"`
	Team       Team        `json:"team"`
	Enterprise string      `json:"enterprise"`
}
