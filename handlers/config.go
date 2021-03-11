package handlers

type Config struct {
	Port                 int    `envconfig:"PORT" default:"3000"`
	FacebookClientID     string `envconfig:"FACEBOOK_CLIENT_ID"`
	FacebookClientSecret string `envconfig:"FACEBOOK_CLIENT_SECRET"`
}
