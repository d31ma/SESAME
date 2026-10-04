type OidcInteractionCompletion struct {
	InteractionID     string `json:"interaction_id"`
	InteractionSecret string `json:"interaction_secret"`
	SessionID         string `json:"session_id"`
	SessionSecret     string `json:"session_secret"`
}
