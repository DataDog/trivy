package rules

type Provider struct {
	Name     string    `json:"name"`
	Services []Service `json:"services"`
}

type Service struct {
	Name   string  `json:"name"`
	Checks []Check `json:"checks"`
}

type Check struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
