package shell

import "testing"

func TestMacOSSessionHistories(t *testing.T) {
	cases := map[string]string{
		"Users/gl/.bash_sessions/1C609A2A-D9D6-4AD4-9D59-A83E83E1D379.history":    "bash",
		"Users/gl/.bash_sessions/1C609A2A-D9D6-4AD4-9D59-A83E83E1D379.historynew": "bash",
		"Users/gl/.bash_sessions/1C609A2A-D9D6-4AD4-9D59-A83E83E1D379.session":    "",
		"Users/gl/.zsh_sessions/ABCD.history":                                     "zsh",
		"Users/gl/.bash_history":                                                  "bash",
		"Users/gl/notes.history":                                                  "",
	}
	for rel, want := range cases {
		if got := classify(rel); got != want {
			t.Errorf("%s: %q, want %q", rel, got, want)
		}
	}
}
