package livecollect

// profiles_test covers the embedded artefact set as data: it decodes and
// validates, the supported vocabulary is what the profiles declare, and the
// validator rejects a path that would escape the stage.

import (
	"reflect"
	"testing"
)

func TestProfilesLoad(t *testing.T) {
	profs, err := Profiles()
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	for _, os := range []string{"linux", "darwin"} {
		p, ok := profs[os]
		if !ok {
			t.Fatalf("no %q profile", os)
		}
		if len(p.Trees) == 0 {
			t.Errorf("%s profile has no trees", os)
		}
		if len(p.Homes.Artefacts) == 0 {
			t.Errorf("%s profile collects no home artefacts", os)
		}
	}
}

func TestSupportedOS(t *testing.T) {
	if got, want := SupportedOS(), []string{"darwin", "linux"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedOS() = %v, want %v", got, want)
	}
}

// TestValidateRejects holds the validator to its job: a profile must be keyed
// by its own OS, carry something, and every path must be a clean relative path
// — an absolute or climbing path would write outside the stage.
func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		key  string
		prof Profile
	}{
		{"os mismatch", "linux", Profile{OS: "darwin", Trees: []Tree{{Path: "etc"}}}},
		{"empty", "linux", Profile{OS: "linux"}},
		{"absolute tree", "linux", Profile{OS: "linux", Trees: []Tree{{Path: "/etc"}}}},
		{"climbing tree", "linux", Profile{OS: "linux", Trees: []Tree{{Path: "../etc"}}}},
		{"empty tree path", "linux", Profile{OS: "linux", Trees: []Tree{{Path: ""}}}},
		{"climbing home root", "linux", Profile{OS: "linux", Homes: Homes{Roots: []string{"../home"}, Artefacts: []string{".bash_history"}}}},
		{"absolute artefact", "linux", Profile{OS: "linux", Homes: Homes{Roots: []string{"home/*"}, Artefacts: []string{"/etc/shadow"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := validate(c.key, c.prof); err == nil {
				t.Fatalf("validate accepted %s", c.name)
			}
		})
	}
}

func TestValidateAcceptsEmbedded(t *testing.T) {
	// the real profiles must pass the same validator.
	if _, err := Profiles(); err != nil {
		t.Fatalf("embedded profiles do not validate: %v", err)
	}
}

func TestStageUnknownOS(t *testing.T) {
	_, err := Stage(Options{OS: "plan9", Root: t.TempDir(), WorkDir: t.TempDir()})
	if err == nil {
		t.Fatal("Stage accepted an OS with no profile")
	}
}
