package desktopui

import (
	"strings"
	"testing"
)

func TestScenesStayInBounds(t *testing.T) {
	for _, size := range [][2]int{{760, 680}, {840, 720}, {1100, 820}} {
		for _, page := range []string{"home", "access", "protocol", "diagnostics"} {
			for _, state := range []string{"disconnected", "connected", "error", "connecting"} {
				s := Build(size[0], size[1], Model{Page: page, State: state, AccessReady: true})
				ids := map[int]bool{}
				for _, c := range s.Controls {
					if ids[c.ID] {
						t.Fatalf("duplicate control %d", c.ID)
					}
					ids[c.ID] = true
					if c.X < 0 || c.Y < 0 || c.X+c.W > s.Width || c.Y+c.H > s.Height {
						t.Fatalf("%s: out of bounds %+v", page, c)
					}
				}
				for _, e := range s.Elements {
					if e.X < 0 || e.Y < 0 || e.X+e.W > s.Width || e.Y+e.H > s.Height {
						t.Fatalf("%s element out of bounds %+v", page, e)
					}
				}
			}
		}
	}
}
func TestControlTargetsDoNotOverlap(t *testing.T) {
	for _, page := range []string{"home", "access", "protocol", "diagnostics"} {
		s := Build(760, 680, Model{Page: page})
		for i, a := range s.Controls {
			for _, b := range s.Controls[i+1:] {
				if a.X < b.X+b.W && b.X < a.X+a.W && a.Y < b.Y+b.H && b.Y < a.Y+a.H {
					t.Fatalf("%s: controls %d and %d overlap", page, a.ID, b.ID)
				}
			}
		}
	}
}
func TestHonestDisconnectedAndAccessStates(t *testing.T) {
	s := Build(840, 720, Model{Page: "home"}).SVG()
	if !strings.Contains(s, "Добавьте персональный ключ") {
		t.Fatal("missing activation guidance")
	}
	s = Build(840, 720, Model{Page: "home", State: "disconnected", AccessReady: true}).SVG()
	if !strings.Contains(s, "Ваш трафик не защищён VPN") {
		t.Fatal("must not claim protection before connect")
	}
}
func TestIssueStagesAndEscape(t *testing.T) {
	s := Build(840, 720, Model{Page: "diagnostics", IssueCode: "ipc.receive", IssueDetail: "<private-test>"}).SVG()
	if strings.Contains(s, "<private-test>") || !strings.Contains(s, "&lt;private-test&gt;") {
		t.Fatal("unsafe SVG text")
	}
}

func TestProtocolIsTruthfulAndLocked(t *testing.T) {
	s := Build(840, 720, Model{Page: "home", State: "connected", AccessReady: true, Mode: "KS"}).SVG()
	if !strings.Contains(s, "VPN подключён · KS") {
		t.Fatal("incorrect connected protocol")
	}
	p := Build(840, 720, Model{Page: "protocol", State: "connected", Protocol: "ks"})
	for _, c := range p.Controls {
		if (c.ID == KSID || c.ID == CITPID) && !c.Disabled {
			t.Fatal("selection enabled during session")
		}
	}
}
