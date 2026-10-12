package auth

import "testing"

func TestActingIsNeverAdmin(t *testing.T) {
	s := Session{Groups: []string{"Cloud"}}
	if !s.IsAdmin([]string{"Cloud"}) || !s.IsRealAdmin([]string{"Cloud"}) {
		t.Fatal("an admin is not admin")
	}
	s.ActAs = "qa-bob@debug.iam.local"
	if s.IsAdmin([]string{"Cloud"}) {
		t.Error("IsAdmin is true while acting")
	}
	if !s.IsRealAdmin([]string{"Cloud"}) {
		t.Error("IsRealAdmin must keep answering for the real person")
	}
}
