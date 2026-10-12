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

func boolPtr(b bool) *bool { return &b }

// IAM's verdict wins in both directions: unified-panel tokens carry no groups
// claim, and IAM falls back to the groups it synced itself.
func TestIAMAnswerBeatsTokenGroups(t *testing.T) {
	admins := []string{"Cloud"}
	if !(Session{IAMAdmin: boolPtr(true)}).IsRealAdmin(admins) {
		t.Error("IAM says admin, but a session with no groups is not")
	}
	if (Session{Groups: []string{"Cloud"}, IAMAdmin: boolPtr(false)}).IsRealAdmin(admins) {
		t.Error("IAM says not admin, but a matching group still made one")
	}
	if !(Session{Groups: []string{"Cloud"}}).IsRealAdmin(admins) {
		t.Error("with no IAM answer the groups claim must still decide")
	}
	if (Session{}).IsRealAdmin(admins) {
		t.Error("no answer and no groups is not an admin")
	}
}

func TestActingIsNeverAdminEvenWhenIAMSaysAdmin(t *testing.T) {
	s := Session{IAMAdmin: boolPtr(true), ActAs: "qa-bob@debug.iam.local"}
	if s.IsAdmin(nil) || !s.IsRealAdmin(nil) {
		t.Errorf("IsAdmin = %v, IsRealAdmin = %v", s.IsAdmin(nil), s.IsRealAdmin(nil))
	}
}
