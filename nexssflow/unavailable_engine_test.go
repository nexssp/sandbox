package nexssflow

import (
	"strings"
	"testing"

	"github.com/nexssp/kernel/xerr"
)

func TestUnavailableStartupErrorIsActionable(t *testing.T) {
	err := unavailableStartupError("docker", xerr.Unavailable("daemon is unreachable"))
	if got := xerr.KindFrom(err); got != xerr.KindUnavailable {
		t.Fatalf("error kind = %q, want %q", got, xerr.KindUnavailable)
	}
	if !strings.Contains(err.Error(), "start Docker Desktop or the Docker daemon and retry") {
		t.Fatalf("error message is not actionable: %q", err)
	}
}
