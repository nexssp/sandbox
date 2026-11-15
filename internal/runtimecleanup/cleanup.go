package runtimecleanup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	DefaultStaleContainerAge = 24 * time.Hour

	labelManaged   = "io.nexss.sandbox.managed"
	labelWorkspace = "io.nexss.sandbox.workspace"
	labelHost      = "io.nexss.sandbox.host"
	labelOwner     = "io.nexss.sandbox.owner"
	labelLease     = "io.nexss.sandbox.lease"
	filterArg      = "--filter"
)

// Labels returns the ownership labels shared by the Docker and Podman engines.
// Values that could expose local paths or account names are stored as hashes.
func Labels(workspaceDir, leaseKey string) (map[string]string, error) {
	workspaceID, err := workspaceID(workspaceDir)
	if err != nil {
		return nil, err
	}
	hostID, err := hostID()
	if err != nil {
		return nil, err
	}
	ownerID, err := ownerID()
	if err != nil {
		return nil, err
	}
	if leaseKey == "" {
		return nil, errors.New("runtime cleanup: lease key is empty")
	}
	return map[string]string{
		labelManaged:   "true",
		labelWorkspace: workspaceID,
		labelHost:      hostID,
		labelOwner:     ownerID,
		labelLease:     leaseKey,
	}, nil
}

// LabelArgs returns labels as Docker/Podman CLI arguments in stable key order.
func LabelArgs(workspaceDir, leaseKey string) ([]string, error) {
	labels, err := Labels(workspaceDir, leaseKey)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	args := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		args = append(args, "--label", key+"="+labels[key])
	}
	return args, nil
}

// PruneStale removes only old containers created by this Sandbox runtime for
// the same workspace, host, and user. It requires the per-container lease to be
// available, then re-inspects ownership and age before removal. Workspaces are
// bind mounts and are never deleted here.
func PruneStale(ctx context.Context, runtimeName, workspaceDir string, maxAge time.Duration) error {
	if runtimeName != "docker" && runtimeName != "podman" {
		return fmt.Errorf("runtime cleanup: unsupported container runtime %q", runtimeName)
	}
	local, err := isLocalRuntime(ctx, runtimeName)
	if err != nil {
		return fmt.Errorf("determine whether %s daemon is local: %w", runtimeName, err)
	}
	if !local {
		slog.Info("sandbox: skip stale-container cleanup for a remote runtime endpoint", "runtime", runtimeName)
		return nil
	}
	if maxAge <= 0 {
		maxAge = DefaultStaleContainerAge
	}
	identity, err := cleanupIdentityForWorkspace(workspaceDir)
	if err != nil {
		return err
	}

	args := []string{
		"ps", "-aq",
		filterArg, "label=" + labelManaged + "=true",
		filterArg, "label=" + labelWorkspace + "=" + identity.workspace,
		filterArg, "label=" + labelHost + "=" + identity.host,
		filterArg, "label=" + labelOwner + "=" + identity.owner,
	}
	out, err := exec.CommandContext(ctx, runtimeName, args...).Output()
	if err != nil {
		return fmt.Errorf("list managed containers: %w", err)
	}

	var cleanupErr error
	for id := range strings.FieldsSeq(string(out)) {
		if !validContainerID(id) {
			continue
		}
		if err := pruneStaleCandidate(ctx, runtimeName, id, identity, maxAge); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	return cleanupErr
}

type cleanupIdentity struct {
	workspace string
	host      string
	owner     string
}

func cleanupIdentityForWorkspace(workspaceDir string) (cleanupIdentity, error) {
	workspace, err := workspaceID(workspaceDir)
	if err != nil {
		return cleanupIdentity{}, err
	}
	host, err := hostID()
	if err != nil {
		return cleanupIdentity{}, err
	}
	owner, err := ownerID()
	if err != nil {
		return cleanupIdentity{}, err
	}
	return cleanupIdentity{workspace: workspace, host: host, owner: owner}, nil
}

func pruneStaleCandidate(ctx context.Context, runtimeName, id string, identity cleanupIdentity, maxAge time.Duration) error {
	container, err := inspectContainer(ctx, runtimeName, id)
	if err != nil {
		slog.Debug("sandbox: skip stale-container candidate after inspect failure", "container", id, "error", err)
		return nil
	}
	leaseKey, stale := staleCandidate(container, identity, time.Now(), maxAge)
	if !stale {
		return nil
	}

	lease, acquired, err := TryAcquire(leaseKey)
	if err != nil {
		return fmt.Errorf("lock stale-container candidate %q: %w", id, err)
	}
	if !acquired {
		return nil
	}

	// Recheck ownership and age after acquiring the lease to fail closed if the
	// candidate changed between inspection and lock acquisition.
	current, inspectErr := inspectContainer(ctx, runtimeName, id)
	if inspectErr != nil {
		slog.Debug("sandbox: skip stale-container candidate after re-inspect failure", "container", id, "error", inspectErr)
		return releaseCandidateLease(id, lease)
	}
	currentLeaseKey, stillStale := staleCandidate(current, identity, time.Now(), maxAge)
	if !stillStale || currentLeaseKey != leaseKey {
		return releaseCandidateLease(id, lease)
	}

	removeErr := exec.CommandContext(ctx, runtimeName, "rm", "-f", id).Run()
	if removeErr != nil {
		removeErr = fmt.Errorf("remove stale container %q: %w", id, removeErr)
	}
	return errors.Join(removeErr, releaseCandidateLease(id, lease))
}

func releaseCandidateLease(id string, lease *Lease) error {
	if err := lease.Close(); err != nil {
		return fmt.Errorf("release stale-container lease %q: %w", id, err)
	}
	return nil
}

type inspectedContainer struct {
	ID      string `json:"Id"`
	Created string `json:"Created"`
	Config  struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func inspectContainer(ctx context.Context, runtimeName, id string) (inspectedContainer, error) {
	out, err := exec.CommandContext(ctx, runtimeName, "inspect", id).Output()
	if err != nil {
		return inspectedContainer{}, err
	}
	var containers []inspectedContainer
	if err := json.Unmarshal(out, &containers); err != nil {
		return inspectedContainer{}, fmt.Errorf("decode inspect result: %w", err)
	}
	if len(containers) != 1 {
		return inspectedContainer{}, fmt.Errorf("inspect returned %d containers, want 1", len(containers))
	}
	if containers[0].ID != "" && !strings.HasPrefix(containers[0].ID, id) && !strings.HasPrefix(id, containers[0].ID) {
		return inspectedContainer{}, errors.New("inspect result ID does not match candidate")
	}
	return containers[0], nil
}

func staleCandidate(container inspectedContainer, identity cleanupIdentity, now time.Time, maxAge time.Duration) (string, bool) {
	labels := container.Config.Labels
	if labels[labelManaged] != "true" ||
		labels[labelWorkspace] != identity.workspace ||
		labels[labelHost] != identity.host ||
		labels[labelOwner] != identity.owner {
		return "", false
	}
	leaseKey := labels[labelLease]
	if leaseKey == "" {
		return "", false
	}
	created, err := time.Parse(time.RFC3339Nano, container.Created)
	if err != nil || now.Sub(created) < maxAge {
		return "", false
	}
	return leaseKey, true
}

func validContainerID(id string) bool {
	if len(id) < 12 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func workspaceID(workspaceDir string) (string, error) {
	abs, err := filepath.Abs(workspaceDir)
	if err != nil {
		return "", fmt.Errorf("resolve workspace for stale cleanup: %w", err)
	}
	return digest(filepath.Clean(abs)), nil
}

func hostID() (string, error) {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		if err == nil {
			err = errors.New("hostname is empty")
		}
		return "", fmt.Errorf("identify host for stale cleanup: %w", err)
	}
	return digest(strings.ToLower(host)), nil
}

func ownerID() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("find user cache directory for stale cleanup: %w", err)
	}
	abs, err := filepath.Abs(cacheDir)
	if err != nil {
		return "", fmt.Errorf("resolve user cache directory for stale cleanup: %w", err)
	}
	return digest(strings.ToLower(filepath.Clean(abs))), nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Lease is an OS-level exclusive lock for one generated container identity.
// Lock files live in the per-user cache directory and are intentionally not
// removed: unlinking a locked file can let concurrent processes lock different
// inodes under the same name.
type Lease struct {
	file   *os.File
	unlock func() error
}

// Acquire holds the lease until Close is called or the process exits.
func Acquire(key string) (*Lease, error) {
	return acquire(key, false)
}

// TryAcquire attempts to acquire a lease without waiting. acquired is false when
// another process currently owns the container identity.
func TryAcquire(key string) (*Lease, bool, error) {
	lease, err := acquire(key, true)
	if errors.Is(err, errLeaseHeld) {
		return nil, false, nil
	}
	return lease, err == nil, err
}

func acquire(key string, nonblocking bool) (*Lease, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("runtime cleanup: lease key is empty")
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("find user cache directory for container lease: %w", err)
	}
	leaseDir := filepath.Join(cacheDir, "nexss", "sandbox", "leases")
	if mkdirErr := os.MkdirAll(leaseDir, 0o700); mkdirErr != nil {
		return nil, fmt.Errorf("create container lease directory: %w", mkdirErr)
	}
	filePath := filepath.Join(leaseDir, digest(key)+".lock")
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open container lease: %w", err)
	}
	unlock, err := lockLeaseFile(file, nonblocking)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Lease{file: file, unlock: unlock}, nil
}

// Close releases the lease. It is safe to call multiple times.
func (l *Lease) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := l.unlock()
	closeErr := l.file.Close()
	l.file = nil
	l.unlock = nil
	return errors.Join(unlockErr, closeErr)
}
