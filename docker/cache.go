package docker

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nexssp/kernel/xerr"
)

type CacheEntry struct {
	Key       string    `json:"key"`
	Tool      string    `json:"tool"`
	Recipe    string    `json:"recipe,omitempty"`
	ImageTag  string    `json:"image_tag"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	FilePath  string    `json:"file_path"`
}

type cacheIndex struct {
	Entries []CacheEntry `json:"entries"`
}

type CacheManager struct {
	mu        sync.Mutex
	dir       string
	maxBytes  int64
	enabled   bool
	entries   map[string]CacheEntry
	indexFile string
}

func NewCacheManager(dir string, maxBytes int64, enabled bool) (*CacheManager, error) {
	if dir == "" {
		return nil, xerr.BadRequest("cache: dir is required")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("cache: create dir %q: %w", dir, err)
	}

	cm := &CacheManager{
		dir:       dir,
		maxBytes:  maxBytes,
		enabled:   enabled,
		entries:   make(map[string]CacheEntry),
		indexFile: filepath.Join(dir, "index.json"),
	}
	cm.loadIndex()

	return cm, nil
}

func (cm *CacheManager) Enabled() bool { return cm != nil && cm.enabled }

func (cm *CacheManager) Dir() string { return cm.dir }

func RecipeKey(tool, recipe string) string {
	h := sha256.Sum256([]byte(tool + "\x00" + recipe))

	return hex.EncodeToString(h[:8])
}

func (cm *CacheManager) loadIndex() {
	data, err := os.ReadFile(cm.indexFile)
	if err != nil {
		return
	}

	var idx cacheIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return
	}

	for i := range idx.Entries {
		e := idx.Entries[i]
		if info, statErr := os.Stat(e.FilePath); statErr == nil {
			e.SizeBytes = info.Size()
			cm.entries[e.Key] = e
		}
	}
}

func (cm *CacheManager) saveIndex() error {
	entries := make([]CacheEntry, 0, len(cm.entries))
	for _, e := range cm.entries {
		entries = append(entries, e)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].CreatedAt.After(entries[j].CreatedAt)
	})

	data, err := json.MarshalIndent(cacheIndex{Entries: entries}, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cm.indexFile, data, 0o600)
}

func (cm *CacheManager) Has(key string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	_, ok := cm.entries[key]

	return ok
}

func (cm *CacheManager) Get(key string) (CacheEntry, bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	e, ok := cm.entries[key]

	return e, ok
}

func (cm *CacheManager) List() []CacheEntry {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	out := make([]CacheEntry, 0, len(cm.entries))
	for _, e := range cm.entries {
		out = append(out, e)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})

	return out
}

func (cm *CacheManager) TotalBytes() int64 {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var total int64
	for _, e := range cm.entries {
		total += e.SizeBytes
	}

	return total
}

func (cm *CacheManager) Latest() (CacheEntry, bool) {
	entries := cm.List()
	if len(entries) == 0 {
		return CacheEntry{}, false
	}

	return entries[0], true
}

func (cm *CacheManager) CommitAndSave(
	ctx context.Context,
	containerName, key, tool, recipe string,
) (CacheEntry, error) {
	if !cm.Enabled() {
		return CacheEntry{}, xerr.Unavailable("cache disabled")
	}

	imageTag := "jumalu-cache:" + key

	if err := runDockerCmd(ctx, "commit", containerName, imageTag); err != nil {
		return CacheEntry{}, fmt.Errorf("docker commit: %w", err)
	}

	finalPath := filepath.Join(cm.dir, "jumalu-cache-"+key+".tar.gz")
	tmpPath := finalPath + ".tmp"

	saveCmd := exec.CommandContext(ctx, "docker", "save", imageTag)

	saveOut, err := saveCmd.StdoutPipe()
	if err != nil {
		return CacheEntry{}, err
	}

	if startErr := saveCmd.Start(); startErr != nil {
		return CacheEntry{}, startErr
	}

	// cleanup reaps the docker save process on error paths. Its own
	// failures are already on an error path, so we just log them at
	// debug level rather than shadowing the caller's primary error.
	cleanup := func() {
		if killErr := saveCmd.Process.Kill(); killErr != nil {
			slog.Debug("cache: kill docker save failed", "err", killErr)
		}
		if waitErr := saveCmd.Wait(); waitErr != nil {
			slog.Debug("cache: wait docker save failed", "err", waitErr)
		}
	}

	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		cleanup()
		return CacheEntry{}, err
	}

	gz, err := gzip.NewWriterLevel(tmpFile, gzip.BestSpeed)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		cleanup()
		return CacheEntry{}, err
	}

	if _, copyErr := io.Copy(gz, saveOut); copyErr != nil {
		_ = gz.Close()
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		cleanup()
		return CacheEntry{}, copyErr
	}

	if gzCloseErr := gz.Close(); gzCloseErr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		cleanup()
		return CacheEntry{}, gzCloseErr
	}

	if fileCloseErr := tmpFile.Close(); fileCloseErr != nil {
		_ = os.Remove(tmpPath)
		cleanup()
		return CacheEntry{}, fileCloseErr
	}

	if waitErr := saveCmd.Wait(); waitErr != nil {
		_ = os.Remove(tmpPath)
		return CacheEntry{}, fmt.Errorf("docker save: %w", waitErr)
	}

	// renameErr is intentionally distinct from the outer err so govet's
	// shadow linter does not flag it.
	if renameErr := os.Rename(tmpPath, finalPath); renameErr != nil {
		_ = os.Remove(tmpPath)
		return CacheEntry{}, renameErr
	}

	info, err := os.Stat(finalPath)
	if err != nil {
		return CacheEntry{}, err
	}

	entry := CacheEntry{
		Key:       key,
		Tool:      tool,
		Recipe:    recipe,
		ImageTag:  imageTag,
		SizeBytes: info.Size(),
		CreatedAt: time.Now().UTC(),
		FilePath:  finalPath,
	}

	cm.mu.Lock()
	cm.entries[key] = entry
	cm.mu.Unlock()

	if err := cm.saveIndex(); err != nil {
		return CacheEntry{}, err
	}

	if err := cm.pruneIfOversized(ctx); err != nil {
		slog.Warn("cache: prune failed", "err", err)
	}

	return entry, nil
}

func (cm *CacheManager) LoadFromDisk(ctx context.Context, key string) (string, error) {
	entry, ok := cm.Get(key)
	if !ok {
		return "", xerr.NotFound("cache entry not found: " + key)
	}

	if err := runDockerCmd(ctx, "image", "inspect", entry.ImageTag); err == nil {
		return entry.ImageTag, nil
	}

	f, err := os.Open(entry.FilePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	loadCmd := exec.CommandContext(ctx, "docker", "load")

	loadCmd.Stdin = gz
	if out, err := loadCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("docker load: %w: %s", err, string(out))
	}

	return entry.ImageTag, nil
}

// rmiImage removes a cached image from the local docker daemon.
//
// The image tag is always "jumalu-cache:<hex>" where <hex> is the
// hex-encoded SHA-256 prefix produced by RecipeKey. Because
// hex.EncodeToString emits only [0-9a-f] and the literal prefix contains
// only [a-z:-], the tag cannot contain shell metacharacters. Using
// exec.CommandContext (rather than exec.Command) also satisfies gosec's
// G204 rule, which is why no nolint directive is needed here.
func rmiImage(ctx context.Context, imageTag string) error {
	return exec.CommandContext(ctx, "docker", "rmi", imageTag).Run()
}

func (cm *CacheManager) Delete(ctx context.Context, key string) error {
	cm.mu.Lock()

	entry, ok := cm.entries[key]
	if !ok {
		cm.mu.Unlock()

		return xerr.NotFound("cache entry not found: " + key)
	}

	delete(cm.entries, key)
	cm.mu.Unlock()

	if err := os.Remove(entry.FilePath); err != nil && !os.IsNotExist(err) {
		slog.Debug("cache: remove archive failed", "key", key, "err", err)
	}
	if err := rmiImage(ctx, entry.ImageTag); err != nil {
		slog.Debug("cache: docker rmi failed", "key", key, "err", err)
	}

	return cm.saveIndex()
}

func (cm *CacheManager) Clear(ctx context.Context) error {
	cm.mu.Lock()

	entries := make([]CacheEntry, 0, len(cm.entries))
	for _, e := range cm.entries {
		entries = append(entries, e)
	}

	cm.entries = make(map[string]CacheEntry)
	cm.mu.Unlock()

	for _, e := range entries {
		if err := os.Remove(e.FilePath); err != nil && !os.IsNotExist(err) {
			slog.Debug("cache: remove archive failed", "key", e.Key, "err", err)
		}
		if err := rmiImage(ctx, e.ImageTag); err != nil {
			slog.Debug("cache: docker rmi failed", "key", e.Key, "err", err)
		}
	}

	return cm.saveIndex()
}

// pruneIfOversized removes the oldest cache entries until the total size
// drops below maxBytes. It returns an aggregate error describing any
// per-entry delete failures but always attempts every eviction it planned.
func (cm *CacheManager) pruneIfOversized(ctx context.Context) error {
	if cm.maxBytes <= 0 {
		return nil
	}

	entries := cm.List()

	total := cm.TotalBytes()
	if total <= cm.maxBytes {
		return nil
	}

	var errs []error
	for i := len(entries) - 1; i >= 0 && total > cm.maxBytes; i-- {
		e := entries[i]
		if err := cm.Delete(ctx, e.Key); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", e.Key, err))
			continue
		}
		total -= e.SizeBytes
	}

	return errors.Join(errs...)
}

func runDockerCmd(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, string(out))
	}

	return nil
}
