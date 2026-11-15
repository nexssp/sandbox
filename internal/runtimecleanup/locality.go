package runtimecleanup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

func isLocalRuntime(ctx context.Context, runtimeName string) (bool, error) {
	if runtimeName == "docker" {
		return isLocalDocker(ctx)
	}
	return isLocalPodman(ctx)
}

func isLocalDocker(ctx context.Context) (bool, error) {
	contextName := strings.TrimSpace(os.Getenv("DOCKER_CONTEXT"))
	if contextName == "" {
		if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); host != "" {
			return isLocalEndpoint(host), nil
		}
		out, err := exec.CommandContext(ctx, "docker", "context", "show").Output()
		if err != nil {
			return false, fmt.Errorf("read selected Docker context: %w", err)
		}
		contextName = strings.TrimSpace(string(out))
		if contextName == "" {
			return false, errors.New("selected Docker context is empty")
		}
	}

	// #nosec G702 -- contextName is passed as one CLI argument; no shell is invoked.
	out, err := exec.CommandContext(ctx, "docker", "context", "inspect", "--", contextName).Output()
	if err != nil {
		return false, fmt.Errorf("inspect Docker context %q: %w", contextName, err)
	}
	var contexts []struct {
		Endpoints struct {
			Docker struct {
				Host string `json:"Host"`
			} `json:"docker"`
		} `json:"Endpoints"`
	}
	if err := json.Unmarshal(out, &contexts); err != nil {
		return false, fmt.Errorf("decode Docker context %q: %w", contextName, err)
	}
	if len(contexts) != 1 || strings.TrimSpace(contexts[0].Endpoints.Docker.Host) == "" {
		return false, fmt.Errorf("docker context %q has no single Docker endpoint", contextName)
	}
	return isLocalEndpoint(contexts[0].Endpoints.Docker.Host), nil
}

func isLocalPodman(ctx context.Context) (bool, error) {
	if host := strings.TrimSpace(os.Getenv("CONTAINER_HOST")); host != "" {
		return isLocalEndpoint(host), nil
	}

	selected := strings.TrimSpace(os.Getenv("CONTAINER_CONNECTION"))
	out, err := exec.CommandContext(ctx, "podman", "system", "connection", "list", "--format", "json").Output()
	if err != nil {
		return false, fmt.Errorf("inspect Podman connections: %w", err)
	}
	var connections []struct {
		Name    string `json:"Name"`
		URI     string `json:"URI"`
		Default bool   `json:"Default"`
	}
	if err := json.Unmarshal(out, &connections); err != nil {
		return false, fmt.Errorf("decode Podman connections: %w", err)
	}
	if len(connections) == 0 {
		return selected == "", nil
	}
	for _, connection := range connections {
		if selected != "" && connection.Name == selected {
			return isLocalEndpoint(connection.URI), nil
		}
	}
	if selected == "" {
		for _, connection := range connections {
			if connection.Default {
				return isLocalEndpoint(connection.URI), nil
			}
		}
	}
	// A configured connection whose active endpoint cannot be determined is
	// treated as remote; failing closed is safer than pruning across hosts.
	return false, nil
}

func isLocalEndpoint(raw string) bool {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	switch strings.ToLower(endpoint.Scheme) {
	case "unix":
		return endpoint.Host == "" && strings.HasPrefix(endpoint.Path, "/")
	case "npipe":
		host := endpoint.Hostname()
		if host != "" {
			return strings.EqualFold(host, ".") || strings.EqualFold(host, "localhost") || isLoopbackHost(host)
		}
		path := strings.TrimLeft(endpoint.Path, "/")
		return strings.HasPrefix(path, "./pipe/") || strings.HasPrefix(strings.ToLower(path), "localhost/pipe/")
	case "tcp", "http", "https":
		// Loopback can be a local port-forward to a remote daemon. Do not prune
		// automatically unless the endpoint is a local socket or named pipe.
		return false
	default:
		return false
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
