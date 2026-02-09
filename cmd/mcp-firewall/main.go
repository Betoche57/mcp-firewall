package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/proxy"
	"github.com/VikingOwl91/mcp-firewall/internal/sandbox"
	"github.com/VikingOwl91/mcp-firewall/internal/supply"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Detect re-exec sentinel BEFORE flag parsing
	if len(os.Args) >= 2 && os.Args[1] == "__sandbox__" {
		if err := sandbox.RunSandboxEntrypoint(); err != nil {
			fmt.Fprintf(os.Stderr, "sandbox: %v\n", err)
			os.Exit(1)
		}
		os.Exit(1) // unreachable — RunSandboxEntrypoint calls syscall.Exec
	}

	home, err := os.UserHomeDir()
	if err != nil {
		slog.Error("failed to determine home directory", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defaultConfig := filepath.Join(home, ".mcp-firewall", "config.yaml")

	configPath := flag.String("config", defaultConfig, "path to config file")
	profileName := flag.String("profile", "", "config profile name (env: MCP_FIREWALL_PROFILE)")
	workspacePath := flag.String("workspace", "", "workspace directory for local override (auto-detected if omitted)")
	generateLockfile := flag.Bool("generate-lockfile", false, "generate lockfile YAML with hashes for all downstreams and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mcp-firewall %s (%s, %s)\n", version, commit, date)
		return
	}

	if *generateLockfile {
		runGenerateLockfile(*configPath)
		return
	}

	// Auto-detect workspace if not specified
	workspace := *workspacePath
	if workspace == "" {
		if cwd, err := os.Getwd(); err == nil {
			workspace = config.DetectWorkspace(cwd)
		}
	}

	resolved, err := config.ResolveConfig(*configPath, *profileName, workspace)
	if err != nil {
		slog.Error("failed to load config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	level := parseLogLevel(resolved.Config.LogLevel)
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	p := proxy.New(resolved.Config, logger,
		proxy.WithVersion(version),
		proxy.WithProvenance(resolved.ProfileName, resolved.LocalOverride),
		proxy.WithWorkspace(workspace),
	)

	if err := p.Run(ctx, &mcp.StdioTransport{}); err != nil {
		logger.Error("proxy exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func runGenerateLockfile(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("downstreams:")
	for alias, sc := range cfg.Downstreams {
		resolved, err := supply.ResolvePath(sc.Command)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: # error resolving: %v\n", alias, err)
			continue
		}
		hash, err := supply.ComputeFileHash(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: # error hashing: %v\n", alias, err)
			continue
		}
		fmt.Printf("  %s:\n    hash: %q\n", alias, hash)
	}
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
