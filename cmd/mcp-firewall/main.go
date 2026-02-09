package main

import (
	"context"
	"errors"
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
	initConfig := flag.Bool("init", false, "create default config file and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mcp-firewall %s (%s, %s)\n", version, commit, date)
		return
	}

	if *initConfig {
		runInit(*configPath)
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
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "error: config file not found: %s\n", *configPath)
			fmt.Fprintf(os.Stderr, "Run 'npx -y @vikingowl/mcp-firewall --init' to create a default config.\n")
			os.Exit(1)
		}
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

const defaultConfigTemplate = `# mcp-firewall configuration
# Docs: https://github.com/VikingOwl91/mcp-firewall

# Downstream MCP servers to proxy
downstreams:
  # example:
  #   command: my-mcp-server
  #   args: ["--port", "3000"]
  #   timeout: 30s
  #   sandbox: strict          # Linux process sandbox (optional)
  #   hash: "sha256:..."       # Supply chain hash pin (optional)

# Policy engine — first matching rule wins, then default applies
policy:
  default: allow               # allow | deny
  # rules:
  #   - name: deny-dangerous
  #     expression: 'tool.name == "rm" || tool.name == "delete"'
  #     effect: deny
  #   - name: prompt-writes
  #     expression: 'tool.name.startsWith("write")'
  #     effect: prompt
  #     message: "This tool will modify data. Approve?"

# Redaction — regex patterns applied to tool inputs and outputs
# redaction:
#   patterns:
#     - name: api-keys
#       pattern: 'sk-[a-zA-Z0-9]{32}'

# Global settings
# timeout: 30s                 # Default tool/resource call timeout
# approval_timeout: 2m         # Interactive approval timeout
# max_output_bytes: 524288     # Output truncation limit
# log_level: info              # debug | info | warn | error
`

func runInit(configPath string) {
	if _, err := os.Stat(configPath); err == nil {
		fmt.Fprintf(os.Stderr, "error: config file already exists: %s\n", configPath)
		os.Exit(1)
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to create directory %s: %v\n", dir, err)
		os.Exit(1)
	}

	if err := os.WriteFile(configPath, []byte(defaultConfigTemplate), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created default config at %s\n", configPath)
	fmt.Println("Edit the file to add your downstream MCP servers, then run mcp-firewall.")
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
