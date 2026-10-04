# Architecture

## Overview

VulnScan follows a **pipeline architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────────────────┐
                            ScanOrchestrator (Pipeline Coordinator)
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌───────────────┐           ┌─────────────────┐           ┌─────────────────┐
│ TargetParser  │           │  PortScanner    │           │ ServiceDetector │
│ (CIDR, range, │──────────▶│ (Virtual Threads)│────────▶│ (Probe Registry)│
│  hostname)    │           │                 │           │                 │
└───────────────┘           └─────────────────┘           └─────────────────┘
                                                                       │
                                                                       ▼
                                                          ┌─────────────────────┐
                                                          │  CheckRegistry      │
                                                          │  (SPI Plugin System)│
                                                          └─────────────────────┘
                                                                       │
                                                                       ▼
                                                          ┌─────────────────────┐
                                                          │  OutputFormatter    │
                                                          │ (JSON/CSV/SARIF/   │
                                                          │  Table/JSON-Lines)  │
                                                          └─────────────────────┘
```

## Core Modules

| Module | Package | Responsibility |
|--------|---------|----------------|
| **CLI** | `com.himanshu.vulnscan` | Command parsing (Picocli), subcommands |
| **Orchestrator** | `com.himanshu.vulnscan.orchestrator` | Pipeline execution, progress tracking |
| **Scanner** | `com.himanshu.vulnscan.scanner` | Target parsing, port scanning, service detection |
| **Checks** | `com.himanshu.vulnscan.check` | Vulnerability check SPI, registry, built-in checks |
| **Models** | `com.himanshu.vulnscan.model` | Data classes (POJOs/Records) with Jackson annotations |
| **Output** | `com.himanshu.vulnscan.output` | Multi-format serialization |
| **Config** | `com.himanshu.vulnscan.config` | YAML configuration, profile management |
| **Persistence** | `com.himanshu.vulnscan.persistence` | SQLite scan state, resume capability |

## Thread Model

```
Main Thread
    │
    ├── ScanOrchestrator.execute() — sequential per-host
    │
    └── PortScanner.scan() — parallel per-port (Virtual Threads)
          │
          ├── ExecutorService (VirtualThreadPerTaskExecutor)
          │
          ├── CompletableFuture per port
          │
          └── Bounded by maxThreads (default 1000)
```

**Virtual Threads** (Java 21) enable 10,000+ concurrent connections on modest hardware without thread pool exhaustion.

## Data Flow

```
Target Input (IP/CIDR/range/hostname/file)
    │
    ▼
TargetParser.parse() → List<String> hosts
    │
    ▼
For each host:
    │
    ├── PortScanner.scan(host, ports) → List<PortScanResult>
    │       │
    │       └── Virtual threads: connect → banner grab → result
    │
    ▼
ServiceDetector.detect(host, portResults) → List<ServiceFingerprint>
    │
    ▼
CheckRegistry.executeChecks(fingerprint) → List<Finding>
    │
    ▼
OutputFormatter.format(result, format) → String
```

## Extension Points

### 1. Service Probes (ServiceDetector)
Add custom service detection via `ServiceDetector.registerProbe()`:

```java
detector.registerProbe(new ServiceProbe(
    "custom-http", "http", "Custom HTTP Server", 80,
    Pattern.compile("(?i)Server:\\s*CustomServer/([\\d.]+)"),
    1, 0.8, List.of("web", "custom"), false,
    Set.of(80, 8080)
));
```

### 2. Vulnerability Checks (SPI)
Implement `VulnerabilityCheck` interface and register via `META-INF/services`:

```java
public class MyCheck implements VulnerabilityCheck {
    @Override
    public CheckMetadata metadata() { ... }
    @Override
    public Optional<Finding> execute(ServiceFingerprint fp) { ... }
}
```

Package as JAR, drop in `~/.vulnscan/checks/` — auto-loaded on startup.

### 3. Output Formats
Extend `OutputFormatter` with new `Format` enum value and implementation.

### 4. Configuration
Add fields to `ScannerConfig` records — automatically persisted to YAML.

## Configuration Hierarchy

```
CLI Arguments (highest priority)
    │
    ▼
Scan Profile (--profile quick/full/stealth)
    │
    ▼
Config File (~/.vulnscan/config.yaml)
    │
    ▼
Built-in Defaults (lowest priority)
```

## Scan State Persistence

SQLite schema (`~/.vulnscan/scans.db`):

```sql
scans (
    scan_id PK, target, input_file, ports, profile,
    start_time, end_time, status, current_host, total_hosts, progress_message
)

scan_hosts (
    id PK, scan_id FK, host, completed,
    port_results JSON, fingerprints JSON, findings JSON
)
```

Enables `--resume <scan-id>` to skip completed hosts.

## Security Considerations

- **No privileged operations** — runs as unprivileged user
- **Input validation** — all targets sanitized by TargetParser
- **Timeout bounds** — connection timeouts enforced at socket level
- **Resource limits** — maxThreads caps virtual thread creation
- **No arbitrary code execution** — checks are data-driven, not scripted

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Max concurrent connections | 10,000+ (virtual threads) |
| Memory per 1000 ports | ~50 MB |
| Port scan throughput | ~50,000 ports/sec (localhost) |
| Startup time (JAR) | ~500ms |
| Startup time (native) | ~50ms |
| Config load time | ~10ms |

## Technology Stack

| Layer | Technology |
|-------|------------|
| Language | Java 21 (preview features) |
| Build | Maven 3.9+ |
| CLI | Picocli 4.7 |
| JSON/YAML | Jackson 2.17 |
| Logging | SLF4J + Logback |
| Database | SQLite (Xerial) |
| Testing | JUnit 5, Mockito, Testcontainers |
| Static Analysis | SpotBugs, Checkstyle, OWASP Dependency Check |
| Native Image | GraalVM 21 |
| Release | JReleaser |

## Directory Structure

```
vulnscan/
├── src/main/java/com/himanshu/vulnscan/
│   ├── Main.java                 # Entry point
│   ├── ScanCommand.java          # scan subcommand
│   ├── ListChecksCommand.java    # list-checks subcommand
│   ├── ConfigCommand.java        # config subcommand
│   ├── orchestrator/             # Pipeline coordinator
│   ├── scanner/                  # TargetParser, PortScanner, ServiceDetector
│   ├── check/                    # VulnerabilityCheck, CheckRegistry, built-ins
│   ├── model/                    # PortScanResult, ServiceFingerprint, Finding, ScanResult
│   ├── output/                   # OutputFormatter (JSON/CSV/SARIF/Table)
│   ├── config/                   # ConfigManager, ScannerConfig
│   └── persistence/              # ScanStateStore (SQLite)
├── src/test/                     # Unit + integration tests
├── .github/workflows/ci.yml      # CI pipeline
├── pom.xml                       # Maven build
├── checkstyle.xml                # Code style rules
└── README.md                     # User documentation
```