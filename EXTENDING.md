# Extending VulnScan

## Overview

VulnScan is designed for extensibility at three levels:

1. **Service Probes** — Add new protocol detection
2. **Vulnerability Checks** — Add new security checks (SPI plugin system)
3. **Output Formats** — Add new serialization formats

---

## 1. Adding Service Probes

### Quick Inline Registration

```java
ServiceDetector detector = new ServiceDetector();
detector.registerProbe(new ServiceDetector.ServiceProbe(
    "my-http",           // unique ID
    "http",              // protocol name
    "My Custom Server",  // product name
    80,                  // priority (higher = checked first)
    Pattern.compile("(?i)Server:\\s*MyServer/([\\d.]+)"), // banner regex
    1,                   // version capture group
    0.8,                 // base confidence
    List.of("web", "custom"), // tags
    false,               // high-value target?
    Set.of(80, 8080, 8081)    // applicable ports
));
```

### Probe Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | String | Unique identifier |
| `protocol` | String | Protocol category (http, ssh, ftp, etc.) |
| `product` | String | Display name |
| `priority` | int | Matching priority (higher wins) |
| `pattern` | Pattern | Compiled regex for banner matching |
| `versionGroup` | int | Regex capture group for version (0 = none) |
| `baseConfidence` | double | 0.0–1.0 confidence baseline |
| `tags` | List<String> | Categorization tags |
| `highValueTarget` | boolean | Marks as high-value for reporting |
| `ports` | Set<Integer> | Applicable ports (empty = all) |

### Version Extraction

The `versionGroup` corresponds to regex capture groups:
- Group 0 = entire match
- Group 1 = first `(...)`
- Group 2 = second `(...)`, etc.

Example: `Server: Apache/2.4.52` with pattern `Server:\\s*Apache/([\\d.]+)` → group 1 = `2.4.52`

---

## 2. Adding Vulnerability Checks (SPI Plugin)

### Step 1: Implement the Interface

```java
package com.myorg.vulnscan.checks;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;

import java.util.List;
import java.util.Optional;

public class SpringBootActuatorCheck implements VulnerabilityCheck {

    @Override
    public CheckMetadata metadata() {
        return CheckMetadata.builder()
            .id("SPRINGBOOT-ACTUATOR")
            .name("Spring Boot Actuator Exposure")
            .description("Spring Boot actuator endpoints exposed without authentication")
            .severity(Severity.MEDIUM)
            .cvss(5.3)
            .affectedProducts(List.of("Spring Boot 1.x, 2.x with spring-boot-actuator"))
            .references(List.of("https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"))
            .tags(List.of("web", "spring", "info-leak", "misconfiguration"))
            .build();
    }

    @Override
    public Optional<Finding> execute(ServiceFingerprint fingerprint) {
        // Only run against HTTP services
        if (!"http".equals(fingerprint.getProtocol())) {
            return Optional.empty();
        }

        // In real implementation, make HTTP requests to /actuator endpoints
        // For now, return empty — actual HTTP client would be injected
        return Optional.empty();
    }

    @Override
    public List<String> getRequiredTags() {
        return List.of("web"); // Only run on web services
    }
}
```

### Step 2: Register via SPI

Create `src/main/resources/META-INF/services/com.himanshu.vulnscan.check.VulnerabilityCheck`:

```
com.myorg.vulnscan.checks.SpringBootActuatorCheck
```

### Step 3: Package as JAR

```xml
<!-- pom.xml -->
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-jar-plugin</artifactId>
    <configuration>
        <archive>
            <manifestEntries>
                <Automatic-Module-Name>com.myorg.vulnscan.checks</Automatic-Module-Name>
            </manifestEntries>
        </archive>
    </configuration>
</plugin>
```

### Step 4: Deploy

```bash
# Build
mvn package

# Install to user directory
mkdir -p ~/.vulnscan/checks
cp target/my-checks-1.0.jar ~/.vulnscan/checks/

# Run vulnscan — automatically loaded
vulnscan scan 192.168.1.100
```

### Loading Order

1. Built-in checks (registered in `CheckRegistry` constructor)
2. External JARs from `~/.vulnscan/checks/*.jar` (alphabetical)
3. Later registrations with same ID are skipped (first wins)

---

## 3. Adding Output Formats

### Extend Format Enum

```java
public enum Format {
    JSON, CSV, SARIF, TABLE, JSON_LINES, XML, HTML
}
```

### Add Formatter Method

```java
private String toXml(ScanResult result) {
    // Implementation
    return xmlString;
}

// In format() method:
case XML -> toXml(result);
```

---

## 4. Dependency Injection for Checks

Checks needing HTTP clients, databases, or external APIs should use constructor injection:

```java
public class HttpBasedCheck implements VulnerabilityCheck {
    private final HttpClient httpClient;

    public HttpBasedCheck(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    // Or use a factory/registry pattern for lazy initialization
}
```

Register via a custom `CheckProvider` interface if needed.

---

## 5. Testing Custom Checks

```java
@Test
void testSpringBootActuatorCheck() {
    CheckRegistry registry = new CheckRegistry();
    registry.register(new SpringBootActuatorCheck());

    ServiceFingerprint fp = new ServiceFingerprint(
        8080, "http", "Spring Boot", "2.7.0", 0.9,
        "Server: Apache-Coyote/1.1", List.of("web", "spring")
    );

    List<Finding> findings = registry.executeChecks(fp);
    // Assert findings...
}
```

---

## 6. Best Practices

| Practice | Why |
|----------|-----|
| Use `getRequiredTags()` | Filters checks early, avoids unnecessary execution |
| Keep `execute()` fast | Runs per-host, per-service; avoid blocking I/O |
| Return `Optional.empty()` for no finding | Clean, no null checks |
| Use descriptive `CheckMetadata.id` | Must be unique; used for enable/disable |
| Include CVSS and references | Enables risk prioritization and remediation |
| Tag appropriately | Enables filtering by category (`--category web`) |

---

## 7. Example: Complete Custom Check JAR

```
my-vulnscan-checks/
├── pom.xml
├── src/
│   └── main/
│       ├── java/
│       │   └── com/myorg/vulnscan/checks/
│       │       ├── SpringBootActuatorCheck.java
│       │       ├── JenkinsExposureCheck.java
│       │       └── DockerRegistryCheck.java
│       └── resources/
│           └── META-INF/services/
│               └── com.himanshu.vulnscan.check.VulnerabilityCheck
```

Build: `mvn package` → Install: `cp target/*.jar ~/.vulnscan/checks/`

---

## 8. Contributing Built-in Checks

1. Add check class to `src/main/java/com/himanshu/vulnscan/check/CheckRegistry.java` (inner class)
2. Register in `loadBuiltInChecks()`
3. Add unit test in `CheckRegistryTest.java`
4. Update `README.md` built-in checks table
5. Ensure `sigma check` equivalent validation passes