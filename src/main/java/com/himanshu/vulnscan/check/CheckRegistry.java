package com.himanshu.vulnscan.check;

import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CheckRegistry {

    private static final Logger log = LoggerFactory.getLogger(CheckRegistry.class);

    private final Map<String, VulnerabilityCheck> checks = new ConcurrentHashMap<>();
    private final Set<String> enabledChecks = ConcurrentHashMap.newKeySet();
    private final Set<String> disabledChecks = ConcurrentHashMap.newKeySet();

    public CheckRegistry() {
        loadBuiltInChecks();
        loadExternalChecks();
    }

    private void loadBuiltInChecks() {
        register(new Log4ShellCheck());
        register(new BlueKeepCheck());
        register(new AnonymousFtpCheck());
        register(new DefaultCredsCheck());
        register(new RedisUnauthCheck());
        register(new MongoOpenCheck());
        register(new SslTlsCheck());
        register(new SshWeakAlgoCheck());
        register(new HttpSecurityHeadersCheck());
        register(new DirectoryListingCheck());

        log.info("Loaded {} built-in vulnerability checks", checks.size());
    }

    private void loadExternalChecks() {
        String userHome = System.getProperty("user.home");
        Path checksDir = Paths.get(userHome, ".vulnscan", "checks");

        if (!Files.exists(checksDir)) {
            return;
        }

        try (Stream<Path> jars = Files.list(checksDir).filter(p -> p.toString().endsWith(".jar"))) {
            jars.forEach(this::loadChecksFromJar);
        } catch (IOException e) {
            log.warn("Failed to load external checks: {}", e.getMessage());
        }
    }

    private void loadChecksFromJar(Path jarPath) {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            URL[] urls = {jarPath.toUri().toURL()};
            var loader = new java.net.URLClassLoader(urls, getClass().getClassLoader());

            var services = loader.getResources("META-INF/services/com.himanshu.vulnscan.check.VulnerabilityCheck");
            while (services.hasMoreElements()) {
                URL url = services.nextElement();
                try (var reader = new java.io.BufferedReader(new java.io.InputStreamReader(url.openStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            try {
                                Class<?> clazz = loader.loadClass(line);
                                if (VulnerabilityCheck.class.isAssignableFrom(clazz)) {
                                    VulnerabilityCheck check = (VulnerabilityCheck) clazz.getDeclaredConstructor().newInstance();
                                    register(check);
                                    log.info("Loaded external check: {} from {}", check.metadata().id(), jarPath.getFileName());
                                }
                            } catch (Exception e) {
                                log.warn("Failed to load check class {}: {}", line, e.getMessage());
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to load checks from {}: {}", jarPath, e.getMessage());
        }
    }

    public void register(VulnerabilityCheck check) {
        String id = check.metadata().id();
        if (checks.containsKey(id)) {
            log.warn("Check {} already registered, skipping", id);
            return;
        }
        checks.put(id, check);
        enabledChecks.add(id);
    }

    public void unregister(String checkId) {
        checks.remove(checkId);
        enabledChecks.remove(checkId);
        disabledChecks.remove(checkId);
    }

    public void enableCheck(String checkId) {
        if (checks.containsKey(checkId)) {
            enabledChecks.add(checkId);
            disabledChecks.remove(checkId);
        }
    }

    public void disableCheck(String checkId) {
        enabledChecks.remove(checkId);
        disabledChecks.add(checkId);
    }

    public void enableOnly(Collection<String> checkIds) {
        enabledChecks.clear();
        enabledChecks.addAll(checkIds);
    }

    public void disableAll(Collection<String> checkIds) {
        disabledChecks.addAll(checkIds);
        enabledChecks.removeAll(checkIds);
    }

    public List<VulnerabilityCheck> getEnabledChecks() {
        return enabledChecks.stream()
                .map(checks::get)
                .filter(Objects::nonNull)
                .filter(VulnerabilityCheck::isEnabled)
                .toList();
    }

    public List<VulnerabilityCheck> getAllChecks() {
        return new ArrayList<>(checks.values());
    }

    public Optional<VulnerabilityCheck> getCheck(String checkId) {
        return Optional.ofNullable(checks.get(checkId));
    }

    public List<Finding> executeChecks(ServiceFingerprint fingerprint) {
        return getEnabledChecks().stream()
                .filter(check -> check.matches(fingerprint))
                .flatMap(check -> check.execute(fingerprint).stream())
                .toList();
    }

    public Map<String, VulnerabilityCheck> getChecksByTag(String tag) {
        return checks.entrySet().stream()
                .filter(e -> e.getValue().metadata().tags().contains(tag))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    public int getTotalCount() { return checks.size(); }
    public int getEnabledCount() { return enabledChecks.size(); }
    public int getDisabledCount() { return disabledChecks.size(); }

    // Built-in Checks

    private static class Log4ShellCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("CVE-2021-44228")
                    .name("Log4Shell RCE")
                    .description("Apache Log4j2 JNDI injection leading to remote code execution")
                    .severity(Severity.CRITICAL)
                    .cvss(10.0)
                    .affectedProducts(List.of("Apache Log4j 2.0-beta9 through 2.14.1"))
                    .references(List.of("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"))
                    .tags(List.of("rce", "log4j", "web", "critical"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            if (!"http".equals(fp.getProtocol())) return Optional.empty();
            // In real implementation, would send ${jndi:ldap://...} payloads
            return Optional.empty();
        }
    }

    private static class BlueKeepCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("CVE-2019-0708")
                    .name("BlueKeep RDP RCE")
                    .description("Pre-authentication remote code execution in RDP")
                    .severity(Severity.CRITICAL)
                    .cvss(9.8)
                    .affectedProducts(List.of("Windows 7, Server 2008 R2, Server 2008"))
                    .references(List.of("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708"))
                    .tags(List.of("rce", "rdp", "windows", "critical"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            if (!"rdp".equals(fp.getProtocol())) return Optional.empty();
            return Optional.empty();
        }
    }

    private static class AnonymousFtpCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("ANON-FTP")
                    .name("Anonymous FTP Access")
                    .description("FTP server allows anonymous login")
                    .severity(Severity.MEDIUM)
                    .cvss(5.3)
                    .affectedProducts(List.of("Any FTP server with anonymous enabled"))
                    .references(List.of("https://owasp.org/www-community/vulnerabilities/Anonymous_FTP_Access"))
                    .tags(List.of("misconfiguration", "ftp", "info-leak"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            if (!"ftp".equals(fp.getProtocol())) return Optional.empty();
            String banner = fp.getRawBanner().toLowerCase();
            if (banner.contains("230") && (banner.contains("anonymous") || banner.contains("guest"))) {
                return Optional.of(Finding.fromCheck(metadata(), banner, "Anonymous FTP login successful"));
            }
            return Optional.empty();
        }
    }

    private static class DefaultCredsCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("DEFAULT-CREDS")
                    .name("Default Credentials")
                    .description("Service uses default/weak credentials")
                    .severity(Severity.HIGH)
                    .cvss(7.5)
                    .affectedProducts(List.of("Various network services"))
                    .references(List.of("https://owasp.org/www-community/vulnerabilities/Default_Credentials"))
                    .tags(List.of("auth", "default-creds", "brute-force"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            // In real implementation, would attempt auth with common default creds
            return Optional.empty();
        }
    }

    private static class RedisUnauthCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("REDIS-UNAUTH")
                    .name("Redis Unauthorized Access")
                    .description("Redis instance accessible without authentication")
                    .severity(Severity.HIGH)
                    .cvss(7.5)
                    .affectedProducts(List.of("Redis < 6.0 without requirepass"))
                    .references(List.of("https://redis.io/topics/security"))
                    .tags(List.of("misconfiguration", "redis", "database"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            if (!"redis".equals(fp.getProtocol())) return Optional.empty();
            String banner = fp.getRawBanner().toLowerCase();
            if (banner.contains("redis_version") && !banner.contains("requirepass")) {
                return Optional.of(Finding.fromCheck(metadata(), banner, "Redis allows unauthenticated access"));
            }
            return Optional.empty();
        }
    }

    private static class MongoOpenCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("MONGO-OPEN")
                    .name("MongoDB Unauthenticated Access")
                    .description("MongoDB instance accessible without authentication")
                    .severity(Severity.HIGH)
                    .cvss(7.5)
                    .affectedProducts(List.of("MongoDB with --bind_ip 0.0.0.0 and no auth"))
                    .references(List.of("https://www.mongodb.com/docs/manual/security/"))
                    .tags(List.of("misconfiguration", "mongodb", "database"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            if (!"mongodb".equals(fp.getProtocol())) return Optional.empty();
            return Optional.of(Finding.fromCheck(metadata(), fp.getRawBanner(), "MongoDB may allow unauthenticated access"));
        }
    }

    private static class SslTlsCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("SSL-TLS-WEAK")
                    .name("Weak SSL/TLS Configuration")
                    .description("Service supports deprecated TLS versions or weak ciphers")
                    .severity(Severity.MEDIUM)
                    .cvss(5.9)
                    .affectedProducts(List.of("Any SSL/TLS service"))
                    .references(List.of("https://owasp.org/www-community/vulnerabilities/Weak_SSL_TLS"))
                    .tags(List.of("crypto", "tls", "ssl"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            return Optional.empty();
        }
    }

    private static class SshWeakAlgoCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("SSH-WEAK-ALGO")
                    .name("SSH Weak Algorithms")
                    .description("SSH server offers weak key exchange, cipher, or MAC algorithms")
                    .severity(Severity.MEDIUM)
                    .cvss(5.3)
                    .affectedProducts(List.of("OpenSSH, Dropbear, other SSH implementations"))
                    .references(List.of("https://infosec.mozilla.org/guidelines/openssh"))
                    .tags(List.of("crypto", "ssh", "config"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            if (!"ssh".equals(fp.getProtocol())) return Optional.empty();
            return Optional.empty();
        }
    }

    private static class HttpSecurityHeadersCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("HTTP-SEC-HEADERS")
                    .name("Missing Security Headers")
                    .description("HTTP response missing security headers (HSTS, CSP, X-Frame-Options, etc.)")
                    .severity(Severity.LOW)
                    .cvss(3.7)
                    .affectedProducts(List.of("Web applications"))
                    .references(List.of("https://owasp.org/www-project-secure-headers/"))
                    .tags(List.of("web", "headers", "config"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            if (!"http".equals(fp.getProtocol())) return Optional.empty();
            return Optional.empty();
        }
    }

    private static class DirectoryListingCheck implements VulnerabilityCheck {
        @Override
        public CheckMetadata metadata() {
            return CheckMetadata.builder()
                    .id("DIR-LISTING")
                    .name("Directory Listing Enabled")
                    .description("Web server exposes directory listing")
                    .severity(Severity.LOW)
                    .cvss(3.7)
                    .affectedProducts(List.of("Apache, Nginx, IIS with autoindex on"))
                    .references(List.of("https://owasp.org/www-community/vulnerabilities/Directory_Listing"))
                    .tags(List.of("web", "info-leak", "config"))
                    .build();
        }

        @Override
        public Optional<Finding> execute(ServiceFingerprint fp) {
            if (!"http".equals(fp.getProtocol())) return Optional.empty();
            return Optional.empty();
        }
    }
}