package com.himanshu.vulnscan.output;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.PortScanResult;
import com.himanshu.vulnscan.model.ScanResult;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class OutputFormatter {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

    public enum Format {
        JSON, CSV, SARIF, TABLE, JSON_LINES
    }

    public String format(ScanResult result, Format format) {
        return switch (format) {
            case JSON -> toJson(result);
            case CSV -> toCsv(result);
            case SARIF -> toSarif(result);
            case TABLE -> toTable(result);
            case JSON_LINES -> toJsonLines(result);
        };
    }

    private String toJson(ScanResult result) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(result);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize JSON", e);
        }
    }

    private String toJsonLines(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        try {
            // Write scan metadata
            sb.append(MAPPER.writeValueAsString(Map.of(
                    "type", "scan_metadata",
                    "scanId", result.getScanId(),
                    "target", result.getTarget(),
                    "startTime", result.getStartTime(),
                    "endTime", result.getEndTime(),
                    "durationMs", result.getDurationMs(),
                    "totalHosts", result.getTotalHosts(),
                    "totalOpenPorts", result.getTotalOpenPorts(),
                    "totalFindings", result.getTotalFindings()
            ))).append("\n");

            // Write findings as separate lines
            for (Map.Entry<String, List<Finding>> entry : result.getFindings().entrySet()) {
                for (Finding finding : entry.getValue()) {
                    sb.append(MAPPER.writeValueAsString(Map.of(
                            "type", "finding",
                            "host", entry.getKey(),
                            "checkId", finding.getCheckId(),
                            "severity", finding.getSeverity().toString(),
                            "cvss", finding.getCvss(),
                            "title", finding.getTitle(),
                            "evidence", finding.getEvidence()
                    ))).append("\n");
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize JSON Lines", e);
        }
        return sb.toString();
    }

    private String toCsv(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("scanId,host,port,protocol,product,version,checkId,severity,cvss,title,evidence\n");

        for (Map.Entry<String, List<Finding>> entry : result.getFindings().entrySet()) {
            String host = entry.getKey();
            for (Finding finding : entry.getValue()) {
                // Find corresponding fingerprint for port info
                String portInfo = "";
                String protocol = "";
                String product = "";
                String version = "";

                List<ServiceFingerprint> fps = result.getFingerprints().get(host);
                if (fps != null) {
                    for (ServiceFingerprint fp : fps) {
                        if (finding.getEvidence() != null && finding.getEvidence().contains(fp.getRawBanner())) {
                            portInfo = String.valueOf(fp.getPort());
                            protocol = fp.getProtocol();
                            product = fp.getProduct();
                            version = fp.getVersion() != null ? fp.getVersion() : "";
                            break;
                        }
                    }
                }

                sb.append(escapeCsv(result.getScanId())).append(",");
                sb.append(escapeCsv(host)).append(",");
                sb.append(escapeCsv(portInfo)).append(",");
                sb.append(escapeCsv(protocol)).append(",");
                sb.append(escapeCsv(product)).append(",");
                sb.append(escapeCsv(version)).append(",");
                sb.append(escapeCsv(finding.getCheckId())).append(",");
                sb.append(escapeCsv(finding.getSeverity().toString())).append(",");
                sb.append(finding.getCvss()).append(",");
                sb.append(escapeCsv(finding.getTitle())).append(",");
                sb.append(escapeCsv(finding.getEvidence())).append("\n");
            }
        }
        return sb.toString();
    }

    private String escapeCsv(String value) {
        if (value == null) return "";
        String escaped = value.replace("\"", "\"\"");
        if (escaped.contains(",") || escaped.contains("\"") || escaped.contains("\n")) {
            return "\"" + escaped + "\"";
        }
        return escaped;
    }

    private String toSarif(ScanResult result) {
        Map<String, Object> sarif = new LinkedHashMap<>();
        sarif.put("$schema", "https://schemastore.org/schemas/json/sarif-2.1.0.json");
        sarif.put("version", "2.1.0");

        List<Map<String, Object>> runs = new ArrayList<>();
        Map<String, Object> run = new LinkedHashMap<>();

        // Tool info
        run.put("tool", Map.of(
                "driver", Map.of(
                        "name", "VulnScan",
                        "version", "1.0.0",
                        "informationUri", "https://github.com/HimanshuJha-2005/vulnscan",
                        "rules", buildSarifRules(result)
                )
        ));

        // Results
        List<Map<String, Object>> results = new ArrayList<>();
        int resultIndex = 0;
        for (Map.Entry<String, List<Finding>> entry : result.getFindings().entrySet()) {
            String host = entry.getKey();
            for (Finding finding : entry.getValue()) {
                results.add(Map.of(
                        "ruleId", finding.getCheckId(),
                        "ruleIndex", resultIndex++,
                        "level", mapSeverityToSarif(finding.getSeverity()),
                        "message", Map.of("text", finding.getTitle()),
                        "locations", List.of(Map.of(
                                "physicalLocation", Map.of(
                                        "artifactLocation", Map.of(
                                                "uri", host,
                                                "uriBaseId", "%TARGET%"
                                        ),
                                        "region", Map.of(
                                                "snippet", Map.of("text", finding.getEvidence())
                                        )
                                )
                        )),
                        "properties", Map.of(
                                "cvss", finding.getCvss(),
                                "severity", finding.getSeverity().toString(),
                                "references", finding.getReferences()
                        )
                ));
            }
        }
        run.put("results", results);
        run.put("invocations", List.of(Map.of(
                "toolExecutionSuccessful", true,
                "startTimeUtc", result.getStartTime().toString(),
                "endTimeUtc", result.getEndTime().toString()
        )));

        runs.add(run);
        sarif.put("runs", runs);

        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(sarif);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize SARIF", e);
        }
    }

    private List<Map<String, Object>> buildSarifRules(ScanResult result) {
        Set<String> seen = new HashSet<>();
        List<Map<String, Object>> rules = new ArrayList<>();

        for (List<Finding> findings : result.getFindings().values()) {
            for (Finding finding : findings) {
                if (seen.add(finding.getCheckId())) {
                    rules.add(Map.of(
                            "id", finding.getCheckId(),
                            "name", finding.getCheckName(),
                            "shortDescription", Map.of("text", finding.getTitle()),
                            "fullDescription", Map.of("text", finding.getDescription()),
                            "defaultConfiguration", Map.of("level", mapSeverityToSarif(finding.getSeverity())),
                            "properties", Map.of(
                                    "cvss", finding.getCvss(),
                                    "tags", finding.getTags(),
                                    "references", finding.getReferences()
                            )
                    ));
                }
            }
        }
        return rules;
    }

    private String mapSeverityToSarif(VulnerabilityCheck.Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }

    private String toTable(ScanResult result) {
        StringBuilder sb = new StringBuilder();

        // Summary
        sb.append("╔═════════════════════════════════════════════════════════════════════════════════════════════╗\n");
        sb.append("║  ").append(String.format("%-90s", "VulnScan Results")).append("  ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════════════════════════════════════╣\n");
        sb.append("║  Scan ID: ").append(String.format("%-80s", result.getScanId())).append("  ║\n");
        sb.append("║  Target:  ").append(String.format("%-80s", result.getTarget() != null ? result.getTarget() : "@" + result.getInputFile())).append("  ║\n");
        sb.append("║  Profile: ").append(String.format("%-80s", result.getProfile())).append("  ║\n");
        sb.append("║  Started: ").append(String.format("%-80s", result.getStartTime())).append("  ║\n");
        sb.append("║  Duration: ").append(String.format("%-79s", result.getDurationMs() + " ms")).append("  ║\n");
        sb.append("║  Hosts: ").append(String.format("%-3d  ", result.getTotalHosts())).append("Open Ports: ").append(String.format("%-4d  ", result.getTotalOpenPorts())).append("Findings: ").append(String.format("%-4d  ", result.getTotalFindings())).append("Critical: ").append(String.format("%-3d  ", result.getCriticalFindings())).append("High: ").append(String.format("%-3d  ", result.getHighFindings())).append("║\n");
        sb.append("╠══════════════════════════════════════════════════════════════════════════════════════════════╣\n");

        if (result.getFindings().isEmpty()) {
            sb.append("║  No vulnerabilities found.                                                                     ║\n");
        } else {
            // Findings table
            sb.append("║  ").append(String.format("%-15s %-15s %-8s %-5s %-50s  ║", "HOST", "PORT", "SEV", "CVSS", "FINDING")).append("\n");
            sb.append("╠").append("─".repeat(98)).append("╣\n");

            for (Map.Entry<String, List<Finding>> entry : result.getFindings().entrySet()) {
                String host = entry.getKey();
                for (Finding finding : entry.getValue()) {
                    String severity = finding.getSeverity().toString();
                    String cvss = String.format("%.1f", finding.getCvss());
                    String title = finding.getTitle();
                    if (title.length() > 50) title = title.substring(0, 47) + "...";

                    sb.append("║  ").append(String.format("%-15s %-15s %-8s %-5s %-50s  ║",
                            truncate(host, 15), "N/A", severity, cvss, title)).append("\n");
                }
            }
        }

        sb.append("╚").append("═".repeat(98)).append("╝\n");
        return sb.toString();
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max - 3) + "..." : s;
    }

    // Console progress formatter
    public String formatProgress(ScanOrchestrator.ScanProgress progress) {
        int barWidth = 40;
        int filled = (int) (progress.getPercentage() / 100 * barWidth);
        String bar = "█".repeat(filled) + "░".repeat(barWidth - filled);
        return String.format("\r[%s] %.1f%% (%d/%d) %s", bar, progress.getPercentage(), progress.current(), progress.total(), progress.message());
    }
}