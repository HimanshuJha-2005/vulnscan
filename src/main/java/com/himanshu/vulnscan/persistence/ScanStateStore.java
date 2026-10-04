package com.himanshu.vulnscan.persistence;

import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.PortScanResult;
import com.himanshu.vulnscan.model.ScanResult;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ScanStateStore {

    private static final Logger log = LoggerFactory.getLogger(ScanStateStore.class);

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

    private static final String DB_DIR = System.getProperty("user.home") + "/.vulnscan";
    private static final String DB_FILE = DB_DIR + "/scans.db";
    private static final String DB_URL = "jdbc:sqlite:" + DB_FILE;

    private Connection connection;

    public ScanStateStore() {
        init();
    }

    private void init() {
        try {
            Files.createDirectories(Paths.get(DB_DIR));
            connection = DriverManager.getConnection(DB_URL);
            createTables();
            log.info("Initialized scan state store at {}", DB_FILE);
        } catch (Exception e) {
            log.error("Failed to initialize scan state store: {}", e.getMessage());
        }
    }

    private void createTables() throws SQLException {
        String sql = """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT,
                input_file TEXT,
                ports TEXT,
                profile TEXT,
                start_time TEXT,
                end_time TEXT,
                status TEXT,
                current_host INTEGER,
                total_hosts INTEGER,
                progress_message TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS scan_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                host TEXT,
                completed BOOLEAN DEFAULT FALSE,
                port_results TEXT,
                fingerprints TEXT,
                findings TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_hosts_scan_id ON scan_hosts(scan_id);
            """;
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    public void saveScan(ScanResult result, String status, int currentHost, int totalHosts, String progressMessage) {
        String sql = """
            INSERT OR REPLACE INTO scans (scan_id, target, input_file, ports, profile, start_time, end_time, status, current_host, total_hosts, progress_message, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, result.getScanId());
            stmt.setString(2, result.getTarget());
            stmt.setString(3, result.getInputFile());
            stmt.setString(4, result.getPorts());
            stmt.setString(5, result.getProfile());
            stmt.setString(6, result.getStartTime().toString());
            stmt.setString(7, result.getEndTime() != null ? result.getEndTime().toString() : "");
            stmt.setString(8, status);
            stmt.setInt(9, currentHost);
            stmt.setInt(10, totalHosts);
            stmt.setString(11, progressMessage);
            stmt.setString(12, Instant.now().toString());
            stmt.executeUpdate();
        } catch (SQLException e) {
            log.error("Failed to save scan: {}", e.getMessage());
        }
    }

    public void saveHostResult(String scanId, String host, List<PortScanResult> portResults,
                               List<ServiceFingerprint> fingerprints, List<Finding> findings) {
        String sql = """
            INSERT INTO scan_hosts (scan_id, host, completed, port_results, fingerprints, findings)
            VALUES (?, ?, TRUE, ?, ?, ?)
            """;

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, scanId);
            stmt.setString(2, host);
            stmt.setString(3, toJson(portResults));
            stmt.setString(4, toJson(fingerprints));
            stmt.setString(5, toJson(findings));
            stmt.executeUpdate();
        } catch (SQLException e) {
            log.error("Failed to save host result for {}: {}", host, e.getMessage());
        }
    }

    private String toJson(Object obj) {
        try {
            return MAPPER.writeValueAsString(obj);
        } catch (Exception e) {
            return "[]";
        }
    }

    public Optional<ScanState> loadScanState(String scanId) {
        String sql = "SELECT * FROM scans WHERE scan_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, scanId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapScanState(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to load scan state: {}", e.getMessage());
        }
        return Optional.empty();
    }

    public List<String> getCompletedHosts(String scanId) {
        List<String> hosts = new ArrayList<>();
        String sql = "SELECT host FROM scan_hosts WHERE scan_id = ? AND completed = TRUE";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, scanId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    hosts.add(rs.getString("host"));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to load completed hosts: {}", e.getMessage());
        }
        return hosts;
    }

    public ScanResult loadScanResult(String scanId) {
        Optional<ScanState> stateOpt = loadScanState(scanId);
        if (stateOpt.isEmpty()) return null;

        ScanState state = stateOpt.get();
        Map<String, List<PortScanResult>> allPortResults = new HashMap<>();
        Map<String, List<ServiceFingerprint>> allFingerprints = new HashMap<>();
        Map<String, List<Finding>> allFindings = new HashMap<>();

        String sql = "SELECT host, port_results, fingerprints, findings FROM scan_hosts WHERE scan_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, scanId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    String host = rs.getString("host");
                    allPortResults.put(host, fromJson(rs.getString("port_results"), PortScanResult.class));
                    allFingerprints.put(host, fromJson(rs.getString("fingerprints"), ServiceFingerprint.class));
                    allFindings.put(host, fromJson(rs.getString("findings"), Finding.class));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to load scan result: {}", e.getMessage());
            return null;
        }

        return new ScanResult(
                state.scanId, state.target, state.inputFile, state.ports, state.profile,
                state.startTime, state.endTime,
                allPortResults, allFingerprints, allFindings
        );
    }

    private <T> List<T> fromJson(String json, Class<T> clazz) {
        if (json == null || json.isBlank()) return List.of();
        try {
            return MAPPER.readValue(json, MAPPER.getTypeFactory().constructCollectionType(List.class, clazz));
        } catch (Exception e) {
            return List.of();
        }
    }

    private ScanState mapScanState(ResultSet rs) throws SQLException {
        return new ScanState(
                rs.getString("scan_id"),
                rs.getString("target"),
                rs.getString("input_file"),
                rs.getString("ports"),
                rs.getString("profile"),
                Instant.parse(rs.getString("start_time")),
                rs.getString("end_time").isBlank() ? null : Instant.parse(rs.getString("end_time")),
                rs.getString("status")
        );
    }

    public List<ScanSummary> listScans() {
        List<ScanSummary> scans = new ArrayList<>();
        String sql = "SELECT scan_id, target, profile, start_time, status, current_host, total_hosts FROM scans ORDER BY start_time DESC";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                scans.add(new ScanSummary(
                        rs.getString("scan_id"),
                        rs.getString("target"),
                        rs.getString("profile"),
                        Instant.parse(rs.getString("start_time")),
                        rs.getString("status"),
                        rs.getInt("current_host"),
                        rs.getInt("total_hosts")
                ));
            }
        } catch (SQLException e) {
            log.error("Failed to list scans: {}", e.getMessage());
        }
        return scans;
    }

    public void close() {
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException e) {
                log.error("Failed to close DB: {}", e.getMessage());
            }
        }
    }

    record ScanState(String scanId, String target, String inputFile, String ports, String profile,
                     Instant startTime, Instant endTime, String status) {}

    record ScanSummary(String scanId, String target, String profile, Instant startTime,
                       String status, int currentHost, int totalHosts) {}
}