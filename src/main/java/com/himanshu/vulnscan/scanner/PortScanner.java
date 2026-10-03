package com.himanshu.vulnscan.scanner;

import com.himanshu.vulnscan.model.PortScanResult;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class PortScanner {

    private static final Logger log = LoggerFactory.getLogger(PortScanner.class);

    private final int timeoutMs;
    private final int maxThreads;
    private final boolean bannerGrab;

    public PortScanner(int timeoutMs, int maxThreads, boolean bannerGrab) {
        this.timeoutMs = timeoutMs;
        this.maxThreads = maxThreads;
        this.bannerGrab = bannerGrab;
    }

    public List<PortScanResult> scan(String target, Set<Integer> ports) {
        log.info("Starting port scan on {} for {} ports", target, ports.size());
        Instant start = Instant.now();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<CompletableFuture<PortScanResult>> futures = ports.stream()
                    .map(port -> CompletableFuture.supplyAsync(() -> scanPort(target, port), executor))
                    .collect(Collectors.toList());

            List<PortScanResult> results = new ArrayList<>();
            AtomicInteger completed = new AtomicInteger(0);
            int total = futures.size();

            for (CompletableFuture<PortScanResult> future : futures) {
                try {
                    PortScanResult result = future.get(timeoutMs + 1000, TimeUnit.MILLISECONDS);
                    if (result.isOpen()) {
                        results.add(result);
                        log.debug("Port {} open on {}", result.getPort(), target);
                    }
                } catch (Exception e) {
                    log.debug("Port scan error: {}", e.getMessage());
                }
                int done = completed.incrementAndGet();
                if (done % 100 == 0 || done == total) {
                    log.info("Progress: {}/{} ports scanned", done, total);
                }
            }

            Duration elapsed = Duration.between(start, Instant.now());
            log.info("Port scan completed in {}ms. Open ports: {}", elapsed.toMillis(), results.size());
            return results;

        } catch (Exception e) {
            log.error("Port scanner executor error: {}", e.getMessage());
            throw new RuntimeException("Port scan failed", e);
        }
    }

    private PortScanResult scanPort(String target, int port) {
        try (SocketChannel channel = SocketChannel.open()) {
            channel.configureBlocking(true);
            channel.socket().setSoTimeout(timeoutMs);

            boolean connected = channel.connect(new InetSocketAddress(target, port));
            if (!connected) {
                return PortScanResult.closed(port);
            }

            String banner = null;
            if (bannerGrab) {
                banner = grabBanner(channel);
            }

            return PortScanResult.open(port, banner);

        } catch (IOException e) {
            return PortScanResult.closed(port);
        }
    }

    private String grabBanner(SocketChannel channel) {
        try (Socket socket = channel.socket()) {
            socket.setSoTimeout(Math.min(timeoutMs, 2000));

            byte[] buffer = new byte[1024];
            int bytesRead = socket.getInputStream().read(buffer);
            if (bytesRead > 0) {
                return new String(buffer, 0, bytesRead).trim();
            }

            String[] probes = {
                    "\r\n",
                    "HEAD / HTTP/1.0\r\n\r\n",
                    "GET / HTTP/1.0\r\n\r\n",
                    "HELP\r\n",
                    "VERSION\r\n"
            };

            for (String probe : probes) {
                try {
                    socket.getOutputStream().write(probe.getBytes());
                    socket.getOutputStream().flush();
                    Thread.sleep(100);
                    bytesRead = socket.getInputStream().read(buffer);
                    if (bytesRead > 0) {
                        return new String(buffer, 0, bytesRead).trim();
                    }
                } catch (Exception ignored) {
                }
            }

        } catch (Exception e) {
            log.debug("Banner grab failed: {}", e.getMessage());
        }
        return null;
    }

    public static Set<Integer> parsePortSpec(String spec) {
        if (spec == null || spec.isBlank()) {
            return Set.of();
        }

        return switch (spec.toLowerCase()) {
            case "top100" -> IntStream.rangeClosed(1, 100).boxed().collect(Collectors.toSet());
            case "top1000" -> IntStream.rangeClosed(1, 1000).boxed().collect(Collectors.toSet());
            case "all" -> IntStream.rangeClosed(1, 65535).boxed().collect(Collectors.toSet());
            default -> parseCustomPortSpec(spec);
        };
    }

    private static Set<Integer> parseCustomPortSpec(String spec) {
        Set<Integer> ports = new java.util.HashSet<>();
        for (String part : spec.split(",")) {
            part = part.trim();
            if (part.contains("-")) {
                String[] range = part.split("-");
                int start = Integer.parseInt(range[0].trim());
                int end = Integer.parseInt(range[1].trim());
                if (start > 0 && end <= 65535 && start <= end) {
                    IntStream.rangeClosed(start, end).forEach(ports::add);
                }
            } else {
                int port = Integer.parseInt(part);
                if (port > 0 && port <= 65535) {
                    ports.add(port);
                }
            }
        }
        return ports;
    }
}