package com.himanshu.vulnscan;

import com.himanshu.vulnscan.model.ScanResult;
import com.himanshu.vulnscan.orchestrator.ScanOrchestrator;
import com.himanshu.vulnscan.output.OutputFormatter;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.concurrent.Callable;

@Command(name = "scan",
        description = "Scan targets for open ports and vulnerabilities",
        mixinStandardHelpOptions = true)
public class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Target specification (IP, CIDR, range, hostname, or file with -iL)")
    private String target;

    @Option(names = {"-p", "--ports"}, description = "Port specification (e.g., 80,443, 1-1000, top100, top1000, all)")
    private String ports = "top1000";

    @Option(names = {"-t", "--threads"}, description = "Maximum concurrent threads (virtual threads)")
    private int threads = 1000;

    @Option(names = {"-T", "--timeout"}, description = "Connection timeout in milliseconds")
    private int timeout = 3000;

    @Option(names = {"-o", "--output"}, description = "Output file (default: stdout)")
    private String output;

    @Option(names = {"-f", "--format"}, description = "Output format: json, csv, sarif, table, json-lines")
    private String format = "table";

    @Option(names = {"-P", "--profile"}, description = "Scan profile: quick, full, stealth, custom")
    private String profile = "full";

    @Option(names = {"-iL", "--input-file"}, description = "Read targets from file")
    private String inputFile;

    @Option(names = {"--checks"}, description = "Comma-separated check IDs to run (default: all)")
    private String checks;

    @Option(names = {"--exclude-checks"}, description = "Comma-separated check IDs to skip")
    private String excludeChecks;

    @Option(names = {"--resume"}, description = "Resume previous scan by ID")
    private String resume;

    @Option(names = {"--no-ping"}, description = "Skip host discovery")
    private boolean noPing = false;

    @Option(names = {"--banner-grab"}, description = "Enable banner grabbing on open ports")
    private boolean bannerGrab = true;

    @Option(names = {"--progress"}, description = "Show progress bar")
    private boolean showProgress = true;

    @Override
    public Integer call() {
        ScanOrchestrator.ScanConfig config = new ScanOrchestrator.ScanConfig(
                ports, threads, timeout, bannerGrab, profile, checks, excludeChecks, noPing
        );

        ScanOrchestrator orchestrator = new ScanOrchestrator(config);
        OutputFormatter formatter = new OutputFormatter();

        if (showProgress) {
            orchestrator.setProgressCallback(progress -> {
                System.out.print(formatter.formatProgress(progress));
            });
        }

        System.out.println("Starting scan...");
        ScanResult result = orchestrator.execute(target, inputFile);

        if (showProgress) {
            System.out.println(); // New line after progress bar
        }

        String formatted = formatter.format(result, OutputFormatter.Format.valueOf(format.toUpperCase().replace("-", "_")));

        if (output != null) {
            try (PrintWriter writer = new PrintWriter(new FileWriter(output))) {
                writer.print(formatted);
                System.out.println("Results written to " + output);
            } catch (Exception e) {
                System.err.println("Failed to write output: " + e.getMessage());
                return 1;
            }
        } else {
            System.out.println(formatted);
        }

        return result.getCriticalFindings() > 0 ? 2 : (result.getTotalFindings() > 0 ? 1 : 0);
    }
}