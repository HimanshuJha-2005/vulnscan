package com.himanshu.vulnscan;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.concurrent.Callable;

@Command(name = "vulnscan",
        version = "1.0.0",
        mixinStandardHelpOptions = true,
        description = "High-performance network vulnerability scanner with plugin architecture",
        subcommands = {
                ScanCommand.class,
                ListChecksCommand.class,
                ConfigCommand.class
        })
public class Main implements Callable<Integer> {

    @Option(names = {"-v", "--verbose"}, description = "Increase verbosity (repeatable)")
    private boolean[] verbose;

    @Override
    public Integer call() {
        System.out.println("VulnScan 1.0.0 - Network Vulnerability Scanner");
        System.out.println("Run 'vulnscan --help' for usage");
        return 0;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }
}