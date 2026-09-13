package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import dev.sbomguard.cli.HashCommand;
import dev.sbomguard.cli.SbomCommand;
import dev.sbomguard.cli.ScanCommand;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

import java.util.concurrent.Callable;

@Command(
        name = "sbomguard",
        mixinStandardHelpOptions = true,
        version = SbomGuardCli.VERSION,
        subcommands = { HashCommand.class, ScanCommand.class, SbomCommand.class },
        description = "Segurança de cadeia de suprimentos: SBOM (CycloneDX), manifesto de integridade, assinatura Ed25519 e verificação para CI/CD."
)
public class SbomGuardCli implements Callable<Integer> {

    static final String VERSION = "sbomguard 0.1.0-SNAPSHOT";

    @Spec
    CommandSpec spec;

    public static void main(String[] args) {
        System.exit(configuredCommandLine().execute(args));
    }

    /**
     * Fábrica única de configuração: usada por main() E pelos testes,
     * garantindo que os testes exercitem exatamente o caminho de produção.
     */
    static CommandLine configuredCommandLine() {
        return new CommandLine(new SbomGuardCli())
                .setParameterExceptionHandler(SbomGuardCli::reportInvalidArgument)
                .setExecutionExceptionHandler(SbomGuardCli::reportInternalError);
    }

    private static int reportInvalidArgument(CommandLine.ParameterException ex, String[] args) {
        CommandLine cmd = ex.getCommandLine();
        cmd.getErr().println(cmd.getColorScheme().errorText(ex.getMessage()));
        cmd.getErr().println();
        cmd.usage(cmd.getErr());
        return ExitCodes.INVALID_ARGUMENT;
    }

    private static int reportInternalError(Exception ex, CommandLine cmd, CommandLine.ParseResult parseResult) {
        cmd.getErr().println(cmd.getColorScheme().errorText("erro interno: " + ex.getMessage()));
        return ExitCodes.GENERIC_ERROR;
    }

    @Override
    public Integer call() {
        spec.commandLine().usage(spec.commandLine().getOut());
        return ExitCodes.OK;
    }
}
