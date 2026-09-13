package dev.sbomguard.cli;

import dev.sbomguard.sbom.SbomGenerator;
import dev.sbomguard.scanner.ProjectScanner;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;

@Command(
        name = "sbom",
        mixinStandardHelpOptions = true,
        description = "Gera SBOM CycloneDX (JSON, spec 1.6) a partir do inventário do projeto."
)
public class SbomCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Parameters(arity = "1", paramLabel = "DIRETÓRIO", description = "Raiz do projeto.")
    private Path directory;

    @Option(names = {"-o", "--output"}, paramLabel = "ARQUIVO",
            description = "Escreve o SBOM em ARQUIVO (default: stdout)")
    private Path output;

    @Override
    public Integer call() {
        CommandLine cmd = spec.commandLine();
        try {
            ProjectScanner.ScanResult scan = new ProjectScanner().scan(directory);
            SbomGenerator generator = new SbomGenerator();
            Bom bom = generator.generate(scan, UUID.randomUUID());
            String json = generator.toJson(bom);

            List<ParseException> errosValidacao = generator.validate(json);
            if (!errosValidacao.isEmpty()) {
                cmd.getErr().println("erro interno: SBOM gerado não passou na validação de schema:");
                for (ParseException erro : errosValidacao) {
                    cmd.getErr().println("  - " + erro.getMessage());
                }
                return ExitCodes.GENERIC_ERROR;
            }

            for (Path link : scan.skippedSymlinks()) {
                cmd.getErr().println("aviso: symlink pulado: " + link);
            }
            for (String erroPom : scan.pomErrors()) {
                cmd.getErr().println("aviso: " + erroPom);
            }
            if (!scan.pomFound()) {
                cmd.getErr().println("aviso: nenhum pom.xml legível — SBOM apenas de artefatos de arquivo");
            }

            if (output != null) {
                if (output.getParent() != null && !Files.isDirectory(output.getParent())) {
                    cmd.getErr().println("erro: diretório de saída inexistente: " + output.getParent());
                    return ExitCodes.GENERIC_ERROR;
                }
                Files.writeString(output, json);
            } else {
                cmd.getOut().println(json);
            }
            return ExitCodes.OK;
        } catch (NoSuchFileException e) {
            cmd.getErr().println("erro: " + e.getFile() + " não é um diretório (ou não existe)");
            return ExitCodes.GENERIC_ERROR;
        } catch (GeneratorException | IOException e) {
            cmd.getErr().println("erro ao gerar SBOM: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
    }
}
