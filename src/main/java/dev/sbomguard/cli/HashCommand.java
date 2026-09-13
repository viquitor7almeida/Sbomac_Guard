package dev.sbomguard.cli;

import dev.sbomguard.crypto.HashService;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
        name = "hash",
        mixinStandardHelpOptions = true,
        description = "Calcula o hash SHA-256 de um ou mais arquivos, em formato compatível com sha256sum."
)
public class HashCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Parameters(arity = "1..*", paramLabel = "ARQUIVO", description = "Arquivos para hashear.")
    private Path[] files;

    @Override
    public Integer call() {
        int falhas = 0;
        for (Path file : files) {
            if (!Files.isRegularFile(file)) {
                spec.commandLine().getErr().println("erro: não é um arquivo regular (ou não existe): " + file);
                falhas++;
                continue;
            }
            try {
                String hex = HashService.sha256Hex(file);
                spec.commandLine().getOut().println(hex + "  " + file);
            } catch (IOException e) {
                spec.commandLine().getErr().println("erro: falha de leitura em " + file + ": " + e.getMessage());
                falhas++;
            }
        }
        return falhas == 0 ? ExitCodes.OK : ExitCodes.GENERIC_ERROR;
    }
}
