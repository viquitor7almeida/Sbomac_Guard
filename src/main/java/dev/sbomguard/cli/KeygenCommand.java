package dev.sbomguard.cli;

import dev.sbomguard.crypto.CryptoException;
import dev.sbomguard.crypto.KeyService;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
        name = "keygen",
        mixinStandardHelpOptions = true,
        description = "Gera par de chaves Ed25519: privada (PEM/PKCS#8, NUNCA commitar) e pública (committável)."
)
public class KeygenCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Option(names = {"--out-dir"}, paramLabel = "DIRETÓRIO", defaultValue = ".",
            description = "Onde gravar as chaves (default: diretório atual).")
    private Path outDir;

    @Override
    public Integer call() {
        CommandLine cmd = spec.commandLine();
        try {
            KeyService.GeneratedKeys keys = new KeyService().generateAndSave(outDir);

            cmd.getOut().println("chave privada: " + keys.privateKeyFile()
                    + "  (NUNCA commitar; o .gitignore bloqueia *.pem)");
            cmd.getOut().println("chave pública: " + keys.publicKeyFile()
                    + "  (committável — verificadores usam esta)");
            cmd.getOut().println("fingerprint:  " + keys.fingerprint());
            return ExitCodes.OK;
        } catch (IOException | CryptoException e) {
            cmd.getErr().println("erro ao gerar chaves: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
    }
}
