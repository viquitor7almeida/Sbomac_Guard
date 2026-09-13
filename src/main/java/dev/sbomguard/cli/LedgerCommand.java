package dev.sbomguard.cli;

import dev.sbomguard.crypto.CryptoException;
import dev.sbomguard.crypto.KeyService;
import dev.sbomguard.ledger.AnchorService;
import dev.sbomguard.ledger.LedgerEntry;
import dev.sbomguard.ledger.LedgerService;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.concurrent.Callable;

@Command(
        name = "ledger",
        mixinStandardHelpOptions = true,
        description = "Consulta o ledger de atestados; com --verify, confere a cadeia de hashes (exit 10 se adulterada)."
)
public class LedgerCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Parameters(arity = "0..1", paramLabel = "ARQUIVO_OU_DIRETÓRIO", defaultValue = ".",
            description = "Ledger (JSONL) ou diretório que o contém (default: diretório atual).")
    private Path caminho;

    @Option(names = {"--verify"},
            description = "Verifica a integridade da cadeia em vez de listar.")
    private boolean verificar;

    @Option(names = {"--anchor"}, paramLabel = "ARQUIVO",
            description = "Verifica o ledger contra esta âncora assinada (implica --verify; exige --key).")
    private Path anchorFile;

    @Option(names = {"--key"}, paramLabel = "PÚBLICA",
            description = "Chave pública para validar a âncora (exigida com --anchor).")
    private Path publicKeyFile;

    @Override
    public Integer call() {
        CommandLine cmd = spec.commandLine();
        Path arquivo = Files.isDirectory(caminho)
                ? caminho.resolve(LedgerService.LEDGER_FILE)
                : caminho;

        if (anchorFile != null) {
            if (publicKeyFile == null) {
                cmd.getErr().println("erro: --anchor exige --key (chave pública que valida a âncora)");
                return ExitCodes.INVALID_ARGUMENT;
            }
            return verificarComAncora(cmd, arquivo);
        }

        try {
            LedgerService service = new LedgerService();

            if (verificar) {
                return verificarCadeia(cmd, service, arquivo);
            }
            return listarEntradas(cmd, service, arquivo);
        } catch (IOException e) {
            cmd.getErr().println("erro ao ler ledger: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
    }

    private int verificarComAncora(CommandLine cmd, Path arquivo) {
        if (!Files.isRegularFile(anchorFile)) {
            cmd.getErr().println("erro: âncora não encontrada: " + anchorFile);
            return ExitCodes.GENERIC_ERROR;
        }
        PublicKey publica;
        try {
            publica = new KeyService().loadPublicKey(publicKeyFile);
        } catch (CryptoException e) {
            cmd.getErr().println("erro: chave pública inválida: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
        try {
            AnchorService.AnchorCheck check =
                    new AnchorService().verify(arquivo, anchorFile, publica);
            if (!check.anchorSignatureValid()) {
                for (String problema : check.problems()) {
                    cmd.getErr().println("violação: " + problema);
                }
                return ExitCodes.SIGNATURE_INVALID;
            }
            if (!check.intact()) {
                for (String problema : check.problems()) {
                    cmd.getErr().println("violação: " + problema);
                }
                return ExitCodes.INTEGRITY_VIOLATION;
            }
            int entradas = new LedgerService().readAll(arquivo).size();
            cmd.getOut().println("cadeia íntegra e conforme a âncora: " + entradas
                    + " entradas, head confere, assinatura válida");
            return ExitCodes.OK;
        } catch (IOException e) {
            cmd.getErr().println("erro ao verificar âncora: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
    }

    private int verificarCadeia(CommandLine cmd, LedgerService service, Path arquivo) throws IOException {
        if (!Files.isRegularFile(arquivo)) {
            cmd.getOut().println("ledger inexistente: cadeia vazia é trivialmente íntegra "
                    + "(deleção total é indetectável sem âncora externa)");
            return ExitCodes.OK;
        }
        LedgerService.ChainVerification verificacao = service.verifyChain(arquivo);
        if (verificacao.intact()) {
            cmd.getOut().println("cadeia íntegra: " + service.readAll(arquivo).size()
                    + " entradas (gênese " + LedgerService.GENESIS.substring(0, 12) + "…)");
            return ExitCodes.OK;
        }
        for (String problema : verificacao.problems()) {
            cmd.getErr().println("violação: " + problema);
        }
        return ExitCodes.INTEGRITY_VIOLATION;
    }

    private int listarEntradas(CommandLine cmd, LedgerService service, Path arquivo) throws IOException {
        if (!Files.isRegularFile(arquivo)) {
            cmd.getOut().println("ledger vazio ou inexistente: nenhum atestado registrado");
            return ExitCodes.OK;
        }
        for (LedgerEntry entry : service.readAll(arquivo)) {
            cmd.getOut().println("#" + entry.index()
                    + "  " + entry.created()
                    + "  chave " + prefixo(entry.keyId())
                    + (entry.subject() != null ? "  " + entry.subject() : "")
                    + "  manifesto " + prefixo(entry.manifestSha256()));
        }
        return ExitCodes.OK;
    }

    private String prefixo(String hash) {
        return hash.substring(0, 12) + "…";
    }
}
