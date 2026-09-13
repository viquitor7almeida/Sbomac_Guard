package dev.sbomguard.cli;

import dev.sbomguard.crypto.CryptoException;
import dev.sbomguard.crypto.KeyService;
import dev.sbomguard.crypto.SignatureService;
import dev.sbomguard.ledger.Anchor;
import dev.sbomguard.ledger.AnchorService;
import dev.sbomguard.ledger.LedgerService;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.Callable;

@Command(
        name = "anchor",
        mixinStandardHelpOptions = true,
        description = "Cria a âncora assinada do ledger (head + contagem) para publicação EXTERNA ao projeto."
)
public class AnchorCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Parameters(arity = "0..1", paramLabel = "ARQUIVO_OU_DIRETÓRIO", defaultValue = ".",
            description = "Ledger (JSONL) ou diretório que o contém (default: diretório atual).")
    private Path caminho;

    @Option(names = {"--key"}, paramLabel = "PRIVADA", required = true,
            description = "Chave privada que assina a âncora.")
    private Path privateKeyFile;

    @Option(names = {"--public-key"}, paramLabel = "PÚBLICA",
            description = "Chave pública (default: derivada da privada por convenção .pem→.pub).")
    private Path publicKeyFile;

    @Option(names = {"--out"}, paramLabel = "ARQUIVO",
            description = "Onde gravar a âncora (default: ao lado do ledger).")
    private Path outFile;

    @Override
    public Integer call() {
        CommandLine cmd = spec.commandLine();
        try {
            Path ledger = Files.isDirectory(caminho)
                    ? caminho.resolve(LedgerService.LEDGER_FILE)
                    : caminho;
            if (!Files.isRegularFile(ledger)) {
                cmd.getErr().println("erro: ledger inexistente: " + ledger + " — nada a ancorar (rode sign primeiro)");
                return ExitCodes.GENERIC_ERROR;
            }

            KeyService keys = new KeyService();
            PrivateKey privada = keys.loadPrivateKey(privateKeyFile);
            Path pubFile = (publicKeyFile != null) ? publicKeyFile : derivarPublica(privateKeyFile);
            PublicKey publica = keys.loadPublicKey(pubFile);

            Anchor anchor = new AnchorService().create(ledger, privada, keys.fingerprint(publica));

            byte[] canonico = anchor.canonicalJson().getBytes(StandardCharsets.UTF_8);
            if (!new SignatureService().verify(canonico, anchor.signatureBytes(), publica)) {
                cmd.getErr().println("erro interno: âncora recém-criada não passou na autoverificação");
                return ExitCodes.GENERIC_ERROR;
            }

            Path destino = (outFile != null) ? outFile : ledger.resolveSibling(AnchorService.ANCHOR_FILE);
            if (destino.getParent() != null) {
                Files.createDirectories(destino.getParent());
            }
            Files.writeString(destino, anchor.serialize());

            cmd.getOut().println("âncora: " + destino + "  (head " + anchor.ledgerHead().substring(0, 12)
                    + "…, " + anchor.entryCount() + " entradas, chave " + anchor.keyId().substring(0, 12) + "…)");
            cmd.getOut().println("publique-a FORA do alcance de quem pode reescrever o projeto: "
                    + "release, outro repositório, transparency log — uma âncora que o atacante "
                    + "também pode reescrever não ancora nada");
            return ExitCodes.OK;
        } catch (CryptoException e) {
            cmd.getErr().println("erro: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        } catch (IOException e) {
            cmd.getErr().println("erro ao ancorar: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
    }

    private Path derivarPublica(Path privada) {
        String nome = privada.getFileName().toString();
        String base = nome.endsWith(".pem") ? nome.substring(0, nome.length() - 4) : nome;
        return privada.resolveSibling(base + ".pub");
    }
}
