package dev.sbomguard.cli;

import dev.sbomguard.crypto.CryptoException;
import dev.sbomguard.crypto.KeyService;
import dev.sbomguard.crypto.SignatureEnvelope;
import dev.sbomguard.crypto.SignatureService;
import dev.sbomguard.ledger.LedgerService;
import dev.sbomguard.manifest.Manifest;
import dev.sbomguard.manifest.ManifestCodec;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.Callable;

@Command(
        name = "sign",
        mixinStandardHelpOptions = true,
        description = "Assina o manifesto de integridade com Ed25519, gravando <manifesto>.sig."
)
public class SignCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Parameters(arity = "1", paramLabel = "MANIFESTO", description = "Caminho do manifesto a assinar.")
    private Path manifest;

    @Option(names = {"--key"}, paramLabel = "PRIVADA", required = true,
            description = "Chave privada (PEM/PKCS#8). A pública é assumida no mesmo diretório: mesmo nome com sufixo .pub.")
    private Path privateKeyFile;

    @Option(names = {"--public-key"}, paramLabel = "PÚBLICA",
            description = "Caminho explícito da chave pública (default: derivada da privada por convenção .pem→.pub).")
    private Path publicKeyFile;

    @Option(names = {"--ledger"}, paramLabel = "ARQUIVO",
            description = "Ledger onde registrar o atestado (default: ao lado do manifesto).")
    private Path ledgerFile;

    @Override
    public Integer call() {
        CommandLine cmd = spec.commandLine();
        try {
            if (!Files.isRegularFile(manifest)) {
                cmd.getErr().println("erro: manifesto não encontrado: " + manifest);
                return ExitCodes.MANIFEST_NOT_FOUND;
            }

            KeyService keys = new KeyService();
            PrivateKey privateKey = keys.loadPrivateKey(privateKeyFile);
            Path pubFile = (publicKeyFile != null) ? publicKeyFile : derivarPublica(privateKeyFile);
            PublicKey publicKey = keys.loadPublicKey(pubFile);

            byte[] conteudo = Files.readAllBytes(manifest);
            byte[] assinatura = new SignatureService().sign(conteudo, privateKey);
            SignatureEnvelope envelope = SignatureEnvelope.ofEd25519(
                    keys.fingerprint(publicKey), assinatura);

            if (!new SignatureService().verify(conteudo, envelope.signatureBytes(), publicKey)) {
                cmd.getErr().println("erro interno: assinatura recém-gerada não passou na autoverificação");
                return ExitCodes.GENERIC_ERROR;
            }

            Path sigFile = manifest.resolveSibling(manifest.getFileName() + ".sig");
            Files.writeString(sigFile, envelope.serialize());

            registrarNoLedger(cmd, conteudo, envelope);

            cmd.getOut().println("assinado: " + manifest);
            cmd.getOut().println("assinatura: " + sigFile);
            cmd.getOut().println("chave (fingerprint): " + envelope.keyId());
            return ExitCodes.OK;
        } catch (NoSuchFileException e) {
            cmd.getErr().println("erro: arquivo não encontrado: " + e.getFile());
            return ExitCodes.GENERIC_ERROR;
        } catch (CryptoException e) {
            cmd.getErr().println("erro: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        } catch (IOException e) {
            cmd.getErr().println("erro de E/S ao assinar: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
    }

    private Path derivarPublica(Path privada) {
        String nome = privada.getFileName().toString();
        String base = nome.endsWith(".pem") ? nome.substring(0, nome.length() - 4) : nome;
        return privada.resolveSibling(base + ".pub");
    }

    private void registrarNoLedger(CommandLine cmd, byte[] conteudoManifesto,
                                   SignatureEnvelope envelope) throws IOException {
        String subject = null;
        try {
            Manifest m = new ManifestCodec()
                    .deserialize(new String(conteudoManifesto, StandardCharsets.UTF_8));
            if (m.subject() != null) {
                subject = m.subject().group() + ":" + m.subject().name() + ":" + m.subject().version();
            }
        } catch (IOException e) {

        }

        Path ledger = (ledgerFile != null)
                ? ledgerFile
                : manifest.resolveSibling(LedgerService.LEDGER_FILE);
        LedgerService.AppendResult registro = new LedgerService().append(
                ledger, envelope.keyId(), subject,
                dev.sbomguard.crypto.HashService.sha256Hex(conteudoManifesto));

        cmd.getOut().println("ledger: " + ledger + "  entrada #" + registro.index()
                + " (hash " + registro.entryHash().substring(0, 12) + "…)");
    }
}
