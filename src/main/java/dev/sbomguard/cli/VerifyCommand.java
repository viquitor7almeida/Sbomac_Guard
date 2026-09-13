package dev.sbomguard.cli;

import dev.sbomguard.crypto.CryptoException;
import dev.sbomguard.crypto.KeyService;
import dev.sbomguard.crypto.SignatureEnvelope;
import dev.sbomguard.crypto.SignatureService;
import dev.sbomguard.manifest.Manifest;
import dev.sbomguard.manifest.ManifestCodec;
import dev.sbomguard.policy.VerificationPolicy;
import dev.sbomguard.scanner.ProjectScanner;
import dev.sbomguard.verification.VerificationEngine;
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
import java.security.PublicKey;
import java.util.List;
import java.util.concurrent.Callable;

@Command(
        name = "verify",
        mixinStandardHelpOptions = true,
        description = "Gate de CI/CD: verifica assinatura E integridade do projeto contra o manifesto atestado."
)
public class VerifyCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Parameters(arity = "1", paramLabel = "MANIFESTO", description = "Caminho do manifesto assinado.")
    private Path manifestFile;

    @Option(names = {"--key"}, paramLabel = "PÚBLICA", required = true,
            description = "Chave pública (PEM/X.509) contra a qual verificar.")
    private Path publicKeyFile;

    @Option(names = {"--project"}, paramLabel = "DIRETÓRIO",
            description = "Raiz do projeto (default: o diretório onde vive o manifesto).")
    private Path projectDir;

    @Override
    public Integer call() {
        CommandLine cmd = spec.commandLine();

        if (!Files.isRegularFile(manifestFile)) {
            cmd.getErr().println("violação: manifesto não encontrado: " + manifestFile);
            return ExitCodes.MANIFEST_NOT_FOUND;
        }
        Path sigFile = manifestFile.resolveSibling(manifestFile.getFileName() + ".sig");
        if (!Files.isRegularFile(sigFile)) {
            cmd.getErr().println("violação: assinatura ausente: " + sigFile);
            return ExitCodes.SIGNATURE_INVALID;
        }

        PublicKey publicKey;
        try {
            publicKey = new KeyService().loadPublicKey(publicKeyFile);
        } catch (CryptoException e) {
            cmd.getErr().println("erro: chave pública do verificador inválida: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }

        byte[] conteudoManifesto;
        SignatureEnvelope envelope;
        try {
            conteudoManifesto = Files.readAllBytes(manifestFile);
            envelope = SignatureEnvelope.deserialize(Files.readString(sigFile));
        } catch (IOException | IllegalArgumentException e) {
            cmd.getErr().println("violação: envelope de assinatura inválido: " + sigFile
                    + " — " + e.getMessage());
            return ExitCodes.SIGNATURE_INVALID;
        }

        if (!SignatureEnvelope.ALGORITHM_ED25519.equals(envelope.algorithm())) {
            cmd.getErr().println("violação: algoritmo não suportado: " + envelope.algorithm());
            return ExitCodes.SIGNATURE_INVALID;
        }

        KeyService keys = new KeyService();
        if (!keys.fingerprint(publicKey).equals(envelope.keyId())) {
            cmd.getErr().println("violação: assinatura feita com outra chave "
                    + "(esperava fingerprint " + keys.fingerprint(publicKey) + ")");
            return ExitCodes.SIGNATURE_INVALID;
        }

        boolean assinaturaValida;
        try {
            assinaturaValida = new SignatureService()
                    .verify(conteudoManifesto, envelope.signatureBytes(), publicKey);
        } catch (CryptoException e) {
            cmd.getErr().println("erro na verificação de assinatura: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
        if (!assinaturaValida) {
            cmd.getErr().println("violação: assinatura inválida — manifesto ou assinatura foi alterada");
            return ExitCodes.SIGNATURE_INVALID;
        }

        Manifest manifest;
        try {
            manifest = new ManifestCodec()
                    .deserialize(new String(conteudoManifesto, StandardCharsets.UTF_8));
        } catch (IOException e) {
            cmd.getErr().println("erro: manifesto assinado é ilegível para esta versão "
                    + "(schemaVersion futuro?): " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
        if (manifest.sbom() == null) {
            cmd.getErr().println("erro: manifesto sem referência de SBOM (formato inválido)");
            return ExitCodes.GENERIC_ERROR;
        }

        Path projeto = (projectDir != null ? projectDir : manifestFile.getParent())
                .toAbsolutePath().normalize();
        if (!Files.isDirectory(projeto)) {
            cmd.getErr().println("erro: diretório do projeto inexistente: " + projeto);
            return ExitCodes.GENERIC_ERROR;
        }

        try {
            ProjectScanner.ScanResult atual = new ProjectScanner().scan(projeto);
            for (Path link : atual.skippedSymlinks()) {
                cmd.getErr().println("aviso: symlink pulado: " + link);
            }
            for (String erroPom : atual.pomErrors()) {
                cmd.getErr().println("aviso: " + erroPom);
            }

            Path sbomArquivo = manifestFile.getParent().resolve(manifest.sbom().path());
            List<VerificationEngine.Finding> findings =
                    new VerificationEngine().verify(manifest, atual, sbomArquivo);

            if (findings.isEmpty()) {
                cmd.getOut().println("verificação aprovada: assinatura válida e "
                        + atual.components().size() + " componentes conferem com o atestado");
                return ExitCodes.OK;
            }

            for (VerificationEngine.Finding f : findings) {
                cmd.getErr().println("violação [" + f.kind() + "]: " + f.message());
            }
            return switch (new VerificationPolicy().verdict(findings)) {
                case INTEGRIDADE_COMPROMETIDA -> ExitCodes.INTEGRITY_VIOLATION;
                case COMPONENTE_INESPERADO -> ExitCodes.UNEXPECTED_DEPENDENCY;
                case APROVADO -> ExitCodes.OK;
            };
        } catch (IOException e) {
            cmd.getErr().println("erro de E/S na verificação: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
    }
}
