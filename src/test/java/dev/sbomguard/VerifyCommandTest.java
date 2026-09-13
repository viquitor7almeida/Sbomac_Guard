package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import dev.sbomguard.crypto.KeyService;
import dev.sbomguard.crypto.SignatureEnvelope;
import dev.sbomguard.testkit.Fixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerifyCommandTest {

    @TempDir
    Path tempDir;

    private Path chavePrivada;
    private Path chavePublica;
    private Path manifestPath;
    private Path sigPath;

    private StringWriter stdout;
    private StringWriter stderr;

    private CommandLine newCli() {
        stdout = new StringWriter();
        stderr = new StringWriter();
        return SbomGuardCli.configuredCommandLine()
                .setOut(new PrintWriter(stdout, true))
                .setErr(new PrintWriter(stderr, true));
    }

    @BeforeEach
    void preparaAtestadoAssinado() throws IOException {
        KeyService.GeneratedKeys chaves = new KeyService().generateAndSave(tempDir.resolve("keys"));
        chavePrivada = chaves.privateKeyFile();
        chavePublica = chaves.publicKeyFile();

        assertEquals(ExitCodes.OK, newCli().execute("attest",
                Fixtures.path("mini-projeto").toString(),
                "--output-dir", tempDir.resolve("attest").toString()));
        manifestPath = tempDir.resolve("attest/sbomguard.manifest.json");
        assertEquals(ExitCodes.OK, newCli().execute("sign", manifestPath.toString(),
                "--key", chavePrivada.toString()));
        sigPath = tempDir.resolve("attest/sbomguard.manifest.json.sig");
    }

    @Test
    void verifyAssinaturaEIntegridadeIdemicasSaiComZero() {
        int exit = newCli().execute("verify", manifestPath.toString(),
                "--key", chavePublica.toString(),
                "--project", Fixtures.path("mini-projeto").toString());

        assertEquals(ExitCodes.OK, exit);
        assertTrue(stdout.toString().contains("verificação aprovada"));
        assertTrue(stdout.toString().contains("assinatura válida"));
    }

    @Test
    void verifyManifestoAlteradoAposAssinaturaSaiComOnze() throws IOException {
        byte[] conteudo = Files.readAllBytes(manifestPath);
        conteudo[10] ^= 0x01;
        Files.write(manifestPath, conteudo);

        int exit = newCli().execute("verify", manifestPath.toString(), "--key", chavePublica.toString());

        assertEquals(ExitCodes.SIGNATURE_INVALID, exit,
                "autenticidade precede integridade: manifesto adulterado → 11, sem comparação de conteúdo");
        assertTrue(stderr.toString().contains("assinatura inválida"));
    }

    @Test
    void verifyAssinaturaAlteradaSaiComOnze() throws IOException {
        SignatureEnvelope envelope = SignatureEnvelope.deserialize(Files.readString(sigPath));
        byte[] assinatura = envelope.signatureBytes();
        assinatura[10] ^= 0x01;
        String base64Alterada = java.util.Base64.getEncoder().encodeToString(assinatura);
        Files.writeString(sigPath, new SignatureEnvelope(
                envelope.algorithm(), envelope.keyId(), base64Alterada).serialize());

        int exit = newCli().execute("verify", manifestPath.toString(), "--key", chavePublica.toString());

        assertEquals(ExitCodes.SIGNATURE_INVALID, exit);
    }

    @Test
    void verifyComChavePublicaErradaSaiComOnze() throws IOException {
        Path outrasChaves = tempDir.resolve("outras-keys");
        new KeyService().generateAndSave(outrasChaves);
        Path publicaErrada = outrasChaves.resolve(KeyService.PUBLIC_KEY_FILE);

        int exit = newCli().execute("verify", manifestPath.toString(), "--key", publicaErrada.toString());

        assertEquals(ExitCodes.SIGNATURE_INVALID, exit);
        assertTrue(stderr.toString().contains("outra chave"));
    }

    @Test
    void verifySemArquivoDeAssinaturaSaiComOnze() throws IOException {
        Files.delete(sigPath);

        int exit = newCli().execute("verify", manifestPath.toString(), "--key", chavePublica.toString());

        assertEquals(ExitCodes.SIGNATURE_INVALID, exit);
        assertTrue(stderr.toString().contains("assinatura ausente"));
    }

    @Test
    void verifyManifestoInexistenteSaiComTreze() {
        int exit = newCli().execute("verify", "/caminho/inexistente/sbomguard.manifest.json",
                "--key", chavePublica.toString());

        assertEquals(ExitCodes.MANIFEST_NOT_FOUND, exit);
    }

    @Test
    void verifyEnvelopeComAlgoritmoDesconhecidoSaiComOnze() throws IOException {
        String envelope = Files.readString(sigPath)
                .replace("\"Ed25519\"", "\"RSA-4096-super-seguro\"");
        Files.writeString(sigPath, envelope);

        int exit = newCli().execute("verify", manifestPath.toString(), "--key", chavePublica.toString());

        assertEquals(ExitCodes.SIGNATURE_INVALID, exit);
        assertTrue(stderr.toString().contains("algoritmo não suportado"));
    }

    private int atestadoAssinadoNaCopia(Consumer<Path> ataque) throws IOException {
        Path projeto = Fixtures.copy("mini-projeto", tempDir);
        assertEquals(ExitCodes.OK, newCli().execute("attest", projeto.toString()));
        Path manifesto = projeto.resolve("sbomguard.manifest.json");
        assertEquals(ExitCodes.OK, newCli().execute("sign", manifesto.toString(),
                "--key", chavePrivada.toString()));

        ataque.accept(projeto);

        return newCli().execute("verify", manifesto.toString(), "--key", chavePublica.toString());
    }

    @Test
    void layoutPadraoAtestadoDentroDoProjetoVerificaAprovado() throws IOException {
        int exit = atestadoAssinadoNaCopia(projeto -> {
        });

        assertEquals(ExitCodes.OK, exit, "estado idêntico ao atestado: gate abre");
        assertTrue(stdout.toString().contains("verificação aprovada"));
    }

    @Test
    void injecaoDeDependenciaNoPomReprovaComDez() throws IOException {
        int exit = atestadoAssinadoNaCopia(projeto -> {
            try {
                Path pom = projeto.resolve("pom.xml");
                String original = Files.readString(pom, StandardCharsets.UTF_8);
                Files.writeString(pom, original.replace("</dependencies>",
                        "  <dependency><groupId>evil.corp</groupId><artifactId>rootkit</artifactId>"
                                + "<version>9.9</version></dependency>\n  </dependencies>"));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });

        assertEquals(ExitCodes.INTEGRITY_VIOLATION, exit,
                "pom adulterado: hash do sujeito diverge → 10 (com a dep injetada reportada junto)");
        assertTrue(stderr.toString().contains("rootkit"), "a injeção deve ser nomeada no relatório");
        assertTrue(stderr.toString().contains("sujeito"));
    }

    @Test
    void injecaoDeJarNaoAtestadoReprovaComDoze() throws IOException {
        int exit = atestadoAssinadoNaCopia(projeto -> {
            try {
                Files.createFile(projeto.resolve("lib/rogue.jar"));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });

        assertEquals(ExitCodes.UNEXPECTED_DEPENDENCY, exit,
                "componente que o manifesto não atesta → 12 (só o que sobra, nada diverge)");
        assertTrue(stderr.toString().contains("rogue.jar"));
    }

    @Test
    void artefatoAtestadoRemovidoReprovaComDez() throws IOException {
        int exit = atestadoAssinadoNaCopia(projeto -> {
            try {
                Files.delete(projeto.resolve("lib/fake-lib.jar"));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });

        assertEquals(ExitCodes.INTEGRITY_VIOLATION, exit, "o que o atestado cobre e sumiu → 10");
        assertTrue(stderr.toString().contains("fake-lib.jar"));
    }

    @Test
    void projetoInexistenteViaFlagSaiComUm() {
        int exit = newCli().execute("verify", manifestPath.toString(),
                "--key", chavePublica.toString(),
                "--project", "/caminho/que/nao/existe");

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stderr.toString().contains("diretório do projeto inexistente"));
    }
}
