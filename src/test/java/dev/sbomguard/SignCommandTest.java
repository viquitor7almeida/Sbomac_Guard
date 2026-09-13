package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import dev.sbomguard.crypto.HashService;
import dev.sbomguard.crypto.KeyService;
import dev.sbomguard.crypto.SignatureEnvelope;
import dev.sbomguard.crypto.SignatureService;
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
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignCommandTest {

    @TempDir
    Path tempDir;

    private Path chavePrivada;
    private Path chavePublica;
    private Path manifestPath;

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
    void preparaChavesEManifesto() throws IOException {
        KeyService.GeneratedKeys chaves = new KeyService().generateAndSave(tempDir.resolve("keys"));
        chavePrivada = chaves.privateKeyFile();
        chavePublica = chaves.publicKeyFile();

        int exit = newCli().execute("attest", Fixtures.path("mini-projeto").toString(),
                "--output-dir", tempDir.resolve("attest").toString());
        assertEquals(ExitCodes.OK, exit);
        manifestPath = tempDir.resolve("attest/sbomguard.manifest.json");
    }

    @Test
    void signGeraEnvelopeAutodescritivoValido() throws Exception {
        int exit = newCli().execute("sign", manifestPath.toString(), "--key", chavePrivada.toString());

        assertEquals(ExitCodes.OK, exit);
        Path sigFile = tempDir.resolve("attest/sbomguard.manifest.json.sig");
        assertTrue(Files.isRegularFile(sigFile));

        SignatureEnvelope envelope = SignatureEnvelope.deserialize(Files.readString(sigFile));
        assertEquals("Ed25519", envelope.algorithm());

        PublicKey publica = new KeyService().loadPublicKey(chavePublica);
        assertEquals(new KeyService().fingerprint(publica), envelope.keyId(),
                "keyId do envelope deve ser o fingerprint da chave que assinou");
        assertTrue(new SignatureService().verify(
                Files.readAllBytes(manifestPath), envelope.signatureBytes(), publica),
                "assinatura gravada deve verificar contra o manifesto");
    }

    @Test
    void signDerivaPublicaPorConvencaoNomePemParaPub() throws Exception {
        Path renomeadaPriv = tempDir.resolve("custom.pem");
        Path renomeadaPub = tempDir.resolve("custom.pub");
        Files.copy(chavePrivada, renomeadaPriv);
        Files.copy(chavePublica, renomeadaPub);

        int exit = newCli().execute("sign", manifestPath.toString(), "--key", renomeadaPriv.toString());

        assertEquals(ExitCodes.OK, exit, "convenção .pem→.pub deve localizar a pública");
    }

    @Test
    void signComChaveInexistenteSaiComUm() {
        int exit = newCli().execute("sign", manifestPath.toString(),
                "--key", "/caminho/que/nao/existe.pem");

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stderr.toString().contains("chave inacessível"));
    }

    @Test
    void signComChaveCorrompidaSaiComUmSemStacktrace() throws Exception {
        Path corrompida = tempDir.resolve("corrompida.pem");
        Files.writeString(corrompida, "-----BEGIN PRIVATE KEY-----\nxyz!\n-----END PRIVATE KEY-----\n");

        int exit = newCli().execute("sign", manifestPath.toString(), "--key", corrompida.toString());

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stderr.toString().contains("inválido"));
        assertTrue(!stderr.toString().contains("at dev.sbomguard"), "sem stacktrace vazeado");
    }

    @Test
    void signManifestoInexistenteSaiComTreze() {
        int exit = newCli().execute("sign", "/caminho/inexistente/sbomguard.manifest.json",
                "--key", chavePrivada.toString());

        assertEquals(ExitCodes.MANIFEST_NOT_FOUND, exit, "contrato: 13 = manifesto inexistente");
    }

    @Test
    void signRegistraNoLedgerPorDefault() throws Exception {
        int exit = newCli().execute("sign", manifestPath.toString(), "--key", chavePrivada.toString());
        assertEquals(ExitCodes.OK, exit);

        Path ledger = tempDir.resolve("attest/sbomguard.ledger.jsonl");
        assertTrue(Files.isRegularFile(ledger), "o sign padrão deve anotar no ledger ao lado do manifesto");

        java.util.List<dev.sbomguard.ledger.LedgerEntry> entries =
                new dev.sbomguard.ledger.LedgerService().readAll(ledger);
        assertEquals(1, entries.size());

        dev.sbomguard.ledger.LedgerEntry entrada = entries.get(0);
        assertEquals(1, entrada.index());
        assertEquals("com.exemplo.demo:app:1.2.3", entrada.subject());
        assertEquals(HashService.sha256Hex(Files.readAllBytes(manifestPath)),
                entrada.manifestSha256(), "o hash do manifesto assinado fica registrado");
        PublicKey publica = new KeyService().loadPublicKey(chavePublica);
        assertEquals(new KeyService().fingerprint(publica), entrada.keyId(),
                "o keyId registrado é o fingerprint de quem assinou");
        assertEquals(dev.sbomguard.ledger.LedgerService.GENESIS, entrada.prevHash());
        assertTrue(stdout.toString().contains("ledger:"), "o resumo menciona o registro");
    }

    @Test
    void signComLedgerExplicitoGravaNoCaminhoIndicado() throws Exception {
        Path ledger = tempDir.resolve("outro-lugar/ledger.jsonl");

        int exit = newCli().execute("sign", manifestPath.toString(),
                "--key", chavePrivada.toString(), "--ledger", ledger.toString());

        assertEquals(ExitCodes.OK, exit);
        assertTrue(Files.isRegularFile(ledger));
        assertEquals(1, new dev.sbomguard.ledger.LedgerService().readAll(ledger).size());
    }
}
