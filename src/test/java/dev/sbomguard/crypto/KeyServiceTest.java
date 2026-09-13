package dev.sbomguard.crypto;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyServiceTest {

    @TempDir
    Path tempDir;

    private final KeyService keys = new KeyService();

    @Test
    void geraParESalvaArquivosComPermissaoRestrictivaNaPrivada() throws IOException {
        KeyService.GeneratedKeys geradas = keys.generateAndSave(tempDir);

        assertTrue(Files.isRegularFile(geradas.privateKeyFile()));
        assertTrue(Files.isRegularFile(geradas.publicKeyFile()));
        assertEquals("sbomguard-signing.pem", geradas.privateKeyFile().getFileName().toString());
        assertEquals("sbomguard-signing.pub", geradas.publicKeyFile().getFileName().toString());
        assertEquals(64, geradas.fingerprint().length());

        Assumptions.assumeTrue(
                Files.getFileStore(tempDir).supportsFileAttributeView(PosixFileAttributeView.class),
                "filesystem sem POSIX");
        assertEquals("rw-------",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(geradas.privateKeyFile())),
                "chave privada deve ser legível apenas pelo dono");
    }

    @Test
    void chavesRecarregadasFechamOCicloCompleto() throws IOException {
        KeyService.GeneratedKeys geradas = keys.generateAndSave(tempDir);

        var privada = keys.loadPrivateKey(geradas.privateKeyFile());
        var publica = keys.loadPublicKey(geradas.publicKeyFile());

        byte[] assinatura = new SignatureService()
                .sign("conteúdo do manifesto".getBytes(StandardCharsets.UTF_8), privada);
        assertTrue(new SignatureService()
                .verify("conteúdo do manifesto".getBytes(StandardCharsets.UTF_8), assinatura, publica));
        assertEquals(64, assinatura.length, "assinatura Ed25519 tem 64 bytes");
        assertEquals(geradas.fingerprint(), keys.fingerprint(publica),
                "fingerprint deve ser estável entre geração e recarga");
    }

    @Test
    void pemCorrompidoDisparaCryptoException() throws IOException {
        Path ruim = tempDir.resolve("ruim.pem");
        Files.writeString(ruim, "isto não é um pem");

        assertThrows(CryptoException.class, () -> keys.loadPrivateKey(ruim));
    }

    @Test
    void chaveDeAlgoritmoErradoDisparaCryptoException() throws Exception {
        var rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(rsa.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        Path arquivo = tempDir.resolve("rsa-como-ed25519.pem");
        Files.writeString(arquivo, pem);

        CryptoException e = assertThrows(CryptoException.class, () -> keys.loadPrivateKey(arquivo));
        assertTrue(e.getMessage().contains("Ed25519"), "mensagem deve nomear o algoritmo esperado");
    }

    @Test
    void carregarChavePublicaComoPrivadaDisparaCryptoException() throws IOException {
        KeyService.GeneratedKeys geradas = keys.generateAndSave(tempDir);

        CryptoException e = assertThrows(CryptoException.class,
                () -> keys.loadPrivateKey(geradas.publicKeyFile()));
        assertTrue(e.getMessage().contains("tipo de chave inesperado"));
    }
}
