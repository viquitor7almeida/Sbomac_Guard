package dev.sbomguard.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

public final class KeyService {

    public static final String PRIVATE_KEY_FILE = "sbomguard-signing.pem";
    public static final String PUBLIC_KEY_FILE = "sbomguard-signing.pub";

    public record GeneratedKeys(Path privateKeyFile, Path publicKeyFile, String fingerprint) {
    }

    public GeneratedKeys generateAndSave(Path outDir) throws IOException {
        Files.createDirectories(outDir);
        KeyPair pair = keyPairGenerator().generateKeyPair();

        Path priv = outDir.resolve(PRIVATE_KEY_FILE);
        writePem(priv, "PRIVATE KEY", pair.getPrivate().getEncoded());
        protegerContraLeituraDeTerceiros(priv);

        Path pub = outDir.resolve(PUBLIC_KEY_FILE);
        writePem(pub, "PUBLIC KEY", pair.getPublic().getEncoded());

        return new GeneratedKeys(priv, pub, fingerprint(pair.getPublic()));
    }

    public PrivateKey loadPrivateKey(Path pemFile) {
        byte[] der = parsePem(pemFile, "PRIVATE KEY");
        try {
            return keyFactory().generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (InvalidKeySpecException e) {
            throw new CryptoException("chave privada inválida (esperava Ed25519/PKCS#8): " + pemFile, e);
        }
    }

    public PublicKey loadPublicKey(Path pemFile) {
        byte[] der = parsePem(pemFile, "PUBLIC KEY");
        try {
            return keyFactory().generatePublic(new X509EncodedKeySpec(der));
        } catch (InvalidKeySpecException e) {
            throw new CryptoException("chave pública inválida (esperava Ed25519/X.509): " + pemFile, e);
        }
    }

    public String fingerprint(PublicKey publicKey) {
        return HashService.sha256Hex(publicKey.getEncoded());
    }

    private KeyPairGenerator keyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance("Ed25519");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK sem Ed25519: ambiente sem suporte ao EdDSA", e);
        }
    }

    private KeyFactory keyFactory() {
        try {
            return KeyFactory.getInstance("Ed25519");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK sem Ed25519: ambiente sem suporte ao EdDSA", e);
        }
    }

    private void writePem(Path file, String type, byte[] der) throws IOException {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(der);
        Files.writeString(file,
                "-----BEGIN " + type + "-----" + System.lineSeparator()
                        + base64 + System.lineSeparator()
                        + "-----END " + type + "-----" + System.lineSeparator());
    }

    private byte[] parsePem(Path file, String expectedType) {
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new CryptoException("chave inacessível: " + file + " — " + e.getMessage(), e);
        }

        boolean viuBegin = false;
        StringBuilder base64 = new StringBuilder();
        for (String line : lines) {
            String limpa = line.trim();
            if (limpa.startsWith("-----BEGIN ")) {
                viuBegin = true;
                if (!limpa.contains(" " + expectedType + "-----")) {
                    throw new CryptoException(
                            "tipo de chave inesperado em " + file + ": esperava " + expectedType);
                }
            } else if (limpa.startsWith("-----END ")) {

            } else if (!limpa.isEmpty()) {
                base64.append(limpa);
            }
        }
        if (!viuBegin || base64.isEmpty()) {
            throw new CryptoException("PEM inválido ou vazio: " + file);
        }
        try {
            return Base64.getDecoder().decode(base64.toString());
        } catch (IllegalArgumentException e) {
            throw new CryptoException("base64 inválido no PEM: " + file, e);
        }
    }

    private void protegerContraLeituraDeTerceiros(Path priv) throws IOException {
        try {
            Files.setPosixFilePermissions(priv, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException e) {

        }
    }
}
