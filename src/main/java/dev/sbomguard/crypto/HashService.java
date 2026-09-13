package dev.sbomguard.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Integridade de artefatos via SHA-256, usando exclusivamente o JDK.
 *
 * Cada chamada cria seu próprio MessageDigest (que NÃO é thread-safe),
 * portanto os métodos são thread-safe por construção, sem sincronização.
 * Hashing sempre em stream: memória constante independente do tamanho do arquivo.
 */
public final class HashService {

    private static final int CHUNK_SIZE_BYTES = 8 * 1024;

    public static String sha256Hex(Path file) throws IOException {
        MessageDigest digest = sha256Digest();
        try (InputStream in = Files.newInputStream(file)) {
            byte[] chunk = new byte[CHUNK_SIZE_BYTES];
            int read;
            while ((read = in.read(chunk)) != -1) {
                digest.update(chunk, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    public static String sha256Hex(byte[] content) {
        return HexFormat.of().formatHex(sha256Digest().digest(content));
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK sem SHA-256: ambiente sem suporte ao JCA mínimo", e);
        }
    }

    private HashService() {
        throw new AssertionError("classe utilitária: não instanciável");
    }
}
