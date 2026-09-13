package dev.sbomguard.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void vetorNistMensagemVazia() {
        assertEquals(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                HashService.sha256Hex(new byte[0]));
    }

    @Test
    void vetorNistAbc() {
        assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                HashService.sha256Hex("abc".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void vetorNistExatamenteUmBloco() {
        // 56 bytes = 448 bits: preenche um bloco de 512 bits; o padding força
        // o processamento de um segundo bloco (fronteira de bloco do SHA-256)
        String entrada = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assertEquals(
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                HashService.sha256Hex(entrada.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void vetorNistMultiBlocos() {
        String entrada = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                + "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assertEquals(
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
                HashService.sha256Hex(entrada.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void arquivoGrandeHasheiaEmStreamComDeterminismo() throws IOException {
        Path grande = tempDir.resolve("grande.bin");
        byte[] padrao = new byte[256 * 1024];
        for (int i = 0; i < padrao.length; i++) {
            padrao[i] = (byte) (i % 251);
        }
        try (OutputStream out = Files.newOutputStream(grande)) {
            for (int i = 0; i < 32; i++) {
                out.write(padrao);
            }
        }

        String primeiro = HashService.sha256Hex(grande);
        String segundo = HashService.sha256Hex(grande);

        assertEquals(primeiro, segundo);
        assertEquals(64, primeiro.length());
    }

    @Test
    void alterarUmBitMudaOHashCompletamente() throws IOException {
        Path alvo = tempDir.resolve("alvo.bin");
        Files.write(alvo, new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10});
        String original = HashService.sha256Hex(alvo);

        byte[] conteudo = Files.readAllBytes(alvo);
        conteudo[4] ^= 0x01;
        Files.write(alvo, conteudo);
        String alterado = HashService.sha256Hex(alvo);

        assertNotEquals(original, alterado);

        int hexDistintos = 0;
        for (int i = 0; i < 64; i++) {
            if (original.charAt(i) != alterado.charAt(i)) {
                hexDistintos++;
            }
        }
        // Avalanche é por BIT (~50% dos 256 bits). Um dígito hex só coincide se
        // os 4 bits dele coincidirem (p = 1/16) → esperado ~60/64 dígitos distintos.
        // Piso 48 detecta degenerescência (função que "quase não espalha").
        assertTrue(hexDistintos > 48,
                "avalanche esperava ~60/64 dígitos distintos, obtido " + hexDistintos);
    }

    @Test
    void arquivoInexistenteLancaExcecaoTratavel() {
        Path inexistente = tempDir.resolve("nao-existe.bin");
        assertThrows(NoSuchFileException.class, () -> HashService.sha256Hex(inexistente));
    }
}
