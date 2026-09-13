package dev.sbomguard.testkit;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public final class Fixtures {

    public static Path path(String nomeRelativo) {
        try {
            return Path.of(Fixtures.class.getResource("/fixtures/" + nomeRelativo).toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException("fixture inacessível: " + nomeRelativo, e);
        }
    }

    public static Path copy(String nome, Path destinoDir) throws IOException {
        Path origem = path(nome);
        Path destino = destinoDir.resolve(nome);
        try (Stream<Path> arquivos = Files.walk(origem)) {
            for (Path arquivo : arquivos.toList()) {
                Path alvo = destino.resolve(origem.relativize(arquivo).toString());
                if (Files.isDirectory(arquivo)) {
                    Files.createDirectories(alvo);
                } else {
                    Files.createDirectories(alvo.getParent());
                    Files.copy(arquivo, alvo);
                }
            }
        }
        return destino;
    }

    private Fixtures() {
        throw new AssertionError("classe utilitária: não instanciável");
    }
}
