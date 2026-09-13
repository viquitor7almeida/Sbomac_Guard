package dev.sbomguard.testkit;

import java.net.URISyntaxException;
import java.nio.file.Path;

/**
 * Acesso a fixtures de teste (src/test/resources/fixtures) para os testes
 * das diversas fases — uma única forma de resolver Path a partir de recurso.
 */
public final class Fixtures {

    public static Path path(String nomeRelativo) {
        try {
            return Path.of(Fixtures.class.getResource("/fixtures/" + nomeRelativo).toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException("fixture inacessível: " + nomeRelativo, e);
        }
    }

    private Fixtures() {
        throw new AssertionError("classe utilitária: não instanciável");
    }
}
