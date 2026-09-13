package dev.sbomguard.scanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.sbomguard.scanner.Component.ComponentType;

/**
 * Orquestra a descoberta: walk do diretório + parsing de cada pom encontrado.
 *
 * Contratos de saída:
 * - component.path é sempre RELATIVO à raiz (manifestos portáveis e
 *   reproduzíveis — caminhos absolutos embutem máquina, caminhos relativos não);
 * - ScanResult.root é a raiz NORMALIZADA absoluta (para re-resolver na verificação);
 * - ordem determinística: PROJECT_POMs por caminho, dependências deduplicadas
 *   por purl em ordem de declaração, artefatos de arquivo por caminho;
 * - pom malformado NÃO aborta o scan: é pulado e reportado em pomErrors
 *   (política de inventário; hard-fail pertence à verificação, não à descoberta);
 * - pomFound = pelo menos um pom parseado com sucesso.
 *
 * Deduplicação por purl: módulos que declaram a mesma dependência geram UM
 * componente (o SBOM espera componentes únicos). Nota: dependências que
 * diferem só por classifier colapsam — limitação documentada do MVP.
 */
public final class ProjectScanner {

    public record ScanResult(Path root, List<Component> components, List<Path> skippedSymlinks,
                             boolean pomFound, List<String> pomErrors) {
    }

    public ScanResult scan(Path projectRoot) throws IOException {
        Path root = projectRoot.toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) {
            throw new NoSuchFileException(projectRoot.toString(), null,
                    "não é um diretório (ou não existe)");
        }

        DirectoryScanner.DirectoryScan dir = new DirectoryScanner().scan(root);
        MavenPomScanner pomScanner = new MavenPomScanner();

        List<Component> poms = new ArrayList<>();
        Map<String, Component> dependenciasPorPurl = new LinkedHashMap<>();
        List<String> pomErrors = new ArrayList<>();

        for (Path pom : dir.pomFiles()) {
            try {
                for (Component c : pomScanner.scan(pom)) {
                    if (c.type() == ComponentType.PROJECT_POM) {
                        poms.add(new Component(c.type(), c.groupId(), c.name(), c.version(), c.scope(),
                                c.purl(), root.relativize(pom)));
                    } else {
                        dependenciasPorPurl.putIfAbsent(c.purl(), c);
                    }
                }
            } catch (ScanException e) {
                pomErrors.add(e.getMessage());
            }
        }

        List<Component> components = new ArrayList<>(poms);
        components.addAll(dependenciasPorPurl.values());
        for (Path artifact : dir.artifactFiles()) {
            Path relativo = root.relativize(artifact);
            components.add(new Component(ComponentType.FILE_ARTIFACT, null,
                    relativo.getFileName().toString(), null, null, null, relativo));
        }

        List<Path> symlinks = new ArrayList<>();
        for (Path link : dir.skippedSymlinks()) {
            symlinks.add(root.relativize(link));
        }
        return new ScanResult(root, List.copyOf(components), List.copyOf(symlinks),
                !poms.isEmpty(), List.copyOf(pomErrors));
    }
}
