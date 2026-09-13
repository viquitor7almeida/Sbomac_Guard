package dev.sbomguard.scanner;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import dev.sbomguard.scanner.Component.ComponentType;

/**
 * Extrai componentes de um pom.xml com o mesmo parser do Maven (Xpp3, modo
 * strict: XML malformado dispara exceção, não silêncio).
 *
 * Lê o pom DECLARADO: não resolve propriedades (${...}), dependencyManagement,
 * BOMs, perfis nem dependências transitivas — limitação documentada do MVP.
 * Versões com placeholder ficam cruas no campo version e o purl é gerado SEM
 * versão (não fabricamos dado que não existe).
 */
public final class MavenPomScanner {

    public List<Component> scan(Path pomXml) {
        Model model = readStrict(pomXml);

        String artifactId = model.getArtifactId();
        if (artifactId == null || artifactId.isBlank()) {
            throw new ScanException("pom sem <artifactId>: " + pomXml);
        }
        String groupId = coordenadaPropriaOuDoParent(model.getGroupId(), model, "groupId");
        String version = coordenadaPropriaOuDoParent(model.getVersion(), model, "version");
        if (groupId == null) {
            throw new ScanException("pom sem <groupId> próprio ou herdado do parent: " + pomXml);
        }

        List<Component> components = new ArrayList<>();
        components.add(new Component(ComponentType.PROJECT_POM, groupId, artifactId, version, null,
                mavenPurl(groupId, artifactId, version), pomXml));
        for (Dependency dep : model.getDependencies()) {
            components.add(dependencyOf(dep, pomXml));
        }
        return components;
    }

    private Model readStrict(Path pomXml) {
        try (InputStream in = Files.newInputStream(pomXml)) {
            return new MavenXpp3Reader().read(in, true);
        } catch (IOException | XmlPullParserException e) {
            throw new ScanException("pom malformado ou ilegível: " + pomXml + " — " + e.getMessage(), e);
        }
    }

    private String coordenadaPropriaOuDoParent(String propria, Model model, String campo) {
        if (propria != null && !propria.isBlank()) {
            return propria;
        }
        if (model.getParent() != null) {
            return switch (campo) {
                case "groupId" -> model.getParent().getGroupId();
                case "version" -> model.getParent().getVersion();
                default -> null;
            };
        }
        return null;
    }

    private Component dependencyOf(Dependency dep, Path pomXml) {
        String g = dep.getGroupId();
        String a = dep.getArtifactId();
        if (g == null || g.isBlank() || a == null || a.isBlank()) {
            throw new ScanException("dependência sem groupId/artifactId em " + pomXml);
        }
        String scope = dep.getScope() == null ? "compile" : dep.getScope();
        return new Component(ComponentType.MAVEN_DEPENDENCY, g, a, dep.getVersion(), scope,
                mavenPurl(g, a, dep.getVersion()), null);
    }

    private String mavenPurl(String groupId, String artifactId, String version) {
        String versaoEfetiva = (version == null || version.isBlank() || version.startsWith("${"))
                ? null
                : version;
        try {
            return new PackageURL("maven", groupId, artifactId, versaoEfetiva, null, null).toString();
        } catch (MalformedPackageURLException e) {
            throw new ScanException("coordenadas geram purl inválido: " + groupId + ":" + artifactId
                    + "@" + version, e);
        }
    }
}
