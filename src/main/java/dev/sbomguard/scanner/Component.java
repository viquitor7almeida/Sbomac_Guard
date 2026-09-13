package dev.sbomguard.scanner;

import java.nio.file.Path;

/**
 * Modelo interno de componente — fonte única de verdade que alimenta o SBOM
 * (F4) e o manifesto de integridade (F5).
 *
 * Regra de honestidade: não inventamos dados. FILE_ARTIFACT não tem purl nem
 * versão porque um arquivo não carrega metadados de ecossistema. Dependências
 * Maven não têm path porque o MVP lê o pom DECLARADO (limitação documentada:
 * sem resolução de transitivas, propriedades, BOMs ou perfis).
 */
public record Component(
        ComponentType type,
        String groupId,
        String name,
        String version,
        String scope,
        String purl,
        Path path) {

    public enum ComponentType {
        /** pom.xml do projeto/módulo. groupId/name/version preenchidos; path = pom relativo à raiz. */
        PROJECT_POM,
        /** Dependência declarada. groupId/name/version/scope/purl preenchidos; path = null. */
        MAVEN_DEPENDENCY,
        /** Artefato de arquivo (jar/war/ear). name = nome do arquivo; path relativo; demais campos null. */
        FILE_ARTIFACT
    }
}
