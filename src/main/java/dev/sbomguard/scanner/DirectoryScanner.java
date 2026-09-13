package dev.sbomguard.scanner;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class DirectoryScanner {

    private static final Set<String> EXCLUDED_DIRS = Set.of(".git", "target", ".idea", ".vscode", "node_modules");
    private static final Set<String> ARTIFACT_EXTENSIONS = Set.of("jar", "war", "ear");

    public record DirectoryScan(List<Path> pomFiles, List<Path> artifactFiles, List<Path> skippedSymlinks) {
    }

    public DirectoryScan scan(Path root) throws IOException {
        List<Path> poms = new ArrayList<>();
        List<Path> artifacts = new ArrayList<>();
        List<Path> symlinks = new ArrayList<>();

        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(root) && EXCLUDED_DIRS.contains(dir.getFileName().toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (attrs.isSymbolicLink()) {
                    symlinks.add(file);
                    return FileVisitResult.CONTINUE;
                }
                String fileName = file.getFileName().toString();
                if ("pom.xml".equals(fileName)) {
                    poms.add(file);
                } else if (isArtifactExtension(fileName)) {
                    artifacts.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });

        Comparator<Path> porCaminho = Comparator.comparing(Path::toString);
        poms.sort(porCaminho);
        artifacts.sort(porCaminho);
        symlinks.sort(porCaminho);
        return new DirectoryScan(List.copyOf(poms), List.copyOf(artifacts), List.copyOf(symlinks));
    }

    private boolean isArtifactExtension(String fileName) {
        int ponto = fileName.lastIndexOf('.');
        if (ponto < 0) {
            return false;
        }
        return ARTIFACT_EXTENSIONS.contains(fileName.substring(ponto + 1).toLowerCase(Locale.ROOT));
    }
}
