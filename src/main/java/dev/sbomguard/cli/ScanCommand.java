package dev.sbomguard.cli;

import dev.sbomguard.scanner.Component;
import dev.sbomguard.scanner.ProjectScanner;
import dev.sbomguard.scanner.ScanException;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
        name = "scan",
        mixinStandardHelpOptions = true,
        description = "Inventária um projeto: dependências Maven declaradas, poms de módulos e artefatos (jar/war/ear)."
)
public class ScanCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Parameters(arity = "1", paramLabel = "DIRETÓRIO", description = "Raiz do projeto a escanear.")
    private Path directory;

    @Override
    public Integer call() {
        CommandLine cmd = spec.commandLine();
        try {
            ProjectScanner.ScanResult result = new ProjectScanner().scan(directory);
            imprimirComponentes(cmd, result);
            for (Path link : result.skippedSymlinks()) {
                cmd.getErr().println("aviso: symlink pulado: " + link);
            }
            for (String erroPom : result.pomErrors()) {
                cmd.getErr().println("aviso: " + erroPom);
            }
            if (!result.pomFound()) {
                cmd.getErr().println("aviso: nenhum pom.xml legível encontrado — inventário apenas de arquivos");
            }
            return ExitCodes.OK;
        } catch (NoSuchFileException e) {
            cmd.getErr().println("erro: " + e.getFile() + " não é um diretório (ou não existe)");
            return ExitCodes.GENERIC_ERROR;
        } catch (ScanException e) {
            cmd.getErr().println("erro: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        } catch (IOException e) {
            cmd.getErr().println("erro de E/S durante o scan: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
    }

    private void imprimirComponentes(CommandLine cmd, ProjectScanner.ScanResult result) {
        int poms = 0, deps = 0, jars = 0;
        for (Component c : result.components()) {
            switch (c.type()) {
                case PROJECT_POM -> {
                    cmd.getOut().println("[pom] " + c.groupId() + ":" + c.name() + ":"
                            + (c.version() != null ? c.version() : "sem-versão") + "  (" + c.path() + ")");
                    poms++;
                }
                case MAVEN_DEPENDENCY -> {
                    cmd.getOut().println("[dep] " + c.purl() + " (" + c.scope() + ")");
                    deps++;
                }
                case FILE_ARTIFACT -> {
                    cmd.getOut().println("[jar] " + c.path());
                    jars++;
                }
            }
        }
        cmd.getOut().println("total: " + result.components().size() + " componentes ("
                + poms + " pom, " + deps + " dependências, " + jars + " artefatos)");
    }
}
