package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import static java.util.Arrays.asList;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.VersionCommand.VersionCommandResult.UNKNOWN;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.VersionCommand.VersionCommandResult;
import org.bouncycastle.util.io.Streams;
import org.junit.Assert;

/**
 * for unknown reasons gpg often fails with an IPC error, meaning the
 * agent could not be started/connected to.
 * Several measures try to mitigate this: short temp-file path (important), non-parallel execution,
 * Config files prepared in #createTempGpgHomeDir(),...
 *
 * Observation: In folders where this error occurs it _consistently_ fails. E.g. opening a shell
 * in these folders an calling 'gpg-connect-agent --homedir=$PWD --verbose /bye' will always fail
 */
public class GPGExec {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(GPGExec.class);

  private final Path homeDir;
  private final String gpg2Executable;

  @Nullable
  private static String GPG2_EXECUTABLE;
  @Nullable
  private static VersionCommandResult GPG_VERSION = UNKNOWN;

  /**
   * Create a gpg instance in a fresh (clean)  homedir.
   *
   * @return new GPG instance in fresh homedir
   *
   * @throws IOException io is dangerous
   * @throws InterruptedException processes are dangerous too
   */
  public static GPGExec newInstance() throws IOException, InterruptedException {
    synchronized (GPGExec.class) {
      // gpg has many names. Find an executable with version 2
      // gpg v1 is not supported by the test driver
      if (GPG2_EXECUTABLE == null) {
        locateGpg2();
        Assert.assertNotNull("Cannot find GPG 2 executable", GPG2_EXECUTABLE);
      }
      return new GPGExec(GPG2_EXECUTABLE);
    }
  }

  private static void locateGpg2() {
    // find a gpg executable with version 2 ... ugly as hell ...

    for (final String candidate : asList("gpg2", "gpg")) {
      try {
        final GPGExec gpgExec = new GPGExec(candidate);
        final VersionCommandResult version = gpgExec.runCommand(Commands.version());

        if (version.exitCode() == 0) {
          if (version.isAtLeast(2)) {
            GPG2_EXECUTABLE = candidate;
            GPG_VERSION = version;
            return;
          } else {
            LOGGER.info(
                "Testing " + candidate + " -> version to low: " + version.getVersionString() + "");
          }
        }

      } catch (IOException | InterruptedException e) {
        LOGGER.info("Testing " + candidate + " -> error: " + e.getMessage() + "");
      }

    }
    LOGGER.warn("No gpg version >=2 found!");
    GPG2_EXECUTABLE = null;
    GPG_VERSION = UNKNOWN;
  }


  private GPGExec(String gpg2Executable) throws IOException, InterruptedException {
    this.gpg2Executable = gpg2Executable;
    homeDir = createTempGpgHomeDir();
    // give gpg the chance to init the working copy
    // without this write tasks, e.g "import" fail.
    runCommand(Commands.listKeys());
  }

  private String gpgExecutable() {
    return gpg2Executable;
  }

  private Path createTempGpgHomeDir() throws IOException {
    final Path homeDir = Files.createTempDirectory("bouncygpg");
    final File homeDirFile = homeDir.toFile();
    // homeDirFile.deleteOnExit();
    LOGGER.debug("Using " + homeDir.toAbsolutePath().toString() + " as temp dir.");

    // configure dedicated gpg-agent instance
    // "cargo cult": might or might not improve reliability!
    // https://dev.gnupg.org/T1752
    PrintWriter agentSocketCfg = new PrintWriter(new File(homeDirFile, "S.gpg-agent"), "UTF-8");
    agentSocketCfg.println("%Assuan%");
    agentSocketCfg.print("socket=");
    agentSocketCfg.println(new File(homeDirFile, "S.gpg-agent.sock").getAbsolutePath());
    agentSocketCfg.close();

    // gpg-agent.conf
    PrintWriter agentCfg = new PrintWriter(new File(homeDirFile, "gpg-agent.conf"), "UTF-8");

    //agentCfg.println("batch");
    //agentCfg.println("disable-scdaemon");
    agentCfg.println("no-grab");

    // this breaks agent communication
    // agentCfg.print("extra-socket ");
    // agentCfg.println(new File(homeDirFile, "S.gpg-agent.extra").getAbsolutePath());

    agentCfg.close();

    // gpg-agent.conf
    PrintWriter gpgCfg = new PrintWriter(new File(homeDirFile, "gpg.conf"), "UTF-8");

    gpgCfg.println("batch");
    if (GPG_VERSION.isAtLeast(2, 1)) {
      // new in 2.1
      gpgCfg.println("pinentry-mode loopback");
    }
    gpgCfg.println("trust-model always");

    gpgCfg.close();

    return homeDir;
  }

  public <T extends Command, R extends Result<T>> R runCommand(T cmd)
      throws IOException, InterruptedException {

    synchronized (getClass()) {
      Process p;
      int exitCode;
      // honestly this does not really work well (or at all on my macbook). the error seems to be
      // located in the filesystem.
      int ipcTriesLeft = 1;
      boolean retry = false;

      do {
        p = gpg(cmd);
        exitCode = p.exitValue();
        final boolean wasIPCerror = exitCode == 2;

        if (wasIPCerror) {
          retry = ipcTriesLeft-- > 0;
          LOGGER.info("Command failed:" + cmd.toString());

          if (retry) {
            LOGGER.info("Retry!");
            Thread.sleep(100);
          }
        }
      } while (retry);

      final Result result = cmd.parse(p.getInputStream(), exitCode);

      if (result.exitCode() != 0) {
        LOGGER.warn("Command failed: " + result.toString());
      }
      return (R) result;
    }
  }


  private Process gpg(Command cmd) throws IOException, InterruptedException {

    List<String> command = new ArrayList<>();
    command.add(gpgExecutable());
    command.add("--homedir");
    command.add(homeDir.toAbsolutePath().toString());

    // command.add("--debug");
    // command.add("8");

    command.addAll(cmd.getArgs());

    ProcessBuilder pb =
        new ProcessBuilder(command);
    Map<String, String> env = pb.environment();
    env.put("GNUPGHOME", homeDir.toAbsolutePath().toString());

    pb.redirectErrorStream(true);

    Process p = pb.start();

    cmd.io(p.getOutputStream(), p.getInputStream(), p.getErrorStream());

    p.waitFor(5, TimeUnit.SECONDS);

    if (p.isAlive()) {
      // hmm
      Streams.pipeAll(p.getInputStream(), System.out);
      LOGGER.warn("Forcibly destroy process!!");
      p.destroyForcibly();
    }

    return p;
  }
}
