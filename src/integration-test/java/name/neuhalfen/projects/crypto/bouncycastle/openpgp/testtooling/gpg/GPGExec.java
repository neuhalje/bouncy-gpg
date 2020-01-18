package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import static java.util.Arrays.asList;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.VersionCommand.VersionCommandResult.UNKNOWN;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.VersionCommand.VersionCommandResult;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.io.TeeInputStream;
import org.bouncycastle.util.io.TeeOutputStream;
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
  private static VersionCommandResult GPG_VERSION = UNKNOWN;

  private int currentCommandNum = 0;

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
        Assert.assertNotNull("GPG version not set?", GPG_VERSION);
        assertTrue(GPG_VERSION.isAtLeast(2));
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
        LOGGER.debug("Testing " + candidate + " -> error: " + e.getMessage() + "");
      }

    }
    LOGGER.warn("No gpg version >=2 found!");
    GPG2_EXECUTABLE = null;
    GPG_VERSION = UNKNOWN;
  }


  private GPGExec(String gpg2Executable) throws IOException {
    this.gpg2Executable = gpg2Executable;
    homeDir = createTempGpgHomeDir();
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

  public final <T extends Command<?>, R extends Result<T>> R runCommand(T cmd)
      throws IOException, InterruptedException {

    synchronized (GPGExec.class) {
      currentCommandNum++;

      IOSniffer sniffer;
      Process p;
      int exitCode;
      LOGGER.debug(cmd.toString());
      sniffer = gpg(cmd);
      p = sniffer.getP();

      exitCode = p.exitValue();

      R result = (R) cmd.parse(sniffer.getInputStream(), exitCode);

      if (result.exitCode() != 0) {
        LOGGER.warn("Command failed: " + result.toString());
      }

      LOGGER.debug(result.toString());

      Path commandLogDir = homeDir
          .resolve(String.format("cmd_%03d_log-%s", currentCommandNum, cmd.displayName()));
      assertTrue(commandLogDir.toFile().mkdir());

      Files.write(commandLogDir.resolve("command.txt"), cmd.toString().getBytes());
      Files.write(commandLogDir.resolve("result.txt"), result.toString().getBytes());
      Files.write(commandLogDir.resolve("process.txt"), p.toString().getBytes());
      sniffer.exportAndClose(commandLogDir);

      return result;
    }
  }

  @SuppressWarnings("unused")
  private void log(final InputStream stream) throws IOException {
    final byte[] text = Streams.readAll(stream);
    if (text != null && text.length > 0) {
      LOGGER.info(new String(text));
    }
  }

  @SuppressWarnings("unused")
  private void log(final byte[] text) {
    if (text != null && text.length > 0) {
      LOGGER.info(new String(text));
    }
  }

  private IOSniffer gpg(Command<?> cmd) throws IOException, InterruptedException {

    List<String> command = new ArrayList<>();
    command.add(gpgExecutable());
    command.add("--homedir");
    command.add(homeDir.toAbsolutePath().toString());

    command.addAll(cmd.getArgs());

    ProcessBuilder pb =
        new ProcessBuilder(command);
    Map<String, String> env = pb.environment();
    env.put("GNUPGHOME", homeDir.toAbsolutePath().toString());

    pb
        .redirectErrorStream(false)
        .directory(homeDir.toFile());

    Process p = pb.start();

    IOSniffer sniffer = IOSniffer.wrapIO(p);
    cmd.io(sniffer.getOutputStream(), sniffer.getInputStream(), sniffer.getErrorStream());
    sniffer.getOutputStream().flush();
    sniffer.getOutputStream().close();
    p.waitFor(15, TimeUnit.SECONDS);

    if (p.isAlive()) {
      // hmm
      LOGGER.warn("Forcibly destroy process " + String.join(" ", command));
      p.destroyForcibly();
    }

    return sniffer;
  }

  public final VersionCommandResult version() {
    return GPG_VERSION;
  }

  private final static class IOSniffer implements Closeable {

    private final TeeInputStream stdin;
    private final TeeInputStream stderr;
    private final TeeOutputStream stdoutWrapper;
    private final ByteArrayOutputStream stdout;

    public Process getP() {
      return p;
    }

    private final Process p;

    public InputStream getInputStream() {
      return stdin;
    }

    public InputStream getErrorStream() {
      return stderr;
    }

    public OutputStream getOutputStream() {
      return stdoutWrapper;
    }

    private IOSniffer(final Process p, final TeeInputStream stdin,
        final ByteArrayOutputStream stdout, TeeOutputStream stdoutWrapper,
        final TeeInputStream stderr) {
      this.stdin = stdin;
      this.stderr = stderr;
      this.stdout = stdout;
      this.stdoutWrapper = stdoutWrapper;
      this.p = p;
    }

    static IOSniffer wrapIO(Process p) {
      final TeeInputStream stdin = new TeeInputStream(p.getInputStream(),
          new ByteArrayOutputStream());
      final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
      final TeeOutputStream stdoutWrapper = new TeeOutputStream(p.getOutputStream(),
          stdout);
      final TeeInputStream stderr = new TeeInputStream(p.getErrorStream(),
          new ByteArrayOutputStream());

      return new IOSniffer(p, stdin, stdout, stdoutWrapper, stderr);
    }

    public byte[] sniffedStdOut() {
      return stdout.toByteArray();
    }


    public byte[] sniffedStdIn() {
      return ((ByteArrayOutputStream) stdin.getOutputStream()).toByteArray();
    }


    public byte[] sniffedStdErr() {
      return ((ByteArrayOutputStream) stderr.getOutputStream()).toByteArray();
    }

    public void exportAndClose(Path dir) {

      swallowException(
          () -> Files.write(dir.resolve("to_gpg_stdin.log"), sniffedStdOut(),
              StandardOpenOption.CREATE_NEW));
      swallowException(
          () -> {

            swallowException(
                () -> Streams.drain(stderr)); // force everything to be moved into the buffer
            Files.write(dir.resolve("gpg_to_stderr.log"), sniffedStdErr(),
                StandardOpenOption.CREATE_NEW);
          });
      swallowException(
          () -> {
            //swallowException(
            //    () -> Streams.drain(stdin)); // force everything to be moved into the buffer
            Files.write(dir.resolve("gpg_to_stdout.log"), sniffedStdIn(),
                StandardOpenOption.CREATE_NEW);
          });

      swallowException(this::close);
    }


    @Override
    public void close() {
      closeSilently(stdin);
      closeSilently(stdout);
      closeSilently(stderr);
      closeSilently(stdoutWrapper);
    }

    private static void closeSilently(final Closeable c) {
      swallowException(c::close);
    }

    @FunctionalInterface
    private interface VoidCall {

      void call() throws Exception;
    }

    private static void swallowException(VoidCall call) {
      try {
        call.call();
      } catch (Exception e) {
        //swallow
        LOGGER.debug("Error in 'swallowException' (ignored)", e);
      }
    }
  }
}
