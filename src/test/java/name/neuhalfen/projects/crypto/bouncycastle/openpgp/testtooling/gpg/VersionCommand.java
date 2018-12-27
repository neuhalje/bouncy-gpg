package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;

import java.io.InputStream;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VersionCommand implements Command {

  // gpg (GnuPG/MacGPG2) 2.2.10
  private Pattern VERSION_STRING = Pattern
      .compile("^gpg.* (?<major>[\\d]+).(?<minor>[\\d]+).(?<revision>[\\d]+)$");


  public final static class VersionCommandResult implements Result<VersionCommand> {

    public final static VersionCommandResult UNKNOWN =
        new VersionCommandResult(-1, "", 0, 0, 0);

    private final int exitCode;
    private final String versionString;
    private final int major;
    private final int minor;
    private final int revision;

    public String getVersionString() {
      return versionString;
    }

    public int getMajor() {
      return major;
    }

    public int getMinor() {
      return minor;
    }

    public int getRevision() {
      return revision;
    }

    public boolean isAtLeast(int major) {
      return this.major >= major;
    }

    public boolean isAtLeast(int major, int minor) {
      return (this.major > major) || (this.major == major && this.minor >= minor);
    }


    private VersionCommandResult(final int exitCode, final String versionString, final int major,
        final int minor,
        final int revision) {
      this.exitCode = exitCode;

      this.versionString = requireNonNull(versionString);
      this.major = major;
      this.minor = minor;
      this.revision = revision;
    }

    @Override
    public int exitCode() {
      return exitCode;
    }

    @Override
    public boolean equals(final Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      final VersionCommandResult that = (VersionCommandResult) o;
      return exitCode == that.exitCode &&
          getMajor() == that.getMajor() &&
          getMinor() == that.getMinor() &&
          getRevision() == that.getRevision() &&
          getVersionString().equals(that.getVersionString());
    }

    @Override
    public int hashCode() {
      return Objects.hash(exitCode, getVersionString(), getMajor(), getMinor(), getRevision());
    }

    @Override
    public String toString() {
      return new StringJoiner(", ", VersionCommandResult.class.getSimpleName() + "[", "]")
          .add("exitCode=" + exitCode)
          .add("versionString='" + versionString + "'")
          .add("major=" + major)
          .add("minor=" + minor)
          .add("revision=" + revision)
          .toString();
    }
  }

  @Override
  public List<String> getArgs() {
    return asList("--version");
  }

  @Override
  public VersionCommandResult parse(InputStream stdout, int exitCode) {

    try (
        Scanner sc = new Scanner(stdout);

    ) {
      while (sc.hasNext()) {

        final String line = sc.nextLine();
        final Matcher matcher = VERSION_STRING.matcher(line);
        if (matcher.matches()) {
          final int major = Integer.parseInt(matcher.group("major"));
          final int minor = Integer.parseInt(matcher.group("minor"));
          final int revision = Integer.parseInt(matcher.group("revision"));

          return new VersionCommandResult(exitCode, line, major, minor, revision);
        }
      }
    }
    return VersionCommandResult.UNKNOWN;
  }
}
