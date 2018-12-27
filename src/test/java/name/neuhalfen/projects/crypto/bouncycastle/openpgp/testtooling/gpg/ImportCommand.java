package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import static java.util.Arrays.asList;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;
import org.bouncycastle.util.io.Streams;

public class ImportCommand implements Command {

  private final byte[] keyData;
  private final String passphrase;

  public ImportCommand(final byte[] keyData, final String passphrase) {
    this.keyData = keyData;
    this.passphrase = passphrase;
  }

  public ImportCommand(final byte[] keyData) {
    this.keyData = keyData;
    this.passphrase = null;
  }

  public final static class ImportCommandResult implements Result<ImportCommand> {

    private final int exitCode;
    private final String output;

    private ImportCommandResult(final int exitCode, final String output) {
      this.exitCode = exitCode;
      this.output = output;
    }

    @Override
    public int exitCode() {
      return exitCode;
    }

    @Override
    public String toString() {
      return new StringJoiner(", ", ImportCommandResult.class.getSimpleName() + "[", "]")
          .add("exitCode=" + exitCode)
          .add("output='" + output + "'")
          .toString();
    }
  }

  @Override
  public List<String> getArgs() {

    final List<String> args = new ArrayList<>(asList("--import",
        "--batch",
        "--import-options", "keep-ownertrust"));

    if (passphrase != null) {
      args.add("--passphrase");
      args.add(passphrase);
    }

    return args;
  }

  public void io(OutputStream outputStream, InputStream inputStream, InputStream errorStream)
      throws IOException {
    inputStream.available();
    outputStream.write(keyData);
    outputStream.close();
  }

  @Override
  public ImportCommandResult parse(InputStream stdout, int exitCode) {
    //  nothing to do
    String output;
    try {
      final byte[] bytes = Streams.readAll(stdout);
      output = new String(bytes);
    } catch (IOException e) {
      output = e.getMessage();
    }
    return new ImportCommandResult(exitCode, output);
  }
}
