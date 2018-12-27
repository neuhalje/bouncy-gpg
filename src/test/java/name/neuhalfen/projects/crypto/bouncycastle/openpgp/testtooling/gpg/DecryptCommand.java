package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import static java.util.Arrays.asList;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.StringJoiner;
import org.bouncycastle.util.io.Streams;

public class DecryptCommand implements Command {

  private final byte[] plaintext;
  private final String passphrase;

  public DecryptCommand(final byte[] plaintext, final String passphrase) {
    this.plaintext = plaintext;
    this.passphrase = passphrase;
  }

  public final static class DecryptCommandResult implements Result<DecryptCommand> {

    private final int exitCode;
    private final byte[] plaintext;
    private final String errorMessage;

    private DecryptCommandResult(final int exitCode, final byte[] plaintext,
        final String errorMessage) {
      this.exitCode = exitCode;
      this.plaintext = plaintext;
      this.errorMessage = errorMessage;
    }

    public byte[] getPlaintext() {
      return plaintext;
    }

    @Override
    public int exitCode() {
      return exitCode;
    }

    @Override
    public String toString() {
      return new StringJoiner(", ", DecryptCommandResult.class.getSimpleName() + "[", "]")
          .add("exitCode=" + exitCode)
          .add("plaintext=" + Arrays.toString(plaintext))
          .add("errorMessage='" + errorMessage + "'")
          .toString();
    }
  }

  @Override
  public List<String> getArgs() {
    return asList("--decrypt", "--batch", "--passphrase", passphrase);
  }

  public void io(OutputStream outputStream, InputStream inputStream, InputStream errorStream)
      throws IOException {
    outputStream.write(plaintext);
    outputStream.close();
  }

  @Override
  public DecryptCommandResult parse(InputStream stdout, int exitCode) {
    //  nothing to do
    byte[] output;
    String errorMessage;
    try {
      final byte[] bytes = Streams.readAll(stdout);

      if (exitCode == 0) {
        errorMessage = "";
        output = Arrays.copyOf(bytes, bytes.length);
      } else {
        errorMessage = new String(bytes);
        output = null;
      }
    } catch (IOException e) {
      output = null;
      errorMessage = e.getMessage();
    }
    return new DecryptCommandResult(exitCode, output, errorMessage);
  }
}
