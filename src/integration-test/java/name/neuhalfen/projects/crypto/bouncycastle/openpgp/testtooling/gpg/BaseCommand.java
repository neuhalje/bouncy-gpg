package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.StringJoiner;
import org.bouncycastle.util.io.Streams;

public abstract class BaseCommand implements Command {

  private final byte[] pipeToGpg;
  protected final String comment;


  public BaseCommand(final String comment, final byte[] pipeToGpg) {
    this.pipeToGpg = pipeToGpg;
    this.comment = comment == null ? "" : comment;
  }

  public void io(OutputStream outputStream, InputStream inputStream, InputStream errorStream)
      throws IOException {
    outputStream.write(pipeToGpg);
    outputStream.flush();
    outputStream.close();
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
        .add("comment='" + comment + "'")
        .add("pipeToGpg=[len:=" + (pipeToGpg == null ? "empty" : pipeToGpg.length) + "]")
        .toString();
  }

  @Override
  public Result<? extends BaseCommand> parse(InputStream stdout, int exitCode) {
    //  nothing to do
    byte[] output;
    try {
      final byte[] bytes = Streams.readAll(stdout);
      output = Arrays.copyOf(bytes, bytes.length);
    } catch (IOException e) {
      output = null;
    }
    return parseStdOut(exitCode, output);
  }

  abstract Result<? extends BaseCommand> parseStdOut(int exitCode, byte[] stdout);

  public class BaseCommandResult<T extends BaseCommand> implements Result<T> {

    private final int exitCode;
    private final byte[] stdOut;

    BaseCommandResult(final int exitCode, final byte[] stdOut) {
      this.exitCode = exitCode;
      this.stdOut = stdOut;
    }

    public byte[] getStdOut() {
      return stdOut;
    }


    @Override
    public int exitCode() {
      return exitCode;
    }

    @Override
    public String toString() {
      return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
          .add("exitCode=" + exitCode)
          .add("comment=" + comment)
          .add("stdOut=[len:=" + (stdOut == null ? "empty" : stdOut.length) + "]")
          .toString();
    }
  }
}
