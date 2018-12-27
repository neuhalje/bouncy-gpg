package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public interface Command<T extends Command> {

  List<String> getArgs();

  Result<T> parse(InputStream stdout, int exitCode);

  default void io(OutputStream outputStream, InputStream inputStream, InputStream errorStream)
      throws IOException {
  }

}
