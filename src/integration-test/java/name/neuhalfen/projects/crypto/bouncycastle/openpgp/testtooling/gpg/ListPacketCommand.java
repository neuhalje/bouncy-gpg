package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import static java.util.Arrays.asList;

import java.util.List;

public class ListPacketCommand extends BaseCommand implements Command {


  public ListPacketCommand(final String comment, final byte[] pipeToGpg) {
    super(comment, pipeToGpg);
  }

  @Override
  public List<String> getArgs() {
    return asList("--list-packet");
  }

  @Override
  public String displayName() {
    return "list-packet";
  }
  @Override
  Result<? extends BaseCommand> parseStdOut(final int exitCode, final byte[] stdout) {
    return new ListPacketCommandResult(exitCode, stdout);
  }

  public final class ListPacketCommandResult extends
      BaseCommandResult<ListPacketCommand> implements
      Result<ListPacketCommand> {

    ListPacketCommandResult(final int exitCode, final byte[] stdOut) {
      super(exitCode, stdOut);
    }

    public String toString() {
      return new String(getStdOut());
    }
  }

}
