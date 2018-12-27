package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list;

import static java.util.Arrays.asList;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Scanner;
import java.util.StringJoiner;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Command;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Commands;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.GPGExec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Result;

public class ListKeysCommand implements Command {

  @Override
  public String toString() {
    return new StringJoiner(", ", ListKeysCommand.class.getSimpleName() + "[", "]")
        .add("listSecretKeys=" + listSecretKeys)
        .toString();
  }

  private final boolean listSecretKeys;

  public ListKeysCommand(final boolean listSecretKeys) {
    this.listSecretKeys = listSecretKeys;
  }

  public static Map<Long, PubKey> masterKeys(GPGExec gpg) throws IOException, InterruptedException {
    final ListKeysCommandResult keys = gpg.runCommand(Commands.listKeys());
    return ListKeysParser.toMasterKeys(keys.getKeyList());

  }


  public static Map<Long, SecretKey> secretKeys(GPGExec gpg)
      throws IOException, InterruptedException {
    final ListKeysCommandResult keys = gpg.runCommand(Commands.listSecretKeys());
    return ListKeysParser.toSecretKeys(keys.getKeyList());

  }

  public static Map<Long, PubKey> subKeys(GPGExec gpg) throws IOException, InterruptedException {
    final ListKeysCommandResult keys = gpg.runCommand(Commands.listKeys());
    return ListKeysParser.toSubKeys(keys.getKeyList());
  }

  @Override
  public List<String> getArgs() {
    return asList(listSecretKeys ? "--list-secret-keys" : "--list-keys", "--with-colons");
  }

  @Override
  public ListKeysCommandResult parse(InputStream stdout, int exitCode) {

    Queue<String> outputLines = toLines(stdout);

    final List<KeyLine> keyList = ListKeysParser.parse(outputLines);
    return new ListKeysCommandResult(exitCode, keyList);
  }

  private Queue<String> toLines(final InputStream stdout) {
    Queue<String> outputLines = new LinkedList<>();
    try (
        Scanner sc = new Scanner(stdout);
    ) {
      while (sc.hasNext()) {
        outputLines.add(sc.nextLine());
      }

    }
    return outputLines;
  }

  public final static class ListKeysCommandResult implements Result<ListKeysCommand> {

    @Override
    public String toString() {
      return new StringJoiner(", ", ListKeysCommandResult.class.getSimpleName() + "[", "]")
          .add("exitCode=" + exitCode)
          .add("keyList=" + keyList)
          .toString();
    }

    private final List<KeyLine> keyList;
    private final int exitCode;

    private ListKeysCommandResult(final int exitCode, final List<KeyLine> keyList) {
      this.keyList = keyList;
      this.exitCode = exitCode;
    }

    @Override
    public int exitCode() {
      return exitCode;
    }

    public List<KeyLine> getKeyList() {
      return keyList;
    }
  }
}
