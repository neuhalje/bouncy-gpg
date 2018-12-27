package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list;

import java.util.Queue;
import java.util.StringJoiner;

class UnparsedLine extends KeyLine {

  private final String unparsedLine;

  UnparsedLine(final String unparsedLine) {
    this.unparsedLine = unparsedLine;
  }


  public String getUnparsedLine() {
    return unparsedLine;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
        .add("unparsedLine='" + unparsedLine + "'")
        .toString();
  }


  static KeyLine unparsedLine(final Queue<String> remainingLines) {
    return new UnparsedLine(remainingLines.poll());
  }
}
