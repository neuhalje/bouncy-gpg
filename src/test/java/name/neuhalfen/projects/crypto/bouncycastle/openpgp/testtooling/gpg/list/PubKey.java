package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysParser.FIELD_TYPE;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.StringJoiner;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysParser.Parser;

public final class PubKey extends KeyLine {


  public int getKeyLength() {
    return keyLength;
  }


  public long getKeyId() {
    return keyId;
  }

  public List<KeyLine> getAssociated() {
    return associated;
  }

  private final int keyLength;
  private final long keyId;
  private final List<KeyLine> associated;
  private final KeyValidity keyValidity;
  private final PubkeyAlgorithm algorithm;

  public KeyValidity getKeyValidity() {
    return keyValidity;
  }

  PubKey(final long keyId, final int keyLength,
      final KeyValidity keyValidity,
      final PubkeyAlgorithm algorithm,
      final List<KeyLine> associated) {
    this.keyLength = keyLength;
    this.keyId = keyId;
    this.algorithm = algorithm;
    this.associated = associated;
    this.keyValidity = keyValidity;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", PubKey.class.getSimpleName() + "[", "]")
        .add("keyLength=" + keyLength)
        .add("keyId=" + keyId)
        .add("associated=" + associated)
        .add("keyValidity=" + keyValidity)
        .add("algorithm=" + algorithm)
        .toString();
  }

  static KeyLine parsePub(final Queue<String> remainingLines) {
    final String pubKeyLine = remainingLines.poll();
    final String[] attributes = pubKeyLine.split("[:]");

    // pub:u:4096:1:0F99F8287AFDF93A:1482435616:::u:::scESCA::::::23::0:
    // https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
    final int KEY_VALIDITY = 1;
    final int KEY_LEN = 2;
    final int KEY_ALGO = 3;
    final int KEY_ID = 4;

    final int keyLength = Integer.parseInt(attributes[KEY_LEN]);
    final long keyId = Long.parseUnsignedLong(attributes[KEY_ID], 16);

    List<KeyLine> associated = getAssociatedKeyLines(remainingLines);

    return new PubKey(keyId, keyLength, KeyValidity.forField(attributes[KEY_VALIDITY]),
        PubkeyAlgorithm.forField(attributes[KEY_ALGO]),
        associated);
  }

  private static List<KeyLine> getAssociatedKeyLines(final Queue<String> remainingLines) {
    List<KeyLine> associated = new ArrayList<>();
    Map<String, Parser> parser = new HashMap<>();
    parser.put("uid", Uid::parseUid);
    parser.put("sub", PubKey::parsePub);

    while (!remainingLines.isEmpty()) {
      final String line = remainingLines.peek();
      final String[] nestedAttributes = line.split("[:]");
      final String type = nestedAttributes[FIELD_TYPE];

      // very ugly
      if ("pub".equals(type)) {
        break;
      }

      Parser p = parser.getOrDefault(type, UnparsedLine::unparsedLine);
      associated.add(p.parse(remainingLines));
    }
    return associated;
  }
}
