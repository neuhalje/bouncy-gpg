package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysParser.FIELD_TYPE;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.StringJoiner;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysParser.Parser;

public final class SecretKey extends KeyLine {

  private final int keyLength;
  private final long keyId;
  private final KeyValidity keyValidity;
  private final List<KeyLine> associated;
  private final PubkeyAlgorithm algorithm;
  SecretKey(final long keyId, final int keyLength,
      final KeyValidity keyValidity,
      final PubkeyAlgorithm algorithm,
      final List<KeyLine> associated) {
    this.keyLength = keyLength;
    this.keyId = keyId;
    this.algorithm = algorithm;
    this.associated = associated;
    this.keyValidity = keyValidity;
  }

  static KeyLine parseSec(final Queue<String> remainingLines) {
    final String secKeyLine = remainingLines.poll();
    final String[] attributes = secKeyLine.split("[:]");

    final int KEY_VALIDITY = 1;
    final int KEY_LEN = 2;
    final int KEY_ALGO = 3;
    final int KEY_ID = 4;

    final int keyLength = Integer.parseInt(attributes[KEY_LEN]);
    final long keyId = Long.parseUnsignedLong(attributes[KEY_ID], 16);

    List<KeyLine> associated = getAssociatedKeyLines(remainingLines);

    return new SecretKey(keyId, keyLength, KeyValidity.forField(attributes[KEY_VALIDITY]),
        PubkeyAlgorithm.forField(attributes[KEY_ALGO]), associated);
  }

  private static List<KeyLine> getAssociatedKeyLines(final Queue<String> remainingLines) {
    List<KeyLine> associated = new ArrayList<>();
    Map<String, Parser> parser = new HashMap<>();
    parser.put("uid", Uid::parseUid);
    parser.put("ssb", SecretKey::parseSec);

    while (!remainingLines.isEmpty()) {
      final String line = remainingLines.peek();
      final String[] nestedAttributes = line.split("[:]");
      final String type = nestedAttributes[FIELD_TYPE];

      // very ugly
      if ("sec".equals(type)) {
        break;
      }

      Parser p = parser.getOrDefault(type, UnparsedLine::unparsedLine);
      associated.add(p.parse(remainingLines));
    }
    return associated;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public long getKeyId() {
    return keyId;
  }

  public List<KeyLine> getAssociated() {
    return associated;
  }

  public KeyValidity getKeyValidity() {
    return keyValidity;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", SecretKey.class.getSimpleName() + "[", "]")
        .add("keyLength=" + keyLength)
        .add("keyId=" + keyId)
        .add("keyValidity=" + keyValidity)
        .add("associated=" + associated)
        .add("algorithm=" + algorithm)
        .toString();
  }
}
