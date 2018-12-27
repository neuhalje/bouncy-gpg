package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.stream.Collectors;


// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
public class ListKeysParser {

  final static int FIELD_TYPE = 0;

  /**
   * returns a map indexed by the ID of the master keys
   */
  public static Map<Long, PubKey> toMasterKeys(List<KeyLine> parsed) {

    return parsed.stream()
        .filter(k -> k instanceof PubKey)
        .map(k -> (PubKey) k)
        .collect(Collectors.toMap(PubKey::getKeyId, pubKey -> pubKey));
  }

  /**
   * returns a map indexed by the ID of the secret keys
   */
  public static Map<Long, SecretKey> toSecretKeys(List<KeyLine> parsed) {

    return parsed.stream()
        .filter(k -> k instanceof SecretKey)
        .map(k -> (SecretKey) k)
        .collect(Collectors.toMap(SecretKey::getKeyId, secretKey -> secretKey));
  }

  /**
   * returns a map indexed by the IDs of the sub keys
   */
  public static Map<Long, PubKey> toSubKeys(List<KeyLine> parsed) {

    return parsed.stream()
        .filter(k -> k instanceof PubKey)
        .map(k -> (PubKey) k)
        .flatMap(pubKey -> pubKey.getAssociated().stream())
        .filter(k -> k instanceof PubKey)
        .map(k -> (PubKey) k)
        .collect(Collectors.toMap(PubKey::getKeyId, pubKey -> pubKey));
  }

  static List<KeyLine> parse(final Queue<String> remainingLines) {

    List<KeyLine> parsedKeys = new ArrayList<>();

    Map<String, Parser> parser = new HashMap<>();
    parser.put("pub", PubKey::parsePub);
    parser.put("sec", SecretKey::parseSec);

    while (!remainingLines.isEmpty()) {
      final String line = remainingLines.peek();
      final String[] attributes = line.split("[:]");
      final String type = attributes[FIELD_TYPE];

      Parser p = parser.getOrDefault(type, UnparsedLine::unparsedLine);
      parsedKeys.add(p.parse(remainingLines));
    }

    return parsedKeys;
  }


  @FunctionalInterface
  public interface Parser {

    KeyLine parse(final Queue<String> remainingLines);
  }


}
