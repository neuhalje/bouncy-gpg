package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Iterator;
import org.bouncycastle.openpgp.PGPPublicKey;

public class KeysTestHelper {

  public static void assertIsCorrectPublicKey(final long expectedKeyId, final PGPPublicKey actual) {
    assertNotNull("A public key is expected but is not delivered", actual);

    assertEquals(String.format("A specific key Id is expected. Actual: %s", formatKey(actual)),
        expectedKeyId, actual.getKeyID());
  }

  public static String formatKey(final PGPPublicKey key) {
    if (key == null) {
      return "<null>";
    }

    StringBuilder b = new StringBuilder("{");
    b.append("id: 0x").append(Long.toHexString(key.getKeyID())).append(", userIds: [");

    final Iterator<String> userIDs = key.getUserIDs();
    while (userIDs.hasNext()) {
      b.append("'").append( userIDs.next()).append("', ");
    }
    b.append("]}");
    return b.toString();

  }
}
