package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import java.io.IOException;
import java.time.Instant;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * <p>This implements the key selection strategy for BouncyGPG and selects keys based on
 * email addresses.</p>
 * <p>
 * For this it wraps the given addresses in &lt;/&gt;.
 * </p>
 * https://tools.ietf.org/html/rfc4880#section-5.2.3.21
 */
public class ByEMailKeySelectionStrategy extends Rfc4880KeySelectionStrategy implements
    KeySelectionStrategy {

  /**
   * @param dateOfTimestampVerification The date used for key expiration date checks as "now".
   */
  public ByEMailKeySelectionStrategy(final Instant dateOfTimestampVerification) {
    super(dateOfTimestampVerification, true, true);
  }

  /**
   * Return all keyrings that ARE valid keys for the given uid.
   *
   * If the uid does not already include '&lt;...&gt;' then wrap it in "&lt;uid&gt;"
   * to filter for e-mails.  E.g. "peter@example.com" will be converted to
   * "&lt;peter@example.com&gt;" but "Klaus &lt;klaus@example.com&gt;" or
   * "&lt;klaus@example.com&gt;" will be left untouched.
   *
   * @param uid the userid as passed by upstream.
   * @param keyringConfig the keyring config
   * @param purpose what is the requested key to be used for
   *
   * @return Set with keyrings, never null.
   *
   * @throws PGPException Something with BouncyCastle went wrong
   * @throws IOException IO is dangerous
   */
  @SuppressWarnings({"PMD.LawOfDemeter"})
  @Override
  protected Set<PGPPublicKeyRing> publicKeyRingsForUid(final PURPOSE purpose, final String uid,
      KeyringConfig keyringConfig)
      throws IOException, PGPException {

    final Set<PGPPublicKeyRing> keyringsForUid = new HashSet<>();

    final String uidQuery;
    final boolean uidAlreadyInBrackets = uid.matches(".*<.*>.*");
    if (uidAlreadyInBrackets) {
      uidQuery = uid;
    } else {
      uidQuery = "<" + uid + ">";
    }

    final Iterator<PGPPublicKeyRing> keyRings = keyringConfig.getPublicKeyRings()
        .getKeyRings(uidQuery, true, true);

    while (keyRings.hasNext()) {
      keyringsForUid.add(keyRings.next());
    }

    return keyringsForUid;
  }
}



