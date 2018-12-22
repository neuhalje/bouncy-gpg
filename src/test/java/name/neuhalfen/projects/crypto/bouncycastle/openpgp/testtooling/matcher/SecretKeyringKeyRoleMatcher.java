package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Set;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyFlag;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class SecretKeyringKeyRoleMatcher extends TypeSafeMatcher<PGPSecretKeyRing> {

  public enum KeyRole {
    SIGNING, MASTER, ENCRYPTION
  }

  private final EnumSet<KeyRole> required;

  private SecretKeyringKeyRoleMatcher(
      final EnumSet<KeyRole> required) {
    this.required = required;
  }

  private static String toString(EnumSet<KeyRole> flags) {
    final StringBuilder builder = new StringBuilder();
    if (flags.isEmpty()) {
      builder.append("<none>");
    } else {
      final Iterator<KeyRole> i = flags.iterator();
      builder.append(i.next());
      while (i.hasNext()) {
        builder.append(", ").append(i.next());
      }
    }
    return builder.toString();
  }

  EnumSet<KeyRole> parseKeyRing(final PGPSecretKeyRing ring) {
    final EnumSet<KeyRole> found = EnumSet.noneOf(KeyRole.class);
    final Iterator<PGPSecretKey> secretKeys = ring.getSecretKeys();
    while (secretKeys.hasNext()) {
      final PGPSecretKey secretKey = secretKeys.next();
      found.addAll(parseKey(secretKey));

    }
    return found;
  }

  EnumSet<KeyRole> parseKey(final PGPSecretKey item) {
    final EnumSet<KeyRole> found = EnumSet.noneOf(KeyRole.class);
    final PGPPublicKey publicKey = item.getPublicKey();
    final Set<KeyFlag> keyFlags = KeyFlag.extractPublicKeyFlags(publicKey);

    if (item.isMasterKey()) {
      found.add(KeyRole.MASTER);
    }

    if (item.isSigningKey()) {
      if (keyFlags.contains(KeyFlag.SIGN_DATA)) {
        found.add(KeyRole.SIGNING);
      }
    }

    if (item.getPublicKey().isEncryptionKey()) {
      final boolean hasEncryptionFlags =
          keyFlags.contains(KeyFlag.ENCRYPT_STORAGE) || keyFlags.contains(KeyFlag.ENCRYPT_COMMS);
      if (hasEncryptionFlags) {
        found.add(KeyRole.ENCRYPTION);
      }
    }

    return found;
  }

  @Override
  protected boolean matchesSafely(final PGPSecretKeyRing item) {
    try {
      final EnumSet<KeyRole> foundFlags = parseKeyRing(item);

      return (foundFlags.containsAll(required));
    } catch (Exception e) {
      return false;
    }
  }

  @Override
  protected void describeMismatchSafely(final PGPSecretKeyRing item,
      final Description mismatchDescription) {
    mismatchDescription.appendText("Key should have the following flags set: ");
    mismatchDescription.appendText(toString(this.required));
    mismatchDescription.appendText(". ");
    mismatchDescription.appendText("The following are set ");
    mismatchDescription.appendText(toString(parseKeyRing(item)));
  }

  @Override
  public void describeTo(final Description description) {
    description.appendText("has flags ").appendText(toString(required));
  }

  static SecretKeyringKeyRoleMatcher hasRoles(final KeyRole[] flags) {
    final EnumSet<KeyRole> required = EnumSet.noneOf(KeyRole.class);
    Collections.addAll(required, flags);
    return new SecretKeyringKeyRoleMatcher(required);
  }
}

