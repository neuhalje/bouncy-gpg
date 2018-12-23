package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.RegEx;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PublicKeyAlgorithm;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.KeyLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.SecretKeyringKeyRoleMatcher.KeyRole;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.hamcrest.Matcher;

public final class KeyMatcher {

  private KeyMatcher() {/* utility */}

  public static Matcher<PGPPublicKeyRing> pubKeyRingForUid(final String uid) {
    return PublicKeyringWithUserIdMatcher.uid(uid);
  }

  public static Matcher<PGPPublicKeyRing> pubKeyRingForUidRegexp(@RegEx final String uidRegexp) {
    return PublicKeyringWithUserIdMatcher.regexp(uidRegexp);
  }


  public static Matcher<PGPSecretKeyRing> secretKeyRingForUid(final String uid) {
    return SecretKeyringWithUserIdMatcher.uid(uid);
  }

  public static Matcher<PGPSecretKeyRing> secretKeyRingHasRoles(final KeyRole... keyRoles) {
    return SecretKeyringKeyRoleMatcher.hasRoles(keyRoles);
  }

  public static Matcher<PGPSecretKeyRing> secretKeyRingForUidRegexp(@RegEx final String uidRegexp) {
    return SecretKeyringWithUserIdMatcher.regexp(uidRegexp);
  }


  /**
   * Check that _all_ secret keys are encrypted.
   */
  public static Matcher<PGPSecretKeyRing> secretKeyIsEncrypted() {
    return SecretKeyringEncryptedMatcher.secretKeyIsEncrypted();
  }

  public static Matcher<PGPSecretKey> keyAlgorithmAnyOf(
      final PublicKeyAlgorithm... allowedAlgorithms) {
    final EnumSet<PublicKeyAlgorithm> s = EnumSet.noneOf(PublicKeyAlgorithm.class);

    Collections.addAll(s, allowedAlgorithms);
    return KeyAlgorithmMatcher.keyAlgorithmAnyOf(s);
  }

  public static Matcher<PGPSecretKey> hasKeyLength(final KeyLength... allowedKeyLengths) {
    final Set<Integer> keyLengthValues = Arrays.stream(allowedKeyLengths)
        .map(KeyLength::getLength).collect(Collectors.toSet());

    return KeyLengthMatcher.hasKeyLength(keyLengthValues);
  }

  public static Matcher<PGPSecretKey> hasKeyLength(final Integer... allowedKeyLengths) {
    final Set<Integer> keyLengthValues = new HashSet<>();
    Collections.addAll(keyLengthValues, allowedKeyLengths);

    return KeyLengthMatcher.hasKeyLength(keyLengthValues);
  }

  /**
   * tests that this issue is fixed in the keyring: https://github.com/bcgit/bc-java/issues/381
   */
  public static Matcher<PGPSecretKeyRing> secretKeyringHasCorrectSubkeyPackets() {
    return SecretKeyringHasCorrectSubkeyPacketsMatcher.secretKeyringHasCorrectSubkeyPackets();
  }
}
