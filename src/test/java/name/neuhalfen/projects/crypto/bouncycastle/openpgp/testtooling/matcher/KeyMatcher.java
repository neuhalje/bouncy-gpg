package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher;

import javax.annotation.RegEx;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.SecretKeyringKeyRoleMatcher.KeyRole;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.hamcrest.Matcher;

public final class KeyMatcher {

  private KeyMatcher() {/* utility */}

  public static Matcher<PGPPublicKeyRing> pubKeyRingForUid(final String uid){
    return  PublicKeyringWithUserIdMatcher.uid(uid);
  }

  public static Matcher<PGPPublicKeyRing> pubKeyRingForUidRegexp(@RegEx final String uidRegexp){
    return  PublicKeyringWithUserIdMatcher.regexp(uidRegexp);
  }


  public static Matcher<PGPSecretKeyRing> secretKeyRingForUid(final String uid){
    return  SecretKeyringWithUserIdMatcher.uid(uid);
  }

  public static Matcher<PGPSecretKeyRing> secretKeyRingHasRoles(final KeyRole... keyRoles){
    return  SecretKeyringKeyRoleMatcher.hasRoles(keyRoles);
  }




  public static Matcher<PGPSecretKeyRing> secretKeyRingForUidRegexp(@RegEx final String uidRegexp){
    return  SecretKeyringWithUserIdMatcher.regexp(uidRegexp);
  }
}
