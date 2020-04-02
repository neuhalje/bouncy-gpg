/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation;

import static java.util.Objects.requireNonNull;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Set;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;

/**
 * <p>Wraps bouncy castles org.bouncycastle.bcpg.sig.KeyFlags into an enum. Provides helper to
 * extract
 * key flags from keys.</p>
 *
 * <p>
 * To quote from <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.21">
 * rfc4880 section 5.2.3.21</a>: </p>
 * <blockquote>
 * The flags in this packet may appear in self-signatures or in
 * certification signatures.  They mean different things depending on
 * who is making the statement -- for example, a certification signature
 * that has the "sign data" flag is stating that the certification is
 * for that use.  On the other hand, the "communications encryption"
 * flag in a self-signature is stating a preference that a given key be
 * used for communications.  Note however, that it is a thorny issue to
 * determine what is "communications" and what is "storage".  This
 * decision is left wholly up to the implementation; the authors of this
 * document do not claim any special wisdom on the issue and realize
 * that accepted opinion may change.
 *
 * The "split key" (0x10) and "group key" (0x80) flags are placed on a
 * self-signature only; they are meaningless on a certification
 * signature.  They SHOULD be placed only on a direct-key signature
 * (type 0x1F) or a subkey signature (type 0x18), one that refers to the
 * key the flag applies to.
 * </blockquote>
 *
 * @see KeyFlags
 */
public enum KeyFlag {

  CERTIFY_OTHER(KeyFlags.CERTIFY_OTHER),
  SIGN_DATA(KeyFlags.SIGN_DATA),
  ENCRYPT_COMMS(KeyFlags.ENCRYPT_COMMS),
  ENCRYPT_STORAGE(KeyFlags.ENCRYPT_STORAGE),
  SPLIT(KeyFlags.SPLIT),
  AUTHENTICATION(KeyFlags.AUTHENTICATION),
  SHARED(KeyFlags.SHARED),
  ;

  private final int flag;

  KeyFlag(int flag) {
    this.flag = flag;
  }

  public static Set<KeyFlag> fromInteger(int bitmask) {
    if (bitmask == 0) {
      return Collections.emptySet();
    }

    final Set<KeyFlag> flags = EnumSet.noneOf(KeyFlag.class);
    int identifiedFlags = 0;

    for (final KeyFlag f : KeyFlag.values()) {
      if ((bitmask & f.flag) != 0) {
        flags.add(f);
        identifiedFlags |= f.flag;
      }
    }

    if (identifiedFlags != bitmask) {
      final int unknownFlags = ~identifiedFlags & bitmask;
      throw new IllegalArgumentException(
          "Could not identify the following KeyFlags: 0b" + Long.toBinaryString(unknownFlags));
    }
    return Collections.unmodifiableSet(flags);
  }

  @SuppressWarnings({"PMD.LawOfDemeter"})
  public static Set<KeyFlag> extractPublicKeyFlags(PGPPublicKey publicKey) {
    requireNonNull(publicKey, "publicKey must not be null");

    int aggregatedKeyFlags = 0;

    final Iterator<PGPSignature> directKeySignatures = publicKey.getSignatures();

    while (directKeySignatures.hasNext()) {
      final PGPSignature signature = directKeySignatures.next();
      final PGPSignatureSubpacketVector hashedSubPackets = signature.getHashedSubPackets();
      // hashedSubPackets is null for PGP v3 and earlier.
      if (hashedSubPackets != null) {
        final int keyFlags = hashedSubPackets.getKeyFlags();
        aggregatedKeyFlags |= keyFlags;
      }
    }
    return fromInteger(aggregatedKeyFlags);
  }

  public int getFlag() {
    return flag;
  }
}
