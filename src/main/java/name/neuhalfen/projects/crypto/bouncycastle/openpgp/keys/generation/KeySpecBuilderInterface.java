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

import java.util.Collection;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.Feature;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPCompressionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPHashAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPSymmetricEncryptionAlgorithms;
import org.bouncycastle.bcpg.sig.Features;

public interface KeySpecBuilderInterface {

  /**
   * <p>Configure the GPG keyflags for a key to allow <b>all</b> key usages. This is not bad or
   * dangerous, but often considered bad style because normally different <i>signature</i> and
   * <i>encryption</i> keys are used and recommended.</p>
   *
   * <p>GPG keys and subkeys carry flags that describe their purpose. Most commonly the master key
   * carries the SIGN_DATA and CERTIFY_OTHER flags and a dedicated encryption key carries the
   * ENCRYPT_STORAGE and ENCRYPT_COMMS flags.</p>
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
   * @param flags Flags to be enabled for this sub- or master-key
   *
   * @return next step
   */
  WithDetailedConfiguration allowKeyToBeUsedTo(KeyFlag... flags);

  /**
   * <p>Configure the GPG keyflags for a key.</p>
   *
   * <p>GPG keys and subkeys carry flags that describe their purpose. Most commonly the master key
   * carries the SIGN_DATA and CERTIFY_OTHER flags and a dedicated encryption key carries the
   * ENCRYPT_STORAGE and ENCRYPT_COMMS flags.</p>
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
   * @return next step
   */
  WithDetailedConfiguration allowKeyToBeUsedForEverything();

  /**
   * Copy all key flags, algorithms, ... from the parent key.
   * @return key spec.
   */
  KeySpec withInheritedSubPackets();

  interface WithDetailedConfiguration {

    WithPreferredSymmetricAlgorithms withDetailedConfiguration();

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <ul>
     * <li>preferred algorithms via recommendedAlgorithmIds()</li>
     * <li>enables the FEATURE_MODIFICATION_DETECTION feature</li>
     * </ul>
     *
     * @return keyspec
     *
     * @see PGPCompressionAlgorithms#recommendedAlgorithmIds()
     * @see PGPSymmetricEncryptionAlgorithms#recommendedAlgorithmIds()
     * @see PGPHashAlgorithms#recommendedAlgorithmIds()
     * @see Features#FEATURE_MODIFICATION_DETECTION
     */
    KeySpec withDefaultAlgorithms();
  }

  /**
   * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
   * assumed that only algorithms listed are supported by the recipient's software.</p>
   *
   * <p>
   * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.7">5.2.3.7.
   * Preferred Symmetric Algorithms</a>:
   * </p>
   * <blockquote>
   * Symmetric algorithm numbers that indicate which algorithms the key
   * holder prefers to use.  The subpacket body is an ordered list of
   * octets with the most preferred listed first.  It is assumed that only
   * algorithms listed are supported by the recipient's software.
   * Algorithm numbers are in Section 9.  This is only found on a self-
   * signature.
   * </blockquote>
   */
  interface WithPreferredSymmetricAlgorithms {

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.7">5.2.3.7.
     * Preferred Symmetric Algorithms</a>:
     * </p>
     * <blockquote>
     * Symmetric algorithm numbers that indicate which algorithms the key
     * holder prefers to use.  The subpacket body is an ordered list of
     * octets with the most preferred listed first.  It is assumed that only
     * algorithms listed are supported by the recipient's software.
     * Algorithm numbers are in Section 9.  This is only found on a self-
     * signature.
     * </blockquote>
     *
     * @param algorithms set of preferred algorithms
     *
     * @return next builder step
     */
    WithPreferredHashAlgorithms withPreferredSymmetricAlgorithms(
        PGPSymmetricEncryptionAlgorithms... algorithms);

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.7">5.2.3.7.
     * Preferred Symmetric Algorithms</a>:
     * </p>
     * <blockquote>
     * Symmetric algorithm numbers that indicate which algorithms the key
     * holder prefers to use.  The subpacket body is an ordered list of
     * octets with the most preferred listed first.  It is assumed that only
     * algorithms listed are supported by the recipient's software.
     * Algorithm numbers are in Section 9.  This is only found on a self-
     * signature.
     * </blockquote>
     *
     * @param algorithms set of preferred algorithms
     *
     * @return next builder step
     */
    WithPreferredHashAlgorithms withPreferredSymmetricAlgorithms(
        Collection<PGPSymmetricEncryptionAlgorithms> algorithms);

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <p>The default is to select algorithms that are deemed safe. {@link
     * PGPSymmetricEncryptionAlgorithms#recommendedAlgorithms()}.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.7">5.2.3.7.
     * Preferred Symmetric Algorithms</a>:
     * </p>
     * <blockquote>
     * Symmetric algorithm numbers that indicate which algorithms the key
     * holder prefers to use.  The subpacket body is an ordered list of
     * octets with the most preferred listed first.  It is assumed that only
     * algorithms listed are supported by the recipient's software.
     * Algorithm numbers are in Section 9.  This is only found on a self-
     * signature.
     * </blockquote>
     *
     * @return next builder step
     *
     * @see PGPSymmetricEncryptionAlgorithms#recommendedAlgorithms()
     */
    WithPreferredHashAlgorithms withDefaultSymmetricAlgorithms();

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     *
     * <p>Sets values for the following algorithms:</p>
     * <ul>
     * <li>Hash</li>
     * <li>Symmetric encryption</li>
     * <li>Compression</li>
     * </ul>
     * <p>The default is to select algorithms that are deemed safe/sensible.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.7">5.2.3.7.
     * Preferred Symmetric Algorithms</a>:
     * </p>
     * <blockquote>
     * Symmetric algorithm numbers that indicate which algorithms the key
     * holder prefers to use.  The subpacket body is an ordered list of
     * octets with the most preferred listed first.  It is assumed that only
     * algorithms listed are supported by the recipient's software.
     * Algorithm numbers are in Section 9.  This is only found on a self-
     * signature.
     * </blockquote>
     *
     * @return next builder step
     *
     * @see PGPSymmetricEncryptionAlgorithms#recommendedAlgorithms()
     * @see PGPCompressionAlgorithms#recommendedAlgorithms()
     * @see PGPHashAlgorithms#recommendedAlgorithms()
     */
    WithFeatures withDefaultAlgorithms();

  }

  interface WithPreferredHashAlgorithms {

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <p>{@link PGPHashAlgorithms#recommendedAlgorithms()}.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.8">5.2.3.8.
     * Preferred Hash Algorithms</a>:
     * </p>
     * <blockquote>
     * Message digest algorithm numbers that indicate which algorithms the
     * key holder prefers to receive.  Like the preferred symmetric
     * algorithms, the list is ordered.  Algorithm numbers are in Section 9.
     * This is only found on a self-signature.
     * </blockquote>
     *
     * @param algorithms the algorithms to set
     *
     * @return next builder step
     *
     * @see PGPHashAlgorithms#recommendedAlgorithms()
     */
    WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(
        PGPHashAlgorithms... algorithms);


    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <p>{@link PGPHashAlgorithms#recommendedAlgorithms()}.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.8">5.2.3.8.
     * Preferred Hash Algorithms</a>:
     * </p>
     * <blockquote>
     * Message digest algorithm numbers that indicate which algorithms the
     * key holder prefers to receive.  Like the preferred symmetric
     * algorithms, the list is ordered.  Algorithm numbers are in Section 9.
     * This is only found on a self-signature.
     * </blockquote>
     *
     * @param algorithms the algorithms to set
     *
     * @return next builder step
     *
     * @see PGPHashAlgorithms#recommendedAlgorithms()
     */
    WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(
        Collection<PGPHashAlgorithms> algorithms);

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <p>The default is to select algorithms that are deemed safe. {@link
     * PGPHashAlgorithms#recommendedAlgorithms()}.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.8">5.2.3.8.
     * Preferred Hash Algorithms</a>:
     * </p>
     * <blockquote>
     * Message digest algorithm numbers that indicate which algorithms the
     * key holder prefers to receive.  Like the preferred symmetric
     * algorithms, the list is ordered.  Algorithm numbers are in Section 9.
     * This is only found on a self-signature.
     * </blockquote>
     *
     * @return next builder step
     *
     * @see PGPHashAlgorithms#recommendedAlgorithms()
     */
    WithPreferredCompressionAlgorithms withDefaultHashAlgorithms();

  }

  interface WithPreferredCompressionAlgorithms {

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <p>{@link PGPCompressionAlgorithms#recommendedAlgorithms()}.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.9">5.2.3.9.
     * Preferred Hash Algorithms</a>:
     * </p>
     * <blockquote>
     * Compression algorithm numbers that indicate which algorithms the key
     * holder prefers to use.  Like the preferred symmetric algorithms, the
     * list is ordered.  Algorithm numbers are in Section 9.  If this
     * subpacket is not included, ZIP is preferred.  A zero denotes that
     * uncompressed data is preferred; the key holder's software might have
     * no compression software in that implementation.  This is only found
     * on a self-signature.
     * </blockquote>
     *
     * @param algorithms the algorithms to set
     *
     * @return next builder step
     *
     * @see PGPCompressionAlgorithms#recommendedAlgorithms()
     */
    WithFeatures withPreferredCompressionAlgorithms(PGPCompressionAlgorithms... algorithms);

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <p>{@link PGPCompressionAlgorithms#recommendedAlgorithms()}.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.9">5.2.3.9.
     * Preferred Hash Algorithms</a>:
     * </p>
     * <blockquote>
     * Compression algorithm numbers that indicate which algorithms the key
     * holder prefers to use.  Like the preferred symmetric algorithms, the
     * list is ordered.  Algorithm numbers are in Section 9.  If this
     * subpacket is not included, ZIP is preferred.  A zero denotes that
     * uncompressed data is preferred; the key holder's software might have
     * no compression software in that implementation.  This is only found
     * on a self-signature.
     * </blockquote>
     *
     * @param algorithms the algorithms to set
     *
     * @return next builder step
     *
     * @see PGPCompressionAlgorithms#recommendedAlgorithms()
     */
    WithFeatures withPreferredCompressionAlgorithms(
        Collection<PGPCompressionAlgorithms> algorithms);

    /**
     * <p>Annotate the public key with the set of algorithms the key holder prefers to use. It is
     * assumed that only algorithms listed are supported by the recipient's software.</p>
     * <p>{@link PGPCompressionAlgorithms#recommendedAlgorithms()}.</p>
     * <p>
     * This is documented in RFC4880 <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.9">5.2.3.9.
     * Preferred Hash Algorithms</a>:
     * </p>
     * <blockquote>
     * Compression algorithm numbers that indicate which algorithms the key
     * holder prefers to use.  Like the preferred symmetric algorithms, the
     * list is ordered.  Algorithm numbers are in Section 9.  If this
     * subpacket is not included, ZIP is preferred.  A zero denotes that
     * uncompressed data is preferred; the key holder's software might have
     * no compression software in that implementation.  This is only found
     * on a self-signature.
     * </blockquote>
     *
     * @return next builder step
     *
     * @see PGPCompressionAlgorithms#recommendedAlgorithms()
     */
    WithFeatures withDefaultCompressionAlgorithms();

  }

  interface WithFeatures {

    /**
     * Add features to the key.
     *
     * @param feature the feature
     *
     * @return next step
     */
    WithFeatures withFeature(Feature feature);

    KeySpec done();
  }

}
