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

  WithDetailedConfiguration withKeyFlags(KeyFlag... flags);

  WithDetailedConfiguration withDefaultKeyFlags();

  KeySpec withInheritedSubPackets();

  interface WithDetailedConfiguration {

    WithPreferredSymmetricAlgorithms withDetailedConfiguration();

    /**
     * Sets sensible default algorithms for this key.
     *
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

  interface WithPreferredSymmetricAlgorithms {

    WithPreferredHashAlgorithms withPreferredSymmetricAlgorithms(
        PGPSymmetricEncryptionAlgorithms... algorithms);

    WithPreferredHashAlgorithms withPreferredSymmetricAlgorithms(
        Collection<PGPSymmetricEncryptionAlgorithms> algorithms);

    WithPreferredHashAlgorithms withDefaultSymmetricAlgorithms();

    WithFeatures withDefaultAlgorithms();

  }

  interface WithPreferredHashAlgorithms {

    WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(
        PGPHashAlgorithms... algorithms);

    WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(
        Collection<PGPHashAlgorithms> algorithms);

    WithPreferredCompressionAlgorithms withDefaultHashAlgorithms();

  }

  interface WithPreferredCompressionAlgorithms {

    WithFeatures withPreferredCompressionAlgorithms(PGPCompressionAlgorithms... algorithms);

    WithFeatures withPreferredCompressionAlgorithms(
        Collection<PGPCompressionAlgorithms> algorithms);

    WithFeatures withDefaultCompressionAlgorithms();

  }

  interface WithFeatures {

    WithFeatures withFeature(Feature feature);

    KeySpec done();
  }

}
