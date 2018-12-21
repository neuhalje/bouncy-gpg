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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;

public interface KeyRingBuilder {

  KeyRingBuilder withSubKey(KeySpec keySpec);

  WithPrimaryUserId withMasterKey(KeySpec keySpec);

  interface WithPrimaryUserId {

    WithPassphrase withPrimaryUserId(String userId);

    WithPassphrase withPrimaryUserId(byte[] userId);

  }

  interface WithPassphrase {

    Build withPassphrase(Passphrase passphrase);

    Build withoutPassphrase();
  }

  interface Build {

    KeyringConfig build() throws NoSuchAlgorithmException, PGPException, NoSuchProviderException,
        InvalidAlgorithmParameterException, IOException;

  }
}
