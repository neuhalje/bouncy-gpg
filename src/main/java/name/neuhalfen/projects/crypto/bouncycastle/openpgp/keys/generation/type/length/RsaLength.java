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
package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length;

public enum RsaLength implements KeyLength {
  @Deprecated
  RSA_1024_BIT(1024),
  @Deprecated
  RSA_2048_BIT(2048),
  RSA_3072_BIT(3072),
  RSA_4096_BIT(4096),
  RSA_8192_BIT(8192),
  ;

  private final int length;

  RsaLength(int length) {
    this.length = length;
  }

  @Override
  public int getLength() {
    return length;
  }
}
