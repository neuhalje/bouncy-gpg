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
package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.curve;

/**
 * See https://safecurves.cr.yp.to/
 * See https://bouncycastle.org/wiki/pages/viewpage.action?pageId=362269
 */
public enum EllipticCurve {
  CURVE_NIST_P256("P-256"),
  CURVE_NIST_P384("P-384"),
  CURVE_NIST_P521("P-521"),
  CURVE_ed25519("curve25519")
  ;

  private final String name;

  EllipticCurve(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }
}
