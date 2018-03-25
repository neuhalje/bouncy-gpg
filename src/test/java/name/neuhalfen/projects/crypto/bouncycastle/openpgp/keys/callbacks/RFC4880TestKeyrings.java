package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import java.io.IOException;
import java.time.Instant;
import java.time.ZonedDateTime;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;

public class RFC4880TestKeyrings {
/*
    <code><pre>
sec  rsa2048/0xF8BEA74E37D9F45D
     created: 2018-03-25  expires: never       usage: SC
     trust: ultimate      validity: ultimate
ssb  rsa2048/0x47377FEDD16C26B3
     created: 2018-03-25  expires: never       usage: E
The following key was revoked on 2018-03-25 by RSA key 0xF8BEA74E37D9F45D RFC4880 Test User <rfc4880@example.org>
ssb  rsa2048/0xDFAAFD6855BAAF35
     created: 2018-03-25  revoked: 2018-03-25  usage: S
ssb  rsa2048/0xC811CA8F998DD2E4
     created: 2018-03-25  expires: never       usage: S
ssb  rsa2048/0xD6FB1B2CCFC1926A
     created: 2018-03-25  expires: never       usage: A
ssb  rsa2048/0x83063C3DA3814052
     created: 2018-03-25  expires: 2018-03-26  usage: S
[ultimate] (1). RFC4880 Test User <rfc4880@example.org>
   </pre></code>
 */


  public final static String UID_EMAIL="rfc4880@example.org";

  public final static Instant EXPIRED_KEY_CREATION_TIME = ZonedDateTime
      .parse("2018-03-25T10:55:31Z").toInstant();

  public final static Instant EXPIRED_KEY_EXPIRATION_DATE = ZonedDateTime
      .parse("2018-03-26T10:56:21Z")
      .toInstant();

  public final static Instant SIGNATURE_KEY_GUARANTEED_EXPIRED_AT = EXPIRED_KEY_EXPIRATION_DATE
      .plusSeconds(1);

  public final static long MASTER_KEY_ID = Long.parseUnsignedLong("F8BEA74E37D9F45D", 16);
  public final static long ENCRYPTION_KEY = Long.parseUnsignedLong("47377FEDD16C26B3", 16);
  public final static long SIGNATURE_KEY_REVOKED = Long.parseUnsignedLong("DFAAFD6855BAAF35", 16);
  public final static long SIGNATURE_KEY_ACTIVE = Long.parseUnsignedLong("C811CA8F998DD2E4", 16);
  public final static long SIGNATURE_KEY_EXPIRED = Long.parseUnsignedLong("83063C3DA3814052", 16);
  public final static long AUTHENTICATION_KEY = Long.parseUnsignedLong("D6FB1B2CCFC1926A", 16);

  public static KeyringConfig publicKeyOnlyKeyringConfig() throws IOException, PGPException {
    final InMemoryKeyring keyring = newKeyring();
    keyring.addPublicKey(PUBLIC_KEY.getBytes("US-ASCII"));
    return keyring;
  }

  public static KeyringConfig publicAndPrivateKeyKeyringConfig() throws IOException, PGPException {
    final InMemoryKeyring keyring = newKeyring();
    keyring.addPublicKey(PUBLIC_KEY.getBytes("US-ASCII"));
    keyring.addSecretKey(PRIVATE_KEY.getBytes("US-ASCII"));
    return keyring;
  }

  private static InMemoryKeyring newKeyring() throws IOException, PGPException {
    return KeyringConfigs
        .forGpgExportedKeys(KeyringConfigCallbacks.withPassword("rfc4880"));
  }

  private final static String PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
      + "\n"
      + "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\n"
      + "=fkLr\n"
      + "-----END PGP PUBLIC KEY BLOCK-----";


  private final static String PRIVATE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
      + "\n"
      + "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\n"
      + "=rT0P\n"
      + "-----END PGP PRIVATE KEY BLOCK-----";
}
