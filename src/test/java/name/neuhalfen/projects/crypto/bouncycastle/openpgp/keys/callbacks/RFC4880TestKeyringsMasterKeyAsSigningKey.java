package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;

public class RFC4880TestKeyringsMasterKeyAsSigningKey {
/*
    <code><pre>
sec  rsa2048/0x1B3932E832F13D50
     created: 2018-03-27  expires: never       usage: SC
     trust: ultimate      validity: ultimate
ssb* rsa2048/0x8FC7643A745538BF
     created: 2018-03-27  expires: never       usage: E
[ultimate] (1). rfc4882 Test User #2 <rfc4880.user2@example.org>
   </pre></code>
 */


  public final static String UID_EMAIL = "rfc4880.user2@example.org";

  public final static long MASTER_KEY_ID = Long.parseUnsignedLong("1B3932E832F13D50", 16);
  public final static long ENCRYPTION_KEY = Long.parseUnsignedLong("8FC7643A745538BF", 16);
  private final static String PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
      + "\n"
      + "mQENBFq6T6UBCAC+aM4EGg+f9JZTQT3L/xKmRPML2JBHiVhIDCe41DAwDb7LKFQh\n"
      + "SpgHDWJ3ReYXgfflz+i3NQY2vzDOVIAn27GhQf3wveipEJGWGOPtB0XgaFZtDqvt\n"
      + "7DwUZRvevVg4ZJBoseZsquuKHCelRqzyziloFGmeYoM6A71bT3dMnyen2AqAm4cC\n"
      + "IsvIjnZ+GyJG9WqEmon3OinXHfJYE+3C31ZtCWu2DrhT4Gt2+R7d8A5MlBoNeHLy\n"
      + "+mMKKGJUchYs4imabHZBWxdYmlsbTR0SQor03hU0L+TJYrSqMdPjf0RfcnQlo5vs\n"
      + "dWNwhTCZfsiuCQPrQq4UB91zHXU8lk48hzpnABEBAAG0MHJmYzQ4ODIgVGVzdCBV\n"
      + "c2VyICMyIDxyZmM0ODgwLnVzZXIyQGV4YW1wbGUub3JnPokBSwQTAQoANQIbAwgL\n"
      + "CQgHDQwLCgUVCgkICwIeAQIXgBYhBPTjIVvtdv7jfawIHRs5Mugy8T1QBQJaulAR\n"
      + "AAoJEBs5Mugy8T1QsNEIAJW8QUy+4mGmf8ktdpwlEJjZuaXdNIE/+btoBAI9SXCK\n"
      + "72+Pybx3FqfcLLhR+EnobRO5YeaknsDwrqxg8czVAJfBY9phEATIrj5JQgc90xxJ\n"
      + "AytjwmPDyk8PRgKoffXzFIvhmnzM1RS1Sv9i5ouctjIdJ3kjPQ8g3JjK7IURJ3hs\n"
      + "BrR18OvW/WHWXuK3Ao5BpVIbOjo02KL+vNGMANo0teVDQ3zO7jgsLsoa/BMbP0Ki\n"
      + "wWR8uhQa5bBWO/PzDW3wxn8MivlE3xulBPqcidYJCjkLbqr+kkBYz8ZI+53eeL/t\n"
      + "F+ZFyTVNM50XcM+bxPgSw35QhS741vLKWHoEYqwLsFW5AQ0EWrpPpQEIANFLDwZW\n"
      + "J0OYtaM7WGJ2NPOlMfYTJcOGUYeA+myz1UJ61rURsGU7GEgFYK9dbrNciCqbcQpP\n"
      + "n4TSmcZvAm29q+o9njmI76iIR/fEK+jap0zSfychhyVIkGszINDNvarSXKqTZUd0\n"
      + "csEmVvKctpRGE+mu8x62Bh4hE7gyaBA+UJ4T0Vzh6t64/RIxmXQrzWHnO7prM7vh\n"
      + "L8CwKW/RX8mtZiQluCGuTJ8tlWuLat9YQPP60FY3fof4mHgSY1jai41Q4c5URc2I\n"
      + "cC3mnPEFQVPrKTDHOfyHOodATRXRD89FB5zL/pCkBCANqJWmf3nZLbn8mA0RN0M1\n"
      + "6k7tseovcmhCuT8AEQEAAYkBNgQYAQoAIAIbDBYhBPTjIVvtdv7jfawIHRs5Mugy\n"
      + "8T1QBQJaulBBAAoJEBs5Mugy8T1QBtMH/RepaO/nfjvGua1MDBv9mj0Pm2NWcw77\n"
      + "ZE+bxzsa+68EwPz2JLuDsz8JK8spmbg/ay7fnMv6mzmThw08ddQL+AA1nzsiTWQI\n"
      + "D+/5FRu38tBe1zTAiPN+BNoOs5K3DSPys4A5Damqj4TUqpGtufV/K+1dbPxhnbXi\n"
      + "dqFygP/Q3mgfWrjfdEFaG9qIa87dGOwx0aERzM+hEK/SWudkbpUDf8mJEN3S5g9L\n"
      + "riiso0a8SfkedZWwKVCNcWl7xjkpDnK591G7R656u1LwkiYCPem83c4+Mujg5lVK\n"
      + "du9hGenFMVxuAkmbgDB7yJPt5Al4//ZZMG4bC4Qj0sGkJewL0t2mqTc=\n"
      + "=8DJV\n"
      + "-----END PGP PUBLIC KEY BLOCK-----";
  private final static String PRIVATE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
      + "\n"
      + "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\n"
      + "=HWaa\n"
      + "-----END PGP PRIVATE KEY BLOCK-----";

  public static KeyringConfig publicKeyOnlyKeyringConfig() throws IOException, PGPException {
    final InMemoryKeyring keyring = newKeyring();
    keyring.addPublicKey(PUBLIC_KEY.getBytes(StandardCharsets.US_ASCII));
    return keyring;
  }

  public static KeyringConfig publicAndPrivateKeyKeyringConfig() throws IOException, PGPException {
    final InMemoryKeyring keyring = newKeyring();
    keyring.addPublicKey(PUBLIC_KEY.getBytes(StandardCharsets.US_ASCII));
    keyring.addSecretKey(PRIVATE_KEY.getBytes(StandardCharsets.US_ASCII));
    return keyring;
  }

  private static InMemoryKeyring newKeyring() throws IOException, PGPException {
    return KeyringConfigs
        .forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
  }
}
