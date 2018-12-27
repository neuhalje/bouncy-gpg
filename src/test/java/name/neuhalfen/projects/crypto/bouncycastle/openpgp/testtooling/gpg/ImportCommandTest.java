package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysCommand.masterKeys;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysCommand.secretKeys;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysCommand.subKeys;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.util.Map;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.ImportCommand.ImportCommandResult;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.PubKey;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.SecretKey;
import org.hamcrest.Matchers;
import org.junit.Test;

// TODO: all example keys
public class ImportCommandTest {

  private final static String SECRET_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
      + "\n"
      + "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\n"
      + "=Pxif\n"
      + "-----END PGP PRIVATE KEY BLOCK-----";
  private final static String PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
      + "\n"
      + "mQENBFwksmQBCAC1/4cWBsAItDEFlSk9+bwZPonEfl7kOwuQir2YLcjTZjnJn8V1\n"
      + "N4/3H9/TErkZnxKE3P5SWY4kDzPx78eLnsEFL4qv1FC1hDZDEjqvquGY6yhvEv9e\n"
      + "UlkJHHYM8lHmGYK/AKQr+O7GZQ8Pmxkd3ANr1/ce858nmajHpP/1bUQh3VblroFw\n"
      + "Mfh0f2/7zdeevtVPpwtTKDtoPAVCQ866j/s4Nk7D108e4KDob8X6uuZ2DYhwH6fu\n"
      + "CdrxHX+/mXSJiuIg3LyaNXk3wmhWKARJtlNTMZ9m6CattVpXeuIC4AjIvpebioxm\n"
      + "tV12YBAuyeucMscCpphTBUcFDTCr0wv9tLSLABEBAAG0G1Rlc3QgS2V5IDx0ZXN0\n"
      + "QGV4YW1wbGUuY29tPokBVAQTAQgAPhYhBNgpE39pr1N0DYe2FjRPmEBFtvMyBQJc\n"
      + "JLJkAhsDBQkDwmcABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEDRPmEBFtvMy\n"
      + "17oH/2wyGI/fdn8Ilqqa5T1lWIcWfAgLoaOKopdKzLErCt4saTKDMDreUue/OiXg\n"
      + "s4HsmYSxpGGqlIVIc6QJMEk03NCrH0BUJxO0sV1/9oBlv0MAhK1nIYMLE9JZ25pZ\n"
      + "Fbo4ZqNz5xsybovqTFdnkucApJADOAWSKXTdir8sy0FkO/y3sdjCOPlDPyEFvPO1\n"
      + "iyG9YoEFW69IFY74armDuDzjTT51jn9IQZJsRVePm2Wu3+NCn+GMa0YNc4r0AKf9\n"
      + "oLQYOmEd3sIh9hPfpRG1gobm5CmxjCuODYKchMhfv1sNelw3NZWZAklPz4pac8Zk\n"
      + "9k4LcuwJ6vNJjRfpkMOisG4jl+K5AQ0EXCSyZAEIANqG3JRp9J0h/r6qRE9vSH6Y\n"
      + "xRhOihfSXaC9QCfZ9WPbjsC0Qgdb0zmSiw3G+kSalDThi9xLEYV8sR1BbA/X7ikT\n"
      + "sA/V9+mlKzlpUaFHTztkchpzZfsxiDmbUt1ymAiFcMd1uuEjZ/qOzw/eHvVHK3Ow\n"
      + "/Cljb9JsUrKX2S2ElT+DYj8VSK2C67SdwSI2HUqnVxIBy9GGfWkR1w8wmR5KhWsq\n"
      + "+8RNJKrUMiVDc28wbJHKtSn2ysMeSWDd2UgfC8VXdLkHXhBU1TN7C2zDxXonXGQH\n"
      + "5wnhQiGVhUPQlcKKfJ5LvJ1BwWhT9LvSjIrWOfb6cjd+iVWUnEP+cRuploYM6v0A\n"
      + "EQEAAYkBPAQYAQgAJhYhBNgpE39pr1N0DYe2FjRPmEBFtvMyBQJcJLJkAhsMBQkD\n"
      + "wmcAAAoJEDRPmEBFtvMy99IH+wbU6zhjoomjus8B3rlQ5AvKbjCd0LeLgypmAv9b\n"
      + "lz9f/Z+J+A/tounPNpfKQcX4NPls74FRyR6Hq7nfmsKZlzr8K8T/KvPr/7GKhInv\n"
      + "UEDmHHCqLQ+1A9UiYoF12fdcLgaxwiFTO0aCKlYgWy8+SGtCQmMRBJ/akwtRh6l2\n"
      + "ZfUkJ+zNzcDhWGXPW0d2xzmGcJFtDBHCnzo/rLCjWqd2iDDw+E9UO0AqVwqaEdwb\n"
      + "ufMKW+Q8xeXbrclz1WzTO87EG2SUhLfhSlMrIwU4l/yd/SK79FTcMXY30jXaSQsI\n"
      + "VIsGNYayJ2uQgFFnXjWWtamIlrQkgdZaM7YuYrtei9B/VoY=\n"
      + "=M/go\n"
      + "-----END PGP PUBLIC KEY BLOCK-----";

  private final static String PASSPHRASE="test";

  private final static long MASTER_PUBLIC_KEY_ID = 0x344F984045B6F332l;
  private final static long SUBKEY_PUBLIC_KEY_ID = 0x7D6A5F380F99AA9Fl;


  @Test
  public void addKeys_doesNotThrow() throws IOException, InterruptedException {
    final GPGExec gpg = new GPGExec();
    final ImportCommandResult result = gpg
        .runCommand(Commands.importKey(SECRET_KEY.getBytes(), PASSPHRASE));

    assertThat("Should be a clean exit code", result.exitCode(), Matchers.equalTo(0));
    System.out.println(result.toString());
  }

  @Test
  public void addKeys_addsSecretKey() throws IOException, InterruptedException {
    final GPGExec gpg = new GPGExec();

    final Map<Long, PubKey> masterKeysPre = masterKeys(gpg);

    assumeTrue(masterKeysPre.isEmpty());

    final ImportCommandResult importCommandResult = gpg
        .runCommand(Commands.importKey(SECRET_KEY.getBytes(), PASSPHRASE));

    System.out.println(importCommandResult.toString());
    assertThat(importCommandResult.exitCode(), Matchers.equalTo(0));

    final Map<Long, PubKey> masterKeysPost = masterKeys(gpg);
    assertThat(masterKeysPost.isEmpty(), is(false));

    // with public keys
    final Map<Long, PubKey> subKeyPost = subKeys(gpg);

    assertThat(subKeyPost.keySet(), contains(SUBKEY_PUBLIC_KEY_ID));

    // with secret keys
    final Map<Long, SecretKey> secretKeys = secretKeys(gpg);
    assertThat(secretKeys.keySet(), contains(MASTER_PUBLIC_KEY_ID));
  }


  @Test
  public void addKeys_addsPublicKey() throws IOException, InterruptedException {
    final GPGExec gpg = new GPGExec();

    final Map<Long, PubKey> masterKeysPre = masterKeys(gpg);

    assumeTrue(masterKeysPre.isEmpty());

    final ImportCommandResult importCommandResult = gpg
        .runCommand(Commands.importKey(ExampleMessages.PUBKEY_SENDER.getBytes()));

    System.out.println(importCommandResult.toString());
    assertThat(importCommandResult.exitCode(), Matchers.equalTo(0));

    final Map<Long, PubKey> masterKeysPost = masterKeys(gpg);
    assertThat(masterKeysPost.isEmpty(), is(false));

    final Map<Long, PubKey> subKeyPost = subKeys(gpg);

    assertThat(subKeyPost.keySet(), contains(ExampleMessages.KEY_ID_SENDER));

    // no secret keys
    assertTrue(secretKeys(gpg).isEmpty());
  }

}
