package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysCommand.masterKeys;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysCommand.subKeys;
import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.util.Map;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.DecryptCommand.DecryptCommandResult;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.ImportCommand.ImportCommandResult;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.PubKey;
import org.hamcrest.Matchers;
import org.junit.Test;

public class DecryptCommandTest {

  final static byte[] SECRET_KEY = ExampleMessages.SECRET_KEY_RECIPIENT.getBytes();
  final static byte[] PUBLIC_KEY = ExampleMessages.PUBKEY_RECIPIENT.getBytes();
  final static String PASSPHRASE = "recipient";
  final static byte[] CIPHERTEXT = ExampleMessages.IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes();
  final static byte[] PLAINTEXT = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes();

  // import the secret key
  void prepareSecretKeys(final GPGExec gpg) throws IOException, InterruptedException {

    final Map<Long, PubKey> masterKeysPre = masterKeys(gpg);

    assumeTrue(masterKeysPre.isEmpty());


    final ImportCommandResult importPublicKeyResult = gpg
        .runCommand(Commands.importKey(PUBLIC_KEY));

    final ImportCommandResult importSecretKeyResult = gpg
        .runCommand(Commands.importKey(SECRET_KEY, PASSPHRASE));

    assertThat(importSecretKeyResult.exitCode(), Matchers.equalTo(0));

    final Map<Long, PubKey> subKeyPost = subKeys(gpg);
    assertThat(subKeyPost.keySet(), contains(ExampleMessages.PUBKEY_ID_RECIPIENT));
  }

  @Test
  public void decrpypt() throws IOException, InterruptedException {
    final GPGExec gpg = new GPGExec();
    prepareSecretKeys(gpg);

    final DecryptCommandResult result = gpg.runCommand(Commands.decrypt(CIPHERTEXT, PASSPHRASE));
    System.out.println(result.toString());

    assertEquals("Clean exit code expected",0, result.exitCode());
    final byte[] plaintext = result.getPlaintext();
    assertArrayEquals("The correct plaintext shound be decrypted", PLAINTEXT,plaintext);
  }


}
