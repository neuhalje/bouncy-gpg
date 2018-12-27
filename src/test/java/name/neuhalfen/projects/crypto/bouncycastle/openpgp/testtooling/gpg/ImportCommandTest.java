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

  @Test
  public void addKeys_doesNotThrow() throws IOException, InterruptedException {
    final GPGExec gpg = new GPGExec();
    final ImportCommandResult result = gpg
        .runCommand(Commands.importKey(ExampleMessages.SECRET_KEY_SENDER.getBytes(), "sender"));

    assertThat("Should be a clean exit code", result.exitCode(), Matchers.equalTo(0));
    System.out.println(result.toString());
  }

  @Test
  public void addKeys_addsSecretKey() throws IOException, InterruptedException {
    final GPGExec gpg = new GPGExec();

    final Map<Long, PubKey> masterKeysPre = masterKeys(gpg);

    assumeTrue(masterKeysPre.isEmpty());

    final ImportCommandResult importCommandResult = gpg
        .runCommand(Commands.importKey(ExampleMessages.SECRET_KEY_SENDER.getBytes(), "sender"));

    System.out.println(importCommandResult.toString());
    assertThat(importCommandResult.exitCode(), Matchers.equalTo(0));

    final Map<Long, PubKey> masterKeysPost = masterKeys(gpg);
    assertThat(masterKeysPost.isEmpty(), is(false));

    // with public keys
    final Map<Long, PubKey> subKeyPost = subKeys(gpg);

    assertThat(subKeyPost.keySet(), contains(ExampleMessages.KEY_ID_SENDER));

    // with secret keys
    final Map<Long, SecretKey> secretKeys = secretKeys(gpg);
    assertThat(secretKeys.keySet(), contains(ExampleMessages.SECRET_KEY_ID_SENDER));
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
