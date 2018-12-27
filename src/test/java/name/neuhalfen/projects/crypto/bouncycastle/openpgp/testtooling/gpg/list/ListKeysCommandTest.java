package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.Map;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Commands;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.GPGExec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list.ListKeysCommand.ListKeysCommandResult;
import org.hamcrest.Matchers;
import org.junit.Test;

public class ListKeysCommandTest {

  @Test
  public void listKeys_doesNotThrow() throws IOException, InterruptedException {
    final GPGExec gpg = new GPGExec();
    final ListKeysCommandResult keys = gpg.runCommand(Commands.listKeys());

    assertThat(keys.exitCode(), Matchers.equalTo(0));
    for (KeyLine s : keys.getKeyList()) {
      System.out.println("key :" + s);
    }
  }

  @Test
  public void emptyKeyRing_listKeys_noPubKeys() throws IOException, InterruptedException {
    final GPGExec gpg = new GPGExec();
    final ListKeysCommandResult keys = gpg.runCommand(Commands.listKeys());

    final Map<Long, PubKey> pubKeyMap = ListKeysParser.toMasterKeys(keys.getKeyList());

    assertThat(pubKeyMap.isEmpty(), is(true));
  }

  @Test
  public void emptyKeyRing_listKeys_noSecretKeys() throws IOException, InterruptedException {
    final GPGExec gpg = new GPGExec();
    final ListKeysCommandResult keys = gpg.runCommand(Commands.listSecretKeys());

    final Map<Long, PubKey> pubKeyMap = ListKeysParser.toMasterKeys(keys.getKeyList());

    assertThat(pubKeyMap.isEmpty(), is(true));
  }
}
