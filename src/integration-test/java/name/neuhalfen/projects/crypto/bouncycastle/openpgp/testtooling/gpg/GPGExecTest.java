package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg;

import java.io.IOException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.VersionCommand.VersionCommandResult;
import org.junit.Assert;
import org.junit.Test;

public class GPGExecTest {

  @Test
  public void assert_gpgVersion_2() throws IOException, InterruptedException {
    final GPGExec gpg = GPGExec.newInstance();
    final VersionCommandResult version = gpg.runCommand(Commands.version());

    System.out.println(version.toString());
    Assert.assertTrue("We have version 2.0 at least (is " + version.toString() + ")"
        , version.isAtLeast(2, 0));
  }
}
