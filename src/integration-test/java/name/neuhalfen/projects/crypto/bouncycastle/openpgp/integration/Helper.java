package name.neuhalfen.projects.crypto.bouncycastle.openpgp.integration;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Commands.listPackets;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.GPGExec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.ListPacketCommand;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Result;

public final class Helper {

  private Helper() {
  }

  public static void logPackets(GPGExec gpg, String tag, byte[] data) {
    try {
      // logging happens as a side effect in gpg.runCommand
      // also "log-packets" hangs when parsing keys in gpg 2.0
      final Result<ListPacketCommand> result = gpg
          .runCommand(listPackets(tag, data));
    } catch (Exception e) {
      // ignore
    }
  }


}
