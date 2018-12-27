package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list;

import java.util.Queue;
import java.util.StringJoiner;

final class Uid extends KeyLine {

  private final String uid;


  Uid(final String uid) {
    this.uid = uid;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", Uid.class.getSimpleName() + "[", "]")
        .add("uid='" + uid + "'")
        .toString();
  }

  static KeyLine parseUid(final Queue<String> remainingLines) {
    final String uidLine = remainingLines.poll();
    final String[] attributes = uidLine.split("[:]");

    // uid:u::::1522242268::D13D448C218DCE9D1C0F8C94CC997FAD98752540::Jens Neuhalfen <jens.neuhalfen@posteo.de>::::::::::0:
    final int UID_NAME = 9;

    final String uid = attributes[UID_NAME];

    return new Uid(uid);
  }
}
