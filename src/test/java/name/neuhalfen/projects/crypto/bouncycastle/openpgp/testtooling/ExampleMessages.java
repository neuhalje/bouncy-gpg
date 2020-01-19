package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;


import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ExampleMessages {

  /**
   * 2048 bit RSA key 'recipient@example.com' - Trusted by recipient. - Private key held by
   * recipient.
   */
  public final static String USER_ID_RECIPIENT = "recipient@example.com";

  public final static long PUBKEY_ID_RECIPIENT = 0x54A3DB374F787AB7L;
  public final static long SECRETKEY_ID_RECIPIENT = 0x3DF16BD7C3F280F3L;
  public final static String PUBKEY_RECIPIENT =
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "mQENBFYHvroBCADQnNvPOqBQ0Gb0oNEbwvIrMPhhGdl/uzNZxBSd12YfwnigXrR0\n" +
          "FcB6+m/NZhzTaN2c2mCvXCBBAJT/HBTHX2H3mmy8w80dpd2e8Z/thx68oBdZBH/J\n" +
          "8nStwyyTsl0l2HdyT52hxH7FH7Vx8qKWbTyza1UV8sSInhZa/CEn049phcZHsGhm\n" +
          "1n+cewekN+DGpBc/QT04WPGC7HSTHeTXHf16KB1skNgJ1h9FpoShzHBZd6impJ6H\n" +
          "XphdVB+KRMdE49xol9TcOPen0urx+3HlkvC9FB3th6seRH10BLiXArP/3p65P6qp\n" +
          "Fi3CEWCruiJsJPcBYyUj5XtmT+qvjOXyy0S3ABEBAAG0O1JlemkgUmVjaXBpZW50\n" +
          "IChQYXN3b3JkOiByZWNpcGllbnQpIDxyZWNpcGllbnRAZXhhbXBsZS5jb20+iQE4\n" +
          "BBMBAgAiBQJWB766AhsvBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRA98WvX\n" +
          "w/KA8/CDB/9xxQgLQ2wqqh8RFruBt0Pl7FE9VOaM5Kzkc2iJK/jzU9iAwQpxvj6d\n" +
          "pEja3azHovjWcL+go6gIaTdI4rRuHgwqNdEOQcp5OPej0jDuGY0PI3M+E7Heuqd9\n" +
          "jH8sIgJHzcMl+/ut38Zd9DCb0V4LHfxIBXJIAqIfh7IS7IaX0LPzZz0BB732etvj\n" +
          "+8Yr2KR/+598oRA6SzCGNGiWiM5buZDevkib1TZELm6AKHfQ7Il4rXUP86CVmBIk\n" +
          "VV2YjnjZGY1RX5DygqpTk5yMyZSj8Dv+def+A7Bw08jeok40fDPPnX/oxGgedW5X\n" +
          "i/DNbh1O9StWB9iaf13r62+WKFWjUsCguQENBFYHvroBCADh4uhrTpn6li5j9tM/\n" +
          "meTtRhzvwRHDqiSDhju7oA61LwyQyQZeqt5YPtxynko+9secJ4odsA2wFzST5EJK\n" +
          "nUhKvmNwhkotA1SuuVH867FESN5aZybQh4RTx3f312suzxSqZThBrY+1YQx0B8JH\n" +
          "spzM4NCg3mZdZgkkoh9TpW85JgZ7/ZRIrBEwRRccEwqu0TgiwQIPR+VsbJ7d/PNS\n" +
          "Eyb2cJ5CC3LPxY1dOZ9Xcr6g4qU+2/QrxHgNXSQnP4SDFnrS+cMqd9UgolnzUBlg\n" +
          "2F1Xd3+c2f3VMZO6l40e7fnazV9AXDPBfIbfhxa675H+l9pKI49ux087b3CUWLav\n" +
          "dlctABEBAAGJAj4EGAECAAkFAlYHvroCGy4BKQkQPfFr18PygPPAXSAEGQECAAYF\n" +
          "AlYHvroACgkQVKPbN094ereQbwgAwG5O9FWcSB5cpuJH9Bvv+w3JzjcjiCnW7kCU\n" +
          "ArVRRemT+GwXwKzpaU+xOOTjZytQlUHB4g7Dl9Tyfrv5OGK0s2JkTcCV9z5tbiEa\n" +
          "5xDvoQgx2IXLNR2Pz2J+CTiGGi7nXe3H8axshmczh0+sTiJ2FfKzdYwMloVezqNl\n" +
          "k/Pm3UXnlSjf/D06x5KWwivy7ULtw5zFZk8MyMP4+CID3N45azhU2kYyA0SClHU6\n" +
          "NolZc7T3v+y5yIDN0uFmKZcZO9vtz3AOKDor/12bOXIeqPax12fCoPRTIItdLues\n" +
          "qfbrGLlde88gFWsNHffv+vePe8VYUWwip4mYMiwTTRrZ2T43B7hzB/9/+f6nkiQ+\n" +
          "8T3SLDXaD/BpOGyj3uXirwLBn41xYo3kqx0UEaryFsCLUBBom93CY0WN9Tw56lzX\n" +
          "gWr+Opb9wqALB2jjBJV6nC5d6hs+x4Qgc5u0Rvm4HQ65rrltT7/9mRGi2vMbQTqN\n" +
          "uevfOAWv901VTOpx7mCLJZ5rsKpAFxeRlBkMHhzEu8GPqJca6kyVOSXUhf/qPJiT\n" +
          "s46yW5Hu2amGPWc9qqo6QEF19BXkZmNUZQx5f9hUWC2CcqdQ94SmtDvO4sfc5nzk\n" +
          "ALVh90zK9h+tPNDwVodYQ7oB9Y9HHj5ZXje9AzMuGD0R2ZraOcUe1EC9yIbqO3lA\n" +
          "57ubFTCKp1cP\n" +
          "=WsAP\n" +
          "-----END PGP PUBLIC KEY BLOCK-----";

  public final static String SECRET_KEY_RECIPIENT =
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
          + "\n"
          + "lQPFBFYHvroBCADQnNvPOqBQ0Gb0oNEbwvIrMPhhGdl/uzNZxBSd12YfwnigXrR0\n"
          + "FcB6+m/NZhzTaN2c2mCvXCBBAJT/HBTHX2H3mmy8w80dpd2e8Z/thx68oBdZBH/J\n"
          + "8nStwyyTsl0l2HdyT52hxH7FH7Vx8qKWbTyza1UV8sSInhZa/CEn049phcZHsGhm\n"
          + "1n+cewekN+DGpBc/QT04WPGC7HSTHeTXHf16KB1skNgJ1h9FpoShzHBZd6impJ6H\n"
          + "XphdVB+KRMdE49xol9TcOPen0urx+3HlkvC9FB3th6seRH10BLiXArP/3p65P6qp\n"
          + "Fi3CEWCruiJsJPcBYyUj5XtmT+qvjOXyy0S3ABEBAAH+BwMCrtLtgZeIeZbmjhq5\n"
          + "LegEYhHOjDonyXvBUrdDsmlMMdqLbqRCsGZ2pcjzvmhAck3njW8lDkCneDAoHZCg\n"
          + "op/VCgRoaILpJpGrYk8Mdva1x+xnDfHoC58EN49a45XF7zOjvHj4uChwTyBkkxDL\n"
          + "21NkeZXN+UFLd+SyREbmEjyWhz/20z3RckNR1kQaLgKMnB8XRoz1e+UAt2kuJAGK\n"
          + "A8YoFPfBA+nKDId73F19pLXMCIMiplofXJrp9fuCVF/7thWnpJRhT9rvf27MeEO2\n"
          + "/n6MFG44TE6OSphBlF6wMW8iKNtyLdZ09Tcon0j0dI3xP8Kdm7o0sinP0Bu1UL4W\n"
          + "RDh5VeGspnVrT7zCFikSNFtxWxc/OOEHJym/cw4JqlhsjQU/+HBC8HyMhmWB0ZN4\n"
          + "xzFx0p8ymtNXRtvEsYxvvFsEQu2ZFxV4nkpm9BxGxqGPhAaI7PhctHTSSoopavzs\n"
          + "GZdiXvW5yYPP3hD6nd3YAFPAD0SeTbbdiSpzp/OxKBa69yvjVjAh6CVX9idPR48K\n"
          + "5hMU7YqNs5sM1UTG/L+412R56WREp9BZEQnSrcG251EF/UI5+MZFbSe0xhO2Ey++\n"
          + "9G81n17ZYL8MW7BqSXDAKVSUB73FKrt7GXTQCM3SvfkyPXJzlRz+ZJFYjexlj5i3\n"
          + "I1bcyWBMeR6mTJrwv02AhUtOFyk/NU9Bm7GUPJgt205J7kNGrZPJ6D4sldUYov+2\n"
          + "F1Sbd1aNKOodjlJe2oAgAcnmRbyqI7JKi85IPg+L+2QsyK72tMXuCV9WMHnnI9kP\n"
          + "pNnPQofL49+y0W8xEhj3phN+/A7+05Auvlil99/kmamz38NST+FCcZ53YOfoaqEJ\n"
          + "fb371XNuOkGZl25WfxqnjcnJ3gkHVtCXafC2Ac4MnIqEqD1RQvoLZZxnkuA43UBs\n"
          + "cUxQfNe2B2y0O1JlemkgUmVjaXBpZW50IChQYXN3b3JkOiByZWNpcGllbnQpIDxy\n"
          + "ZWNpcGllbnRAZXhhbXBsZS5jb20+iQE4BBMBAgAiBQJWB766AhsvBgsJCAcDAgYV\n"
          + "CAIJCgsEFgIDAQIeAQIXgAAKCRA98WvXw/KA8/CDB/9xxQgLQ2wqqh8RFruBt0Pl\n"
          + "7FE9VOaM5Kzkc2iJK/jzU9iAwQpxvj6dpEja3azHovjWcL+go6gIaTdI4rRuHgwq\n"
          + "NdEOQcp5OPej0jDuGY0PI3M+E7Heuqd9jH8sIgJHzcMl+/ut38Zd9DCb0V4LHfxI\n"
          + "BXJIAqIfh7IS7IaX0LPzZz0BB732etvj+8Yr2KR/+598oRA6SzCGNGiWiM5buZDe\n"
          + "vkib1TZELm6AKHfQ7Il4rXUP86CVmBIkVV2YjnjZGY1RX5DygqpTk5yMyZSj8Dv+\n"
          + "def+A7Bw08jeok40fDPPnX/oxGgedW5Xi/DNbh1O9StWB9iaf13r62+WKFWjUsCg\n"
          + "nQPGBFYHvroBCADh4uhrTpn6li5j9tM/meTtRhzvwRHDqiSDhju7oA61LwyQyQZe\n"
          + "qt5YPtxynko+9secJ4odsA2wFzST5EJKnUhKvmNwhkotA1SuuVH867FESN5aZybQ\n"
          + "h4RTx3f312suzxSqZThBrY+1YQx0B8JHspzM4NCg3mZdZgkkoh9TpW85JgZ7/ZRI\n"
          + "rBEwRRccEwqu0TgiwQIPR+VsbJ7d/PNSEyb2cJ5CC3LPxY1dOZ9Xcr6g4qU+2/Qr\n"
          + "xHgNXSQnP4SDFnrS+cMqd9UgolnzUBlg2F1Xd3+c2f3VMZO6l40e7fnazV9AXDPB\n"
          + "fIbfhxa675H+l9pKI49ux087b3CUWLavdlctABEBAAH+BwMC0cJUSssvr2zmOOLM\n"
          + "MPhJzDATiY+xQ8fcGyTR/fmx4iUJwArU7CXItjVFodNbozWrZyW2+dZx+3demWLK\n"
          + "Y+kq/qUVrRceohkaDphV3htkLUjmDk52LmGy8wK5JTGeoF4NgMz+PVwDtv0GuFFq\n"
          + "X5kj8TQRNMm4ShrPJLAnExgr7MWDhvqHpAm7aMTVcZxnxMEr0FPWWSWDl/3M9f39\n"
          + "pTJbvD8HH2EYr+xeE+33c0XI+DCmyrQ8cxp9tfmq6NtKQMSeTPqrKeonIyEkdsAG\n"
          + "/Zj4sARrgoDzeU78738B/v0SEuthK38aZN/1M8ZOrsBNJ009IBDAJ3oXt+UBF9e0\n"
          + "Tbyn0VpgH94Vg6C57aChcdhlTBwPU7R0t1P1iZg/JoSLUe+7vuAPBr2iTcSJoGon\n"
          + "Z8iTOCKsess937KpldwopxLzeMqQwNRgW3dbG8uf97AlfC+5XvJ90SuLc4dlXaMV\n"
          + "+w7y7Sx2eOAA6yLL7PUGEu0YWhpHdvAoT6IVPIEkfJ5i2nWo+tZCAx3IL1t7z0WA\n"
          + "7K+eKfUvIBTbsb2Dm9uvC3ENb3y8myvd5lZ6W5WlY6wds8ppcmHPlTJXWbxJY+pk\n"
          + "JZqQDxjEHOqDGxMRBVgM+iwKIhH72fRrYox7RQ1k4I5dyxyiRx1LTKKUbc60Ktfj\n"
          + "cuj/b/MUDLDBjWmq93bRmKPVAP0EY5K5VYpZ0nrbbJklE5M7HsCCDHYXXlM6VnKn\n"
          + "oHwLauNcV4mm6h9SsgFqJP/zXtOJtfGbODA5N34jgRxCZGxN9gcAZKdeLzt6tt6u\n"
          + "04XH39HNM9TPzZPloYSUaGcAUAtPOo+xFb3+7BJ4oEAXRQwr5eebU+I2/CWP3jQi\n"
          + "Cq41VKaVqc1X+HkaCpDQRaFhujgBD2UOCUVCeIseM6tbVDcIgA5SZLCHI6DnjTYB\n"
          + "oGuF5EJBVV3KiQI+BBgBAgAJBQJWB766AhsuASkJED3xa9fD8oDzwF0gBBkBAgAG\n"
          + "BQJWB766AAoJEFSj2zdPeHq3kG8IAMBuTvRVnEgeXKbiR/Qb7/sNyc43I4gp1u5A\n"
          + "lAK1UUXpk/hsF8Cs6WlPsTjk42crUJVBweIOw5fU8n67+ThitLNiZE3Alfc+bW4h\n"
          + "GucQ76EIMdiFyzUdj89ifgk4hhou513tx/GsbIZnM4dPrE4idhXys3WMDJaFXs6j\n"
          + "ZZPz5t1F55Uo3/w9OseSlsIr8u1C7cOcxWZPDMjD+PgiA9zeOWs4VNpGMgNEgpR1\n"
          + "OjaJWXO097/suciAzdLhZimXGTvb7c9wDig6K/9dmzlyHqj2sddnwqD0UyCLXS7n\n"
          + "rKn26xi5XXvPIBVrDR337/r3j3vFWFFsIqeJmDIsE00a2dk+Nwe4cwf/f/n+p5Ik\n"
          + "PvE90iw12g/waThso97l4q8CwZ+NcWKN5KsdFBGq8hbAi1AQaJvdwmNFjfU8Oepc\n"
          + "14Fq/jqW/cKgCwdo4wSVepwuXeobPseEIHObtEb5uB0Oua65bU+//ZkRotrzG0E6\n"
          + "jbnr3zgFr/dNVUzqce5giyWea7CqQBcXkZQZDB4cxLvBj6iXGupMlTkl1IX/6jyY\n"
          + "k7OOsluR7tmphj1nPaqqOkBBdfQV5GZjVGUMeX/YVFgtgnKnUPeEprQ7zuLH3OZ8\n"
          + "5AC1YfdMyvYfrTzQ8FaHWEO6AfWPRx4+WV43vQMzLhg9Edma2jnFHtRAvciG6jt5\n"
          + "QOe7mxUwiqdXDw==\n"
          + "=Zc9A\n"
          + "-----END PGP PRIVATE KEY BLOCK-----";


  /**
   * 2048 bit RSA key 'sender@example.com' - Trusted by recipient. - Private key held by sender.
   */
  public final static long KEY_ID_SENDER = 0x86DAC13816FE6FE2L;
  public final static long SECRET_KEY_ID_SENDER = 0xAFF0658D23FB56E6l;

  public final static String USER_ID_SENDER = "sender@example.com";
  public final static String FULL_USER_ID_SENDER = "Sven Sender (Pasword: sender) <sender@example.com>";
  public final static String PUBKEY_SENDER =
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "mQENBFYHvrkBCADIwiZO8znNer+ZPOG0BntuWQoQHuuXd8Dm4fkzPRm3sEYk/3Rb\n" +
          "vdaPBUCMQY0tjcxKFMl2JNh+cA3zrG9H3gqknOEYLzxfiHt+Kpmb45h4apdvcUM5\n" +
          "8GiQxaCwzkdEGSemWAhqY/ZSDWqwG3K/gB6zJ3gIKxU1j8htDzWdaF27uHUXBPUE\n" +
          "6WrAd0nL3KauxCbQAQItdmMaMRKNoNGGQuXQaxkBR+dW7BDxEx5dAovrWjN7FAur\n" +
          "rbJCTPSgjdIrnRH+iZyaGIlHqYE4NX7axfOEMTfm7wWcH7BkykO0y3bgthyL5cJs\n" +
          "CLvhtUBLb3hNJY82b2uUpU0niJ8vAndldx1TABEBAAG0MlN2ZW4gU2VuZGVyIChQ\n" +
          "YXN3b3JkOiBzZW5kZXIpIDxzZW5kZXJAZXhhbXBsZS5jb20+iQE4BBMBAgAiBQJW\n" +
          "B765AhsvBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRCv8GWNI/tW5tVNB/9g\n" +
          "KDrMULRM3HozzK5yTFvacGFi5aB1UvLVe+RpKnF57CgOM2C1x3QBZMn25/wQ93nt\n" +
          "NAXLBTGRf9qy7zlb0VDMPL2LXqBBvFaNEhxQn6VPETzGY52C3YEl7q0gMRxbNakg\n" +
          "kQVmS0K0FcOiq6vDbQxEMDVJs5lkWKfQItM4sFmyW2pRG/ytO2pOLFPH7YG7yDEN\n" +
          "bmJ6oDR2PxWwG11wGdqeTLyKS8pL98+jrLZjt0yimGeg/u+ceaqaFH1bL1zmDIV/\n" +
          "FkaK0R97dvAhA52SvAmhSZYSLmVOaMazm/RXUaHEQ7n7HFVc7mRxz1LBKDZ8hSNC\n" +
          "5F6k4Q2hV81JfrfYKUfpuQENBFYHvrkBCACvqEephb36Kx60fL3M87YLxbZi8iG6\n" +
          "Hxt6lsJk27YqpPJ+QiNs8TsTqRceKJQYu/F6AmSrPMu4a6yzYtKnmMNG9dJaXqBw\n" +
          "P/6u5ZB8bgim5bQ15OcJMvRke/qkm84MrYkQiSiSNSvXgxFTSJnYVfBMXNjGZYap\n" +
          "nRGHHw10SIAMcJz3QCv9gNKsRFsTfnoaJJM4Uls8xbxL1nW2Bk0Xvno7zWPHrLoc\n" +
          "BWY3c0u/Cv9PVQ9oEYjPOjM7D6YIht5kflJJZSKuieBWIwEF10AuCTlEmmSETxIC\n" +
          "VZ/1UFmfS05xP0GCg2xKKHLCf6Yr5jhWHqGb4rKafzqlajm7W3teabuPABEBAAGJ\n" +
          "Aj4EGAECAAkFAlYHvrkCGy4BKQkQr/BljSP7VubAXSAEGQECAAYFAlYHvrkACgkQ\n" +
          "htrBOBb+b+ItHwf+Lnlvs/uWB16a3BiBsnXVqfEhp3ounhdKgfaEx3HRUiMkNqKD\n" +
          "AKunqlY9i4L7oeIsUkjt9i/zXn+pvpcw1UbUJRfnHY9c5izJxGxoWyhaj7ry4b2A\n" +
          "fHUALg/YpP49duzgoA4wiL1Soy/rhbz67nikn64ZwCaKDSTDAhngN8kDvtaEWm5E\n" +
          "XXsSnN193P8m6TQpaKpOCeeaN99nZ9US/t04AwNQAM0SyIf8p0qw4nN/VzEXpGpv\n" +
          "nVftoB6l+pATzqXbKC6sz4RjBsTQFsrLcPXZfkN9Uiu4SrhtRGl/gWb2HK6Usuqo\n" +
          "LZPN6dp8L3rGKbakdRHBYwPLLRHpdJUt0g4bGuugB/0WEfGU5gJFJUYVazN9ca05\n" +
          "k3GKSSDya/fSwPFOTY/2BCFzh72hzFY4CrOfaFjuU5T/jukYwz2UgTdzhCbIUEYV\n" +
          "JzcBaoizdD3YmGVSssKgIq8sBv3dRdZHLaX5GD9lNOk2TYuRcTa2JdWc2JsepOud\n" +
          "iLTzWypawajv8Hg5F9hhlpCca/CEvfAIH/wva4NFHSA4x9opIiJzEAsztpQrEuxc\n" +
          "Qk2momwRM3dOB4gYt/8E07tL2B3Q5usOpZs+RYJO6on22VOLQGgKcmg4Mb7pHyUM\n" +
          "QYaXLJoqLwBvpPfX8WPva8MLrMaoz/rZj8NEnhJwSQeI6Q77I7651XU3F2g2VK0M\n" +
          "=RJho\n" +
          "-----END PGP PUBLIC KEY BLOCK-----";

  public final static String SECRET_KEY_SENDER =
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "lQO+BFYHvrkBCADIwiZO8znNer+ZPOG0BntuWQoQHuuXd8Dm4fkzPRm3sEYk/3Rb\n" +
          "vdaPBUCMQY0tjcxKFMl2JNh+cA3zrG9H3gqknOEYLzxfiHt+Kpmb45h4apdvcUM5\n" +
          "8GiQxaCwzkdEGSemWAhqY/ZSDWqwG3K/gB6zJ3gIKxU1j8htDzWdaF27uHUXBPUE\n" +
          "6WrAd0nL3KauxCbQAQItdmMaMRKNoNGGQuXQaxkBR+dW7BDxEx5dAovrWjN7FAur\n" +
          "rbJCTPSgjdIrnRH+iZyaGIlHqYE4NX7axfOEMTfm7wWcH7BkykO0y3bgthyL5cJs\n" +
          "CLvhtUBLb3hNJY82b2uUpU0niJ8vAndldx1TABEBAAH+AwMCc38x5Y8MHh9gA4+Q\n" +
          "k84LxyqBDrDjr4BHF2Fty76L+jVSChJLAjs8ae45AHy4tkfRjQW4yAxUjSWP94kj\n" +
          "CwiYrCvA6/gascPc4qdVVEjsYYRO2ESYxgqCcK7I+oackiMPc8lEP5RFOucHIQCo\n" +
          "WufXlnAHemoDMSuKsq/JbHgKkUdF04wzNAN3YNHZN+7vZiIwJ2fMON6KuhhGzVOx\n" +
          "5qaeM+jxZEWxYRzbm8bZZILdNOS5qp63ayAHgQwu+VjPQDNQOAQ7oFZN/JcgVsdt\n" +
          "OQqaf5V81qkvZo7m2S6aEZzp1MmYGwIDvz2WmbjXY1F6Y26DinmDRbjAgtkBdnX0\n" +
          "2Zw9LvEg33f9h5jAT540ED2mONGHiS7883dlNxH1SQ1sfh30al1fj8tH4RwOC0mq\n" +
          "ESQGy4hk6m9dmQ7Iog563rjaGXV6FlTOJUiWm8xvhqY2ctN6R8zxxx+9oIsy+VHx\n" +
          "rjjNfML7gPu6NLLHJUUzetsTT/U6/5RaF2dprufzdMSl3HSBrDfNx+XW2xN1qUsh\n" +
          "PhplxNxgQWNQF2K9Ro86odLyAU8FBzH93tjgDkvW7HE9VThH7eWVGUHNlzptHqYp\n" +
          "Ydt75ZPlww3GvPj5oCOet6iTM+nzoV/ClAh3UjTZX6Aj2vMYJCcSJlwH6O4Jkn2J\n" +
          "7G5ZRZzA2eobdJwJSTiouoAIb9NVD+nvvvnzA8edG0x+zOMiEDjgG0DpIP/s68R4\n" +
          "fG97cEM2TZMGkX3C+TCO0BC2NR5ahpSDW4ly3ZGru1Fh8s5f74ehzBCPAwndD40H\n" +
          "nM8QhGTnJ+/3gZ3li4tvNrjIn2bjyVQoJM0LPDWiU/tFTX6kGHpviJ0mozQOFHFN\n" +
          "y0sHEhFpoz2yqursXF8zHIpjAXqBBssRrB/DzTvDCOufWj9tV1BNy4HQGKkxZMF7\n" +
          "irQyU3ZlbiBTZW5kZXIgKFBhc3dvcmQ6IHNlbmRlcikgPHNlbmRlckBleGFtcGxl\n" +
          "LmNvbT6JATgEEwECACIFAlYHvrkCGy8GCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheA\n" +
          "AAoJEK/wZY0j+1bm1U0H/2AoOsxQtEzcejPMrnJMW9pwYWLloHVS8tV75GkqcXns\n" +
          "KA4zYLXHdAFkyfbn/BD3ee00BcsFMZF/2rLvOVvRUMw8vYteoEG8Vo0SHFCfpU8R\n" +
          "PMZjnYLdgSXurSAxHFs1qSCRBWZLQrQVw6Krq8NtDEQwNUmzmWRYp9Ai0ziwWbJb\n" +
          "alEb/K07ak4sU8ftgbvIMQ1uYnqgNHY/FbAbXXAZ2p5MvIpLykv3z6OstmO3TKKY\n" +
          "Z6D+75x5qpoUfVsvXOYMhX8WRorRH3t28CEDnZK8CaFJlhIuZU5oxrOb9FdRocRD\n" +
          "ufscVVzuZHHPUsEoNnyFI0LkXqThDaFXzUl+t9gpR+mdA74EVge+uQEIAK+oR6mF\n" +
          "vforHrR8vczztgvFtmLyIbofG3qWwmTbtiqk8n5CI2zxOxOpFx4olBi78XoCZKs8\n" +
          "y7hrrLNi0qeYw0b10lpeoHA//q7lkHxuCKbltDXk5wky9GR7+qSbzgytiRCJKJI1\n" +
          "K9eDEVNImdhV8Exc2MZlhqmdEYcfDXRIgAxwnPdAK/2A0qxEWxN+ehokkzhSWzzF\n" +
          "vEvWdbYGTRe+ejvNY8esuhwFZjdzS78K/09VD2gRiM86MzsPpgiG3mR+UkllIq6J\n" +
          "4FYjAQXXQC4JOUSaZIRPEgJVn/VQWZ9LTnE/QYKDbEoocsJ/pivmOFYeoZvispp/\n" +
          "OqVqObtbe15pu48AEQEAAf4DAwJzfzHljwweH2BhNZGjrqEuXJ+Kra0HruNw2HPv\n" +
          "NOYVgKfOHjaiSKX8JUG0QFmyP/UogKWtVxjot8lGe5eSOp52FFvYIEgo0rVAmj5X\n" +
          "VprgkIdOoezhu0k3xo34z2+7nLhKvAgwuBvzHLJAygc9TGZlKZlePtaWU2OhwSMZ\n" +
          "Ijtv4uvua8+xlPdKgL0Xd3BSi0dJ0NY8UBD75yeI+ShwYMFwX0C+tePrcHY5UYDw\n" +
          "kx5deKSaERRbElYog9l77XdnTtBmaj4lsk9BLDFyLWhHUsOStxadA82pkzOovBpQ\n" +
          "nJ9UBxdgPuPD+UVOtf/KwOvFXAvv7ZXnh1ta9zQ8H5RgIfaLxwi+/I6FMevsEhIr\n" +
          "NFTCKVi3SJgVtjXZJhfQ0f4HN2bdjpwmfjGLQfPc6UH8sZA971tJb9+bsq7ruhPH\n" +
          "fCGtfeeS0z8g549heFSqviQAg4cbRYutcuXNJa3MFUBHlpBSHsAF+aa1aTdaI/db\n" +
          "FI1fnCe79J9ssCuyhLB8A5RTST6TQnzmxDspL6uNPcx4wHfCliA8Rbr6dJ7sdiC6\n" +
          "zJzmvoSbimxo7zCXwfkOwDK7CSc7IJzwsYMJ2PZYXAvKHSC3q+7wDpfIuOt+DCvE\n" +
          "861v6tWOLOy2qjRq9sfWR5Pn8TcT6D4nZInFSCSxbOc97Y3m8x1X26iD7Ei5tAsX\n" +
          "nFbu8iXkWZfjXVTPJ7Qd6yg3AXorcNnEL9jC+1eu5iusJKyzn+bJHwvcqwE94DRM\n" +
          "89h8IN29shDFi5K9jODhYO97SPvg1RK9lQdKnWHji2axfclmXNGP2UjchfVVwBz4\n" +
          "U+IKiwsFrlZWhzC0sqViN03CoGGPqGYOCPBoyXEfRL2JiONOP1hQGqqeCMi2VjCh\n" +
          "xVr0cCt9i7ISix0k7oR3p/DoPr5Ud+ytnpd9zUShjD/0iQI+BBgBAgAJBQJWB765\n" +
          "AhsuASkJEK/wZY0j+1bmwF0gBBkBAgAGBQJWB765AAoJEIbawTgW/m/iLR8H/i55\n" +
          "b7P7lgdemtwYgbJ11anxIad6Lp4XSoH2hMdx0VIjJDaigwCrp6pWPYuC+6HiLFJI\n" +
          "7fYv815/qb6XMNVG1CUX5x2PXOYsycRsaFsoWo+68uG9gHx1AC4P2KT+PXbs4KAO\n" +
          "MIi9UqMv64W8+u54pJ+uGcAmig0kwwIZ4DfJA77WhFpuRF17Epzdfdz/Juk0KWiq\n" +
          "TgnnmjffZ2fVEv7dOAMDUADNEsiH/KdKsOJzf1cxF6Rqb51X7aAepfqQE86l2ygu\n" +
          "rM+EYwbE0BbKy3D12X5DfVIruEq4bURpf4Fm9hyulLLqqC2TzenafC96xim2pHUR\n" +
          "wWMDyy0R6XSVLdIOGxrroAf9FhHxlOYCRSVGFWszfXGtOZNxikkg8mv30sDxTk2P\n" +
          "9gQhc4e9ocxWOAqzn2hY7lOU/47pGMM9lIE3c4QmyFBGFSc3AWqIs3Q92JhlUrLC\n" +
          "oCKvLAb93UXWRy2l+Rg/ZTTpNk2LkXE2tiXVnNibHqTrnYi081sqWsGo7/B4ORfY\n" +
          "YZaQnGvwhL3wCB/8L2uDRR0gOMfaKSIicxALM7aUKxLsXEJNpqJsETN3TgeIGLf/\n" +
          "BNO7S9gd0ObrDqWbPkWCTuqJ9tlTi0BoCnJoODG+6R8lDEGGlyyaKi8Ab6T31/Fj\n" +
          "72vDC6zGqM/62Y/DRJ4ScEkHiOkO+yO+udV1NxdoNlStDA==\n" +
          "=/2Co\n" +
          "-----END PGP PRIVATE KEY BLOCK-----";

  /**
   * 4096 bit RSA key 'sender2@example.com' - Trusted by recipient. - Private key held by sender.
   */
  public final static long KEY_ID_SENDER_2 = 0xF873744002F1D7C3L;
  public final static String PUBKEY_SENDER_2 =
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "mQINBFiS4bIBEAC6s1SfLA4oaDfS42REJhlLOHZREvsmE93RiqWzJHDWwAoSPAtY\n" +
          "rgPxb8IREy/0tSlOKvbdjAxceI09S6KQ2d7cF51MReIuVArdO2Mk4lTZwQD1/A3A\n" +
          "sdzTbE0o9bHElTDvDiM8srDrKVyGqwBN6blIRRYZM6umFpNrBnMD4P3NvM6b7SUW\n" +
          "fr+nGECede3iUiaQG3o+m9eO0xwEI+6kO7RN4JaoNpo0DhzN3m0OLhf/RBnhOczL\n" +
          "YV17I12Y0DEgp+DmCNdboYmGERvsctCZwyS65Gpr8mrtYRIhcWzCIAh/BBoggHGp\n" +
          "yT/Gm10CO37R65CQboQ+Wdrxqg9W/EpV7PnKs96W4fDQTz/13oOVEclgK94eQCwW\n" +
          "WCepfno9LUHBwUlhkKOT/bRdOTaur6Q62I4+d+79ig15tuURFwEUYFXrSifReZ5h\n" +
          "WIFcO8sfQkrlf4tZxQR6VBG9ze52f7hOP0gd+6W6x++ZIMRdAOXc5y5fINQ/8Lvf\n" +
          "QRlJ49Gkfq32Le/UD9lB/rtrXow+/ggnO+U4M5iH16XSeDmtDvc5SExKIp84fmTH\n" +
          "p7wqUIbSq5KRWO15An+5edxl2X7wTsObKknWS2W+7UxAYkopFR5ja0moOsqstxSj\n" +
          "E67hNU1yu0doIZWd/e3LZHC7kV/8mdoBOgClnz7kVkTOQeLhyqiGmJBdAwARAQAB\n" +
          "tDxTdmVuIFNlbmRlciBkZXIgSUkuIChQYXN3b3JkOiBzZW5kZXIyKSA8c2VuZGVy\n" +
          "MkBleGFtcGxlLmNvbT6JAjkEEwEIACMFAliS4bICGy8HCwkIBwMCAQYVCAIJCgsE\n" +
          "FgIDAQIeAQIXgAAKCRB+vq3axoqWkgiID/4/06CaRIdfm1qBp+1EQvNCZRAEKr9F\n" +
          "KdE/HR8uDlZQ6DBcebfhU1jgigGvsk68zTPV2zQfoJJYfOqp+PRlLUpZXZdIju7e\n" +
          "1fJegZr44G7BD/3NAH6vY31Hrz0xKMZRG+BQrt9yNkyrk2qg1zOIDGefLJkWxm88\n" +
          "p5jI+qQWHQAYwTFSpn6a2U46KJbgP0gIwT4/sZ9MhXGH/YS7N6Vqex5YcX4UP4ep\n" +
          "uAGudTDwPWD+CpiVh32EtUKdE2F0OIty05JZxdflQF053OLSW+p1rydmkafdl1z8\n" +
          "mMBxLTZ/KqsitkjA/BfIsufQ8RlkjLdu3hx0xYkMz4lA1QHwkT/ezp7hdnS6oWd3\n" +
          "3FGLir1jKjZoh7PT/0wbKanuQoaDmAbjWUjb08jOYw/M/6RvwE+OBtaNqhmk/HpX\n" +
          "BdYYN5+/Op9Zd1eWHMXqtuCQpD2uV+LCnC6+yj62xCPi49AYubfgyNkvuKnhyBd5\n" +
          "5iYRtZAAA/IHc3vxVRsyvltg8VMfarA3Xy6kET05BhWyIN9A2KqLrb/1Sfk2HK0R\n" +
          "dqComN6vs6cjPmqTe1HE3UX2w3jqRFAEDFVBvUJwcSqWgMMcUdNL4ox/g0cHd7nV\n" +
          "yFd3t1Jj9WxeX+r56jsBGG4OipviI/ewZc26vfll9r4o6d1ob4eNrkmgWlXHi/rD\n" +
          "6qT0PyxsSAqtlrkCDQRYkuGyARAAppmGcH3haxLakVmiZawyNum0YnIafWosfqMA\n" +
          "gTMtxDXWsDoq2iE2a1DmjnHztyIYYEBJ33duyxD+9WzBIFcBn8UTIDhlnpZIZ9Vc\n" +
          "M4Ml6bp5j8RVpzGcV2+IdTiKwr9FuKeZU4/4445djrAvXeHFsNNp/4tU4z0VWr62\n" +
          "24wBBTgHsUIlGL5KWTDwxsz7F+cEaTN/tbc5PIqe90Ahw+ds3FygrRnF1KWFuW+W\n" +
          "K4sgsU7cpW9D+tQ9ZsOnFca8aoYKVYYS5LhqlArnEKJCf10cI/KehDVofv8mKCeb\n" +
          "NCsH0i4qc8/yf2NvfgZUCeilpah7x1NtIr5Opj8E3T2Jq0K0EAP4frbJcOdjzOEf\n" +
          "KJ+IGdk7AC3yTUsKrccU/MjE1WMH/5qgmm4U6keHPuznHystJSTjy5ezZgJfi/aO\n" +
          "dguZONaFjqq0MTqR6Q+5JlFZu9ecjKw6c0HBh35I4jiFGNFK41Qf996yZCl48eg5\n" +
          "rqShYr4L2EUI+eUpnyPpRsw043kHK4eDvUwF8DdVUr6YwlYATpMkKWdnlSu4NFN+\n" +
          "hpGTcUxVdnh+rAG5U+rXhcp2IfImfa3s0MFiQa2BzIh+LRKZxBTB40NYHjmxq+gm\n" +
          "+T0+kBDm4PCgNw2skbf485G+YjLG1UacmXPdzPPa1LLu5a8TijHXqO8bBjBdv79I\n" +
          "OM8SPQsAEQEAAYkEPgQYAQgACQUCWJLhsgIbLgIpCRB+vq3axoqWksFdIAQZAQgA\n" +
          "BgUCWJLhsgAKCRD4c3RAAvHXw73aEACHek33FeuQQS34v+PG+nGQLBYjAeck/+Zv\n" +
          "fQ4/Zz0oTnfDXJii2clr7HBX96SwTrUAvYOJb7ZV/tesIsWjVipoKXauuDfXpXnX\n" +
          "jjdgRgTrA26/u7vSSsDHCMN/wEZLEhHUTzZNrkpMXRyDniXvZDtSVBnltQVh2+5w\n" +
          "/6Qd++QC9AaX9yp6Oh2xEQl6QellLzfoho6wGApO8kvYplxaxzrzjx3BkpzfNC8W\n" +
          "k6/aom3JJbEVkWj6/DFE6fYh7TbbSDGjpQZuaHxlVyYac0qjYSQu8YmJ5Uo9Ecll\n" +
          "hvL4oh+SWtBQsyFEKU7CqoXZmLt63gyIGmtD2J4vFOz1MlY9BCKOiX4cRWQPaM3M\n" +
          "M4+6RhNwxDpbqIXgrFjbetRA8D+2NkSD81tJbZrxn+rP1dVkmoIiIxEI76QZ3eOq\n" +
          "PuyseJ2m7zBJl9xubwA/sA6UYqJn1X2TxhWz4eilVIaP8O4jNVhrk+WB+v/gnwPT\n" +
          "0YVYmTnqmPmwonv6+Z0UI1EGTvtG6AFuggokBWvHaNrslEpdMX6ZJ1YYlEpJWixX\n" +
          "NAFzhK0N2LUn2YbhrFwEpe11sn98Iv50KjH11lriOjUx7KeITa6R8ZWb66rl+d/4\n" +
          "IYr4UBHydWc45zZHWMVFtJ+73Z/JcH1i0sl9v1tszdEQLQwrLujXYU2x69Yz/8fB\n" +
          "Bz2kzwZq0t7fD/0a4uSxHec7K3VYYTEmjfT3cixYVQFYnaHW9oULA0fP2E6oqtuk\n" +
          "ObzhOIIhvdM1lx4VVHMkcwpPhCE2+vDGbHZmW/YUio/egN3yLJHn28stF/0DSQ7T\n" +
          "u96muYqvqvEq8PzqLO9H8cClZ+o4TsnyDt2YQl4ece8uTw1UF+zXOC1WRntVS+Z6\n" +
          "QAVBnyQkAXv2a9k82CWlbVbxyXyDfERrqxhjlWymSXbBtVIAaA9u17wQK/8UBB2o\n" +
          "xK0CgdOWL8TI0oTbiEldRQge36fMXziirQXV5xDW753SpqRYcfkHSC1XWyC8YMp/\n" +
          "DRhbWwK5FpqHnbhfUHQ5D+stVfLyldsRFPtbli1i/pevvtB81GuY5do2qXxGBDFZ\n" +
          "40Ily1l0bYXaT5MnlzWD4UJK1YVmRcze4n+U5tAKZuO/a9OBzuOtXnQ4TpE6360e\n" +
          "l9aRY+EsRZFkC+0e/SvC9nBDOFfnw7yuzhNBpzrLYOxxPiFNy8nUXq5EIHm2kHVC\n" +
          "dY1npnuu2VhIC1Kj5/4k+p4cAEn5A0uSyxuQ6dQZp4nEjaNmH6mVkXeBrJWDuvht\n" +
          "6U7eIeUoTBvmMLIndS4GmEH13f9zgp3w6LC7jGO8a4y79i3pho97pACASnywri4s\n" +
          "OP/4cyqRl9l9G2lpaEEu+sQ62l757EDQa3/MXclEarfAusFJiY4SoY98Ew==\n" +
          "=uiOb\n" +
          "-----END PGP PUBLIC KEY BLOCK-----";
  /**
   * 2048 bit RSA key 'another_sender@example.com' - Unknown to recipient. - Private key held by
   * sender.
   */
  public final static long KEY_ID_ANOTHER_SENDER = 0x7B7DA94F0876E36EL;
  public final static String PUBKEY_ANOTHER_SENDER =
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "mQENBFiSRZsBCADKglJqGIIHoQExaEsjhQS/hcUY3oPl/15YskANrg+ODca6pFMo\n" +
          "Jlc/ow+37/cbXpyMY+ZSZgLVPJ/BTbQekefcdhgOk5naU40r4wm1nGSg5hPTZrd4\n" +
          "sDTCqHX5U9isobjjEmOJyAeR2Dm0Ha6MCPaB36xsMWE/1aHHCbhreJGR6nOhZdXl\n" +
          "LKIthAP3Z+0XlAeTRv2Sl5XnO5Kau3v9lWwnwO2M2m/BfEXZ4tqnGX+d/F/Ar/ds\n" +
          "0GqrW8Pa1C8r9uiEGynRnTi6w1NYbW4/hRccKZRBHQUM5EpdWq40X64bSoovlzU1\n" +
          "JcX5y+wbYN5yca5M5jU88EfCuNG5jR9DcdgvABEBAAG0Q1NvbmphIFNlbmRlciAo\n" +
          "UGFzd29yZDogYW5vdGhlcl9zZW5kZXIpIDxhbm90aGVyX3NlbmRlckBleGFtcGxl\n" +
          "LmNvbT6JATkEEwEIACMFAliSRZsCGy8HCwkIBwMCAQYVCAIJCgsEFgIDAQIeAQIX\n" +
          "gAAKCRAPVVpnU+0ebsXkCAC6u8RaXxlhlR3HxCgsfAlbcqN8SagVCGMFS0DsX3AD\n" +
          "3ZJJPQQIV6t0ze9B+hW0Hr7edtMXZL6efgHtNZzWY2RZ5niMsx4MY/mlcg5vBwSy\n" +
          "ILBp99PCdEf9vlzGwql/AXI+JTV3eFojqam+u6NrqyfbMJP//4HMVhK2ByUCE6t7\n" +
          "jdZ8R7MMJjO7U6LI9TIADMUufcAr14TVu4J4TfRkFPEqw6T54PftUDEzvypUhBqx\n" +
          "2WAWG2d0CRVx69u8B4sdjASTbH6XSKeox+uVyIVsPvHzWpmfTES5eUY3ZIDM2tSc\n" +
          "iy8C32jjQCeWaYvMd0LH/G3w5H0G6ru+SMU4OtZe+f+xuQENBFiSRZsBCADB0yS9\n" +
          "B3sy7F63Xa6sp5rKqQ5HFPC0GS693oZFZLX+Ei/l8Jap5wG2Dr6YmFY9HiZWdJi8\n" +
          "MH47isgdJH/8rNxyAMmI6DYxM9Ci9Bc3SXpKjAPAYSbPsEo24z0WAE0mwWqVxRRe\n" +
          "o2PG2VgfAoqu7HATPzARo5fjrz61n5jqtxs/oaWADSMgsW1ZiHgH6ihxoaNso97F\n" +
          "2DvI+pqGTtOzR0bv+OzWzQEqjincC/7qHwuOVRh9nMQNLpKH/3J11L07LVSV4S7Q\n" +
          "FshJwgJnSUhvZFaQw56yh/EgxUa/SAlL0XgPzcKYp+UN3Mc5RM89hIvsLg7VoKHA\n" +
          "3qVw8X1vXSLRtwwlABEBAAGJAj4EGAEIAAkFAliSRZsCGy4BKQkQD1VaZ1PtHm7A\n" +
          "XSAEGQEIAAYFAliSRZsACgkQe32pTwh2427+pwf/Ty4f/IYfrFI3lxpNBtFdJgZq\n" +
          "bm9s25p8HLybVR1pDOOgEFVVkKF+poiJEHwgT0FACxM+To1lS5G8uG3mh63qvKoK\n" +
          "8axGs7HdqXm/fBUzPJVCUiYBAR//7wZ/G9xcF1PHVzpar66fC5wuTfxPbDLq0GOY\n" +
          "Oz2ZAiqttGuLypqR2GF7pPoFUwjOQ+/LN1s5gQcqab6zjcJ0U7F4iuhvFv2e2rtv\n" +
          "YiEqNcBjgCq7KVX5Nb7kp+f1/sLF1zGxfiiY1PXzx34J3/dYKX6LXAUVusK1OKHn\n" +
          "UcA0IEQC4aG7p8bSiiv0d43JF6fWk29fiBu3EHatojmdjG4kBrZsvWbI6i7Pqg2j\n" +
          "B/0ddKpxYvfRrMhMIt1O7etleFgWAvO0jHkpfV0Ro2qsYCedo8Vfrn/AJCUwfNTN\n" +
          "DXYHUjAwkFlptjg9J8JcaTK2I8pLiRzI/HOUTWWy50j0k9R6VkETo6w/Xa5DXXzX\n" +
          "2u1zZk0flAogofxOHRCwC3/ePUXOt2HKs8XrRQsNvUfYIT+uAHGsEOAeT/smZOPH\n" +
          "UrY9AuQe7Lxer2h1aY5Xho8GTdp1oSM7cwVc5iZCf5QsmJLaMwTcBLcCQFU5/8vl\n" +
          "wKTH16YriY6ugCb6DoA+yAx50t6JZrhCYaNH2ugp9+zwjVnx3WiZkQMv35Dhu6bC\n" +
          "N6AfMH9OO3ci1tjxgc/dQKOa\n" +
          "=B/x9\n" +
          "-----END PGP PUBLIC KEY BLOCK-----";

  public final static long KEY_ID_SENDER_DSA_SIGN_ONLY = 0x064A7E2DD3D079FAL;
  public final static String PUBKEY_SENDER_DSA_SIGN_ONLY =
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "mQSuBFiboaIRDACtNn7L5OrTvYqJXAZqmNLmyj0GEqOsk7mTVO1i2qKhiUv2wA5I\n" +
          "HnFf7FcBwhPzmJ0ys+PHkBh8SIwPUAPZ5OkEJfbbsw0b0TBey80CQqWAmHukMJFS\n" +
          "avpHVkIYGAoFB7aRhIiWTk5CeeX65LXZQgPn9Kuml54K1jMpYUuiu8TZtoIxsvCw\n" +
          "CpaExn50zfSu41Ttt+CaRm/5kt5gANvK1gIy+NvUHLCBwJU76RjCU5Gp/KiVF+E/\n" +
          "LaRvvlk1jp+eBZkRUya263R998NkQ4/gAMoYkR+zWZvJ0FvtKhOj/I+EPF1fYHd1\n" +
          "UMTehzh/O/+tW26ULLqEe98ZGNt3mxlr/gJErlST3e0oBnnuh7iOu/ALhGbNCnMZ\n" +
          "gPXdPGXtgvle3UOTxj9AFQjik4Ldnhx5RJVf58nIeQVwsXA0R/5V2ICphERcIjXd\n" +
          "LG1jaFX7t0JsdQdulv8H/s9drK35KNBiCKWS67tp1iaCWndk93QFsFHgtN2qFI6G\n" +
          "y/kIExiQ81+MVQcBAP1w9Pb0PQ6fY3XkB8CxSh2/JNpOx/NRALMojFKuXNOrDACN\n" +
          "yjhaFGhVoZxJKRyXYF8YUecSfhnW0EipWwQjMJc0kLi8o8YWzc2kLaVwh2VfxPH5\n" +
          "SwZ4zfnP1MI6XTP8NFT3MaRaTmPuEnJjxPxtO1QHCWeibfecF/bdH/zr/QlPGdgp\n" +
          "i+zODfzi74Bs+z2e6dbDZS3kOpF7JikqxUTkJuCI+k/OwW8mmBy2wZOGYVK/0wVJ\n" +
          "TUqnc38LKJlv16jqN9x2Z466YfAGqV7EiQ198OiyTeyfwSKwpTe8qAfIXwDt8jO2\n" +
          "5I4R9QS03HSrZlQSPOlWlrlJwVN4YFrxbA1ugOkDwuDFmUNIYmQVPqyjrJe+h/fD\n" +
          "4gwxWMaBru4sDnMw0SwKojpgYUZlv4vtHDemes8Q1ZrYA7LqlSKfQQxiZrd14ste\n" +
          "LJW3P2DwWkypGkJArMFb+MEY8guXJfQYAnf54Y6rRjBsmQAXXVxOEAzFY3v3fCbe\n" +
          "qEOGiF4yC1I/f9QJGlZQYQY8VCco+ufKDowyu4rK8shBv/hTtSsIpVAec/BXY9YM\n" +
          "AIZu+ZDpiWImIQL/f+Gz/HhvB8Ow0Ka2an7J58cT6sKwUOktwa6dgxtPVr+Cx0EM\n" +
          "D8vukA24lx+ni3Vbyw+y52NRs3YcL8+8BVzUB8tBUNoE21MRH4u2e6FsQgeQap07\n" +
          "aTxSbs+WMSlVqSwDQqZdgXSHw7fZ0r1pRPXGDy4qTQGd5jKmN8jbsUtqaH4Y6Irf\n" +
          "c9Sx+54uw1RT+7+nOkWU+riyVHdHk18VGYhCSO7+faLok7Ovhf2YmXnciQy7WHfw\n" +
          "+lsj0ReQ6P0ABFpfa95jUUHkjtI3xl/wNhsMpWWrMWWom5AubHaGG8iQ1EbSC+lC\n" +
          "fd0M61CAsRZ0/tzJIxJQxNzTKq12s7kI63yc1PmW1r1UPRVy6fsNea5DNJjTSpUl\n" +
          "dPSKItm5wFL5I6VbwkU+y0Uait9fRZVztZo4MLm7kcHl2yNq2BqpPOuWdOLfBLWe\n" +
          "QTd0bHU2Dw0oEPYEyjdvmu1JEB42JAaiTDlTNq7ZSNocJ1y/8q042id3PfADQd9O\n" +
          "NLQ/U2VuZGVyIFNpZ24gT25seSAoUGFzc3dvcmQ6IHNpZ24pIDxzZW5kZXIuc2ln\n" +
          "bm9ubHlAZXhhbXBsZS5jb20+iHsEExEIACMFAliboaICGwMHCwkIBwMCAQYVCAIJ\n" +
          "CgsEFgIDAQIeAQIXgAAKCRAGSn4t09B5+nArAP9rykkiN6t4Xk/pMISdLOa3rL1z\n" +
          "P2uJJpDJMyDGx7MgXAEAqLakohIW4pD+vWnSRWL1Qf+aavjyye+olK80aMJKZVI=\n" +
          "=UzjI\n" +
          "-----END PGP PUBLIC KEY BLOCK-----";

  public final static String SECRET_KEY_SENDER_DSA_SIGN_ONLY =
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "lQT5BFiboaIRDACtNn7L5OrTvYqJXAZqmNLmyj0GEqOsk7mTVO1i2qKhiUv2wA5I\n" +
          "HnFf7FcBwhPzmJ0ys+PHkBh8SIwPUAPZ5OkEJfbbsw0b0TBey80CQqWAmHukMJFS\n" +
          "avpHVkIYGAoFB7aRhIiWTk5CeeX65LXZQgPn9Kuml54K1jMpYUuiu8TZtoIxsvCw\n" +
          "CpaExn50zfSu41Ttt+CaRm/5kt5gANvK1gIy+NvUHLCBwJU76RjCU5Gp/KiVF+E/\n" +
          "LaRvvlk1jp+eBZkRUya263R998NkQ4/gAMoYkR+zWZvJ0FvtKhOj/I+EPF1fYHd1\n" +
          "UMTehzh/O/+tW26ULLqEe98ZGNt3mxlr/gJErlST3e0oBnnuh7iOu/ALhGbNCnMZ\n" +
          "gPXdPGXtgvle3UOTxj9AFQjik4Ldnhx5RJVf58nIeQVwsXA0R/5V2ICphERcIjXd\n" +
          "LG1jaFX7t0JsdQdulv8H/s9drK35KNBiCKWS67tp1iaCWndk93QFsFHgtN2qFI6G\n" +
          "y/kIExiQ81+MVQcBAP1w9Pb0PQ6fY3XkB8CxSh2/JNpOx/NRALMojFKuXNOrDACN\n" +
          "yjhaFGhVoZxJKRyXYF8YUecSfhnW0EipWwQjMJc0kLi8o8YWzc2kLaVwh2VfxPH5\n" +
          "SwZ4zfnP1MI6XTP8NFT3MaRaTmPuEnJjxPxtO1QHCWeibfecF/bdH/zr/QlPGdgp\n" +
          "i+zODfzi74Bs+z2e6dbDZS3kOpF7JikqxUTkJuCI+k/OwW8mmBy2wZOGYVK/0wVJ\n" +
          "TUqnc38LKJlv16jqN9x2Z466YfAGqV7EiQ198OiyTeyfwSKwpTe8qAfIXwDt8jO2\n" +
          "5I4R9QS03HSrZlQSPOlWlrlJwVN4YFrxbA1ugOkDwuDFmUNIYmQVPqyjrJe+h/fD\n" +
          "4gwxWMaBru4sDnMw0SwKojpgYUZlv4vtHDemes8Q1ZrYA7LqlSKfQQxiZrd14ste\n" +
          "LJW3P2DwWkypGkJArMFb+MEY8guXJfQYAnf54Y6rRjBsmQAXXVxOEAzFY3v3fCbe\n" +
          "qEOGiF4yC1I/f9QJGlZQYQY8VCco+ufKDowyu4rK8shBv/hTtSsIpVAec/BXY9YM\n" +
          "AIZu+ZDpiWImIQL/f+Gz/HhvB8Ow0Ka2an7J58cT6sKwUOktwa6dgxtPVr+Cx0EM\n" +
          "D8vukA24lx+ni3Vbyw+y52NRs3YcL8+8BVzUB8tBUNoE21MRH4u2e6FsQgeQap07\n" +
          "aTxSbs+WMSlVqSwDQqZdgXSHw7fZ0r1pRPXGDy4qTQGd5jKmN8jbsUtqaH4Y6Irf\n" +
          "c9Sx+54uw1RT+7+nOkWU+riyVHdHk18VGYhCSO7+faLok7Ovhf2YmXnciQy7WHfw\n" +
          "+lsj0ReQ6P0ABFpfa95jUUHkjtI3xl/wNhsMpWWrMWWom5AubHaGG8iQ1EbSC+lC\n" +
          "fd0M61CAsRZ0/tzJIxJQxNzTKq12s7kI63yc1PmW1r1UPRVy6fsNea5DNJjTSpUl\n" +
          "dPSKItm5wFL5I6VbwkU+y0Uait9fRZVztZo4MLm7kcHl2yNq2BqpPOuWdOLfBLWe\n" +
          "QTd0bHU2Dw0oEPYEyjdvmu1JEB42JAaiTDlTNq7ZSNocJ1y/8q042id3PfADQd9O\n" +
          "NP4DAwK40eNdZGsE/9L4shX3KTm8V6A03yDNAle42+WRyrW9DaeIyftleZ1Lt+0Z\n" +
          "e+JCJQ/qg6ML7s36sBp+PIQ+FJoK3WQveZmujbQ/U2VuZGVyIFNpZ24gT25seSAo\n" +
          "UGFzc3dvcmQ6IHNpZ24pIDxzZW5kZXIuc2lnbm9ubHlAZXhhbXBsZS5jb20+iHsE\n" +
          "ExEIACMFAliboaICGwMHCwkIBwMCAQYVCAIJCgsEFgIDAQIeAQIXgAAKCRAGSn4t\n" +
          "09B5+nArAP9rykkiN6t4Xk/pMISdLOa3rL1zP2uJJpDJMyDGx7MgXAEAqLakohIW\n" +
          "4pD+vWnSRWL1Qf+aavjyye+olK80aMJKZVI=\n" +
          "=zGKV\n" +
          "-----END PGP PRIVATE KEY BLOCK-----";

  public final static Map<Long, char[]> ALL_KEYRINGS_PASSWORDS = BUILD_ALL_KEYRINGS_PASSWORDS();
  /**
   * Encrypted-To:    recipient@example.com Signed-By:       sender@example.com Compressed: false
   */
  public final static String IMPORTANT_QUOTE_SIGNED_NOT_COMPRESSED =
      "-----BEGIN PGP MESSAGE-----\n" +
          "Version: GnuPG v1\n" +
          "\n" +
          "hQEMA1Sj2zdPeHq3AQgAoY5qm/9RNyWpvqR+fOn/VsJSXDzaqeYgR34xAdu1Yvqq\n" +
          "uGsLhVG1VG5WJlZPkh8WtFvMmOUfaMi5yKqGiKA1KP+xuiH5KWjkiSEnBnzpA0o4\n" +
          "1JrwHMBqdrHEDDGityOG+uDuMIA9ou0RJnSDHCTEtTrK2hcV5a7b4z7z9kFYlkq9\n" +
          "x1oFCUFt8BRMrNO6EQMHa2apMb2LLK//QYuscg3GTm6Vi9Pt6xKeaAam4ygLmD5b\n" +
          "nTHBys0GlXZV2stD3CRjW4UdJ89XjdjDin0GH4ZWfbWby4gqNbap03Epsz1qCNDF\n" +
          "WlQSeuxHZcn0Va3jNyFXGsWkVFTrPEOEG15B5OKdsdLA8wGZLLys06GIlqvcpjXu\n" +
          "pmRUoj1vusDFrhhhzUpBD3SlHLUWnYs5UYK6rB8ZUeF3MjRWzjT8xctGgR2JG2Jg\n" +
          "hpYQZai9fNQ8hefhMdtW4TfiqTpNNmtTCgx7RSvDidOxHI6N9v5HR8WNQlE05ogr\n" +
          "wJ5l5emgWKD9cVJR5VVM/GXjffG5Mmncr7HHy9z0P/5PJkocTxtVR2QR9vyT0f/X\n" +
          "ds7yS9w+WPXMbx3MtU07X/5mjaWpC5ZoCjypHJfk1GjW65eZzMi7NDvsoSLCFh3L\n" +
          "5yOrvvmNWBLcgTQiIdc7CMjkRCtdpjWLgdJNyn7HIiy5CHg9iggiPLt5xr6As7Iw\n" +
          "befmmkBk6Uy5ft4NFXs70oetXZLPDLFokAzfes3E0pUMLYgr4ZzIj+cdINs4+L3d\n" +
          "80nqx4TKgIQvNPgtPwKUUAJE3N7zW9hD0HpJjG5pgvvmsARp831U1DCZGtjE18du\n" +
          "+19nGVuPU9nFKEW/VMofxJdb2tXp083i3ZUEYgcNYcB22kM17xRmJ239BRnBa2BJ\n" +
          "MAA9m9UBHrWopfDACZF0mjpMvQdr68AiOTHtrxFgtou/axa8wg==\n" +
          "=xVAW\n" +
          "-----END PGP MESSAGE-----\n";

  // public final static String
  /**
   * Encrypted-To:    recipient@example.com Signed-By:       sender@example.com Compressed: true
   */
  public final static String IMPORTANT_QUOTE_SIGNED_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
      "Version: GnuPG v1\n" +
      "\n" +
      "hQEMA1Sj2zdPeHq3AQf8CPN1Fbg0HXQHSFzONYZyxkabSAMgIzXf/VOp+FWER0A1\n" +
      "o9RCajzYwbcSZCLpg9T+xbCJ3nS+ndFs0cx7MSevBSk1tVriiv/Vn0Odj17keX+a\n" +
      "YlRkfk1n10JWKrJwS3BJx6JuK8uRmZwpqr+IqFlMu0TJH7rNAfGwbSFgJrHUd4Je\n" +
      "ieA8eTXkjnassNTvMlaZVmVi//BjpzK9o91r0zWvp66k6v2uZML0SQT3E6xDTWBM\n" +
      "WtHuJqdaAziShn27w9M26zOO9UEpVhjz8fDQAetdMEp1z6p6BL/2p3jayOMeIIcq\n" +
      "iCTB0dRgqakBHnY/izzsCXYr3xigchi+gXBAjvzoM9LA+wFSRA3v+jJu6NK2ackD\n" +
      "W4gFPNuhI1IoIt9cjP9hZS7rb1stHrQ0QFMwTM/2djRJSw6jjhi7zSnPL61FOdtY\n" +
      "NaxNPUv+Ab+QvmM/0notYfNQZIdpaDpJ6jOuXe2qJ2xH4oAGOqqscTO9jB2p6ykQ\n" +
      "JtRq4BCcfMk8RddScpZzSK9JA1jslzpXbYAFWqvMVDSYwHGSP8FgAJUMbI7ZdNGt\n" +
      "nRXDxDhBdfR7ix1NcYwg+g1f7qf3j2cgYhgMVajSqGSW84HfUOcNVSQz9M+GrWtS\n" +
      "nwzrqU3ar1qg5TcaPc2NE8b5SGh/3afG+kpkVufUqPPgAtfSMxgB9d9fqdqtO8zp\n" +
      "jqC6lrR63jXiH1CovCUPJ65jJou6EZ+vbjx9ISxMqYuqBSuafxvPsAhb2fu5NsJW\n" +
      "Y4BCBhe3gFr40bhlnK7P1+ot3XYLm01GTTI1CmDLlQIH2aSozhsRE/ahc/1xf75U\n" +
      "jidHHK5iPFfBAo2ouCmb6HRhPUOzMHuMHCMRqScOSI/Css6BvLaqoHCUBwzN8Dhb\n" +
      "kfkE8g9Jm9QfsIaCwfcTqJslO22BSIANmm2Ho8vevPzS0uTxnugoRaA6r0qw\n" +
      "=dQ4L\n" +
      "-----END PGP MESSAGE-----";
  /**
   * Encrypted-To:    recipient@example.com Signed-By:       sender@example.com AND
   * another_sender@example.com Compressed:      true
   */
  public final static String IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED =
      "-----BEGIN PGP MESSAGE-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "hQEMA1Sj2zdPeHq3AQgApWQVGzjMlmIRHNLXh/jtPzwRAredDH/XUQt20zU94pg1\n" +
          "jIE+fYnG8sV37BdzIK7VQW7juOK356Wwq4+f4RSziYiYGJLCKDoQqJSklWYR1e1h\n" +
          "TUlUuZPttv80AXujCvhyWykRAs5GTQRFxQmBAAhwzJAsKDPpVQQ5QAO223+WNi5p\n" +
          "E2JIjEpOVMAMBGPt7nZEPuyHcXNZQPhA4WFFHKZwNGOh6Do64pjNYoCDbzkrCQxa\n" +
          "dvLwuEEEVSoyPbmkWS5/P/QXVgXzR1/+H3gxg/wDp9xSz29hIOZbFLvfZ21PRCnx\n" +
          "xBD0xpmNEGZxRoaf49NWGWlVwEJSK/877ILPvvnmo9LpAbExHiktgLOEuGLQJk2W\n" +
          "bIZft2c8fzOhyHv4vEE6AOupLBNjYbhEXutPPYErxdnNaJ1katUvIHb+VgvxiqLl\n" +
          "2oJL6ZP0/UWj46v7Wl30Pm3EQXFLqaYYIxzuznlRzRx1+LrwjTTKh69uV9ZA+Ook\n" +
          "qMPRbZ5LyXi9h7sk4Vi7rHQ0xJ8sGsa65a0TjojLlnUvz9XN5yceWm0fivsrXETZ\n" +
          "Q86X6DFcBJupjfY3BzLujYGaZVL6a/y3pH+rj+U4Vj4N9EzaYIEGY7Olq5NerTNk\n" +
          "UmqTruJGeU695YKvky+LtHxKdxFQaaCYTgLZyQdLlZ4ElcCPsDpR2zuv4nlrR6aS\n" +
          "dQVDXeyKGplD1keItJ03n9rosn3/mifjJvofsdArtQDytN3QL+lXJsV/VUbjCUeN\n" +
          "RJuM7kspVCA1/iHQIS0qtpygk3QyowZvOGefkmJwA6Y27fWG8/gI6Q8uKuwZ1Ey8\n" +
          "J8KOCnKhaAyFS3TSBRYeIm93tLcam6qiLNbluRBPFPvPpjlr9zqGIoMkEqWOlO9a\n" +
          "tJve376X6t1i8119mDxyv6PdR3WpASy1defkOzS0II6G07ETkrjnhiYPfllQQDOw\n" +
          "uCUg2zb+yFQBr50f6Tkmq5uMCyDd4P1VnEt5GaSSyVl2iwQZLdTC/NtBLu+63iDY\n" +
          "43prtr9ENZogKsnEOy846aPAHo6NAG+1v2IN2BlhoHyLGah8EIbL2CJ9ZHrcxHI8\n" +
          "VKLkA3yMb6z2Fn8I3I4ytDxFfuqd1edrluNH9CfKlTNCtmaOz4sbI8v1NFW5uqvz\n" +
          "FjTH8ZpZ0f8QqOm4bqR0teOg5eLX64w2tO6O79FJPoBnxSq5Gw7lrImrtvQUmygk\n" +
          "2rP9E3RFGJR2z9J/r+aAEqYn9/AICXFfm9/jswxmkBlEXP9kAStgssX82aPTdHLc\n" +
          "xsp6H8mB42WG2QxH59b6oqfkVgaHCt81z7LC/9QBSY1CR0SsHawUL47KRsSw7m7W\n" +
          "Yw==\n" +
          "=OxhG\n" +
          "-----END PGP MESSAGE-----";
  /**
   * Like #IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED but the order of signatures is reversed. <p>
   * Encrypted-To:    recipient@example.com Signed-By:       another_sender@example.com AND
   * sender@example.com Compressed:      true
   */
  public final static String IMPORTANT_QUOTE_SIGNED_MULTIPLE_V2_COMPRESSED =
      "-----BEGIN PGP MESSAGE-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "hQEMA1Sj2zdPeHq3AQgAwGqEeSJpTfWku/djqSOGxmMFk40LTvWBOb8e+T4U+cig\n" +
          "LMMa4iECySrjQAeJdHfL+29uoA98svlizzOUC1SOoUHKvbjnYT8CxH47rMmD1ZrE\n" +
          "qD8678HlRKYQToWTWiDoz85L443BuZedlCe8Vj60pMY5x+i8rElrZTLtAkeGey/3\n" +
          "QjgVJUoW4vgOkFUj8xe/d1/dJzGDG2C+aAZYhQ7IvQghCD8fKSwaJGFrusoEeGff\n" +
          "uWP5xotgxN2rx2L5NycT7QRlyL1OK6jP3RH2dskMB41wsX5rbPFGrBaOpOYR7cdp\n" +
          "Msl1aCCU74DXXUQ0756wyRVS75jUGRTZodNcmvTXR9LpAVxLabsoViv49J2J4brX\n" +
          "XEtc+DMK11CgDGTpbPmSyGj/WUIh0pw7XkVbN4bjvM6ooMV9ZfKv1tGkqrGrT2Bd\n" +
          "bgtyQZLnf7DqK+IJzB/LHyUm/yt1gF9BEgXqiH7AALWkSfN1X6nRGfhIBmS4S9DC\n" +
          "DNU957hZ6fUQY/fWIVWkhoXu7urCtpNbjfRE3a8flSIhT01f5ZER8B4t43oIyXKZ\n" +
          "0yT61pVVLANBVnj01FySPiG0uvNugVyhqxw9uYZwK93X2ri5HC79jibt7vZ8e2X5\n" +
          "7NPovb+BhtUA4PdHr0Ou6A8gyQ/QiHBT78od1R80r0TABcshYRMZGglw5dMX65oK\n" +
          "uQcOdvY1FRaczw/1hmlIVmJxUjTZalk/kH/BzIGLSwiE/Q7MV+myZChzfda0dAtK\n" +
          "rsdaXDHJQp+RJkJ3Unuc3XcyMLfXI/CX7zJgiT2pJ4mvHn9Zh24MZ289CdgUE4NT\n" +
          "t/PM3n0lFVt6tylCi4KI9p36QBzNbhfAyOjaYGBQhRkhPA2ETYyneeoUXQc9LCHu\n" +
          "SG6FxeVSTCVDqA42UC1nrhmVYdF9R8+C9ts7FjUGkdRwi48PmMIBO8TGu+HAoB+o\n" +
          "/fkKq4w5vYMPfpgBDthtR9rO2hMAsqW9XGfaje+QvE5QPmLXLU8ow7MrAI52Wi3r\n" +
          "Tl9vDbZ+aDvCc2f4752p9trAGzKzCRxGxyBxVbNMIqH4TZdhGF44ZEhzujlpZO1a\n" +
          "ysbaExBOk1gtssuQ3pjvXjRI2CDY0DIBCD7NQLp3EdLIGn/Dfqg9VUhOUgLKsA3V\n" +
          "rHtc3R8WcjxmPQWhR/YIsqORKFBBT/8i9gsJIE4L4sC21tFHlByr4CgYZDRfbTcH\n" +
          "okCfv9bES0dqmcvH6ou+SG/2amSdHWOu/rnulAh5Vs5r3xcB+CkNZy3S7jFfCoAh\n" +
          "KXFleR9runn1K4a2Ut17/dSKcVT7qQWSD2pEsx+0vYVPiKWfe0Nn9TETRrdZyA==\n" +
          "=SCj5\n" +
          "-----END PGP MESSAGE-----";
  /**
   * Encrypted-To:    recipient@example.com Signed-By:       another_sender@example.com Compressed:
   * true
   */
  public final static String IMPORTANT_QUOTE_SIGNED_UNKNOWN_KEY_COMPRESSED =
      "-----BEGIN PGP MESSAGE-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "hQEMA1Sj2zdPeHq3AQgAxIKzL2Q4146ej+4R5xEkYsvzTRbn/itHyDL8BAxkuTXP\n" +
          "bku1p7y87HmgkJmthq1jLq04uGDKvOSo/VAy31KqyDBlnyGXJWIeNvIFAODxb+3K\n" +
          "2eDda+7Ijv/RWagdB20Bn7Duyw+iUlzyiZDoMS9u4/OuN1NbYrgb2wAydmAaBWkl\n" +
          "kK5V2wH7u7lThXAAYc9kaNIbjd9qZlCblNmUW7mKbt0ZnyuHDeTt52Nlgr6WpMMT\n" +
          "SEcODnkpzszRhu9sjuYefALhSxqrU0b1muh1XbGBExa2eSaaA8JOdOFKNYF1Aql9\n" +
          "STETTJKiQNpnruNzb4yJ9Yh7bdS8E3z8n59ATACLwNLA+QGr3E/l0ecbd2eB+Vwe\n" +
          "DwQB6NHhc4xrNyytSlEKBqMo7dpjMEGYwGuSyuTYSlBbq6Bxly3uJhzeR41mrcZt\n" +
          "5Rz9z4qfEh227d/MaQ4SiAmYK0GowXv6zbaTZHzAHPqaLB0V9fHjyOOUWtybCwup\n" +
          "8/O4ZI0FgwTnJ9KBQxq997Q7pz3l2UwFrglOFoYafKqSHFcTMgwajRFDb/3gFWtj\n" +
          "q6Gsylb9ipB9wj3HzyL0w1s58HQ92IhrcXTRLIA4GibbopIBRl1g1FoqVozbPVJp\n" +
          "cva/t4iUxiP0Bh1SHvD4yxR8x7FFkQ94RKBYmmMvtY6sa8p6VsHGYfWpCJqpU7YP\n" +
          "SwkSWGDuehZKfFJ8mP//SUknKV4gWYe2Sh4qvisKlzXt/Is+AMB3mT0hYqZnsj9u\n" +
          "PdXy0lOgmycHZJlaHzbQ+mdHAePRgkfe8WNz3s220L7LYi3DlolBsgYYKZf6FW1A\n" +
          "x60aZxZ2o2p5lnQloEM4a15mx/bsa9tL4b3Hlv0At1m8MwVrLHVv1/tjagOdH0Y7\n" +
          "WVr8a1FkXuriJtcDEUJcyl/cPDvtx3ootxskKZgpAqrJ4dF9woRp+GhaOA==\n" +
          "=UKuw\n" +
          "-----END PGP MESSAGE-----";
  /**
   * Encrypted-To:    recipient@example.com Signed-By:       another_sender@example.com,
   * sender@example.com AND sender2@example.com Compressed:      false
   */
  public final static String IMPORTANT_QUOTE_SIGNED_BY_2_KNOWN_1_UNKNOWN_KEY =
      "-----BEGIN PGP MESSAGE-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "hQEMA1Sj2zdPeHq3AQf/TEsFPsGmKA3ajZJqd/hUWTJOjBU57aFOap/MCsNdCGfi\n" +
          "SZzjFcUBRXTqwTrnWvGbjFUkWrzB1cI3oqLlWbK2/dJkJjJ9wFa6fm3CnUfjVh5J\n" +
          "vVUVdzLiGsjr7zz66EGLT7bJcGOfP4c6cvIeb9sghZdxjZi/MMklWaj4dszyb0fH\n" +
          "MheRS2vimxprhvE/3KX+UtaXDG7uM9F/2zT6L37A2ubfxQ51q4YZ4XZZ2iAq0IRG\n" +
          "Q1vYCuJgh03QRY5/Z1L7k/IPlWyqLfXcnNDErZqzUCMievQrixvllLdwgFUYmBck\n" +
          "53GHcBcjPk2KICKR81GhTKHjlONYJGZ3PDY/m8L+qNLqAWeXxxlTrAPuK6s5TZGB\n" +
          "v56WzmyMXVlFo4lUtBPEJHOVdEM68i6XDK1+6Q7wMgXq+VyhXtSRlYGZJE/oEVAm\n" +
          "qgeaWsShdCVYRj/TMRg4UH+V3HDEF/u9IGpGCoX1sWNNkvWss8mskh2LYLWdvojS\n" +
          "QyvB3h4a5aFODJkYTpFYhXgkyFGtzvGxYfClUuTofhlTwNCJzxXfblEBir8CXRqr\n" +
          "uyzT8NYZvbjQYyarhO/CKNr99bb95LYST6mbE++EFAaT7WtONU6HKrY79UMcCRe/\n" +
          "xBkK6xrwvfGsMQ/FLr5QFHeG0kP2+6Va05tvKpvXeizxlX+qIhUuaASZXMNkBy9u\n" +
          "m/ztmbDQwoftxlH5ZvGHTuZSejJNFQGCtHu7CX/voX8vqN4Wb9x+tIKFaLlG7krL\n" +
          "M2ScgnRRNdpdMMXnalP/sjAwxw5H7+BeRH3v/YY5OimbvLqG/MIMtzUvp4OP0z6m\n" +
          "wIC2I+VjDHn1unDMnLEG9elGp+ieJ3GQN7k1mKbXXB2/bH4CViKVg4gorUGXVrGL\n" +
          "qc6p61GZOqB2xkuwNrWgvExVgYQDq1vIbUtlfIKblhwymPMu9Qvrl6SLzmOCG2Am\n" +
          "Du2YpTY92RXD1om9oj9ltrOLqRmj7t5kbt+Z3Xszb3jPHEvQACcNqaETJ4bkuIeh\n" +
          "44bANu0W4erYn5PqA/vTPOrfIwkSQtqaZqivHG3gSZclvMq8ASlPwbIcUlB2duSI\n" +
          "k74nYB5DF2tag6rU4a3gGEE4/+/lDicAnGMO/Ht6YoiKBadfqabflyCAStRFXkz0\n" +
          "Th1jeH72s1QX6DYGypXtzLiyfp0liCIlKGGYX4OhooC3cjU4JdvNeZz/RXSi2UKD\n" +
          "zRDaMvPVOelRgxJB0YA01LZO35j1Tb9ukExBXgRRVOPp2VCU5fh9VlqUC7ocX5mb\n" +
          "/hxhqR4aumGWkoh86nXojSCmTY0SEePZOlRkvFt/8Eyh+Ac1IgxJmXoL9JwcTtDS\n" +
          "L/MX9VUQvAd0BOk+gaabaGKUglqLErXAsBRPxfCswipfjVyZjchbGZ9rXlpjUz7B\n" +
          "4dMxnXtyadbKbCcmzUZ7IFIx0HQCu31FDbzUsxJAbPfpDV9AwbbpgllbFLVuQz8n\n" +
          "kpW4nHsSvwcKKF304PtpJxXbgsUc36nYAB6MgDimiAG4UkCAUFCPi6rVb+ufwFjl\n" +
          "AjYbxxJvBEkoc3nVj+JsJPTfMQycYinuCqiU4v3rH7CFxiP8BoOEtn0am9tjbpFx\n" +
          "wx7K2/4ymM/YR/YsKEGB5J3/t66Ql7G0sw+7xxkySNv0TH5i2PmTJBJk17/bXVB1\n" +
          "oDA9i9YjFVrOmIvxhzEqQ+5rNNV0g9SNrVMnwI7Jjcuh6x8DCU/EYxcNArz63yKz\n" +
          "kMBPoFrbLa0RJYL5FsyLzeoY7Wsy1+TVperBXUAX+/lYfci2Fexgy7wh+mmSrUE7\n" +
          "Ip+6vGrdBzyV09BlCJ3Cu1cA/XT8MkMVZSUvXqCpwQs738amqrhhvMVVpM+L1T3I\n" +
          "ZdNr6uTGuptssLycI9kLpc1ssFleKW3Zw4tJ9cTkHEruKm83o1+us0J3qefMdW0p\n" +
          "2Hbbc79X4kALGkulDCEey3Ykix+KYyCwB7JUhTdPW7OeECUZe+mi7Mg3vwEcbEIC\n" +
          "3pAyJirJYx8LCXFehrWbIkjXR41Y93T0Oj6H28SOVjGLz8Ab6qhJoRFSpNMCShg7\n" +
          "kQcAYvGRCMo1bBdw15LOOdAMEyoNAzMZA9f/rfCmD9nMQQ==\n" +
          "=o6bw\n" +
          "-----END PGP MESSAGE-----";
  /**
   * Encrypted-To:    recipient@example.com Signed-By:       not signed Compressed:      no
   */
  public final static String IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED =
      "-----BEGIN PGP MESSAGE-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "hQEMA1Sj2zdPeHq3AQf/RLl46D7Abw+UEKjKW5yS3d5WQVTxXvDKJH8yK7lZUp3a\n" +
          "ntH9k3QiL/eFLW7/MZlsQqR4aCjHQsyQVBmGzkKeTNjD67ljr7t7BNtrShBLdEWe\n" +
          "yER8DSnV7F2tf3ba+7udSsNZ/6neTJ6J3/Z+FUmiC+yK3iCExfhbJP4KpvUhEJOt\n" +
          "LwIspR3vIN6U8u/cLXoret50FNamoksZJfCDWwQ/WVqDa3IqiML2L9P8qOEq3mSy\n" +
          "QY6KYnVbuf0NIffEkkDn1Yh1KrPn1CUZLURd7s18LduJ2vofmJIIQ57QN1fpw3zf\n" +
          "MMq1N/vSmZIYAJENHxiSMOm4WrAsQ7db4zCYoLxaTdKFAYjNVw3Xqv3bnnnoUTiQ\n" +
          "eV/X83fC18A7xv+RqKBWSi1noU759rlgRrY9hZdjJWGkJtxhhayL/qNajF46ZFBl\n" +
          "YoneVaRCC7tJQA2SRuZtSCRr/8D9iaXKF7bWylgid4/PK+JRFrB57ZZ8+cKYnT07\n" +
          "znd5CR+Jye1UXfLusnylrlfgKZcCRA==\n" +
          "=q3RN\n" +
          "-----END PGP MESSAGE-----";
  /**
   * Encrypted-To:    sender@example.com Signed-By:       not signed Compressed:      no
   */
  public final static String IMPORTANT_QUOTE_NOT_ENCRYPTED_TO_ME =
      "-----BEGIN PGP MESSAGE-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "hQEMA4bawTgW/m/iAQf/YN/QMvkhVXhBqPyzFFdCfPxMRYaOpH9aM0fHaB4B5AgL\n" +
          "eExiPwmU8s3UcslwUy3C5rRrrQX6YPxH515pExtmKeWlu6yl/x9QJ84n/nCiCRra\n" +
          "gl3V90jsXNsNjqDDETXrztEPcoZBADpH9TYX7YdmR1lRil5//r5Gq8DTDUo6AX2K\n" +
          "2IDZ86jsQtg61TJZbdtuN3RqvfuVkvpWOPcPmbvL/NycX/GNbS5XoLnvoqxzguen\n" +
          "+MPP4NHd4fAeAMYbcBAjrJiIqhJEIQsW8BsngIWJZdRyWsTPKXIdD9Ewl1FjQpRu\n" +
          "dwrRIgc+TqKBpbHQFiQHURBxCznMqbZGqc6pfqFpedKFAVYuq0n4TYNWmcDPeJTX\n" +
          "SIEu8Xz9kvE0aBDNJXXAgVgBStBF5CKwhOMh64cm2DbKI8ECcJbs5DYWmxbMQaoY\n" +
          "khmxsLG7AODfIo777rMtTRPp+1UJvjGAqU0Hebkz79OSeXijvHZ0zpkQexNmSBoK\n" +
          "Mp1o2aStMLdDWHCgJK1Sc2MSvX6Eyw==\n" +
          "=GQV9\n" +
          "-----END PGP MESSAGE-----";
  /**
   * Encrypted-To:    recipient@example.com Signed-By:       sender.signonly@example.com  (DSA, sign
   * only key) Compressed:      no
   */
  public final static String IMPORTANT_QUOTE_SIGNED_BY_SIGN_ONLY_DSA_KEY =
      "-----BEGIN PGP MESSAGE-----\n" +
          "Version: GnuPG v2\n" +
          "\n" +
          "hQEMA1Sj2zdPeHq3AQf9HMO/ADCovbhQcNoo34YxsEg/j7DyMAUZqWXloLbBgynR\n" +
          "g17oROXUsOFnKWt9k/YHTXZtA5MhAb6xOpui7bC9Ux6gYZ421aloT1gmUjT2vuc/\n" +
          "eQ+z/7ZyWsJGBnQ3gBkzre4rvx/wSzhD5aFnDnitCBKeqv5idLCuhrGyAGprxvJL\n" +
          "YkzJPi6XDYu68tOxb049FLUxEn09J6X97YC9D96WFtFntVi+U3KiAuoO1CxIT9fD\n" +
          "GPJvaViqcesz54UAzsDQvRI9sk9Y3zMZd5yxm5L+YaUwJot4SXT07EEW+9gsJVVZ\n" +
          "A9sYQw4PdAmy2xCcp5u2cRMhjjhmS0upCPzQL7qGs9LAMAGexkJhWZo7AWTKbBCT\n" +
          "uD3RHxnjSiKDnmvydkVDBPAMTXI6P0lTxtb1yVCyxnBnpkcI0aHJ/lu07TaXdYDk\n" +
          "YW8UAYbP1Pip8acVtIp9dV2EsoT8cmDEmuI3jQvjgz89V+wcsDkLH8IjGIzqvgDQ\n" +
          "Yevqo5E6QXTMHxFI4y75bmAKy5GMqs7FzdCbwLwBbVYBw6yjlJzXmZc9/Dga+Ou/\n" +
          "Abvu/0HC3dCPxxxpT1rnVThX7YMifX4dxUjahms7ze4Sfjat/3fvklN0mIdoQ7vt\n" +
          "3t8SrgBTRvT3rET2OyaaLAx8hD3lxo03CQxA0uEkrjidUQ==\n" +
          "=qyRp\n" +
          "-----END PGP MESSAGE-----";
  /*
   * Create cipher text by 'echo -n ${IMPORTANT_QUOTE_TEXT} | gpg -e -a -s -r recipient@example.com'
   */
  public final static String IMPORTANT_QUOTE_TEXT = "I love deadlines. I like the whooshing sound they make as they fly by. Douglas Adams";
  public final static String IMPORTANT_QUOTE_SHA256 = "5A341E2D70CB67831E837AC0474E140627913C17113163E47F1207EA5C72F86F";

  private static Map<Long, char[]> BUILD_ALL_KEYRINGS_PASSWORDS() {
    Map<Long, char[]> m = new HashMap<>();
    m.put(ExampleMessages.KEY_ID_SENDER, "sender".toCharArray());
    m.put(ExampleMessages.KEY_ID_SENDER_2, "sender2".toCharArray());
    m.put(ExampleMessages.KEY_ID_SENDER_DSA_SIGN_ONLY, "sign".toCharArray());
    m.put(ExampleMessages.KEY_ID_ANOTHER_SENDER, "another_sender".toCharArray());

    m.put(ExampleMessages.PUBKEY_ID_RECIPIENT, "recipient".toCharArray());

    return Collections.unmodifiableMap(m);
  }

}
