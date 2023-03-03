package net.greg.jwt.algorithms;

import java.nio.charset.StandardCharsets;
import java.security.*;


/**
 *
 */
public final class RSAAlgorithm extends Algorithm {

  private final KeyPair keyPair;

  RSAAlgorithm(String name, String description, KeyPair keyPr) {
    super(name, description);
    keyPair = keyPr;
  }

  /**
   *
   */
  @Override
  public byte[] sign(String data) throws Exception {
    return sign(data.getBytes(StandardCharsets.UTF_8));
  }

  /**
   *
   */
  @Override
  public byte[] sign(byte[] data) throws Exception {

    try {

      final Signature signature =
        Signature.getInstance(description);

      signature.initSign(keyPair.getPrivate());
      signature.update(data);

      return signature.sign();
    }
    catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new Exception(e.getMessage());
    }
  }

  /**
   *
   */
  @Override
  public boolean verify(byte[] data, byte[] expected) throws Exception {

    try {

      final Signature signature =
        Signature.getInstance(description);

      signature.initVerify(keyPair.getPublic());
      signature.update(data);

      return signature.verify(expected);
    }
    catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new Exception(e.getMessage());
    }
  }
}
