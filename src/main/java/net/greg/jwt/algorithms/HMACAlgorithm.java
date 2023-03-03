package net.greg.jwt.algorithms;

import java.nio.charset.StandardCharsets;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 */
public final class HMACAlgorithm extends Algorithm {

  /**
   *
   */
  private final byte[] secret;

  /**
   *
   */
  HMACAlgorithm(String name, String desc, byte[] secretBytes) {
    super(name, desc);
    secret = secretBytes;
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

      Mac mac = Mac.getInstance(description);

      SecretKeySpec secretKey = new SecretKeySpec(secret, description);
      mac.init(secretKey);

      return mac.doFinal(data);
    }
    catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new Exception(e.getMessage());
    }
  }

  /**
   *
   */
  @Override
  public boolean verify(byte[] data, byte[] expected) throws Exception {

    try {

      byte[] signed = sign(data);

      return Arrays.equals(signed, expected);
    }
    catch (Exception e) {
      throw new Exception(e.getMessage());
    }
  }
}
