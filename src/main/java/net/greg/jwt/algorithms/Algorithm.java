package net.greg.jwt.algorithms;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;


/**
 * Serves as an API for concrete implementation classes
 */
public abstract class Algorithm {


  Algorithm(String moniker, String desc) {
    name = moniker;
    description = desc;
  }


  /**
   *
   */
  public static Algorithm HMAC256(String secret) {
    return new HMACAlgorithm("HS256", "HmacSHA256", secret.getBytes(StandardCharsets.UTF_8));
  }

  /**
   *
   */
  public static Algorithm HMAC384(String secret) {
    return new HMACAlgorithm("HS384", "HmacSHA384", secret.getBytes(StandardCharsets.UTF_8));
  }


  /**
   *
   */
  public static Algorithm HMAC512(String secret) {
    return new HMACAlgorithm("HS512", "HmacSHA512", secret.getBytes(StandardCharsets.UTF_8));
  }


  /**
   *
   */
  public static Algorithm RSA256(KeyPair keyPair) {
    return new RSAAlgorithm("RS256", "SHA256withRSA", keyPair);
  }

  /**
   *
   */
  public static Algorithm RSA384(KeyPair keyPair) {
    return new RSAAlgorithm("RS384", "SHA384withRSA", keyPair);
  }

  /**
   *
   */
  public static Algorithm RSA512(KeyPair keyPair) {
    return new RSAAlgorithm("RS512", "SHA512withRSA", keyPair);
  }


  /**
   *
   */
  public abstract boolean verify(byte[] data, byte[] expected) throws Exception;


  /**
   *
   */
  public abstract byte[] sign(String data) throws Exception;

  /**
   *
   */
  public abstract byte[] sign(byte[] data) throws Exception;


  /**
   *
   */
  protected final String name;

  /**
   *
   */
  public String getName() { return name; }


  /**
   *
   */
  protected final String description;

  /**
   *
   */
  public String getDescription() { return description; }
}
