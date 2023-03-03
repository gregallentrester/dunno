package net.greg.jwt;

import java.nio.charset.StandardCharsets;
import java.util.*;

import org.json.JSONException;

import net.greg.jwt.algorithms.Algorithm;

import net.greg.jwt.claims.*;

import net.greg.jwt.utils.Base64Utils;

/**
 *
 */
public final class Token {

  /**
   * Three (3) distinct segments comprise a valid Token
   *  <ul>
   *    <li> Header                         </li>
   *    <li> Payload                        </li>
   *    <li> Signature &ndash; a HashOf
   *         the Header &amp; the Payload)   </li>
   *  </ul>
   **/
  private static final int NUMBER_OF_SEGMENTS = 3;

  private final Algorithm algorithm;
  private final Header header;
  private final Payload payload;
  private final String signature;


  public Token(Algorithm algo, Header hdr, Payload pay) throws Exception {

    algorithm = algo;
    header = hdr;
    payload = pay;
    signature = createSignature();
  }


  private Token(Algorithm algo, Header hdr, Payload pay, String sign) {

    algorithm = algo;
    header = hdr;
    payload = pay;
    signature = sign;
  }


  private Token(Builder builder) throws Exception {

    algorithm = builder.algorithm;
    payload = builder.payload;
    header = builder.header;
    signature = createSignature();
  }


  public Algorithm getAlgorithm() { return algorithm; }

  public Payload getPayload() { return payload; }

  public Header getHeader() { return header; }

  public String getSignature() { return signature; }


  /**
   * Create a new JWT instance based on a raw JWT
   *
   * @param algorithm algorithm to use when signing JWT
   * @param jwt Raw JWT
   * @return Newly created JWT instance
   * @throws Exception When the raw JWT could not be decoded
   */
  public static Token fromRawToken(Algorithm algorithm, String jwt) throws Exception {

    String[] segments = jwt.split("\\.");

    if (segments.length != NUMBER_OF_SEGMENTS) {
      throw new Exception("The number of segments must be " + NUMBER_OF_SEGMENTS);
    }

    try {

      Header header = Header.fromBase64EncodedJSON(segments[0]);
      Payload payload = Payload.fromBase64EncodedJSON(segments[1]);
      String signature = segments[2];

      if ( ! header.getAlgorithm().equals(algorithm.getName())) {
        throw new Exception("Algorithm defined in header does not match " + algorithm.getName());
      }

      return new Token(algorithm, header, payload, signature);
    }
    catch (IllegalArgumentException | JSONException e) {
      throw new Exception("Error decoding Token");
    }
  }


  /**
   * Checks whether the JWT is valid or not with a custom validator
   *
   * @param validator JWT Validator
   * @throws Exception when JWT is not valid
   */
  public void validate(TokenValidator validator) throws Exception {
    validator.validate(this);
  }


  /**
   * Checks whether the JWT is valid or not with the default JWT validator
   *
   * @throws Exception when JWT is not valid
   */
  public void validate() throws Exception {
    validate(new TokenValidator());
  }


  /**
   * Create a new JWT
   *
   * @return A new JWT
   * @throws Exception when JWT could not be created
   */
  public String sign() throws Exception {

    return
      String.format(
        "%s.%s.%s",
        header.base64Encoded(),
        payload.base64Encoded(),
        signature);
  }


  /**
  * Create signature based on algorithm, header and payload
  *
  * @return Created signature
  * @throws Exception when Sign exception occurs
  */
  private String createSignature() throws Exception {

    try {

      String concatenated =
        String.format(
          "%s.%s",
          header.base64Encoded(),
          payload.base64Encoded());

      byte[] signed =
        algorithm.sign(
          concatenated.getBytes(StandardCharsets.UTF_8));

      return Base64Utils.encodeBase64URL(signed);
    }
    catch (Exception e) {
      throw new Exception(e.getMessage());
    }
  }


  public static class Builder {

    private final Algorithm algorithm;
    private Header header;
    private Payload payload;


    /**
     * Creates a new JWT Builder instance
     *
     * @param algo algorithm to use when signing JWT
     */
    public Builder(Algorithm algo) {

      if (algo == null) {
        throw new IllegalArgumentException("Algorithm must not be null");
      }

      algorithm = algo;
      header = new Header();
      payload = new Payload();

      header.setAlgorithm(algorithm.getName());
    }


    /**
     * Add type (typ) claim to header
     *
     * @param type type header
     * @return the same builder instance
     */
    public Builder withType(String type) {

      header.setType(type);
      return this;
    }


    /**
     * Add a content type (cty) claim to header
     *
     * @param contentType content type value
     * @return the same builder instance
     */
    public Builder withContentType(String contentType) {
      header.setContentType(contentType);
      return this;
    }


    /**
     * Add an issuer (iss) claim to payload
     *
     * @param issuer issuer value
     * @return the same builder instance
     */
    public Builder withIssuer(String issuer) {
      payload.setIssuer(issuer);
      return this;
    }


    /**
     * Add a subject (sub) claim to payload
     *
     * @param subject subject value
     * @return the same builder instance
     */
    public Builder withSubject(String subject) {
      payload.setSubject(subject);
      return this;
    }


    /**
     * Add an audience (aud) claim to payload
     *
     * @param audience audience value
     * @return the same builder instance
     */
    public Builder withAudience(String... audience) {
      payload.setAudience(audience);
      return this;
    }


    /**
     * Add an expiration time (exp) to payload
     *
     * @param expirationTime expiration time as date
     * @return the same builder instance
     */
    public Builder withExpirationTime(Date expirationTime) {
      payload.setExpirationTime(expirationTime);
      return this;
    }


    /**
     * Add an expiration time (exp) to payload
     *
     * @param timeSinceEpoch Milliseconds since January 1, 1970
     * @return the same builder instance
     */
    public Builder withExpirationTime(long timeSinceEpoch) {
      payload.setExpirationTime(timeSinceEpoch);
      return this;
    }


    /**
     * Add a not-before (nbf) claim to payload
     *
     * @param notBefore not before date object
     * @return the same builder instance
     */
    public Builder withNotBefore(Date notBefore) {
      payload.setNotBefore(notBefore);
      return this;
    }


    /**
     * Add a not-before (nbf) claim to payload
     *
     * @param timeSinceEpoch Milliseconds since January 1, 1970
     * @return the same builder instance
     */
    public Builder withNotBefore(long timeSinceEpoch) {
      payload.setNotBefore(timeSinceEpoch);
      return this;
    }


    /**
     * Add an issued at (iat) claim to payload
     *
     * @param issuedAt issued at date
     * @return the same builder instance
     */
    public Builder withIssuedAt(Date issuedAt) {
      payload.setIssuedAt(issuedAt);
      return this;
    }


    /**
     * Add an issued at (iat) claim to payload
     *
     * @param timeSinceEpoch Milliseconds since January 1, 1970
     * @return the same builder instance
     */
    public Builder withIssuedAt(long timeSinceEpoch) {
      payload.setIssuedAt(timeSinceEpoch);
      return this;
    }


    /**
     * Add a key ID (kid) to the header claims
     *
     * @param id the key ID
     * @return the same builder instance
     */
    public Builder withID(String id) {
      payload.setID(id);
      return this;
    }


    /**
     * Add a header claim
     *
     * @param name name of header claim
     * @param value value of header claim
     */
    public Builder withHeader(String name, String value) {

      if (name == null || value == null) {
        throw new IllegalArgumentException("Header value cannot be null");
      }

      header.addClaim(name, value);
      return this;
    }


    /**
     * Set the header. This will replace the current header
     *
     * @param headerVal Header data
     * @return the same builder instance
     */
    public Builder withHeader(Header headerVal) {

      if (header == null)  {
        throw new IllegalArgumentException("Header cannot be null");
      }

      header = headerVal;

      return this;
    }


    /**
     * Set the payload. This will replace the current payload
     *
     * @param payVal Payload data
     * @return the same builder instance
     */
    public Builder withPayload(Payload payVal) {

      if (payload == null) { throw new IllegalArgumentException("Payload cannot be null"); }

      payload = payVal;

      return this;
    }


    /**
     * Add a claim to the payload
     *
     * @param name name of payload claim
     * @param value value of payload claim
     * @return the same builder instance
     */
    public Builder withClaim(String name, Object value) {

      if (name == null || value == null) {
        throw new IllegalArgumentException("Claim value cannot be null");
      }

      payload.addClaim(name, value);

      return this;
    }


    /**
     * Add multiple claims to payload
     *
     * @param claims the values used in the payload
     */
    public Builder withClaim(Map<String, ?> claims) {

      for (Map.Entry<String, ?> claim: claims.entrySet()) {
        withClaim(claim.getKey(), claim.getValue());
      }

      return this;
    }


    /**
     * Creates a new Token
     *
     * @return a new Token
     * @throws Exception when the Token could not be created
     */
    public String sign() throws Exception {

      if ( ! header.containsClaim(Claims.Registered.TYPE.getValue())) {
        withType("JWT");
      }

      return new Token(this).sign();
    }


    /**
     * Creates a new Token with additional payload
     *
     * @param payload map of additional payload
     * @return  String representation of the Token
     * @throws Exception when the JWT could not be created
     */
    public String sign(Map<String, ?> payload) throws Exception {

      withClaim(payload);

      return sign();
    }


    /**
     * Create a new Token instance
     *
     * @return New Token instance
     */
    public Token build() throws Exception {

      return new Token(this);
    }
  }
}
