package net.greg.jwt.claims;

import java.util.*;
import java.util.stream.Collectors;

import org.json.JSONObject;

import net.greg.jwt.utils.Base64Utils;


/**
 *
 */
public abstract class Claims {

  private final Registered[] registeredDateClaims =
    { Registered.EXPIRATION_TIME, Registered.ISSUED_AT, Registered.NOT_BEFORE };


  protected final Map<String, Object> claims;


  protected Claims() {
    claims = new HashMap();
  }


  public boolean containsClaim(String name) {
    return claims.containsKey(name);
  }


  public Map<String, Object> getAsMap() {
    return new HashMap(claims);
  }


  public String base64Encoded() {

    String json =
      new JSONObject(claims).toString();

    return Base64Utils.encodeBase64URL(json);
  }


  /**
   * Get a claim by name and cast it to a specific type
   *
   * @param name of the claim
   * @param type of the claim
   * @return claim value cast to specified type
   */
  @SuppressWarnings("unchecked")
  public <T> T getClaim(String name, Class<T> type) {

    Object value = claims.get(name);

System.err.println("\n Claims.getClaim()");
System.err.println("   name: " + name);
System.err.println("   type: " + type);
System.err.println("   eval: " + value);

    boolean isDateClaim =
      Arrays.
        stream(registeredDateClaims).
          map(Claims.Registered::getValue).
            collect(Collectors.toList()).
              contains(name);

System.err.println("isDateClaim == " + isDateClaim);

    if (isDateClaim) {

      long millisSinceEpoch =
        Long.parseLong(String.valueOf(value));

System.err.println(
  "FANCY " +
  (T) new Date(millisSinceEpoch));

      return (T) new Date(millisSinceEpoch);
    }

System.err.println(
  "PLAIN, type.cast " + type.cast(value) + "\n");

    return type.cast(value);
  }


  public Object getClaim(String name, ClaimConverter converter) {

    return converter.convert(claims.get(name));
  }


  public void addClaim(String name, Object value) {

    if (name == null) { throw new IllegalArgumentException("'name' cannot be null"); }
    if (value == null) { throw new IllegalArgumentException("'value' cannot be null"); }

    claims.put(name, value);
  }


  public enum Registered {

    ISSUER("iss"),
    SUBJECT("sub"),
    AUDIENCE("aud"),
    EXPIRATION_TIME("exp"),
    NOT_BEFORE("nbf"),
    ISSUED_AT("iat"),
    JWT_ID("jti"),
    TYPE("typ"),
    CONTENT_TYPE("cty"),
    ALGORITHM("alg");


    private final String value;
    public String getValue() { return value; }
    Registered(String any) { value = any; }
  }
}
