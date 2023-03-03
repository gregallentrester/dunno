package net.greg.jwt;

import java.nio.charset.StandardCharsets;
import java.util.*;

import net.greg.jwt.claims.*;

/**
 *
 */
public final class TokenValidator {

  private final Map<String, ClaimValidator> headerValidators;
  private final Map<String, ClaimValidator> payloadValidators;


  public TokenValidator() {
    this(new Builder().withType("JWT"));
  }


  public TokenValidator(Builder builder) {

    this.headerValidators = builder.headerValidators;
    this.payloadValidators = builder.payloadValidators;
  }


  // @Override
  public final void validate(Token token) throws Exception {

    validateAlgorithm(token);
    verifyValidators(token.getHeader().getAsMap(), headerValidators);
    verifyPayload(token.getPayload());
  }


  private void validateAlgorithm(Token token) throws Exception {

    String concatenated =
      String.format(
        "%s.%s",
        token.getHeader().base64Encoded(),
        token.getPayload().base64Encoded());

    byte[] concatenatedBytes =
      concatenated.getBytes(StandardCharsets.UTF_8);

    if ( ! token.getAlgorithm().verify(concatenatedBytes, Base64.getUrlDecoder().decode(token.getSignature()))) {
      throw new Exception("Signature is not valid");
    }
  }


  private void verifyValidators(
      Map<String, Object> map,
      Map<String, ClaimValidator> validators) throws Exception {

    for (Map.Entry<String, ClaimValidator> validatorEntry : validators.entrySet()) {

      String key =
        validatorEntry.getKey();

      ClaimValidator validator =
        validatorEntry.getValue();

      if ( ! map.containsKey(key)) {
        throw new Exception(key + " is not present in payload");
      }

      if (map.get(key) == null) {
        throw new Exception(key + " is null");
      }

      if ( ! validator.validate(map.get(key))) {
        throw new Exception(key + " does not conform to constraint");
      }
    }
  }


  private void verifyPayload(Payload payload) throws Exception {

    Date currentDate = new Date();

    validateExpirationTime(payload, currentDate);
    validateNotBefore(payload, currentDate);
    verifyValidators(payload.getAsMap(), payloadValidators);
  }


  private void validateNotBefore(Payload payload, Date currentDate) throws Exception {

    // Checks that if the not-before (nbf) claim is set,
    // the current date is after or equal to the not-before date.
    if (payload.containsClaim(Claims.Registered.NOT_BEFORE.getValue())) {

      Date notBefore = payload.getNotBefore();

      if ( ! (currentDate.getTime() > notBefore.getTime())) {
        throw new Exception("JWT is only valid after " + notBefore);
      }
    }
  }


  private void validateExpirationTime(Payload payload, Date currentDate) throws Exception {

    if (payload.containsClaim(Claims.Registered.EXPIRATION_TIME.getValue())) {

      Date expirationTime = payload.getExpirationTime();

      if (currentDate.getTime() > expirationTime.getTime()) {
        throw new Exception("JWT expired on " + expirationTime);
      }
    }
  }


  public final Map<String, ClaimValidator> getHeaderValidators() {
    return new HashMap(headerValidators);
  }


  public final Map<String, ClaimValidator> getPayloadValidators() {
    return new HashMap(payloadValidators);
  }



  public static class Builder {

    private final Map<String, ClaimValidator> headerValidators;
    private final Map<String, ClaimValidator> payloadValidators;


    public Builder() {
      this.headerValidators = new HashMap();
      this.payloadValidators = new HashMap();
    }

    public Builder withType(String type) {
      withHeader(Claims.Registered.TYPE.getValue(), type::equals);
      return this;
    }


    public Builder withContentType(String type) {
      withHeader(Claims.Registered.CONTENT_TYPE.getValue(), type::equals);
      return this;
    }


    public Builder withAlgorithm(String algorithm) {
      withHeader(Claims.Registered.ALGORITHM.getValue(), algorithm::equals);
      return this;
    }


    public Builder withIssuer(String issuer) {
      withClaim(Claims.Registered.ISSUER.getValue(), issuer::equals);
      return this;
    }


    public Builder withSubject(String subject) {
      withClaim(Claims.Registered.SUBJECT.getValue(), subject::equals);
      return this;
    }


    public Builder withOneOfAudience(String... audience) {

      withClaim(Claims.Registered.AUDIENCE.getValue(), value -> {

        for (String audienceItem: audience) {

          if (Arrays.asList((Object[]) value).contains(audienceItem)) {
            return true;
          }
        }

        return false;
      });

      return this;
    }


    public Builder withAllOfAudience(String... audience) {

      withClaim(Claims.Registered.AUDIENCE.getValue(), value -> {
        String[] values = (String[]) value;
        return Arrays.asList(values).containsAll(Arrays.asList(audience));
      });

      return this;
    }


    public Builder withExpirationTime(Date expirationTime) {
      withClaim(Claims.Registered.EXPIRATION_TIME.getValue(), value ->
      value.equals(expirationTime.getTime()));
      return this;
    }


    public Builder withExpirationTime(long timeSinceEpoch) {
      withClaim(Claims.Registered.EXPIRATION_TIME.getValue(), value ->
      value.equals(timeSinceEpoch));
      return this;
    }


    public Builder withNotBefore(Date notBefore) {
      withClaim(Claims.Registered.NOT_BEFORE.getValue(), value ->
      value.equals(notBefore.getTime()));
      return this;
    }


    public Builder withNotBefore(long timeSinceEpoch) {
      withClaim(Claims.Registered.NOT_BEFORE.getValue(), value ->
      value.equals(timeSinceEpoch));
      return this;
    }


    public Builder withIssuedAt(Date issuedAt) {
      withClaim(Claims.Registered.ISSUED_AT.getValue(), value ->
      value.equals(issuedAt.getTime()));
      return this;
    }


    public Builder withIssuedAt(long timeSinceEpoch) {
      withClaim(Claims.Registered.ISSUED_AT.getValue(), value ->
      value.equals(timeSinceEpoch));
      return this;
    }


    public Builder withID(String id) {
      withClaim(Claims.Registered.JWT_ID.getValue(), id::equals);
      return this;
    }


    public Builder withHeader(String name, Object value) {
      withHeader(name, value::equals);
      return this;
    }


    public Builder withHeader(String name, ClaimValidator validator) {

      if (name == null) { throw new IllegalArgumentException("name cannot be null"); }
      if (validator == null) { throw new IllegalArgumentException("validator cannot be null"); }

      headerValidators.put(name, validator);
      return this;
    }


    public Builder withClaim(String name, Object value) {
      withClaim(name, value::equals);
      return this;
    }


    public Builder withClaim(String name, ClaimValidator validator) {
      if (name == null) { throw new IllegalArgumentException("name cannot be null"); }
      if (validator == null) { throw new IllegalArgumentException("validator cannot be null"); }

      payloadValidators.put(name, validator);
      return this;
    }


    public TokenValidator build() {
      return new TokenValidator(this);
    }
  }
}
