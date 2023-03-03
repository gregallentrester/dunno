package net.greg.jwt.claims;

/**
 *
 */
public interface ClaimValidator {
  boolean validate(Object value);
}
