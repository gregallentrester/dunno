package net.greg.jwt.delegate;

import java.time.Instant;
import java.util.Date;

import net.greg.jwt.algorithms.Algorithm;

import net.greg.jwt.*;


public final class ClaimsForgeryDetectionDelegate {

  /**
   *
   */
  public static final void simulateInvalidNotBefore() throws Exception {

    final int TOMORROW_SECONDS_DISPLACEMENT = 86_400;

    Date tomorrow =
      Date.from(Instant.
        now().plusSeconds(TOMORROW_SECONDS_DISPLACEMENT));

    Date now = Date.from(Instant.now());


  System.err.println(
    "\n\n Expect VIOLATION" +
    " | withInvalidNotBefore_throwsException()" +
    "\n\n -------->>--->>> tomorrow " + tomorrow +
    "\n -------->>--->>>    today " + now + "\n\n");

    Token token =
      new Token.Builder(algorithm).
        withNotBefore(tomorrow).build();

    TokenValidator validator =
      new TokenValidator.Builder().
        withNotBefore(tomorrow).build();

    /// validator.validate(token);
  }


  /**
   *
   */
  public static final void simulateValidNotBefore() throws Exception {

    final int YESTERDAY_SECONDS_DISPLACEMENT = 86_400;

    Date yesterday =
      Date.from(Instant.
        now().minusSeconds(YESTERDAY_SECONDS_DISPLACEMENT));

    Date now = Date.from(Instant.now());


    System.err.println(
      "\n\n Expect COMPLIANCE" +
      " | withValidNotBefore_noThrow()" +
      "\n\n -------->>--->>> yesterday " + yesterday +
      "\n -------->>--->>>     today " + now + "\n\n");


    Token token =
      new Token.Builder(algorithm).
        withNotBefore(yesterday).build();

    TokenValidator validator =
      new TokenValidator.Builder().
        withNotBefore(yesterday).build();

    validator.validate(token);
  }


  private static final String SECRET = "secret";
  private static final String JWT = "JWT";

  private static final String ALGO_HS384 = "HS384";

  private static Algorithm algorithm;


  static {
    algorithm = Algorithm.HMAC384(SECRET);
  }


  public static final String RED = "\033[1;91m";
  public static final String GRN = "\033[1;92m";
  public static final String YLW = "\033[1;93m";
  public static final String NC = "\u001B[0m";
}
