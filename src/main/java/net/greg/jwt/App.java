package net.greg.jwt;

import net.greg.jwt.delegate.*;


/*
  This app calls JWT-based routines that model two scenarios:

  <ul>
    <li>Model an intentional FAIL </li>
    <li>Make an attempt date reflect yesterday, and the NBF Claim reflect today.</li>
    <br>
    <br>
    <li>Nodel an intentional SUCCESS</li>
    <li>Make the attempt date reflect tomorrow, and the NBF Claim reflect today.</li>
  </ul>
*/
public final class App {

  /**
   * Make delegating calls which model an intentional JWT SUCCESS, followed by an intentional JWT FAIL.
   */
  public static void main(String[] args) throws Exception {

    ClaimsForgeryDetectionDelegate.simulateValidNotBefore();
    ClaimsForgeryDetectionDelegate.simulateInvalidNotBefore();
  }


  public static final String RED = "\033[1;91m";
  public static final String GRN = "\033[1;92m";
  public static final String YLW = "\033[1;93m";
  public static final String NC = "\u001B[0m";
}
