package com.provys.auth.mock;

import com.google.errorprone.annotations.Immutable;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Defines username + password pair for use with mock provider.
 */
@Immutable
public final class UsernamePasswordPair {

  private final String userName;
  private final String password;

  UsernamePasswordPair(String userName, String password) {
    this.userName = userName;
    this.password = password;
  }

  /**
   * Value of field userName.
   *
   * @return value of field userName
   */
  public String getUserName() {
    return userName;
  }

  /**
   * Value of field password.
   *
   * @return value of field password
   */
  public String getPassword() {
    return password;
  }

  @Override
  public boolean equals(@Nullable Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UsernamePasswordPair that = (UsernamePasswordPair) o;
    return userName.equals(that.userName)
        && password.equals(that.password);
  }

  @Override
  public int hashCode() {
    int result = userName.hashCode();
    result = 31 * result + password.hashCode();
    return result;
  }

  @Override
  public String toString() {
    return "UsernamePasswordPair{"
        + "userName='" + userName + '\''
        + ", password='" + password + '\''
        + '}';
  }
}
