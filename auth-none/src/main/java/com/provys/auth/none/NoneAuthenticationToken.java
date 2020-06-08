package com.provys.auth.none;

import com.provys.common.exception.InternalException;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * Authentication token, carrying no information about principal nor rights. Enables to call
 * {@link NoneAuthProvider} without reading anything from request, providing anonymous access
 * with used defined by environment.
 */
public final class NoneAuthenticationToken extends AbstractAuthenticationToken {

  private static final NoneAuthenticationToken INSTANCE = new NoneAuthenticationToken();
  private static final long serialVersionUID = 6379795557131208263L;

  /**
   * Retrieve empty authentication token.
   *
   * @return singleton instance of None authentication token
   */
  public static NoneAuthenticationToken getInstance() {
    return INSTANCE;
  }

  private NoneAuthenticationToken() {
    super(null);
  }

  @Override
  public Object getCredentials() {
    return "";
  }

  @Override
  public Object getPrincipal() {
    return "";
  }

  @Override
  public void setAuthenticated(boolean authenticated) {
    if (authenticated) {
      throw new InternalException("Set authorised not allowed in None authentication token");
    }
  }

  @Override
  public void setDetails(Object details) {
    throw new InternalException("Set details not allowed in None authentication token");
  }

  @Override
  public String toString() {
    return "NoneAuthenticationToken{"
        + ", " + super.toString() + '}';
  }
}
