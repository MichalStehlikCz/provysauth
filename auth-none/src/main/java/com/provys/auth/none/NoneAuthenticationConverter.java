package com.provys.auth.none;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * Converter that converts any request into NoneAuthenticationToken. Used to allow inclusion of
 * NoneAuthProvider without having any information in request.
 */
public final class NoneAuthenticationConverter implements AuthenticationConverter {

  private static final NoneAuthenticationConverter INSTANCE = new NoneAuthenticationConverter();

  public static NoneAuthenticationConverter getInstance() {
    return INSTANCE;
  }

  private NoneAuthenticationConverter() {
  }

  @Override
  public Authentication convert(HttpServletRequest httpServletRequest) {
    return NoneAuthenticationToken.getInstance();
  }
}
