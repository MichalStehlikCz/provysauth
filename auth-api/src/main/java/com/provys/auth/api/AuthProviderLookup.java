package com.provys.auth.api;

import com.provys.common.exception.InternalException;
import java.util.Locale;
import java.util.Objects;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.stereotype.Component;

/**
 * Class allows lookup of authentication provider bean by name.
 *
 * <p>Note that it does not register authentication providers - appropriate libraries must be
 * included by application using this look-up, otherwise lookup will fail with message that bean has
 * not been found.
 */
@Component
public class AuthProviderLookup {

  private final ApplicationContext applicationContext;

  @Autowired
  AuthProviderLookup(ApplicationContext applicationContext) {
    this.applicationContext = Objects.requireNonNull(applicationContext);
  }

  /**
   * Retrieve authentication provider bean for given authentication provider name.
   *
   * @param name is used to look up authentication provider
   * @return authentication provider instance (bean)
   */
  public AuthenticationProvider getAuthProvider(String name) {
    var upperName = name.toUpperCase(Locale.ENGLISH);
    AuthProviders authProviderDef;
    try {
      authProviderDef = AuthProviders.valueOf(upperName);
    } catch (IllegalArgumentException e) {
      throw new InternalException("Invalid authentication provider name " + upperName, e);
    }
    try {
      return applicationContext
          .getBean(authProviderDef.getBeanName(), AuthenticationProvider.class);
    } catch (BeansException e) {
      throw new InternalException("Authentication provider bean retrieval failed for name "
          + authProviderDef.name() + ", bean name " + authProviderDef.getBeanName(), e);
    }
  }

  @Override
  public String toString() {
    return "AuthProviderLookup{"
        + "applicationContext=" + applicationContext
        + '}';
  }
}
