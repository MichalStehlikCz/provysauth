package com.provys.auth.api;

import com.provys.common.datatype.DtUid;
import com.provys.common.exception.InternalException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public final class ProvysUserContext implements UserContext {

  @Override
  public UserData getCurrentUser() {
    SecurityContext context = SecurityContextHolder.getContext();
    Authentication authentication = context.getAuthentication();
    if (authentication == null) {
      throw new InternalException("Cannot retrieve current user - session not authenticated");
    }
    return (UserData) authentication.getPrincipal();
  }

  @Override
  public DtUid getCurrentUserId() {
    return getCurrentUser().getUserId();
  }
}
