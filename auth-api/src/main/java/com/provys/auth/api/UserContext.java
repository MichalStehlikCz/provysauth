package com.provys.auth.api;

import com.provys.common.datatype.DtUid;

/**
 * Allows applications to abstract from Spring security when accessing current logged-in user.
 */
public interface UserContext {

  /**
   * Get data about authenticated user.
   *
   * @return authenticated user description
   */
  UserData getCurrentUser();

  /**
   * Provys user Id of current logged in user.
   *
   * @return Provys user Id of current logged in user.
   */
  DtUid getCurrentUserId();
}
