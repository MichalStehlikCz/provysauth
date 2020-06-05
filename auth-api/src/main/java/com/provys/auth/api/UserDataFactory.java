package com.provys.auth.api;

import com.provys.common.datatype.DtUid;
import java.sql.Connection;

public interface UserDataFactory {

  /**
   * Retrieve user data object from supplied connection.
   *
   * @param connection is connection user data should be read from
   * @return user data read from connection
   */
  UserData getUserData(Connection connection);

  /**
   * Retrieve user data for specified user. Technical user must be able to impersonate this user in
   * order for function to work.
   *
   * @param userId is Id of user whose data we want to read
   * @return user data record for given user
   */
  UserData getUserData(DtUid userId);
}
