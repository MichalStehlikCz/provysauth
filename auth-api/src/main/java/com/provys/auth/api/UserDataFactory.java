package com.provys.auth.api;

import com.provys.common.crypt.DtEncryptedString;
import com.provys.common.datatype.DtUid;
import java.sql.Connection;

public interface UserDataFactory {

  /**
   * Retrieve user data object with supplied characteristics.
   *
   * @param userId      is Id of user data item belongs to
   * @param shortNameNm is short name of user
   * @param fullName    is full name of user account
   * @param dbToken     is database token, used to switch database session
   * @return user data token
   */
  UserData getUserData(DtUid userId, String shortNameNm, String fullName,
      DtEncryptedString dbToken);

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
