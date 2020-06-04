package com.provys.auth.api;

import com.google.errorprone.annotations.Immutable;
import com.provys.common.crypt.DtEncryptedString;
import com.provys.common.datatype.DtUid;
import java.io.Serializable;
import java.security.Principal;

/**
 * User data is data object that describes user context derived from authentication.
 */
@Immutable
public interface UserData extends Principal, Serializable {

  /**
   * Value of field userId.
   *
   * @return value of field userId
   */
  DtUid getUserId();

  /**
   * Value of field shortNameNm.
   *
   * @return value of field shortNameNm
   */
  String getShortNameNm();

  /**
   * Value of field fullName.
   *
   * @return value of field fullName
   */
  String getFullName();

  /**
   * Get database token, usable for login within this user context.
   *
   * @return database token, usable for login within this user context.
   */
  DtEncryptedString getDbToken();
}
