package com.provys.auth.api;

import com.google.errorprone.annotations.Immutable;
import com.provys.common.crypt.DtEncryptedString;
import com.provys.common.datatype.DtUid;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Data structure that provides information about currently connected user, that can be consumed
 * by service.
 */
@Immutable
final class ProvysUserData implements UserData {

  private static final long serialVersionUID = -8230441895302242132L;

  private final DtUid userId;
  private final String shortNameNm;
  private final String fullName;
  private final DtEncryptedString dbToken;

  /**
   * Create provys user data value object based on provided information.
   *
   * @param userId is Provys Uid of logged in user
   * @param shortNameNm is short name (natural key of user account)
   * @param fullName is display name associated with logged in user
   * @param dbToken is token that can be used to switch database session to this user context
   */
  ProvysUserData(DtUid userId, String shortNameNm, String fullName, DtEncryptedString dbToken) {
    this.userId = userId;
    this.shortNameNm = shortNameNm;
    this.fullName = fullName;
    this.dbToken = dbToken;
  }

  @Override
  public DtUid getUserId() {
    return userId;
  }

  @Override
  public String getShortNameNm() {
    return shortNameNm;
  }

  @Override
  public String getFullName() {
    return fullName;
  }

  @Override
  public DtEncryptedString getDbToken() {
    return dbToken;
  }

  @SuppressWarnings("SuspiciousGetterSetter") // needed to implement principal interface
  @Override
  public String getName() {
    return shortNameNm;
  }

  @Override
  public boolean equals(@Nullable Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ProvysUserData that = (ProvysUserData) o;
    return userId.equals(that.userId)
        && shortNameNm.equals(that.shortNameNm)
        && fullName.equals(that.fullName)
        && dbToken.equals(that.dbToken);
  }

  @Override
  public int hashCode() {
    // Id is unique and thus sufficient for hash code calculation
    return userId.hashCode();
  }

  @Override
  public String toString() {
    return "ProvysUserData{"
        + "userId=" + userId
        + ", shortNameNm='" + shortNameNm + '\''
        + ", fullName='" + fullName + '\''
        // dbToken is intentionally omitted, as it is secret
        + '}';
  }
}
