package com.provys.auth.api;

import com.google.errorprone.annotations.Immutable;
import com.provys.common.datatype.DtUid;
import java.util.Objects;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Data structure that provides information about currently connected user, that can be consumed
 * by service.
 */
@Immutable
public final class ProvysUserData implements UserData {

  private static final long serialVersionUID = -8230441895302242132L;

  private final DtUid userId;
  private final String shortNameNm;
  private final String fullName;

  /**
   * Create provys user data value object based on provided information.
   *
   * @param userId is Provys Uid of logged in user
   * @param shortNameNm is short name (natural key of user account)
   * @param fullName is display name associated with logged in user
   */
  public ProvysUserData(DtUid userId, String shortNameNm, String fullName) {
    this.userId = userId;
    this.shortNameNm = shortNameNm;
    this.fullName = fullName;
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
    return Objects.equals(userId, that.userId)
        && Objects.equals(shortNameNm, that.shortNameNm)
        && Objects.equals(fullName, that.fullName);
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
        + '}';
  }
}
