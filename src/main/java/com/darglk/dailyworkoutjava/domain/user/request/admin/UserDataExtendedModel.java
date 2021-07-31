package com.darglk.dailyworkoutjava.domain.user.request.admin;


import com.darglk.dailyworkoutjava.domain.user.request.UserDataRequestModel;
import com.darglk.dailyworkoutjava.utils.ValidationErrorMessages;

import javax.validation.constraints.NotNull;
import java.util.Set;

/**
 * Extension of UserDataRequest. Should be used only by admin endpoints.
 * 
 * @author darglk
 *
 */
public class UserDataExtendedModel extends UserDataRequestModel {

	/**
	 * enabled - boolean field determining if user account should be
	 * enabled/disabled.
	 */
	@NotNull(message = ValidationErrorMessages.USER_ENABLED_NOT_EMPTY_MESSAGE)
	private Boolean enabled;

	/**
	 * authorityIds - IDs of authorities for a given user.
	 */
	@NotNull(message = ValidationErrorMessages.AUTHORITY_IDS_NOT_NULL_MESSAGE)
	private Set<String> authorityIds;

	/**
	 * roleIds - IDs of roles for a given user.
	 */
	@NotNull(message = ValidationErrorMessages.ROLE_IDS_NOT_NULL_MESSAGE)
	private Set<String> roleIds;

	public UserDataExtendedModel(String email, Boolean enabled, Set<String> authorityIds,
			Set<String> roleIds) {
		super(email);
		this.enabled = enabled;
		this.authorityIds = authorityIds;
		this.roleIds = roleIds;
	}

	public UserDataExtendedModel() {
		super();
	}

	public Boolean getEnabled() {
		return enabled;
	}

	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}

	public Set<String> getAuthorityIds() {
		return authorityIds;
	}

	public void setAuthorityIds(Set<String> authorityIds) {
		this.authorityIds = authorityIds;
	}

	public Set<String> getRoleIds() {
		return roleIds;
	}

	public void setRoleIds(Set<String> roleIds) {
		this.roleIds = roleIds;
	}
}
