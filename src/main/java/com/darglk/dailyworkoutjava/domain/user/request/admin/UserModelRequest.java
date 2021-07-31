package com.darglk.dailyworkoutjava.domain.user.request.admin;

import com.darglk.dailyworkoutjava.domain.user.request.UserDataRequestModel;
import com.darglk.dailyworkoutjava.utils.ValidationErrorMessages;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.Set;

/**
 * Model used for creating new user by admin.
 * 
 * @author darglk
 *
 */
@Data
@NoArgsConstructor
public class UserModelRequest {

	/**
	 * userId - user ID in DB.
	 */
	private Long userId;

	/**
	 * userData - user-specific account data.
	 */
	@Valid
	@NotNull(message = ValidationErrorMessages.USER_DATA_ATTRIBUTES_NOT_NULL_MESSAGE)
	private UserDataRequestModel userData;

	/**
	 * password - wrapper for user password.
	 */
	@Valid
	@NotNull(message = ValidationErrorMessages.PASSWORDS_NOT_EMPTY_MESSAGE)
	private PasswordRequestModel passwords;

	/**
	 * enabled - boolean value which determines if user account should be
	 * enabled/disabled.
	 */
	@NotNull(message = ValidationErrorMessages.USER_ENABLED_NOT_EMPTY_MESSAGE)
	private Boolean enabled;

	/**
	 * authorityIds - IDs of authorities for newly created user.
	 */
	@NotNull(message = ValidationErrorMessages.AUTHORITY_IDS_NOT_NULL_MESSAGE)
	private Set<String> authorityIds;

	/**
	 * roleIds - IDs of roles for newly created user.
	 */
	@NotNull(message = ValidationErrorMessages.ROLE_IDS_NOT_NULL_MESSAGE)
	private Set<String> roleIds;
}
