package com.darglk.dailyworkoutjava.domain.user.request;

import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;
import com.darglk.dailyworkoutjava.utils.ValidationErrorMessages;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * Model containing new user account data.
 * 
 * @author darglk
 *
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationRequestModel {

	/**
	 * userData - wrapper for user-specific account data.
	 */
	@Valid
	@NotNull(message = ValidationErrorMessages.USER_DATA_ATTRIBUTES_NOT_NULL_MESSAGE)
	private UserDataRequestModel userData;

	/**
	 * password - password wrapper (contains confirmation of password).
	 */
	@Valid
	@NotNull(message = ValidationErrorMessages.PASSWORDS_NOT_EMPTY_MESSAGE)
	private PasswordRequestModel passwords;
}
