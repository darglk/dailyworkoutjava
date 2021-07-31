package com.darglk.dailyworkoutjava.domain.user.request;

import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;
import com.darglk.dailyworkoutjava.utils.ValidationErrorMessages;
import com.darglk.dailyworkoutjava.utils.ValidationRules;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

/**
 * This model is used by /change_password endpoint when user wants to change his
 * password to the application.
 * 
 * @author darglk
 *
 */
@Data
@NoArgsConstructor
public class ChangePasswordRequestModel {

	/**
	 * oldPassword - current user password.
	 */
	@Pattern(regexp = ValidationRules.PASSWORD_REGEX, message = ValidationErrorMessages.INVALID_OLD_PASSWORD_MESSAGE)
	@NotBlank(message = ValidationErrorMessages.OLD_PASSWORD_NOT_EMPTY_MESSAGE)
	private String oldPassword;

	/**
	 * password - wrapper for new password (with confirmation).
	 */
	@Valid
	@NotNull(message = ValidationErrorMessages.PASSWORDS_NOT_EMPTY_MESSAGE)
	private PasswordRequestModel passwords;
}
