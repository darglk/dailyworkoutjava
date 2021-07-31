package com.darglk.dailyworkoutjava.domain.user.request;

import com.darglk.dailyworkoutjava.utils.ValidationErrorMessages;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

/**
 * This model is used when user submits an email address to /forgot_password
 * endpoint.
 * 
 * @author darglk
 *
 */
@Data
@NoArgsConstructor
public class ForgotPasswordRequestModel {

	/**
	 * email - email of user who has forgotten his password.
	 */
	@NotBlank(message = ValidationErrorMessages.EMAIL_NOT_BLANK_MESSAGE)
	@Email(message = ValidationErrorMessages.EMAIL_INVALID_MESSAGE)
	private String email;
}
