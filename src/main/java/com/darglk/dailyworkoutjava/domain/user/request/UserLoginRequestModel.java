package com.darglk.dailyworkoutjava.domain.user.request;

import com.darglk.dailyworkoutjava.utils.ValidationRules;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

/**
 * Model containing credentials of a given user.
 * 
 * @author darglk
 *
 */
@Data
@NoArgsConstructor
public class UserLoginRequestModel {

	/**
	 * email - login to the application.
	 */
	@Email
	@NotBlank
	private String email;

	/**
	 * password - non hashed password value.
	 */
	@NotBlank
	@Pattern(regexp = ValidationRules.PASSWORD_REGEX)
	private String password;
}