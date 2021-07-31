package com.darglk.dailyworkoutjava.domain.user.request.validator;

import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class PasswordsEqualValidator implements ConstraintValidator<PasswordsEqual, Object> {

	@Override
	public boolean isValid(Object value, ConstraintValidatorContext context) {
		if (value instanceof PasswordRequestModel) {
			return ((PasswordRequestModel) value).arePasswordsEqual();
		}
		return false;
	}
}
