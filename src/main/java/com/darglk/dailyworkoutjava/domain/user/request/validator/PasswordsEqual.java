package com.darglk.dailyworkoutjava.domain.user.request.validator;


import com.darglk.dailyworkoutjava.utils.ValidationErrorMessages;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = { PasswordsEqualValidator.class })
public @interface PasswordsEqual {
	String message() default ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE;

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};
}
