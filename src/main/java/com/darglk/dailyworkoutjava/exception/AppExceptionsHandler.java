package com.darglk.dailyworkoutjava.exception;

import com.darglk.dailyworkoutjava.domain.user.response.ErrorMessage;
import com.darglk.dailyworkoutjava.domain.user.response.ModelValidationError;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@ControllerAdvice
public class AppExceptionsHandler {

	@ExceptionHandler(value = { Exception.class, TokenBlacklistedException.class })
	public ResponseEntity<Object> handleOtherExceptions(Exception ex, WebRequest webRequest) {

		ErrorMessage errorMessage = new ErrorMessage(new Date(), ex.getMessage());

		return new ResponseEntity<>(errorMessage, new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);
	}

	@ExceptionHandler(value = { ValidationException.class })
	public ResponseEntity<Object> handlePasswordValidationException(ValidationException ex, WebRequest webRequest) {
		ModelValidationError errors = new ModelValidationError();
		ex.getErrors().getAllErrors().forEach(oe -> {
			String fieldName = oe instanceof FieldError ? ((FieldError) oe).getField() : "other";
			if (fieldName.contains(".")) {
				String[] fieldNames = fieldName.split("\\.");
				fieldName = fieldNames[fieldNames.length - 1];
			}
			errors.getErrors().compute(fieldName, (k, v) -> {
				if (v == null) {
					List<String> errorList = new ArrayList<>();
					errorList.add(oe.getDefaultMessage());
					return errorList;
				}
				v.add(oe.getDefaultMessage());
				return v;
			});
		});
		return new ResponseEntity<>(errors, new HttpHeaders(), HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(value = { InvalidOldPasswordException.class, UsernameAlreadyExistsException.class,
			PasswordResetTokenExpiredException.class })
	public ResponseEntity<Object> handleValuesInDb(Exception ex, WebRequest webRequest) {

		ErrorMessage errorMessage = new ErrorMessage(new Date(), ex.getMessage());

		return new ResponseEntity<>(errorMessage, new HttpHeaders(), HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(value = { AccessDeniedException.class })
	public ResponseEntity<Object> handleAccessDenied(AccessDeniedException ex, WebRequest webRequest) {

		ErrorMessage errorMessage = new ErrorMessage(new Date(), ex.getMessage());

		return new ResponseEntity<>(errorMessage, new HttpHeaders(), HttpStatus.UNAUTHORIZED);
	}

	@ExceptionHandler(value = { UsernameNotFoundException.class, InvalidActivationTokenException.class,
			InvalidPasswordResetTokenException.class })
	public ResponseEntity<Object> handleNotFoundExceptions(Exception ex, WebRequest webRequest) {
		ErrorMessage errorMessage = new ErrorMessage(new Date(), ex.getMessage());

		return new ResponseEntity<>(errorMessage, new HttpHeaders(), HttpStatus.NOT_FOUND);
	}
}