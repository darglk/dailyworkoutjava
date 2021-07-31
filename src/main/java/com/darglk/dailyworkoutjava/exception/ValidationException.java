package com.darglk.dailyworkoutjava.exception;

import org.springframework.validation.Errors;

/**
 * Exception class which should be thrown when given model contains validation
 * errors.
 * 
 * @author darglk
 *
 */
public class ValidationException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8352099489250430048L;

	/**
	 * errors - model validation errors.
	 */
	private Errors errors;

	public ValidationException(Errors errors) {
		super("");
		this.errors = errors;
	}

	public Errors getErrors() {
		return errors;
	}

	public void setErrors(Errors errors) {
		this.errors = errors;
	}
}
