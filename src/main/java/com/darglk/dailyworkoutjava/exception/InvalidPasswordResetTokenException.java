package com.darglk.dailyworkoutjava.exception;

public class InvalidPasswordResetTokenException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6944210213404910992L;

	public InvalidPasswordResetTokenException(String message) {
		super(message);
	}
}
