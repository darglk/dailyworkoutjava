package com.darglk.dailyworkoutjava.exception;

public class PasswordResetTokenExpiredException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -8785021979017439356L;

	public PasswordResetTokenExpiredException(String message) {
		super(message);
	}
}
