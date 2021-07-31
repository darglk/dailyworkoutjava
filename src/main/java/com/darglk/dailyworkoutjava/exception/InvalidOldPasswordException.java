package com.darglk.dailyworkoutjava.exception;

public class InvalidOldPasswordException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6961131345069217215L;

	public InvalidOldPasswordException(String message) {
		super(message);
	}
}
