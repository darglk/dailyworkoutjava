package com.darglk.dailyworkoutjava.exception;

public class TokenBlacklistedException extends RuntimeException {
	/**
	 * 
	 */
	private static final long serialVersionUID = -1445873918467814780L;

	public TokenBlacklistedException(String message) {
		super(message);
	}
}
