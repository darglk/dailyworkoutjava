package com.darglk.dailyworkoutjava.utils;

/**
 * Utility class containing email messages for this application.
 * @author darglk
 *
 */
public class MailMessages {

	//TODO: change these values for production mode
	public static final String APP_MAIL_ADDRESS = "test@test.com";
	public static final String WELCOME_MESSAGE = "Hello World";
	public static final String PASSWORD_RESET_LINK_SUBJECT = "Password Reset";
	public static final String RESET_PASSWORD_MESSAGE = "Hello World";

	private MailMessages() {}
	
	public static String ACCOUNT_ACTIVATION_LINK_SUBJECT = "Activate account";
}
