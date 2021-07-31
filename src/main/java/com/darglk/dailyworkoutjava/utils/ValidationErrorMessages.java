package com.darglk.dailyworkoutjava.utils;

public class ValidationErrorMessages {

	private static final String PASSWORD_MESSAGE_RULE = " is invalid. It should contain at least one: digit, "
			+ "upper, lower case letter, special character and its length should be in range from 6 to 60 chars";
	
	private static final String PASSWORD_NOT_NULL_RULE = " must not be null";
	
	private static final String PASSWORD_NOT_EMPTY_RULE = " must not be empty";
	
	public static final String INVALID_PASSWORD_MESSAGE = "Password" + PASSWORD_MESSAGE_RULE;
	
	public static final String INVALID_OLD_PASSWORD_MESSAGE = "Old password" + PASSWORD_MESSAGE_RULE;
	
	public static final String INVALID_PASSWORD_CONFIRMATION_MESSAGE = "Password confirmation" + PASSWORD_MESSAGE_RULE;

	public static final String PASSWORDS_NOT_EQUAL_MESSAGE = "Passwords are not equal";

	public static final String OLD_PASSWORD_NOT_NULL_MESSAGE = "Old password" + PASSWORD_NOT_NULL_RULE;

	public static final String OLD_PASSWORD_NOT_EMPTY_MESSAGE = "Old password" + PASSWORD_NOT_EMPTY_RULE;
	
	public static final String PASSWORD_NOT_NULL_MESSAGE = "Password" + PASSWORD_NOT_NULL_RULE;

	public static final String PASSWORD_NOT_EMPTY_MESSAGE = "Password" + PASSWORD_NOT_EMPTY_RULE;
	
	public static final String PASSWORD_CONFIRMATION_NOT_NULL_MESSAGE = "Password confirmation" + PASSWORD_NOT_NULL_RULE;

	public static final String PASSWORD_CONFIRMATION_NOT_EMPTY_MESSAGE = "Password confirmation" + PASSWORD_NOT_EMPTY_RULE;

	public static final String OLD_PASSWORD_DOES_NOT_MATCH = "Old password does not match";

	public static final String EMAIL_NOT_NULL_MESSAGE = "Email address cannot be empty";

	public static final String EMAIL_INVALID_MESSAGE = "Invalid email address";

	public static final String USERNAME_EXISTS_MESSAGE = "Username already exists";

	public static final String USER_NOT_FOUND_MESSAGE = "Username does not exist!";

	public static final String INVALID_ACTIVATION_TOKEN_EXCEPTION = "Invalid activation token";

	public static final String INVALID_PASSWORD_RESET_TOKEN_MESSAGE = "Invalid reset token";

	public static final String PASSWORD_RESET_TOKEN_EXPIRED_MESSAGE = "Token is expired";

	public static final String EMAIL_NOT_BLANK_MESSAGE = "Email address cannot be blank";

	public static final String USER_DATA_ATTRIBUTES_NOT_NULL_MESSAGE = "User data attributes cannot be null";

	public static final String USER_ENABLED_NOT_EMPTY_MESSAGE = "User enabled flag must be not empty";

	public static final String AUTHORITY_IDS_NOT_NULL_MESSAGE = "Authority ids must not be empty";

	public static final String ROLE_IDS_NOT_NULL_MESSAGE = "Role ids must not be empty";

	public static final String USER_ID_NOT_NULL_MESSAGE = "User ID must not be empty";

	public static final String PASSWORDS_NOT_EMPTY_MESSAGE = "Passwords cannot be empty";
	
	public static final String PHONE_NUMBER_NOT_EMPTY_MESSAGE = "Phone number cannot be empty";
	
	public static final String ADDRESS_NOT_EMPTY_MESSAGE = "Address cannot be empty";

	public static final String QUANTITY_HIGHER_THAN_ZERO_MESSAGE = "Quantity must be greater than zero";

	public static final String QUANTITY_NOT_EMPTY_MESSAGE = "Quantity cannot be empty";

	public static final String PRODUCT_ID_NOT_EMPTY_MESSAGE = "Product ID cannot be empty";

	public static final String CUSTOMER_ID_NOT_EMPTY_MESSAGE = "Customer ID cannot be empty";

	public static final String ORDER_MUST_HAVE_DETAILS_MESSAGE = "Order must have information about ordered products";

	public static final String PRODUCT_NAME_NOT_EMPTY_MESSAGE = "Product name cannot be empty";

	public static final String PRODUCT_PRICE_NOT_EMPTY_MESSAGE = "Product price cannot be empty";

	public static final String PRODUCT_PRICE_HIGHER_THAN_ZERO_MESSAGE = "Product price must be greater than zero";

	public static final String CUSTOMER_NOT_FOUND_MESSAGE = "Customer was not found";

	public static final String PRODUCT_NOT_FOUND_MESSAGE = "Product was not found";

	public static final String ORDER_ID_NOT_NULL_MESSAGE = "Order ID must not be empty";

	public static final String ORDER_STATUS_NOT_BLANK_MESSAGE = "Order status must not be blank";

	public static final String ORDER_NOT_FOUND_MESSAGE = "Order not found";

	public static final String CUSTOMER_EMAIL_EXISTS_MESSAGE = "Customer with given email already exists";

	public static final String CUSTOMER_PHONE_EXISTS_MESSAGE = "Customer with given phone already exists";
	
	public static final String FIRST_NAME_NOT_EMPTY_MESSAGE = "First name cannot be empty";
	
	public static final String SECOND_NAME_NOT_EMPTY_MESSAGE = "Second name cannot be empty";
	
	public static final String EMAIL_NOT_EMPTY_MESSAGE = "Email cannot be empty";
	
	public static final String INVALID_EMAIL_MESSAGE = "Email is invalid";

	public static final String INVALID_ORDER_STATUS_MESSAGE = "Invalid order status";
}
