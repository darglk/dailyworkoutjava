package com.darglk.dailyworkoutjava.domain.user.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * UserData Data Transfer Object
 * @author darglk
 *
 */
@Data
@NoArgsConstructor
public class UserDataDTO {
	/**
	 * email - user email address
	 */
	private String email;
}
