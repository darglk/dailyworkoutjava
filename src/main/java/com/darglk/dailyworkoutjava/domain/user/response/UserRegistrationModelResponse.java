package com.darglk.dailyworkoutjava.domain.user.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationModelResponse {
	private String userId;
	private UserDataResponse userData;
}
