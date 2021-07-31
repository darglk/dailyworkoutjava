package com.darglk.dailyworkoutjava.domain.user.mappers;

import com.darglk.dailyworkoutjava.domain.user.dto.UserDTO;
import com.darglk.dailyworkoutjava.domain.user.dto.UserDataDTO;
import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import com.darglk.dailyworkoutjava.domain.user.response.UserDataResponse;

public class UserModelMapping {

	public static UserDTO of(AppUser user) {
		UserDTO userDTO = new UserDTO();
		userDTO.setUserId(user.getId());
		UserDataDTO userDataDTO = new UserDataDTO();
		userDataDTO.setEmail(user.getEmail());
		userDTO.setUserData(userDataDTO);
		return userDTO;
	}

	public static UserDataResponse res(UserDTO user) {
		UserDataResponse response = new UserDataResponse();
		response.setEmail(user.getUserData().getEmail());
		return response;
	}
}
