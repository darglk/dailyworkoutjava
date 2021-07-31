package com.darglk.dailyworkoutjava.domain.user.response.admin;

import com.darglk.dailyworkoutjava.domain.user.dto.UserDataDTO;
import com.darglk.dailyworkoutjava.domain.user.response.AuthorityResponse;
import com.darglk.dailyworkoutjava.domain.user.response.RoleResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserModelResponse {
	private String userId;

	private UserDataDTO userData;

	private Boolean enabled;

	private Date lastAccountUpdateDate;

	private Set<AuthorityResponse> authorities = new HashSet<>();

	private Set<RoleResponse> roles = new HashSet<>();
}
