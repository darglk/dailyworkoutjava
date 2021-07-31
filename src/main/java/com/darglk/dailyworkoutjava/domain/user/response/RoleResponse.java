package com.darglk.dailyworkoutjava.domain.user.response;

import com.darglk.dailyworkoutjava.domain.user.entity.RoleName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RoleResponse {
	private String id;
	private RoleName name;
}
