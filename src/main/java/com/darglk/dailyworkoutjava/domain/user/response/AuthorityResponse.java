package com.darglk.dailyworkoutjava.domain.user.response;

import com.darglk.dailyworkoutjava.domain.user.entity.AuthorityName;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AuthorityResponse {
	private String id;
	private AuthorityName name;
}
