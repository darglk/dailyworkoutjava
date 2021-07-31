package com.darglk.dailyworkoutjava.domain.user.dto;

import com.darglk.dailyworkoutjava.domain.user.entity.AuthorityName;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Authority Data Transfer Object
 * @author darglk
 *
 */
@Data
@NoArgsConstructor
public class AuthorityDTO {
	/**
	 * id - authority id
	 */
	private Long id;
	/**
	 * name - authority name
	 */
	private AuthorityName name;
}
