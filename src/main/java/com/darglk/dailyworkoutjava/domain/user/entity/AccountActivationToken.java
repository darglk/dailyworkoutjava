package com.darglk.dailyworkoutjava.domain.user.entity;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.UUID;

/**
 * Model representing account activation token. It is stored in DB when user signs up to the page.
 * @author Dariusz Kulig
 *
 */
@Entity
@Data
@NoArgsConstructor
public class AccountActivationToken {

	/**
	 * id - token id.
	 */
	@Id
	@Column(name = "account_activation_token_id")
	private String id = UUID.randomUUID().toString();
	
	/**
	 * token - generated random string value used to reset the password.
	 */
	@Column(name = "token", nullable = false)
	@NotNull(message = "token cannot be empty.")
	private String token;

	/**
	 * user - user which signed up to the page.
	 */
	@OneToOne(targetEntity = AppUser.class, fetch = FetchType.EAGER)
	@JoinColumn(nullable = false, name = "app_user_id")
	@NotNull(message = "app_user_id cannot be empty.")
	private AppUser user;
	
	@Override
	public String toString() {
		return "token: " + token;
	}
}
