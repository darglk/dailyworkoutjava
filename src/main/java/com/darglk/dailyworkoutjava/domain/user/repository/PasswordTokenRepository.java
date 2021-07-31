package com.darglk.dailyworkoutjava.domain.user.repository;

import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import com.darglk.dailyworkoutjava.domain.user.entity.PasswordResetToken;
import org.springframework.data.repository.CrudRepository;


/**
 * Repository for PasswordResetToken class.
 * @author Dariusz Kulig
 *
 */
public interface PasswordTokenRepository extends CrudRepository<PasswordResetToken, String> {

	/**
	 * Method used for finding password reset token instance by token string value.
	 * @param token - string value used to be found in db.
	 * @return - found password reset token instance.
	 */
	PasswordResetToken findByToken(String token);

	/**
	 * Method used for finding password reset token instance by given user id.
	 * @param user - user instance with id used to be found in db.
	 * @return - found password reset token instance.
	 */
	PasswordResetToken findByUser(AppUser user);
}