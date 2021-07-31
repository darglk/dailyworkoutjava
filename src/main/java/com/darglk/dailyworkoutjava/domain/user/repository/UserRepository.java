package com.darglk.dailyworkoutjava.domain.user.repository;

import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<AppUser, String> {

	AppUser findAppUserByUserDataEmail(String email);

	@Query(value = "FROM AppUser a WHERE a.userData.email LIKE %?1% ORDER BY a.id", countQuery = "SELECT COUNT (a) FROM AppUser a WHERE a.userData.email LIKE %?1%", nativeQuery = false)
	Page<AppUser> findByUserDataEmail(String search, Pageable pageable);
}
