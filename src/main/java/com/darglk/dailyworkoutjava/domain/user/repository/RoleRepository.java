package com.darglk.dailyworkoutjava.domain.user.repository;

import com.darglk.dailyworkoutjava.domain.user.entity.Role;
import com.darglk.dailyworkoutjava.domain.user.entity.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, String> {
	public Role findByName(RoleName roleName);
}
