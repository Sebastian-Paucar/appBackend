package com.espe.msvc.usuarios.repositories;

import com.espe.msvc.usuarios.enums.RoleName;
import com.espe.msvc.usuarios.models.entity.Role;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RoleRepository extends CrudRepository<Role, Integer> {
    Optional<Role> findByRole(RoleName roleName); // Corregido: findByRole
}
