package com.espe.msvc.usuarios.services;

import com.espe.msvc.usuarios.enums.RoleName;
import com.espe.msvc.usuarios.models.entity.Role;
import com.espe.msvc.usuarios.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;
@Service
public class RoleService {
    private final RoleRepository roleRepository;
    @Autowired
    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public Optional<Role> findRole(RoleName roleName) {
        return roleRepository.findByRole(roleName);
    }
}
