package com.espe.msvc.usuarios.services;

import com.espe.msvc.usuarios.enums.RoleName;
import com.espe.msvc.usuarios.models.entity.Role;
import com.espe.msvc.usuarios.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import java.util.List;

@Service
public class RoleService {
    @Autowired
    private RoleRepository roleRepository;

    public List<Role> getAllRoles() {
        return (List<Role>) roleRepository.findAll();
    }
}
