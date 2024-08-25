package com.espe.msvc.usuarios.repositories;

import com.espe.msvc.usuarios.models.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
 Optional<Usuario>findByEmail(String email);
 Optional<Usuario>findByNombre(String nombre);
}
