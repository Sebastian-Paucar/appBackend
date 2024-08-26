package com.espe.msvc.usuarios.services;

import com.espe.msvc.usuarios.models.entity.Role;
import com.espe.msvc.usuarios.models.entity.Usuario;
import com.espe.msvc.usuarios.repositories.RoleRepository;
import com.espe.msvc.usuarios.repositories.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class UsuarioServiceImpl implements UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UsuarioServiceImpl(UsuarioRepository usuarioRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional(readOnly = true)
    public List<Usuario> listar() {
        return (List<Usuario>) usuarioRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<Usuario> porId(Long id) {
        return usuarioRepository.findById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<Usuario> porEmail(String email) {
        return usuarioRepository.findByEmail(email);
    }

    @Override
    @Transactional
    public Usuario guardar(Usuario usuario) {
        // Encriptamos la contraseña antes de guardar si es nueva o ha sido modificada
        if (usuario.getPassword() != null) {
            usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
        }

        // Guardamos los roles si no existen
        Set<Role> rolesGuardados = new HashSet<>();
        for (Role role : usuario.getRoles()) {
            // Buscar el rol por su nombre
            Optional<Role> roleExistente = roleRepository.findByRole(role.getRole());
            if (roleExistente.isEmpty()) {
                rolesGuardados.add(roleRepository.save(role));
            } else {
                rolesGuardados.add(roleExistente.get());
            }
        }
        usuario.setRoles(rolesGuardados);

        return usuarioRepository.save(usuario);
    }

    @Override
    @Transactional
    public void eliminar(Long id) {
        usuarioRepository.deleteById(id);
    }

    @Override
    @Transactional
    public Optional<Usuario> buscarPorNombre(String nombre) {
        return usuarioRepository.findByNombre(nombre);
    }

    @Override
    @Transactional
    public Usuario actualizar(Long id, Usuario usuarioActualizado) {
        Optional<Usuario> usuarioExistente = usuarioRepository.findById(id);

        if (usuarioExistente.isPresent()) {
            Usuario usuario = usuarioExistente.get();

            usuario.setNombre(usuarioActualizado.getNombre());
            usuario.setEmail(usuarioActualizado.getEmail());

            // Encriptamos la nueva contraseña si se ha proporcionado
            if (usuarioActualizado.getPassword() != null) {
                usuario.setPassword(passwordEncoder.encode(usuarioActualizado.getPassword()));
            }

            // Actualizamos los roles
            Set<Role> rolesGuardados = new HashSet<>();
            for (Role role : usuarioActualizado.getRoles()) {
                Optional<Role> roleExistente = roleRepository.findByRole(role.getRole());
                if (roleExistente.isEmpty()) {
                    rolesGuardados.add(roleRepository.save(role));
                } else {
                    rolesGuardados.add(roleExistente.get());
                }
            }
            usuario.setRoles(rolesGuardados);

            return usuarioRepository.save(usuario);
        }

        return null;  // o lanza una excepción si el usuario no existe
    }
}
