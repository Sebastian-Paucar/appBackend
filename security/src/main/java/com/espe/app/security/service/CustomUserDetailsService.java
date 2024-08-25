package com.espe.app.security.service;

import com.espe.app.security.client.UsuarioClient;

import com.espe.app.security.entity.RoleName;
import com.espe.app.security.entity.Usuario;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UsuarioClient usuarioClient;

    @Autowired
    public CustomUserDetailsService(UsuarioClient usuarioClient) {
        this.usuarioClient = usuarioClient;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario usuario = usuarioClient.buscarPorEmail(email);
        if (usuario == null) {
            throw new UsernameNotFoundException("Usuario no encontrado: " + email);
        }

        // Convertir roles a una lista de Strings, sin el prefijo ROLE_
        String[] roles = usuario.getRoles().stream()
                .map(role -> role.getRole().name().replace("ROLE_", "")) // Elimina el prefijo ROLE_
                .toArray(String[]::new);

        return User.builder()
                .username(usuario.getEmail())
                .password(usuario.getPassword()) // Ya debe estar encriptada
                .roles(roles) // Asigna los roles correctamente sin el prefijo ROLE_
                .build();
    }

}


