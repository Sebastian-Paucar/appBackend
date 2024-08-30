package com.espe.msvc_cursos.clients;

import com.espe.msvc_cursos.models.entity.Usuario;
import  org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name = "msvc-usuarios", url = "http://msvc-usuarios:8001/usuarios")
public interface UsuarioClientRest {

    @GetMapping("/{id}")
    Usuario detalle(@PathVariable Long id, @RequestHeader("Authorization") String token);
}


