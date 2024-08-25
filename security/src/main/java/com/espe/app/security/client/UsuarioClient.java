package com.espe.app.security.client;


import com.espe.app.security.entity.Usuario;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;


@FeignClient(name = "msvc-usuarios", url = "http://localhost:8001")
public interface UsuarioClient {

    @GetMapping("/usuarios/email/{email}")
    Usuario buscarPorEmail(@PathVariable("email") String name);
}