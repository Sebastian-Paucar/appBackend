package com.espe.app.security.client;
import com.espe.app.security.entity.Usuario;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertNotNull;


@SpringBootTest
public class UsuariotTest {

    @Autowired
    private UsuarioClient usuarioClient;

    @Test
    public void testBuscarPorName() {
        // Reemplaza "nombreDeUsuario" con un nombre válido para la prueba
        String nombreDeUsuario = "Pedro";

        Usuario usuario = usuarioClient.buscarPorEmail(nombreDeUsuario);

        // Verificar que el usuario no es nulo
        assertNotNull(usuario);
        assertNotNull(usuario);


    }
}