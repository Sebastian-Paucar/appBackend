package com.espe.msvc_cursos.controllers;

import com.espe.msvc_cursos.models.entity.Curso;
import com.espe.msvc_cursos.models.entity.Usuario;
import com.espe.msvc_cursos.services.CursoService;
import feign.FeignException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/cursos")
public class CursoController {

    @Autowired
    private CursoService service;
    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'ROLE_ADMIN')")
    @GetMapping
    public List<Curso> listar() {
        return service.listar();
    }


    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'ROLE_ADMIN')")
    @GetMapping("/{id}")
    public ResponseEntity<?> detalle(@PathVariable Long id) {
        Optional<Curso> cursoOptional = service.porId(id);
        if (cursoOptional.isPresent()) {
            return ResponseEntity.ok().body(cursoOptional.get());
        }
        return ResponseEntity.notFound().build();
    }
    @PreAuthorize("hasAuthority( 'ROLE_ADMIN')")
    @PostMapping
    public ResponseEntity<?> crear(@Valid @RequestBody Curso curso, BindingResult result) {
        if (result.hasErrors()) {
            return validar(result);
        }

        // Verificar si ya existe un curso con el mismo nombre (u otro atributo único)
        Optional<Curso> cursoExistente = service.findByNombre(curso.getNombre());
        if (cursoExistente.isPresent()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("El curso ya existe");
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(service.guardar(curso));
    }

    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'ROLE_ADMIN')")
    @PutMapping("/{id}")
    public ResponseEntity<?> editar(@Valid @RequestBody Curso curso, BindingResult result, @PathVariable Long id) {
        if (result.hasErrors()) {
            return validar(result);
        }
        Optional<Curso> cursoOptional = service.porId(id);
        if (cursoOptional.isPresent()) {
            Curso cursoDB = cursoOptional.get();
            cursoDB.setNombre(curso.getNombre());
            return ResponseEntity.status(HttpStatus.CREATED).body(service.guardar(cursoDB));
        }
        return ResponseEntity.notFound().build();
    }
    @PreAuthorize("hasAuthority( 'ROLE_ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<?> eliminar(@PathVariable Long id) {
        Optional<Curso> cursoOptional = service.porId(id);
        if (cursoOptional.isPresent()) {
            service.eliminar(id);
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }

    private static ResponseEntity<Map<String, String>> validar(BindingResult result) {
        Map<String, String> errores = new HashMap<>();
        result.getFieldErrors().forEach(error -> {
            errores.put(error.getField(), "El campo " + error.getField() + " " + error.getDefaultMessage());
        });
        return ResponseEntity.badRequest().body(errores);
    }
    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'ROLE_ADMIN')")
    @PutMapping("/asignar-usuario/{idcurso}")
    public ResponseEntity<?> asignarUsuario(@RequestBody Usuario usuario, @PathVariable Long idcurso) {
        Optional<Usuario> o;
        try {
            // Obtener el access_token desde el contexto de seguridad
            String accessToken = "Bearer " + getAccessToken();

            // Llamar al servicio que se comunica con el microservicio de usuarios
            o = service.agregarUsuarioConToken(usuario, idcurso, accessToken);
        } catch (FeignException e) {
            // Manejar la excepción específica de Feign
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body(Collections.singletonMap("mensaje", "Error de comunicación con otro servicio: " + e.getMessage()));
        } catch (Exception e) {
            // Manejar cualquier otra excepción no específica
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("mensaje", "Error interno del servidor: " + e.getMessage()));
        }
        if (o.isPresent()) {
            return ResponseEntity.status(HttpStatus.CREATED).body(o.get());
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("mensaje", "El usuario no fue encontrado o no pudo ser asignado al curso."));
        }
    }

    @PreAuthorize("hasAuthority( 'ROLE_ADMIN')")
    @DeleteMapping("/eliminar-usuario/{idcurso}")
    public ResponseEntity<?> eliminarUsuario(@RequestParam Long usuarioId, @PathVariable Long idcurso) {

        String accessToken = "Bearer " + getAccessToken();
        try {
            Optional<Usuario> optionalUsuario = service.eliminarUsuario(usuarioId, idcurso, accessToken);

            if (optionalUsuario.isPresent()) {
                return ResponseEntity.status(HttpStatus.OK)
                        .body(Collections.singletonMap("mensaje", "Usuario eliminado exitosamente"));
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Collections.singletonMap("mensaje", "Usuario no encontrado en el curso especificado"));
            }
        } catch (FeignException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("mensaje", "Error en la comunicación con el servicio remoto: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("mensaje", "Error interno del servidor: " + e.getMessage()));
        }
    }
    public String getAccessToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
            return jwtToken.getToken().getTokenValue();  // Devuelve el token JWT
        }
        return null;
    }
}


