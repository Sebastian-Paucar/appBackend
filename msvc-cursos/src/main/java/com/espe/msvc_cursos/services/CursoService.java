package com.espe.msvc_cursos.services;

import com.espe.msvc_cursos.models.entity.Curso;
import com.espe.msvc_cursos.models.entity.Usuario;

import java.util.List;
import java.util.Optional;

public interface CursoService {
    List<Curso> listar();
    Optional<Curso> porId(Long id);
    Curso guardar(Curso curso);
    void eliminar(Long id);

    Optional<Usuario> agregarUsuario(Usuario usuario, Long idCurso, String token);

    Optional<Usuario> eliminarUsuario(Long idUsuario, Long idCurso, String token);

    Optional<Curso> findByNombre(String nombre);

    Optional<Usuario> agregarUsuarioConToken(Usuario usuario, Long idcurso, String accessToken);
}


