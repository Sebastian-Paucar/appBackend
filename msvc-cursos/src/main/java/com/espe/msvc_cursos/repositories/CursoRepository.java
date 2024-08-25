package com.espe.msvc_cursos.repositories;


import com.espe.msvc_cursos.models.entity.Curso;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface CursoRepository extends CrudRepository<Curso, Long> {
    Optional<Curso> findByNombre(String nombre);
}
