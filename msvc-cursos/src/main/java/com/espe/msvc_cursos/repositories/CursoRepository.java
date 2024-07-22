package com.espe.msvc_cursos.repositories;


import com.espe.msvc_cursos.models.entity.Curso;
import org.springframework.data.repository.CrudRepository;

public interface CursoRepository extends CrudRepository<Curso, Long> {
}
