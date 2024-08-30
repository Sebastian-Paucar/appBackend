package com.espe.msvc_cursos.services;

import com.espe.msvc_cursos.clients.UsuarioClientRest;
import com.espe.msvc_cursos.models.entity.Curso;
import com.espe.msvc_cursos.models.entity.CursoUsuario;
import com.espe.msvc_cursos.models.entity.Usuario;
import com.espe.msvc_cursos.repositories.CursoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class CursoServiceImpl implements CursoService {
    @Autowired
    private CursoRepository repository;

    @Autowired
    UsuarioClientRest usuarioClientRest;

    @Override
    @Transactional(readOnly = true)
    public List<Curso> listar(){
        return (List<Curso>) repository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<Curso> porId(Long id){
        return repository.findById(id);
    }

    @Override
    @Transactional
    public Curso guardar(Curso curso){
        return repository.save(curso);
    }

    @Override
    @Transactional
    public void eliminar(Long id){
        repository.deleteById(id);
    }


    @Override
    public Optional<Usuario> agregarUsuario(Usuario usuario, Long idCurso, String token){
        Optional<Curso> o =repository.findById(idCurso);
        if(o.isPresent()){
            Usuario usuarioMicro = usuarioClientRest.detalle(usuario.getId(), token);
            System.out.println(usuarioMicro);
            Curso curso= o.get();
            CursoUsuario cursoUsuario = new CursoUsuario();
            cursoUsuario.setUsuarioId(usuarioMicro.getId());

            curso.addCursoUsuario(cursoUsuario);
            repository.save(curso);
            return Optional.of(usuarioMicro);

        }
        return Optional.empty();
    }

    public Optional<Usuario> agregarUsuarioConToken(Usuario usuario, Long idcurso, String token) {
        Optional<Curso> o =repository.findById(idcurso);
        if(o.isPresent()){
            Usuario usuarioMicro = usuarioClientRest.detalle(usuario.getId(), token);
            System.out.println(usuarioMicro);
            Curso curso= o.get();
            CursoUsuario cursoUsuario = new CursoUsuario();
            cursoUsuario.setUsuarioId(usuarioMicro.getId());

            curso.addCursoUsuario(cursoUsuario);
            repository.save(curso);
            return Optional.of(usuarioMicro);

        }
        return Optional.empty();
    }


    @Override
    public Optional<Usuario> eliminarUsuario(Long idusuario, Long idCurso, String token) {
        Optional<Curso> cursoOptional = repository.findById(idCurso);
        if (cursoOptional.isPresent()) {
            Usuario usuarioMicro = usuarioClientRest.detalle(idusuario, token);
            if (usuarioMicro != null) {
                Curso curso = cursoOptional.get();
                CursoUsuario cursoUsuario = new CursoUsuario();
                cursoUsuario.setUsuarioId(usuarioMicro.getId());

                boolean removed = curso.removeCursoUsuario(cursoUsuario);
                if (removed) {
                    repository.save(curso);
                    return Optional.of(usuarioMicro);
                }
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<Curso> findByNombre(String nombre) {
        return repository.findByNombre(nombre);
    }



}
