package com.espe.msvc_cursos;

import com.espe.msvc_cursos.clients.UsuarioClientRest;
import com.espe.msvc_cursos.models.entity.Curso;
import com.espe.msvc_cursos.models.entity.Usuario;
import com.espe.msvc_cursos.repositories.CursoRepository;
import com.espe.msvc_cursos.services.CursoServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CursoServiceImplTest {
/*
    @Mock
    private CursoRepository cursoRepository;

    @Mock
    private UsuarioClientRest usuarioClientRest;

    @InjectMocks
    private CursoServiceImpl cursoService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void listar() {
        List<Curso> cursos = Arrays.asList(new Curso(), new Curso());
        when(cursoRepository.findAll()).thenReturn(cursos);

        List<Curso> result = cursoService.listar();

        assertEquals(2, result.size());
        verify(cursoRepository, times(1)).findAll();
    }

    @Test
    void porId() {
        Curso curso = new Curso();
        when(cursoRepository.findById(1L)).thenReturn(Optional.of(curso));

        Optional<Curso> result = cursoService.porId(1L);

        assertTrue(result.isPresent());
        verify(cursoRepository, times(1)).findById(1L);
    }

    @Test
    void guardar() {
        Curso curso = new Curso();
        when(cursoRepository.save(any(Curso.class))).thenReturn(curso);

        Curso result = cursoService.guardar(curso);

        assertNotNull(result);
        verify(cursoRepository, times(1)).save(any(Curso.class));
    }

    @Test
    void eliminar() {
        cursoService.eliminar(1L);

        verify(cursoRepository, times(1)).deleteById(1L);
    }

    @Test
    void agregarUsuario() {
        Curso curso = new Curso();
        Usuario usuario = new Usuario();
        usuario.setId(1L);
        when(cursoRepository.findById(1L)).thenReturn(Optional.of(curso));
        when(usuarioClientRest.detalle(1L)).thenReturn(usuario);

        Optional<Usuario> result = cursoService.agregarUsuario(usuario, 1L);

        assertTrue(result.isPresent());
        assertEquals(1L, result.get().getId());
        verify(cursoRepository, times(1)).save(any(Curso.class));
    }


    @Test
    void eliminarUsuario() {
        Curso curso = new Curso();
        Usuario usuario = new Usuario();
        usuario.setId(1L);
        when(cursoRepository.findById(1L)).thenReturn(Optional.of(curso));
        when(usuarioClientRest.detalle(1L)).thenReturn(usuario);

        Optional<Usuario> result = cursoService.eliminarUsuario(usuario.getId(), 1L);

        assertTrue(result.isPresent());
        assertEquals(1L, result.get().getId());
        verify(cursoRepository, times(1)).save(any(Curso.class));
    }*/
}
