package com.espe.msvc_cursos;

import com.espe.msvc_cursos.controllers.CursoController;
import com.espe.msvc_cursos.models.entity.Curso;
import com.espe.msvc_cursos.models.entity.Usuario;
import com.espe.msvc_cursos.services.CursoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(CursoController.class)
class CursoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CursoService cursoService;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void listar() throws Exception {
        when(cursoService.listar()).thenReturn(Arrays.asList(new Curso(), new Curso()));

        mockMvc.perform(get("/cursos")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$").isNotEmpty());

        verify(cursoService, times(1)).listar();
    }

    @Test
    void detalle() throws Exception {
        Curso curso = new Curso();
        curso.setId(1L);
        when(cursoService.porId(1L)).thenReturn(Optional.of(curso));

        mockMvc.perform(get("/cursos/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1L));

        verify(cursoService, times(1)).porId(1L);
    }

    @Test
    void crear() throws Exception {
        Curso curso = new Curso();
        curso.setNombre("Matematicas");
        when(cursoService.guardar(any(Curso.class))).thenReturn(curso);

        mockMvc.perform(post("/cursos")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nombre\": \"Matematicas\"}"))
                .andExpect(status().isCreated());

        verify(cursoService, times(1)).guardar(any(Curso.class));
    }

    @Test
    void editar() throws Exception {
        Curso curso = new Curso();
        curso.setId(1L);
        curso.setNombre("Matematicas");
        when(cursoService.porId(1L)).thenReturn(Optional.of(curso));
        when(cursoService.guardar(any(Curso.class))).thenReturn(curso);

        mockMvc.perform(put("/cursos/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nombre\": \"Fisica\"}"))
                .andExpect(status().isCreated());

        verify(cursoService, times(1)).porId(1L);
        verify(cursoService, times(1)).guardar(any(Curso.class));
    }

    @Test
    void eliminar() throws Exception {
        Curso curso = new Curso();
        curso.setId(1L);
        when(cursoService.porId(1L)).thenReturn(Optional.of(curso));

        mockMvc.perform(delete("/cursos/1")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent());

        verify(cursoService, times(1)).porId(1L);
        verify(cursoService, times(1)).eliminar(1L);
    }

    @Test
    void asignarUsuario() throws Exception {
        Usuario usuario = new Usuario();
        usuario.setId(1L);
        usuario.setNombre("Usuario Test");

        when(cursoService.agregarUsuario(any(Usuario.class), anyLong())).thenReturn(Optional.of(usuario));

        mockMvc.perform(put("/cursos/asignar-usuario/{idcurso}", 1L)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(usuario)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1L))
                .andExpect(jsonPath("$.nombre").value("Usuario Test"));

        verify(cursoService, times(1)).agregarUsuario(any(Usuario.class), eq(1L));
    }

}
