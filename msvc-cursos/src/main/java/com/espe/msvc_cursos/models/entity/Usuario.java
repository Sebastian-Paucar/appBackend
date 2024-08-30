package com.espe.msvc_cursos.models.entity;

import java.util.Set;

public class Usuario {
    private long id;
    private String nombre;
    private String email;
    private String password;

    public long getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    private Set<Role> roles;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;


}
