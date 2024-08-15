package org.suspensive.basicjwtwebfluxsecurity.models;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Set;

@Data
@AllArgsConstructor
public class Role {

    public static final Role DEFAULT_ROLE = new Role(1,"DEFAULT_USER",Set.of("READ"));

    private int id;

    private String roleName;

    private Set<String> permissions;
}
