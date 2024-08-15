package org.suspensive.basicjwtwebfluxsecurity.models.dtos;

public record AuthResponseDTO(String username,
                              String message,
                              String token,
                              boolean status) {
}
