package com.example;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/managed")
public class HasAnyRoleDocController {
    private final DocRepository docRepository;

    @DeleteMapping("/c/{docId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public void admins(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }

    @DeleteMapping("/e/{docId}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public void authorities(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }

    @DeleteMapping("/f/{docId}")
    @PreAuthorize("hasAnyRole('USER', 'EDITOR')")
    public void anyUserRole(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }

    @DeleteMapping("/g/{docId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public void adminOrUser(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }

    @DeleteMapping("/h/{docId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    public void adminOrUserSpel(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }
}
