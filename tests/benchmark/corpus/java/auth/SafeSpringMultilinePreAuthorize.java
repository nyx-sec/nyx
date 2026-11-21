package com.example;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

// A `@PreAuthorize` that wraps over several lines is still the check.
@RestController
@RequestMapping("/api/docs")
public class SafeSpringMultilinePreAuthorize {
    private final DocRepository docRepository;

    @GetMapping("/{docId}")
    @PreAuthorize(
        "@docSecurity.isOwner(#docId, authentication)"
    )
    public Doc show(@PathVariable String docId) {
        return docRepository.findById(docId).orElseThrow();
    }
}
