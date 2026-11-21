package com.example;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/docs")
public class MultilineDocController {
    private final DocRepository docRepository;

    @GetMapping("/{docId}")
    @PreAuthorize("@docSecurity.isOwner(#docId, authentication)")
    public Doc single(@PathVariable String docId) {
        return docRepository.findById(docId).orElseThrow();
    }

    @GetMapping("/b/{docId}")
    @PreAuthorize(
        "@docSecurity.isOwner(#docId, authentication)"
    )
    public Doc wrapped(@PathVariable String docId) {
        return docRepository.findById(docId).orElseThrow();
    }

    // a comment between annotations must not end the scan
    @GetMapping("/c/{docId}")
    // second comment
    @PreAuthorize("@docSecurity.isOwner(#docId, authentication)"
        + " and hasRole('USER')")
    public Doc concatenated(@PathVariable String docId) {
        return docRepository.findById(docId).orElseThrow();
    }

    @DeleteMapping("/d/{docId}")
    public void unguarded(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }
}
