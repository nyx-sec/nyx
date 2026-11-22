package com.example;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/admin/reports")
public class AdminReportController {
    private final ReportRepository reportRepository;

    @GetMapping("/export")
    @PreAuthorize("hasAnyRole('USER', 'AUDITOR')")
    public Object notAdmin() {
        return reportRepository.findAll();
    }

    @GetMapping("/purge")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public Object admin() {
        return reportRepository.findAll();
    }

    @GetMapping("/archive")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public Object anyUser() {
        return reportRepository.findAll();
    }
}
