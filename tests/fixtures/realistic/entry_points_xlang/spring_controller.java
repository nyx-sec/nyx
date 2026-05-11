// Phase 16 fixture: Spring `@PostMapping` controller method.  The
// `@PostMapping("/users")` annotation marks `addUser` as a
// `SpringMapping { method: POST }` entry point; the seeding policy
// paints `name` (the `@RequestParam`) as `Source(Cap::all())`.  The
// taint composes with Phase 15's Hibernate `entityManager.createNativeQuery`
// SQL_QUERY sink at the `String.format`-interpolated SQL string.
package com.example;

import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    private EntityManager entityManager;

    @PostMapping("/users")
    public Object addUser(@RequestParam String name) {
        String sql = String.format("INSERT INTO users (name) VALUES ('%s')", name);
        return entityManager.createNativeQuery(sql).getResultList();
    }
}
