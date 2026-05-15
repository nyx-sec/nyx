package com.example;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/users")
    public String list() {
        return "[]";
    }
}
