package com.example;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

@Path("/users")
public class UserResource {

    @GET
    @Path("/{id}")
    public String get() {
        return "{}";
    }
}
