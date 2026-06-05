package com.example;

import io.quarkus.runtime.Quarkus;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

@ApplicationScoped
@Path("/api")
public class GreetResource {

    @GET
    @Path("/hello")
    public String hello() {
        return "hi";
    }
}
