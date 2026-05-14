// Phase 14 fixture stub — minimal `@Path` annotation (Jakarta REST).
// Lives in the default package; the fixture imports the symbol as
// plain `@Path` so javac is happy without a Quarkus / Jakarta REST
// Maven dep.

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface Path {
    String value() default "";
}
