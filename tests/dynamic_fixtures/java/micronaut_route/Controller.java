// Phase 14 fixture stub — minimal Micronaut `@Controller`.
// Lives in `io.micronaut.http.annotation` so the fixture's
// `import io.micronaut.http.annotation.Controller;` compiles under
// plain javac (no Micronaut Maven dep required).

package io.micronaut.http.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Controller {
    String value() default "";
}
