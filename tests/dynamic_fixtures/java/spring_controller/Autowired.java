// Phase 14 fixture stub — minimal `@Autowired` annotation.
// Lives in the default package so the fixture's @Autowired field
// compiles under plain javac (no Spring Maven dep required).

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.CONSTRUCTOR})
public @interface Autowired {
}
