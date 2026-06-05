// Phase 14 fixture stub — minimal `@Test` annotation in the default
// package.  Lives here so the fixture's `@Test`-annotated method
// compiles under plain javac without a junit-jupiter Maven dep.  The
// fixture's comment carries a literal `org.junit` marker so the
// Phase 14 [`JavaShape::detect`] still selects the JUnit shape.

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Test {
}
