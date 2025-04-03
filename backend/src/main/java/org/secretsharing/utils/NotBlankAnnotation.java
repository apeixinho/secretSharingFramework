package org.secretsharing.utils;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ ElementType.FIELD, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Constraint(validatedBy = NotBlankValidator.class)
public @interface NotBlankAnnotation {
    String message() default "Value must not be blank";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
