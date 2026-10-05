package org.secretsharing.validation;

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
@Constraint(validatedBy = ValidShareValueValidator.class)
public @interface ValidShareValue {
    String message() default "Share field must be present and positive";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
