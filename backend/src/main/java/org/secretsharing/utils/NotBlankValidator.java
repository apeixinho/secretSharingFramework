package org.secretsharing.utils;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.math.BigInteger;

public class NotBlankValidator implements ConstraintValidator<NotBlankAnnotation, Object> {

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {

        if (value == null) {
            return false;
        }
        if (value instanceof byte[] byteArray) {
            return byteArray.length > 0;
        } else if (value instanceof Integer integer) {
            return integer > 0;
        } else if (value instanceof BigInteger bigInteger) {
            return bigInteger.signum() > 0;
        }
        return true;
    }
}
