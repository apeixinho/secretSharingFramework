package org.secretsharing.utils;

import java.math.BigInteger;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class NotBlankValidator implements ConstraintValidator<NotBlankAnnotation, Object> {

    @Override
    public void initialize(NotBlankAnnotation constraintAnnotation) {
    }

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {

        if (value == null) {
            return false;
        }
        if (value instanceof byte[]) {
            byte[] byteArray = (byte[]) value;
            return byteArray.length > 0;
        } else if (value instanceof Integer) {
            Integer integer = (Integer) value;
            return (integer != null && integer > 0);
        } else if (value instanceof BigInteger) {
            BigInteger bigInteger = (BigInteger) value;
            return (bigInteger != null && bigInteger.compareTo(BigInteger.ZERO) != 1);
        }
        return true;
    }

}
