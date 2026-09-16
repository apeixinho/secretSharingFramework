package org.secretsharing.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.math.BigInteger;

public class ValidShareValueValidator implements ConstraintValidator<ValidShareValue, Object> {

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        if (value == null) {
            return false;
        }
        if (value instanceof byte[] byteArray) {
            return byteArray.length > 0;
        }
        if (value instanceof Integer integer) {
            return integer > 0;
        }
        if (value instanceof BigInteger bigInteger) {
            return bigInteger.signum() > 0;
        }
        return true;
    }
}
