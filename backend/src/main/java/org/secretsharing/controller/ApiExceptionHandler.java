package org.secretsharing.controller;

import java.util.logging.Level;
import java.util.logging.Logger;

import jakarta.validation.ConstraintViolationException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@RestControllerAdvice
public class ApiExceptionHandler {

	private static final Logger log = Logger.getLogger(ApiExceptionHandler.class.getName());

	private static final String MSG_BAD_REQUEST = "Invalid request parameters.";
	private static final String MSG_FORBIDDEN = "Share signature verification failed.";
	private static final String MSG_UNEXPECTED = "Unexpected error.";

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<String> handleIllegalArgument(IllegalArgumentException ex) {
		logFailure(ex);
		return text(HttpStatus.BAD_REQUEST, MSG_BAD_REQUEST);
	}

	@ExceptionHandler(SecurityException.class)
	public ResponseEntity<String> handleSecurity(SecurityException ex) {
		logFailure(ex);
		return text(HttpStatus.FORBIDDEN, MSG_FORBIDDEN);
	}

	@ExceptionHandler({
			MethodArgumentNotValidException.class,
			MissingServletRequestParameterException.class,
			MethodArgumentTypeMismatchException.class,
			HttpMessageNotReadableException.class,
			ConstraintViolationException.class,
			NumberFormatException.class
	})
	public ResponseEntity<String> handleValidation(Exception ex) {
		logFailure(ex);
		return text(HttpStatus.BAD_REQUEST, MSG_BAD_REQUEST);
	}

	@ExceptionHandler(Throwable.class)
	public ResponseEntity<String> handleUnexpected(Throwable ex) {
		logFailure(ex);
		return text(HttpStatus.INTERNAL_SERVER_ERROR, MSG_UNEXPECTED);
	}

	private static ResponseEntity<String> text(HttpStatus status, String body) {
		return ResponseEntity.status(status).contentType(MediaType.TEXT_PLAIN).body(body);
	}

	private static void logFailure(Throwable ex) {
		log.log(Level.WARNING, "Request failed: {0}", ex.getClass().getSimpleName());
	}
}
