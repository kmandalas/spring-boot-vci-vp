package dev.kmandalas.trustvalidator.model;

/**
 * Error response hierarchy.
 */
public sealed interface ErrorResponseTO permits ErrorResponseTO.ClientError, ErrorResponseTO.ServerError {

    String description();

    record ClientError(String description) implements ErrorResponseTO {}
    record ServerError(String description) implements ErrorResponseTO {}
}
