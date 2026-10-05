package org.secretsharing.model;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Request to split a secret into n shares with threshold k")
public record SplitSecretRequest(
        @NotNull
        @Min(1)
        @Max(60)
        @Schema(description = "Reconstruction threshold (minimum shares required)", example = "3")
        Integer k,

        @NotNull
        @Min(1)
        @Max(60)
        @Schema(description = "Total number of shares to generate (must be >= k)", example = "5")
        Integer n,

        @NotBlank
        @Size(min = 3, max = 300)
        @Schema(description = "Secret text to split", example = "for-your-eyes-only")
        String secret) {
}
