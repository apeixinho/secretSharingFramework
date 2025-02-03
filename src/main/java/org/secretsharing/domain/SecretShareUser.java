package org.secretsharing.domain;

import jakarta.validation.constraints.Size;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;
import java.util.Set;

public class SecretShareUser {

    @Id
    private String userId;

    @Size(max = 255)
    private String userName;

    private Set<SecretShareGroup> secretShareGroups;

    @CreatedDate
    private LocalDateTime createdDate;

    @LastModifiedDate
    private LocalDateTime lastModifiedDate;

}
