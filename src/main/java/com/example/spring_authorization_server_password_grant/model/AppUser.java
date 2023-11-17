package com.example.spring_authorization_server_password_grant.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

@Data
@Entity
@Table(name = "app_users")
@NoArgsConstructor
public class AppUser implements Serializable {
   private static final long serialVersionUID = -1L;
   @Id
   @GeneratedValue(generator = "UUID")
   @Column(columnDefinition = "uuid-char")
   private UUID id;
   private String password;
   private String firstName;
   private String lastName;
   private String loginId;
}
