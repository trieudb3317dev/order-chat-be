package com.example.securty.models;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "users")
public class User {

    // moved enums inside class as public so other packages can access
    public static enum Role {
        ADMIN,
        USER,
        MODERATOR
    }

    public static enum Gender {
        MALE,
        FEMALE,
        OTHER
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "uid")
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(name = "first_name", nullable = true)
    private String firstName;

    @Column(name = "last_name", nullable = true)
    private String lastName;

    @Column(name = "phone_number", nullable = true)
    private String phoneNumber;

    @Column(name = "address", nullable = true)
    private String address;

    @Column(name = "profile_picture", nullable = true)
    private String profilePicture;

    @Column(name = "role", nullable = true)
    @Enumerated(EnumType.STRING)
    private Role role = Role.USER;

    @Column(name = "gender", nullable = true)
    @Enumerated(EnumType.STRING)
    private Gender gender = Gender.OTHER;

    @Column(name = "is_active", nullable = false, columnDefinition = "boolean default false")
    private Boolean isActive = false;

    @Column(name = "reset_token", nullable = true)
    private String resetToken;

    @Column(name = "reset_token_expiry", nullable = true)
    private Instant resetTokenExpiry;

    @Column(name = "created_at", nullable = true, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "is_verified", nullable = true, columnDefinition = "boolean default false")
    private Boolean isVerified = false;

    @Column(name = "login_at", nullable = true, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", updatable = false)
    private Instant loginAt = Instant.now();

    public User() {
    }

    public User(String username, String password, String email, Role role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getProfilePicture() {
        return profilePicture;
    }

    public void setProfilePicture(String profilePicture) {
        this.profilePicture = profilePicture;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public Gender getGender() {
        return gender;
    }

    public void setGender(Gender gender) {
        this.gender = gender;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    public String getResetToken() {
        return resetToken;
    }

    public void setResetToken(String resetToken) {
        this.resetToken = resetToken;
    }

    public Instant getResetTokenExpiry() {
        return resetTokenExpiry;
    }

    public void setResetTokenExpiry(Instant resetTokenExpiry) {
        this.resetTokenExpiry = resetTokenExpiry;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Boolean getIsVerified() {
        return isVerified;
    }

    public void setIsVerified(Boolean isVerified) {
        this.isVerified = isVerified;
    }

    public Instant getLoginAt() {
        return loginAt;
    }

    public void setLoginAt(Instant loginAt) {
        this.loginAt = loginAt;
    }
}