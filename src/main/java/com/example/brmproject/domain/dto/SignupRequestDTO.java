package com.example.brmproject.domain.dto;

import java.util.Set;



import jakarta.validation.constraints.*;

public class SignupRequestDTO {
 
  @NotBlank
  @Email(message = "Requires email type")
  private String username;

  private Set<String> role;

  @NotBlank
  @Size(min=6 , max = 20, message = "Requires 6 to 20 characters")
  private String password;
  
  private String name;

  private String phone;
 
  private String address;

  private String email;

  private Double debit;

  private Integer userId;



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

  public Set<String> getRole() {
    return this.role;
  }

  public void setRole(Set<String> role) {
    this.role = role;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getPhone() {
    return phone;
  }

  public void setPhone(String phone) {
    this.phone = phone;
  }

  public String getAddress() {
    return address;
  }

  public void setAddress(String address) {
    this.address = address;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public Double getDebit() {
    return debit;
  }

  public void setDebit(Double debit) {
    this.debit = debit;
  }

  public Integer getUserId() {
    return userId;
  }

  public void setUserId(Integer userId) {
    this.userId = userId;
  }

  

}
