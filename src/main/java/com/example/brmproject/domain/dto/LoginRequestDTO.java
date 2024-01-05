package com.example.brmproject.domain.dto;

import jakarta.validation.constraints.*;

public class LoginRequestDTO {
    @NotBlank(message = "Please enter value")
	@Email(message = "Requires email type")
	private String username;

	@NotBlank(message = "Please enter value")
	@Size(min=6 , max = 20, message = "Requires 6 to 20 characters")
	private String password;

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
    
}
