package com.example.brmproject.controller.auth;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.brmproject.domain.dto.JwtResponseDTO;
import com.example.brmproject.domain.dto.LoginRequestDTO;
import com.example.brmproject.domain.dto.SignupRequestDTO;

import com.example.brmproject.domain.entities.CustomerEntity;
import com.example.brmproject.domain.entities.ERole;
import com.example.brmproject.domain.entities.RoleEntity;
import com.example.brmproject.domain.entities.StaffEntity;
import com.example.brmproject.domain.entities.UserEntity;
import com.example.brmproject.repositories.CustomerEntityRepository;
import com.example.brmproject.repositories.RoleEntityRepository;
import com.example.brmproject.repositories.StaffEntityRepository;
import com.example.brmproject.repositories.UserEntityRepository;
import com.example.brmproject.security.jwt.JwtUtils;
import com.example.brmproject.service.imp.UserDetailsImpl;
import com.example.brmproject.domain.dto.MessageResponseDTO;
import org.apache.commons.lang3.RandomStringUtils;




import jakarta.validation.Valid;

@CrossOrigin
@RestController
@RequestMapping("/api")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserEntityRepository userEntityRepository;

  @Autowired
  RoleEntityRepository roleEntityRepository;

  @Autowired
  CustomerEntityRepository customerEntityRepository;

  @Autowired
  StaffEntityRepository staffEntityRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;


  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequestDTO loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());



    return ResponseEntity.ok(new JwtResponseDTO(jwt, userDetails.getId(), userDetails.getUsername(), roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequestDTO signUpRequest) {
    if (userEntityRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponseDTO("Error: Email is already exist!"));
    }

    // Create new user's account
    UserEntity user = new UserEntity(signUpRequest.getUsername(),
        encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<RoleEntity> roles = new HashSet<>();

    if (strRoles == null) {
      RoleEntity userRole = roleEntityRepository.findByName(ERole.CUSTOMER)
          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);

    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            RoleEntity adminRole = roleEntityRepository.findByName(ERole.ADMIN)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);

            break;
          case "staff":
            RoleEntity modRole = roleEntityRepository.findByName(ERole.STAFF)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(modRole);

            break;
          default:
            RoleEntity userRole = roleEntityRepository.findByName(ERole.CUSTOMER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userEntityRepository.save(user);
    
    int userId = userEntityRepository.save(user).getId();

    for(RoleEntity role : roles){
      if(role.getName() == ERole.ADMIN || role.getName() == ERole.STAFF){
        StaffEntity newStaff = new StaffEntity();
        newStaff.setEmail(signUpRequest.getUsername());
        newStaff.setName(signUpRequest.getName());
        newStaff.setEmployeeCode(RandomStringUtils.randomAlphanumeric(10));
        newStaff.setUserId(userId);
        newStaff.setUserByUserId(user);
        staffEntityRepository.save(newStaff);
        break;
      } else {
        CustomerEntity newCustomer = new CustomerEntity();
        newCustomer.setAddress(signUpRequest.getAddress());
        newCustomer.setEmail(signUpRequest.getUsername());
        newCustomer.setName(signUpRequest.getName());
        newCustomer.setPhone(signUpRequest.getPhone());
        newCustomer.setUserId(userId);
        newCustomer.setUserByUserId(user);
        customerEntityRepository.save(newCustomer);
      }
    }

    return ResponseEntity.ok(new MessageResponseDTO("User registered successfully!"));
  }

}