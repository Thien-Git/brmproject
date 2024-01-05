package com.example.brmproject.domain.dto;

import com.example.brmproject.domain.entities.CustomerEntity;
import com.example.brmproject.domain.entities.StaffEntity;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Collection;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
     private int id;
     private String username;
     private String password;
//     private Collection<CustomerDTO> customersById;
//     private Collection<StaffDTO> staffById;
//     private Collection<UserRoleDTO> userRolesById;

}
