package com.example.brmproject.domain.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.HashSet;
import java.util.Set;
import java.util.List;


@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "user", schema = "brmproject", catalog = "")
public class UserEntity {
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    @Column(name = "id", nullable = false)
    private int id;
    
    
    @Basic
    @Column(name = "username", nullable = true, length = 100)
    private String username;
    
    @Basic
    @Column(name = "password", nullable = true, length = -1)
    private String password;
    
    @OneToMany(mappedBy = "userByUserId")
    private List<CustomerEntity> customersById;
    
    @OneToMany(mappedBy = "userByUserId")
    private List<StaffEntity> staffById;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(  name = "user_role", 
        joinColumns = @JoinColumn(name = "user_id"), 
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<RoleEntity> roles = new HashSet<>();
    

    


    public UserEntity(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
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

    public Set<RoleEntity> getRoles() {
        return roles;
      }
    
      public void setRoles(Set<RoleEntity> roles) {
        this.roles = roles;
      }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserEntity that = (UserEntity) o;
        return id == that.id && Objects.equals(username, that.username) && Objects.equals(password, that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, username, password);
    }

    public List<CustomerEntity> getCustomersById() {
        return customersById;
    }

    public void setCustomersById(List<CustomerEntity> customersById) {
        this.customersById = customersById;
    }

    public List<StaffEntity> getStaffById() {
        return staffById;
    }

    public void setStaffById(List<StaffEntity> staffById) {
        this.staffById = staffById;
    }






}
