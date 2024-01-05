package com.example.brmproject.repositories;

import com.example.brmproject.domain.entities.ERole;
import com.example.brmproject.domain.entities.RoleEntity;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleEntityRepository extends JpaRepository<RoleEntity, Integer> {
      Optional<RoleEntity> findByName(ERole name);
}