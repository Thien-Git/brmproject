package com.example.brmproject.repositories;

import com.example.brmproject.domain.entities.CustomerEntity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface CustomerEntityRepository extends JpaRepository<CustomerEntity, Integer> {
     Optional<CustomerEntity> findByUserId(int userId);
}