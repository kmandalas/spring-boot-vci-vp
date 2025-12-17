package com.example.walletprovider.repository;

import com.example.walletprovider.entity.WalletUnitAttestation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface WuaRepository extends JpaRepository<WalletUnitAttestation, UUID> {

    Optional<WalletUnitAttestation> findByWalletPublicKeyThumbprint(String thumbprint);

    boolean existsByWalletPublicKeyThumbprint(String thumbprint);
}
