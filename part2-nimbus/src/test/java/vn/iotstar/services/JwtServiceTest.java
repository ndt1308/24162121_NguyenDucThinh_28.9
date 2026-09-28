package vn.iotstar.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import vn.iotstar.exception.InvalidJwtException;
import vn.iotstar.exception.InvalidJwtException.Reason;

class JwtServiceTest {

    private JwtService jwtService;

    private UserDetails alice;
    private UserDetails mallory;

    @BeforeEach
    void setUp() {
        byte[] key = new byte[48];
        new SecureRandom().nextBytes(key);

        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", Base64.getEncoder().encodeToString(key));
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 3_600_000L);

        alice = org.springframework.security.core.userdetails.User
                .withUsername("alice@hcmute.edu.vn").password("x").authorities("ROLE_USER").build();
        mallory = org.springframework.security.core.userdetails.User
                .withUsername("mallory@hcmute.edu.vn").password("x").authorities("ROLE_USER").build();
    }

    @Test
    void generatedTokenIsValidAndHasThreeParts() {
        String token = jwtService.generateToken(alice);

        assertEquals(3, token.split("\\.").length);
        assertEquals("alice@hcmute.edu.vn", jwtService.extractUsername(token));
        assertTrue(jwtService.isTokenValid(token, alice));
        assertFalse(jwtService.isTokenValid(token, mallory));
    }

    @Test
    void extraClaimsAreKept() {
        String token = jwtService.generateToken(Map.of("role", "ADMIN"), alice);

        assertEquals("ADMIN", jwtService.extractClaim(token, c -> c.getClaim("role")));
        assertNotNull(jwtService.extractClaim(token, c -> c.getJWTID()));
    }

    @Test
    void tamperedPayloadIsRejected() {
        String[] a = jwtService.generateToken(alice).split("\\.");
        String[] m = jwtService.generateToken(mallory).split("\\.");
        // payload cua mallory + chu ky cua alice
        String forged = a[0] + "." + m[1] + "." + a[2];

        InvalidJwtException ex = assertThrows(InvalidJwtException.class, () -> jwtService.extractUsername(forged));
        assertEquals(Reason.INVALID_SIGNATURE, ex.getReason());
    }

    @Test
    void expiredTokenIsRejected() {
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", -1_000L);
        String token = jwtService.generateToken(alice);

        InvalidJwtException ex = assertThrows(InvalidJwtException.class, () -> jwtService.extractUsername(token));
        assertEquals(Reason.EXPIRED, ex.getReason());
    }

    @Test
    void garbageTokenIsRejected() {
        InvalidJwtException ex = assertThrows(InvalidJwtException.class, () -> jwtService.extractUsername("dfdfdfd"));
        assertEquals(Reason.MALFORMED, ex.getReason());
    }
}
