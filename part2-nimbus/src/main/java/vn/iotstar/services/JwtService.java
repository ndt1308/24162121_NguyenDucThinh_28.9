package vn.iotstar.services;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import vn.iotstar.exception.InvalidJwtException;
import vn.iotstar.exception.InvalidJwtException.Reason;

/**
 * Tao / xac thuc JWT (JWS, HS256) bang Nimbus JOSE + JWT.
 *
 * Tuong ung voi ban JJWT:
 *   Jwts.builder()...compact()          ->  SignedJWT + MACSigner + serialize()
 *   Jwts.parser().verifyWith(k)...      ->  SignedJWT.parse() + MACVerifier + verify()
 *   Claims                              ->  JWTClaimsSet
 */
@Service
public class JwtService {
    private static final JWSAlgorithm ALGORITHM = JWSAlgorithm.HS256;

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        try {
            Date now = new Date();

            // 1. Tao claims (payload)
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .issueTime(now)
                    .expirationTime(new Date(now.getTime() + expiration))
                    .jwtID(UUID.randomUUID().toString());
            extraClaims.forEach(claimsBuilder::claim);

            // 2. Tao header
            JWSHeader header = new JWSHeader.Builder(ALGORITHM)
                    .type(JOSEObjectType.JWT)
                    .build();

            // 3. Tao SignedJWT = header + claims
            SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());

            // 4. Ky bang secret (HMAC)
            signedJWT.sign(new MACSigner(getSecret()));

            // 5. Ket qua: header.payload.signature
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign JWT", e);
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username != null && username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    /** Parse -> kiem tra thuat toan -> verify chu ky -> kiem tra han. Sai o buoc nao nem InvalidJwtException tuong ung. */
    private JWTClaimsSet extractAllClaims(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Chi chap nhan dung thuat toan da cau hinh (chong tan cong doi alg)
            if (!ALGORITHM.equals(signedJWT.getHeader().getAlgorithm())) {
                throw new InvalidJwtException(Reason.MALFORMED, "Unsupported JWT algorithm");
            }

            if (!signedJWT.verify(new MACVerifier(getSecret()))) {
                throw new InvalidJwtException(Reason.INVALID_SIGNATURE, "JWT signature does not match");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            Date exp = claims.getExpirationTime();
            if (exp == null) {
                throw new InvalidJwtException(Reason.MALFORMED, "JWT has no expiration (exp) claim");
            }
            if (exp.before(new Date())) {
                throw new InvalidJwtException(Reason.EXPIRED, "JWT expired at " + exp);
            }
            return claims;
        } catch (ParseException e) {
            throw new InvalidJwtException(Reason.MALFORMED, "Invalid JWT format: " + e.getMessage(), e);
        } catch (JOSEException e) {
            throw new InvalidJwtException(Reason.INVALID_SIGNATURE, "Cannot verify JWT signature", e);
        }
    }

    private byte[] getSecret() {
        // Khoa la chuoi Base64 (>= 32 byte de dung HS256)
        return Base64.getDecoder().decode(secretKey);
    }
}
