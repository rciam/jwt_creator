package com.example.jwt; // This line must be present and correct

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;
import java.util.UUID;

public class EntityStatementGenerator {

    private static final String DEFAULT_CLIENT_ID = "https://offa.hadem.vm.grnet.gr";
    private static final String DEFAULT_AUD = "https://rciam.example.org/auth/realms/rciam";
    private static final JWSAlgorithm DEFAULT_ALGORITHM = JWSAlgorithm.ES512;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // The Key ID (kid) from your original JWT, which your system expects
    private static final String EXPECTED_KID = "xxx";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        String choice;
        String privateKeyPath;

        if (args.length >= 2) {
            choice = args[0];
            privateKeyPath = args[1];
        } else {
            // Fallback to defaults if not provided
            System.out.print("Enter mode (assertion/entity) [assertion]: ");
            String inputChoice = scanner.nextLine().trim();
            choice = inputChoice.isEmpty() ? "assertion" : inputChoice;

            System.out.print("Enter full path to EC private key PEM file [/etc/keys/es512-private.pem]: ");
            String inputPath = scanner.nextLine().trim();
            privateKeyPath = inputPath.isEmpty() ? "/etc/keys/es512-private.pem" : inputPath;
        }

        try {
            switch (choice.toLowerCase()) {
                case "assertion":
                    // Optional overrides (user can just press Enter to use defaults)
                    System.out.print("Enter CLIENT_ID [" + DEFAULT_CLIENT_ID + "]: ");
                    String inputClientId = scanner.nextLine().trim();
                    String clientId = (!inputClientId.isEmpty()) ? inputClientId : DEFAULT_CLIENT_ID;

                    System.out.print("Enter AUDIENCE [" + DEFAULT_AUD + "]: ");
                    String inputAud = scanner.nextLine().trim();
                    String aud = (!inputAud.isEmpty()) ? inputAud : DEFAULT_AUD;

                    System.out.print("Enter JWS Algorithm [" + DEFAULT_ALGORITHM.getName() + "]: ");
                    String inputAlg = scanner.nextLine().trim();
                    JWSAlgorithm algorithm = (!inputAlg.isEmpty()) ? new JWSAlgorithm(inputAlg) : DEFAULT_ALGORITHM;
                    System.out.println("Generated client_assertion: "
                            + generateClientAssertion(privateKeyPath, clientId, aud, algorithm));
                    break;
                case "entity":
                    System.out.println("Generated Signed Entity Statement JWT: "
                            + generateEntityStatement(privateKeyPath));
                    break;
                default:
                    System.err.println("Unknown option. Use 'assertion' or 'entity'.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String generateClientAssertion(String keyPath, String clientId, String aud, JWSAlgorithm algorithm) throws Exception {
        //Build JWT claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(aud)
                .jwtID(UUID.randomUUID().toString())
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(5000)))
                .issueTime(java.util.Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(algorithm)
                        .type(JOSEObjectType.JWT)
                        .build(),
                claims
        );

        signedJWT.sign(new ECDSASigner((ECPrivateKey) loadECPrivateKey(keyPath)));
        return signedJWT.serialize();
    }

    private static PrivateKey loadECPrivateKey(String keyPath) throws Exception {
        try (PEMParser pemParser = new PEMParser(new FileReader(keyPath))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PEMKeyPair) {
                // For "-----BEGIN EC PRIVATE KEY-----"
                return converter.getKeyPair((PEMKeyPair) object).getPrivate();
            } else {
                throw new IllegalArgumentException("Unsupported key format: " + object.getClass());
            }
        }
    }

    private static String generateEntityStatement(String keyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        // Add Bouncy Castle as a security provider for PEM parsing
        Security.addProvider(new BouncyCastleProvider());

        // 1. Load the EC private key from the PEM string
        try (PEMParser pemParser = new PEMParser(new FileReader(keyPath))) {
            Object object = pemParser.readObject();

            // --- Debugging and Error Handling for PEMParser Output ---
            System.out.println("Object read by PEMParser: " + object);
            if (object == null) {
                throw new IOException("PEMParser returned null object. Check PEM string format for correctness.");
            }
            if (!(object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo)) {
                // If it's a PEMKeyPair (contains both public and private key info)
                if (object instanceof org.bouncycastle.openssl.PEMKeyPair) {
                    System.out.println("PEMParser read a PEMKeyPair. Extracting PrivateKeyInfo.");
                    object = ((org.bouncycastle.openssl.PEMKeyPair) object).getPrivateKeyInfo();
                } else {
                    throw new IOException("Unexpected object type from PEMParser: " + object.getClass().getName() + ". Expected PrivateKeyInfo or PEMKeyPair.");
                }
            }
            // --- End Debugging and Error Handling ---

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC"); // Use Bouncy Castle provider
            ECPrivateKey privateKey = (ECPrivateKey) converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object);

            // 2. Derive the ECPublicKey from the ECPrivateKey using Bouncy Castle for point multiplication
            ECParameterSpec params = privateKey.getParams();
            // Get Bouncy Castle's curve parameters for P-521
            ECNamedCurveParameterSpec bcParams = ECNamedCurveTable.getParameterSpec("P-521");
            ECCurve curve = bcParams.getCurve();
            org.bouncycastle.math.ec.ECPoint generator = bcParams.getG();

            // Perform scalar multiplication: publicPoint = privateKey.s * generator
            org.bouncycastle.math.ec.ECPoint publicBcPoint = generator.multiply(privateKey.getS()).normalize(); // Corrected: Added .normalize()

            // Convert Bouncy Castle ECPoint back to Java Security ECPoint
            ECPoint publicPoint = new ECPoint(
                    publicBcPoint.getAffineXCoord().toBigInteger(),
                    publicBcPoint.getAffineYCoord().toBigInteger()
            );

            ECPublicKeySpec pubSpec = new ECPublicKeySpec(publicPoint, params);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);


            // 3. Create the ECKey for the JWKS using the derived ECPublicKey
            ECKey ecJwk = new ECKey.Builder(Curve.P_521, publicKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES512)
                    .keyID(EXPECTED_KID) // Use the specific KID you provided
                    .build();

            // Create a JWKSet containing this key
            JWKSet jwkSet = new JWKSet(ecJwk);

            // 4. Prepare the JWT claims set (payload)
            Instant now = Instant.now();
            Date iat = Date.from(now);
            Date exp = Date.from(now.plusSeconds(24 * 60 * 60)); // 24 hours from now

            // Build the metadata JSONObject
            JSONObject metadata = new JSONObject();
            JSONObject federationEntity = new JSONObject();
            federationEntity.put("logo_uri", "https://offa.hadem.vm.grnet.gr/static/img/offa-text.svg");
            metadata.put("federation_entity", federationEntity);

            JSONObject openidRelyingParty = new JSONObject();
            openidRelyingParty.put("application_type", "web");
            openidRelyingParty.put("client_name", "Hademrp");
            openidRelyingParty.put("client_registration_types", Arrays.asList("automatic"));
            openidRelyingParty.put("grant_types", Arrays.asList("authorization_code"));

            // Inner JWKS for openid_relying_party
            JSONObject innerJwks = new JSONObject();
            innerJwks.put("keys", Arrays.asList(
                    new JSONObject() {{
                        put("alg", "ES512");
                        put("crv", "P-521");
                        put("kid", "ECEFhhOQI3CEUqBfLdTlU4DRewMQl-g9aBpnfaTt3Pc");
                        put("kty", "EC");
                        put("use", "sig");
                        put("x", "ttt");
                        put("y", "ttt");
                    }}
            ));
            openidRelyingParty.put("jwks", jwkSet.toJSONObject());

            openidRelyingParty.put("logo_uri", "https://offa.hadem.vm.grnet.gr/static/img/offa-text.svg");
            openidRelyingParty.put("redirect_uris", Arrays.asList("https://offa.hadem.vm.grnet.gr/redirect"));
            openidRelyingParty.put("response_types", Arrays.asList("code"));
            openidRelyingParty.put("scope", "openid email profile entitlements voperson_external_affiliation schac_home_organization");
            metadata.put("openid_relying_party", openidRelyingParty);


            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer("https://offa.hadem.vm.grnet.gr")
                    .subject("https://offa.hadem.vm.grnet.gr")
                    .issueTime(iat)
                    .expirationTime(exp)
                    .audience("https://aai-dev.egi.eu/auth/realms/id")
                    .claim("authority_hints", Arrays.asList("https://trust-anchor.sandbox.eosc.grnet.gr"))
                    .claim("typ", "entity-statement+jwt") // Add the requested 'typ' claim
                    .claim("jwks", jwkSet.toJSONObject()) // Embed the JWKSet for the top-level signature
                    .claim("metadata", metadata) // Use the constructed metadata JSONObject
                    .build();

            // 5. Create the JWS header
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES512)
                    .keyID(EXPECTED_KID) // Use the specific KID
                    .type(new JOSEObjectType("entity-statement+jwt")) // Set the 'typ' in the header
                    .build();

            // 6. Create and sign the JWT
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            ECDSASigner signer = new ECDSASigner(privateKey);
            signedJWT.sign(signer);

            // Get the serialised JWT
            return signedJWT.serialize();
        }
    }
}
