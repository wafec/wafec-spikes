package spikes;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class RSAPublicKeys {
    private RSAPublicKeys() {
        throw new AssertionError();
    }

    public static PublicKey from( BigInteger modulus, BigInteger exponent ) throws GeneralSecurityException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec( modulus, exponent );
        KeyFactory factory = KeyFactory.getInstance( "RSA" );
        return factory.generatePublic( spec );
    }

    public static KeyPair newInstance() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "RSA" );
        keyPairGenerator.initialize( 2048 );
        return keyPairGenerator.generateKeyPair();
    }

    public static String sign( KeyPair keyPair, String content ) throws GeneralSecurityException {
        byte[] data = content.getBytes( StandardCharsets.UTF_8 );
        Signature sig = Signature.getInstance( "SHA1WithRSA" );
        sig.initSign( keyPair.getPrivate() );
        sig.update( data );
        byte[] sigBytes = sig.sign();
        return Base64.getEncoder().encodeToString( sigBytes );
    }

    public static boolean verifySignature( PublicKey pub, String signature, String content ) throws GeneralSecurityException {
        Signature sig = Signature.getInstance( "SHA1WithRSA" );
        sig.initVerify( pub );
        sig.update( content.getBytes( StandardCharsets.UTF_8 ) );
        return sig.verify( Base64.getDecoder().decode( signature.getBytes( StandardCharsets.UTF_8 ) ) );
    }
}
