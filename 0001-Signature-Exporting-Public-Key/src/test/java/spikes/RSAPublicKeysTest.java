package spikes;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

public class RSAPublicKeysTest {
    @Test
    void testSignature() throws GeneralSecurityException {
        KeyPair keyPair = RSAPublicKeys.newInstance();
        RSAPublicKey rsaPub = (RSAPublicKey) keyPair.getPublic();
        PublicKey pub = RSAPublicKeys.from( rsaPub.getModulus(), rsaPub.getPublicExponent() );
        String content = "I am telling the truth! I am John!";
        String signature = RSAPublicKeys.sign( keyPair, content );
        Assertions.assertTrue( RSAPublicKeys.verifySignature( pub, signature, content ) );
        String fakeContent = "I am telling truth! I am Clarke!";
        Assertions.assertFalse( RSAPublicKeys.verifySignature( pub, signature, fakeContent ) );
    }
}
