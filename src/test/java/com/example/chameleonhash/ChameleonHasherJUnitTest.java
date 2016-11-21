package com.example.chameleonhash;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.*;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bUniversalHasher;
import com.example.TestUtils;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/10/20.
 *
 * Chameleon hash test.
 */
public class ChameleonHasherJUnitTest extends TestCase {

    private AsymmetricKeySerPairGenerator asymmetricCipherKeyPairGenerator;
    private ChameleonHasher chameleonHasher;

    private void runAllTests() {
        //KeyGen
        AsymmetricKeySerPair keyPair = asymmetricCipherKeyPairGenerator.generateKeyPair();
        AsymmetricKeySerParameter publicKey = keyPair.getPublic();
        AsymmetricKeySerParameter secretKey = keyPair.getPrivate();

        String message1 = "This is message 1";
        String message2 = "This is message 2";
        System.out.println("========================================");
        System.out.println("Test chameleon hash functionality.");
        try {
            System.out.println("Test inequality with different messages.");
            chameleonHasher.init(false, publicKey);
            chameleonHasher.update(message1.getBytes(), 0, message1.getBytes().length);
            byte[][] cHashResult1 = chameleonHasher.computeHash();
            chameleonHasher.reset();
            chameleonHasher.update(message2.getBytes(), 0, message2.getBytes().length);
            byte[][] cHashResult2 = chameleonHasher.computeHash();

            //Test inequality with different messages
            System.out.println("Hash Result 1 = " + Arrays.toString(cHashResult1[0]));
            System.out.println("Hash Result 2 = " + Arrays.toString(cHashResult2[0]));
            assertEquals(false, Arrays.equals(cHashResult1[0], cHashResult2[0]));

            //Test equality without / with randomness r
            System.out.println("Test equality without / with randomness r.");
            chameleonHasher.reset();
            chameleonHasher.update(message1.getBytes(), 0, message1.getBytes().length);
            byte[][] cHashResult1Prime = chameleonHasher.computeHash(cHashResult1[0], cHashResult1[1]);
            System.out.println("Hash Result 1' = " + Arrays.toString(cHashResult1Prime[0]));
            assertEquals(true, Arrays.equals(cHashResult1[0], cHashResult1Prime[0]));

            //Test collision
            System.out.println("Test equality with collision finding.");
            chameleonHasher.init(true, secretKey);
            chameleonHasher.update(message2.getBytes(), 0, message2.getBytes().length);
            byte[][] cHashCollision = chameleonHasher.findCollision(cHashResult1[0], cHashResult1[1]);
            System.out.println("Coll. Resist. = " + Arrays.toString(cHashCollision[0]));
            assertEquals(true, Arrays.equals(cHashResult1[0], cHashCollision[0]));
            System.out.println("Chameleon hash functionality test pass.");

            System.out.println("========================================");
            System.out.println("Test signer parameters serialization & de-serialization.");
            //serialize public key
            System.out.println("Test serialize & de-serialize public key.");
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            assertEquals(publicKey, anPublicKey);

            //serialize secret key
            System.out.println("Test serialize & de-serialize secret keys.");
            //serialize sk4
            byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
            CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
            assertEquals(secretKey, anSecretKey);

            System.out.println("Signer parameter serialization tests passed.");
            System.out.println();

        } catch (CryptoException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void testKR00UniversalChameleonHash() {
        SecureRandom secureRandom = new SecureRandom();
        //RFC 3526, 1536-bit MODP Group
        SecurePrimeSerParameter securePrimeSerParameter = SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP;
        AsymmetricKeySerPairGenerator signKeyPairGenerator = new DLogKR00bKeyPairGenerator();
        signKeyPairGenerator.init(new DLogKR00bKeyGenerationParameters(secureRandom, securePrimeSerParameter));
        this.chameleonHasher = new KR00bDigestHasher(new DLogKR00bHasher(), new SHA256Digest());
        this.asymmetricCipherKeyPairGenerator = signKeyPairGenerator;
        System.out.println("Test Krawczyk-Rabin Chameleon hash function");
        runAllTests();
    }

    public void testKR00ChameleonHash() {
        SecureRandom secureRandom = new SecureRandom();
        //RFC 3526, 1536-bit MODP Group
        SecurePrimeSerParameter securePrimeSerParameter = SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP;
        AsymmetricKeySerPairGenerator signKeyPairGenerator = new DLogKR00bKeyPairGenerator();
        signKeyPairGenerator.init(new DLogKR00bKeyGenerationParameters(secureRandom, securePrimeSerParameter));
        this.chameleonHasher = new KR00bDigestHasher(new DLogKR00bUniversalHasher(new SHA256Digest()), new SHA256Digest());
        this.asymmetricCipherKeyPairGenerator = signKeyPairGenerator;
        System.out.println("Test Universal Collision-Resistant Krawczyk-Rabin Chameleon hash function");
        runAllTests();
    }
}
