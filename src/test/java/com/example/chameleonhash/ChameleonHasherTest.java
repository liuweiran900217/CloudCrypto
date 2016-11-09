package com.example.chameleonhash;

import cn.edu.buaa.crypto.algebra.serparams.SecurePrimeSerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bUniversalHasher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
/**
 * Created by Weiran Liu on 2016/10/20.
 *
 * Chameleon hash test.
 */
public class ChameleonHasherTest {

    private AsymmetricCipherKeyPairGenerator asymmetricCipherKeyPairGenerator;
    private ChameleonHasher chameleonHasher;

    private ChameleonHasherTest(AsymmetricCipherKeyPairGenerator asymmetricCipherKeyPairGenerator, ChameleonHasher chameleonHasher) {
        this.asymmetricCipherKeyPairGenerator = asymmetricCipherKeyPairGenerator;
        this.chameleonHasher = chameleonHasher;
    }

    public void processTest() {
        //KeyGen
        AsymmetricCipherKeyPair keyPair = asymmetricCipherKeyPairGenerator.generateKeyPair();
        AsymmetricKeyParameter publicKey = keyPair.getPublic();
        AsymmetricKeyParameter secretKey = keyPair.getPrivate();

        String message1 = "This is message 1";
        String message2 = "This is message 2";
        try {
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
            chameleonHasher.reset();
            chameleonHasher.update(message1.getBytes(), 0, message1.getBytes().length);
            byte[][] cHashResult1Prime = chameleonHasher.computeHash(cHashResult1[0], cHashResult1[1]);
            System.out.println("Hash Result 1' = " + Arrays.toString(cHashResult1Prime[0]));
            assertEquals(true, Arrays.equals(cHashResult1[0], cHashResult1Prime[0]));

            //Test collision
            chameleonHasher.init(true, secretKey);
            chameleonHasher.update(message2.getBytes(), 0, message2.getBytes().length);
            byte[][] cHashCollision = chameleonHasher.findCollision(cHashResult1[0], cHashResult1[1]);
            System.out.println("Coll. Resist. = " + Arrays.toString(cHashCollision[0]));
            assertEquals(true, Arrays.equals(cHashResult1[0], cHashCollision[0]));

            System.out.println("Test pass.");
            System.out.println();
        } catch (CryptoException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        SecureRandom secureRandom = new SecureRandom();
        //RFC 3526, 1536-bit MODP Group
        SecurePrimeSerParameter securePrimeSerParameter = SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP;

        //test Krawczyk-Rabin Chameleon hash
        System.out.println("Test Krawczyk-Rabin Chameleon hash function");
        AsymmetricCipherKeyPairGenerator signKeyPairGenerator = new DLogKR00bKeyPairGenerator();
        signKeyPairGenerator.init(new DLogKR00bKeyGenerationParameters(secureRandom, securePrimeSerParameter));
        ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bHasher(), new SHA256Digest());
        new ChameleonHasherTest(signKeyPairGenerator, chameleonHasher).processTest();

        //test Krawczyk-Rabin Chameleon hash
        System.out.println("Test Universal Collision-Resistant Krawczyk-Rabin Chameleon hash function");
        chameleonHasher = new KR00bDigestHasher(new DLogKR00bUniversalHasher(new SHA256Digest()), new SHA256Digest());
        new ChameleonHasherTest(signKeyPairGenerator, chameleonHasher).processTest();
    }
}
