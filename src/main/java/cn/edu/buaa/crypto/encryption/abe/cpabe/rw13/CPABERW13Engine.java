package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.CPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13DecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13EncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/9/19.
 *
 * Engines for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13Engine extends CPABEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "RW13KP-ABE";

    private static CPABERW13Engine engine;

    public static CPABERW13Engine getInstance() {
        if (engine == null) {
            engine = new CPABERW13Engine();
        }
        return engine;
    }

    private CPABERW13Engine() {

    }

    @Override
    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength) {
        CPABERW13KeyPairGenerator keyPairGenerator = new CPABERW13KeyPairGenerator();
        keyPairGenerator.init(new CPABERW13KeyPairGenerationParameters(rBitLength, qBitLength, this.accessControlEngineInstance));
        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String[] attributeSet) {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof CPABERW13MasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + CPABERW13MasterSecretKeySerParameter.class.getName());
        }
        CPABERW13SecretKeyGenerator secretKeyGenerator = new CPABERW13SecretKeyGenerator();
        secretKeyGenerator.init(new CPABERW13SecretKeyGenerationParameters(
                publicKey, masterKey, attributeSet));

        return secretKeyGenerator.generateKey();
    }

    @Override
    public PairingKeyEncapsulationSerPair encapsulation(CipherParameters publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CPABERW13PublicKeySerParameter.class.getName());
        }
        CPABERW13EncapsulationPairGenerator keyEncapsulationPairGenerator = new CPABERW13EncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new CPABERW13CiphertextGenerationParameters(
                publicKey, accessPolicyIntArrays, rhos));
        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    @Override
    public byte[] decapsulation(CipherParameters publicKey, CipherParameters secretKey, int[][] accessPolicyIntArrays, String[] rhos, CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABERW13SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + CPABERW13SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof CPABERW13CipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + CPABERW13CipherSerParameter.class.getName());
        }
        CPABERW13DecapsulationGenerator keyDecapsulationGenerator = new CPABERW13DecapsulationGenerator();
        keyDecapsulationGenerator.init(new CPABERW13DecapsulationParameters(
                publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}
