package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.CPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.*;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.*;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters large-universe CP-ABE engine.
 */
public class CPABERW13Engine extends CPABEEngine {
    private static final String SCHEME_NAME = "Rousekalis-Waters-13 large-universe CP-ABE";
    private static CPABERW13Engine engine;

    public static CPABERW13Engine getInstance() {
        if (engine == null) {
            engine = new CPABERW13Engine();
        }
        return engine;
    }

    private CPABERW13Engine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        CPABERW13KeyPairGenerator keyPairGenerator = new CPABERW13KeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof CPABERW13MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, CPABERW13MasterSecretKeySerParameter.class.getName());
        }
        CPABERW13SecretKeyGenerator secretKeyGenerator = new CPABERW13SecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));
        return secretKeyGenerator.generateKey();
    }

    public PairingKeySerParameter IDKeyGen(PairingKeySerParameter publicKey,
                                           PairingKeySerParameter masterKey, String ID) {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof CPABERW13MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, CPABERW13MasterSecretKeySerParameter.class.getName());
        }
        CPABERW13IDSecretKeyGenerator IDsecretKeyGenerator = new CPABERW13IDSecretKeyGenerator();
        IDsecretKeyGenerator.init(new CPABEIDSecretKeyGenerationParameter(publicKey, masterKey, ID));
        return IDsecretKeyGenerator.generateKey();
    }

    public PairingKeySerParameter reKeyGen(PairingKeySerParameter publicKey,
                                           PairingKeySerParameter secretKey, String ID) {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABERW13SecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABERW13SecretKeySerParameter.class.getName());
        }
        CPABERW13ReKeyGenerator reEncryptionKey = new CPABERW13ReKeyGenerator();
        reEncryptionKey.init(new CPABEReKeyGenerationParameter(publicKey, secretKey, ID));
        return reEncryptionKey.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERW13PublicKeySerParameter.class.getName());
        }
        CPABERW13EncryptionGenerator encryptionGenerator = new CPABERW13EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message));
        return encryptionGenerator.generateCiphertext();
    }

    public PairingCipherSerParameter reEncryption(PairingKeySerParameter publicKey,
                                                  PairingKeySerParameter reEncryptionKey,
                                                  PairingCipherSerParameter Ciphertext,
                                                  int[][] accessPolicyIntArrays,
                                                  String[] rhos) throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(reEncryptionKey instanceof CPABERW13ReKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, reEncryptionKey, CPABERW13ReKeySerParameter.class.getName());
        }
        if (!(Ciphertext instanceof CPABERW13CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, Ciphertext, CPABERW13CiphertextSerParameter.class.getName());
        }
        CPABERW13ReEncryptionGenerator reEncryptionGenerator = new CPABERW13ReEncryptionGenerator();
        reEncryptionGenerator.init(new CPABEReEncGenerationParameter(publicKey, reEncryptionKey,
                Ciphertext, accessControlEngine, accessPolicyIntArrays, rhos));
        return reEncryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERW13PublicKeySerParameter.class.getName());
        }
        CPABERW13EncryptionGenerator encryptionGenerator = new CPABERW13EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null));
        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABERW13SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABERW13SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof CPABERW13CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, CPABERW13CiphertextSerParameter.class.getName());
        }
        CPABERW13DecryptionGenerator decryptionGenerator = new CPABERW13DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public Element reDecryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                PairingCipherSerParameter reEncCiphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABERW13IDSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABERW13SecretKeySerParameter.class.getName());
        }
        if (!(reEncCiphertext instanceof CPABERW13ReEncHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, reEncCiphertext, CPABERW13ReEncHeaderSerParameter.class.getName());
        }
        CPABERW13ReDecryptionGenerator reDecryptionGenerator = new CPABERW13ReDecryptionGenerator();
        reDecryptionGenerator.init(new CPABEReDecGenerationParameter(publicKey, secretKey, reEncCiphertext));
        return reDecryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABERW13SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABERW13SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof CPABERW13HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, CPABERW13HeaderSerParameter.class.getName());
        }
        CPABERW13DecryptionGenerator decryptionGenerator = new CPABERW13DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header));
        return decryptionGenerator.recoverKey();
    }
}
