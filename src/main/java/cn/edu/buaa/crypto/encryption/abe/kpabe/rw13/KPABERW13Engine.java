package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/30.
 *
 * Rouselakis-Waters KP-ABE engine.
 */
public class KPABERW13Engine extends KPABEEngine {
    private static final String SCHEME_NAME = "Rouselakis-Waters-13 large-universe KP-ABE";

    private static KPABERW13Engine engine;

    public static KPABERW13Engine getInstance() {
        if (engine == null) {
            engine = new KPABERW13Engine();
        }
        return engine;
    }

    private KPABERW13Engine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        KPABERW13KeyPairGenerator keyPairGenerator = new KPABERW13KeyPairGenerator();
        keyPairGenerator.init(new KPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof KPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof KPABERW13MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, KPABERW13MasterSecretKeySerParameter.class.getName());
        }
        KPABERW13SecretKeyGenerator secretKeyGenerator = new KPABERW13SecretKeyGenerator();
        secretKeyGenerator.init(new KPABESecretKeyGenerationParameter(
                accessControlEngine, publicKey, masterKey, accessPolicyIntArrays, rhos));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] attributes, Element message) {
        if (!(publicKey instanceof KPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABERW13PublicKeySerParameter.class.getName());
        }
        KPABERW13EncryptionGenerator encryptionGenerator = new KPABERW13EncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] attributes) {
        if (!(publicKey instanceof KPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABERW13PublicKeySerParameter.class.getName());
        }
        KPABERW13EncryptionGenerator encryptionGenerator = new KPABERW13EncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABERW13SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, KPABERW13SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof KPABERW13CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, KPABERW13CiphertextSerParameter.class.getName());
        }
        KPABERW13DecryptionGenerator decryptionGenerator = new KPABERW13DecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABERW13PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABERW13PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABERW13SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, KPABERW13SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof KPABERW13HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, KPABERW13HeaderSerParameter.class.getName());
        }
        KPABERW13DecryptionGenerator decryptionGenerator = new KPABERW13DecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, header));
        return decryptionGenerator.recoverKey();
    }
}
