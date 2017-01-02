package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.OOKPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.*;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators.*;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 OO-KP-ABE engine.
 */
public class OOKPABEHW14Engine extends OOKPABEEngine {
    private static final String SCHEME_NAME = "Hohenberger-Waters-14 CPA-secure large-universe OO-KP-ABE";
    private static OOKPABEHW14Engine engine;

    public static OOKPABEHW14Engine getInstance() {
        if (engine == null) {
            engine = new OOKPABEHW14Engine();
        }
        return engine;
    }

    private OOKPABEHW14Engine() {
        super(SCHEME_NAME, Engine.ProveSecModel.Standard, Engine.PayloadSecLevel.CPA, Engine.PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        KPABEHW14KeyPairGenerator keyPairGenerator = new KPABEHW14KeyPairGenerator();
        keyPairGenerator.init(new KPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof KPABEHW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof KPABEHW14MasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + KPABEHW14MasterSecretKeySerParameter.class.getName());
        }
        KPABEHW14SecretKeyGenerator secretKeyGenerator = new KPABEHW14SecretKeyGenerator();
        secretKeyGenerator.init(new KPABESecretKeyGenerationParameter(
                accessControlEngine, publicKey, masterKey, accessPolicyIntArrays, rhos));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] attributes, Element message) {
        if (!(publicKey instanceof KPABEHW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEHW14PublicKeySerParameter.class.getName());
        }
        KPABEHW14EncryptionGenerator encryptionGenerator = new KPABEHW14EncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] attributes) {
        if (!(publicKey instanceof KPABEHW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEHW14PublicKeySerParameter.class.getName());
        }
        KPABEHW14EncryptionGenerator encryptionGenerator = new KPABEHW14EncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABEHW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABEHW14SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + KPABEHW14SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof KPABEHW14CiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + KPABEHW14CiphertextSerParameter.class.getName());
        }
        KPABEHW14DecryptionGenerator decryptionGenerator = new KPABEHW14DecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABEHW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABEHW14SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + KPABEHW14SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof KPABEHW14HeaderSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + header.getClass().getName() + ", require "
                            + KPABEHW14HeaderSerParameter.class.getName());
        }
        KPABEHW14DecryptionGenerator decryptionGenerator = new KPABEHW14DecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, header));
        return decryptionGenerator.recoverKey();
    }

    public PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n) {
        if (!(publicKey instanceof KPABEHW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEHW14PublicKeySerParameter.class.getName());
        }
        KPABEHW14IntermediateGenerator intermediateGenerator = new KPABEHW14IntermediateGenerator();
        intermediateGenerator.init(new KPABEIntermediateGenerationParameter(publicKey, n));
        return intermediateGenerator.generateCiphertext();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] attributes, Element message) {
        if (!(publicKey instanceof KPABEHW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof KPABEHW14IntermediateSerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                    + intermediate.getClass().getName() + ", require "
                    + KPABEHW14IntermediateSerParameter.class.getName());
        }
        KPABEHW14EncryptionGenerator encryptionGenerator = new KPABEHW14EncryptionGenerator();
        KPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new KPABEEncryptionGenerationParameter(publicKey, attributes, message);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] attributes) {
        if (!(publicKey instanceof KPABEHW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof KPABEHW14IntermediateSerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + intermediate.getClass().getName() + ", require "
                            + KPABEHW14IntermediateSerParameter.class.getName());
        }
        KPABEHW14EncryptionGenerator encryptionGenerator = new KPABEHW14EncryptionGenerator();
        KPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new KPABEEncryptionGenerationParameter(publicKey, attributes, null);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateEncryptionPair();
    }
}
