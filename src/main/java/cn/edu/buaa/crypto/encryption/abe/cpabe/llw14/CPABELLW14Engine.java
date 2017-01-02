package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.*;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.CPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.generators.CPABELLW14DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.generators.CPABELLW14EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.generators.CPABELLW14KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.generators.CPABELLW14SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu CCA2-secure CP-ABE engine.
 */
public class CPABELLW14Engine extends CPABEEngine {
    private static final String SCHEME_NAME = "Liu-Liu-Wu-14 CCA2-secure large-universe CP-ABE";
    private static CPABELLW14Engine engine;
    private ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bHasher(), new SHA256Digest());
    private AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
    private KeyGenerationParameters chKeyPairGenerationParameter
            = new DLogKR00bKeyGenerationParameters(new SecureRandom(), SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);

    public static CPABELLW14Engine getInstance() {
        if (engine == null) {
            engine = new CPABELLW14Engine();
        }
        return engine;
    }

    private CPABELLW14Engine() {
        super(SCHEME_NAME, Engine.ProveSecModel.Standard, Engine.PayloadSecLevel.CCA2, Engine.PredicateSecLevel.NON_ANON);
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher,
                                   AsymmetricKeySerPairGenerator chKeyPairGenerator,
                                   KeyGenerationParameters keyGenerationParameters) {
        this.chameleonHasher = chameleonHasher;
        this.chKeyPairGenerator = chKeyPairGenerator;
        this.chKeyPairGenerationParameter = keyGenerationParameters;
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        CPABELLW14KeyPairGenerator keyPairGenerator = new CPABELLW14KeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(
                pairingParameters, this.chKeyPairGenerator, this.chKeyPairGenerationParameter));
        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof CPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CPABELLW14PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof CPABELLW14MasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + CPABELLW14MasterSecretKeySerParameter.class.getName());
        }
        CPABELLW14SecretKeyGenerator secretKeyGenerator = new CPABELLW14SecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof CPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CPABELLW14PublicKeySerParameter.class.getName());
        }
        CPABELLW14EncryptionGenerator encryptionGenerator = new CPABELLW14EncryptionGenerator();
        CPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new CPABEEncryptionGenerationParameter(accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerator.init(encryptionGenerationParameter);

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof CPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CPABELLW14PublicKeySerParameter.class.getName());
        }
        CPABELLW14EncryptionGenerator encryptionGenerator = new CPABELLW14EncryptionGenerator();
        CPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new CPABEEncryptionGenerationParameter(accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerator.init(encryptionGenerationParameter);

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CPABELLW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABELLW14SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + CPABELLW14SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof CPABELLW14CiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + CPABELLW14CiphertextSerParameter.class.getName());
        }
        CPABELLW14DecryptionGenerator decryptionGenerator = new CPABELLW14DecryptionGenerator();
        CPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new CPABEDecryptionGenerationParameter(
                        accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CPABELLW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABELLW14SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + CPABELLW14SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof CPABELLW14HeaderSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + header.getClass().getName() + ", require "
                            + CPABELLW14HeaderSerParameter.class.getName());
        }
        CPABELLW14DecryptionGenerator decryptionGenerator = new CPABELLW14DecryptionGenerator();
        CPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new CPABEDecryptionGenerationParameter(
                        accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverKey();
    }
}
