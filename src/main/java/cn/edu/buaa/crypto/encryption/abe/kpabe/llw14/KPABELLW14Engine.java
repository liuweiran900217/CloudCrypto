package cn.edu.buaa.crypto.encryption.abe.kpabe.llw14;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.*;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.generators.KPABELLW14DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.generators.KPABELLW14EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.generators.KPABELLW14KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.generators.KPABELLW14SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2017/1/1.
 * Liu-Liu-Wu-14 CCA2-secure KP-ABE engine.
 */
public class KPABELLW14Engine extends KPABEEngine {
    private static final String SCHEME_NAME = "Liu-Liu-Wu-14 CCA2-secure large-universe KP-ABE";

    private static KPABELLW14Engine engine;
    private ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bHasher(), new SHA256Digest());
    private AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
    private KeyGenerationParameters chKeyGenerationParameter
            = new DLogKR00bKeyGenerationParameters(new SecureRandom(), SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);

    public static KPABELLW14Engine getInstance() {
        if (engine == null) {
            engine = new KPABELLW14Engine();
        }
        return engine;
    }

    private KPABELLW14Engine() {
        super(SCHEME_NAME, Engine.ProveSecModel.Standard, Engine.PayloadSecLevel.CCA2, Engine.PredicateSecLevel.NON_ANON);
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher,
                                   AsymmetricKeySerPairGenerator chKeyPairGenerator,
                                   KeyGenerationParameters keyGenerationParameter) {
        this.chameleonHasher = chameleonHasher;
        this.chKeyPairGenerator = chKeyPairGenerator;
        this.chKeyGenerationParameter = keyGenerationParameter;
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        KPABELLW14KeyPairGenerator keyPairGenerator = new KPABELLW14KeyPairGenerator();
        keyPairGenerator.init(new KPABEKeyPairGenerationParameter(
                pairingParameters, this.chKeyPairGenerator, this.chKeyGenerationParameter));
        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof KPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABELLW14PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof KPABELLW14MasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + KPABELLW14MasterSecretKeySerParameter.class.getName());
        }
        KPABELLW14SecretKeyGenerator secretKeyGenerator = new KPABELLW14SecretKeyGenerator();
        secretKeyGenerator.init(new KPABESecretKeyGenerationParameter(
                accessControlEngine, publicKey, masterKey, accessPolicyIntArrays, rhos));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] attributes, Element message) {
        if (!(publicKey instanceof KPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABELLW14PublicKeySerParameter.class.getName());
        }
        KPABELLW14EncryptionGenerator encryptionGenerator = new KPABELLW14EncryptionGenerator();
        KPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new KPABEEncryptionGenerationParameter(publicKey, attributes, message);
        encryptionGenerationParameter.setChameleonHasher(chameleonHasher);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] attributes) {
        if (!(publicKey instanceof KPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABELLW14PublicKeySerParameter.class.getName());
        }
        KPABELLW14EncryptionGenerator encryptionGenerator = new KPABELLW14EncryptionGenerator();
        KPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new KPABEEncryptionGenerationParameter(publicKey, attributes, null);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerator.init(encryptionGenerationParameter);

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABELLW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABELLW14SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + KPABELLW14SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof KPABELLW14CiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + KPABELLW14CiphertextSerParameter.class.getName());
        }
        KPABELLW14DecryptionGenerator decryptionGenerator = new KPABELLW14DecryptionGenerator();
        KPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new KPABEDecryptionGenerationParameter(accessControlEngine, publicKey, secretKey, attributes, ciphertext);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABELLW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABELLW14SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + KPABELLW14SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof KPABELLW14HeaderSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + header.getClass().getName() + ", require "
                            + KPABELLW14HeaderSerParameter.class.getName());
        }
        KPABELLW14DecryptionGenerator decryptionGenerator = new KPABELLW14DecryptionGenerator();
        KPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new KPABEDecryptionGenerationParameter(accessControlEngine, publicKey, secretKey, attributes, header);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverKey();
    }
}
