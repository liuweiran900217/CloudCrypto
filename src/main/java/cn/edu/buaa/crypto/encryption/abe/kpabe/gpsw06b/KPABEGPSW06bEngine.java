package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators.KPABEGPSW06bDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators.KPABEGPSW06bEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators.KPABEGPSW06bKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators.KPABEGPSW06bSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles engine.
 */
public class KPABEGPSW06bEngine extends KPABEEngine {
    //Scheme name, used for exceptions
    private static final String SCHEME_NAME = "Goyal-Pandey-Sahai-Waters-06 large-universe KP-ABE";

    private static KPABEGPSW06bEngine engine;

    public static KPABEGPSW06bEngine getInstance() {
        if (engine == null) {
            engine = new KPABEGPSW06bEngine();
        }
        return engine;
    }

    private KPABEGPSW06bEngine() {

    }

    public String getEngineName() {
        return SCHEME_NAME;
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        KPABEGPSW06bKeyPairGenerator keyPairGenerator = new KPABEGPSW06bKeyPairGenerator();
        keyPairGenerator.init(new KPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof KPABEGPSW06bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEGPSW06bPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof KPABEGPSW06bMasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + KPABEGPSW06bMasterSecretKeySerParameter.class.getName());
        }
        KPABEGPSW06bSecretKeyGenerator secretKeyGenerator = new KPABEGPSW06bSecretKeyGenerator();
        secretKeyGenerator.init(new KPABESecretKeyGenerationParameter(
                accessControlEngine, publicKey, masterKey, accessPolicyIntArrays, rhos));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] attributes, Element message) {
        if (!(publicKey instanceof KPABEGPSW06bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEGPSW06bPublicKeySerParameter.class.getName());
        }
        KPABEGPSW06bEncryptionGenerator encryptionGenerator = new KPABEGPSW06bEncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABEGPSW06bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEGPSW06bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABEGPSW06bSecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + KPABEGPSW06bSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof KPABEGPSW06bCiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + KPABEGPSW06bCiphertextSerParameter.class.getName());
        }
        KPABEGPSW06bDecryptionGenerator decryptionGenerator = new KPABEGPSW06bDecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

}
