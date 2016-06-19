package cn.edu.buaa.crypto.application.llw15;

import cn.edu.buaa.crypto.application.llw15.generators.*;
import cn.edu.buaa.crypto.application.llw15.params.*;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/17.
 */
public class RBACLLW15Engine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW15-RBAC";
    // Default strength for KeyPairGenerator, useless in Pairing based cryptography
    public static final int STENGTH = 12;

    public RBACLLW15Engine() {

    }

    public AsymmetricCipherKeyPair Setup(int rBitLength, int qBitLength, int maxRoleNumber) {
        RBACLLW15KeyPairGenerator keyPairGenerator = new RBACLLW15KeyPairGenerator();
        keyPairGenerator.init(new RBACLLW15KeyPairGenerationParameters(rBitLength, qBitLength, maxRoleNumber));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters ACGenM(CipherParameters publicKey, CipherParameters masterKey, String[] roles, String time) {
        if (!(publicKey instanceof RBACLLW15PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RBACLLW15PublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof RBACLLW15MasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + RBACLLW15MasterSecretKeyParameters.class.getName());
        }
        RBACLLW15AccessCredentialMGenerator secretKeyGenerator = new RBACLLW15AccessCredentialMGenerator();
        secretKeyGenerator.init(new RBACLLW15AccessCredentialMGenParameters(
                publicKey, masterKey, roles, time));

        return secretKeyGenerator.generateKey();
    }

    public CipherParameters ACDeleM(CipherParameters publicKey, CipherParameters accessCredentialM, int index, String role) {
        if (!(publicKey instanceof RBACLLW15PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RBACLLW15PublicKeyParameters.class.getName());
        }
        if (!(accessCredentialM instanceof RBACLLW15AccessCredentialMParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + accessCredentialM.getClass().getName() + ", require"
                            + RBACLLW15AccessCredentialMParameters.class.getName());
        }
        RBACLLW15AccessCredentialMGenerator secretKeyGenerator = new RBACLLW15AccessCredentialMGenerator();
        secretKeyGenerator.init(new RBACLLW15AccessCredentialMDeleParameters(
                publicKey, accessCredentialM, index, role));

        return secretKeyGenerator.generateKey();
    }

    public CipherParameters ACGenP(CipherParameters publicKey, CipherParameters masterKey, String id) {
        if (!(publicKey instanceof RBACLLW15PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RBACLLW15PublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof RBACLLW15MasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + RBACLLW15MasterSecretKeyParameters.class.getName());
        }
        RBACLLW15AccessCredentialPGenerator secretKeyGenerator = new RBACLLW15AccessCredentialPGenerator();
        secretKeyGenerator.init(new RBACLLW15AccessCredentialPGenParameters(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair EHREnc(CipherParameters publicKey, String id, String[] roles, String time){
        if (!(publicKey instanceof RBACLLW15PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RBACLLW15PublicKeyParameters.class.getName());
        }
        RBACLLW15KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new RBACLLW15KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new RBACLLW15EncapsulationGenParameters(
                publicKey, id, roles, time));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public boolean EHRAudit(CipherParameters publicKey, String id, String[] roles, String time, CipherParameters encapsulation) {
        if (!(publicKey instanceof RBACLLW15PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RBACLLW15PublicKeyParameters.class.getName());
        }
        if (!(encapsulation instanceof RBACLLW15EncapsulationParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + encapsulation.getClass().getName() + ", require "
                            + RBACLLW15EncapsulationParameters.class.getName());
        }
        RBACLLW15EncapsulationAudit encapsulationAudit = new RBACLLW15EncapsulationAudit();
        encapsulationAudit.init(new RBACLLW15EncapsulationAuditParameters(
                publicKey, id, roles, time, encapsulation));
        return encapsulationAudit.audit();
    }

    public byte[] EHRDecM (
            CipherParameters publicKey, String id, String[] roles, String time,
            CipherParameters encapsulation, CipherParameters accessCredentialM) throws InvalidCipherTextException {
        if (!(publicKey instanceof RBACLLW15PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RBACLLW15PublicKeyParameters.class.getName());
        }
        if (!(accessCredentialM instanceof RBACLLW15AccessCredentialMParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + accessCredentialM.getClass().getName() + ", require "
                            + RBACLLW15AccessCredentialMParameters.class.getName());
        }
        if (!(encapsulation instanceof RBACLLW15EncapsulationParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + encapsulation.getClass().getName() + ", require "
                            + RBACLLW15EncapsulationParameters.class.getName());
        }
        if (!EHRAudit(publicKey, id, roles, time, encapsulation)) {
            throw new InvalidCipherTextException("Encapsulation is invalid due to EHRAudit");
        } else {
            RBACLLW15DecapsulationMGenerator keyDecapsulationGenerator = new RBACLLW15DecapsulationMGenerator();
            keyDecapsulationGenerator.init(new RBACLLW15DecapsulationMParameters(
                    publicKey, accessCredentialM, id, roles, time, encapsulation));
            return keyDecapsulationGenerator.recoverKey();
        }
    }

    public byte[] EHRDecP (
            CipherParameters publicKey, String id, String[] roles, String time,
            CipherParameters encapsulation, CipherParameters accessCredentialP) throws InvalidCipherTextException {
        if (!(publicKey instanceof RBACLLW15PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RBACLLW15PublicKeyParameters.class.getName());
        }
        if (!(accessCredentialP instanceof RBACLLW15AccessCredentialPParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + accessCredentialP.getClass().getName() + ", require "
                            + RBACLLW15AccessCredentialMParameters.class.getName());
        }
        if (!(encapsulation instanceof RBACLLW15EncapsulationParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + encapsulation.getClass().getName() + ", require "
                            + RBACLLW15EncapsulationParameters.class.getName());
        }
        if (!EHRAudit(publicKey, id, roles, time, encapsulation)) {
            throw new InvalidCipherTextException("Encapsulation is invalid due to EHRAudit");
        } else {
            RBACLLW15DecapsulationPGenerator keyDecapsulationGenerator = new RBACLLW15DecapsulationPGenerator();
            keyDecapsulationGenerator.init(new RBACLLW15DecapsulationPParameters(
                    publicKey, accessCredentialP, id, roles, time, encapsulation));
            return keyDecapsulationGenerator.recoverKey();
        }
    }
}
