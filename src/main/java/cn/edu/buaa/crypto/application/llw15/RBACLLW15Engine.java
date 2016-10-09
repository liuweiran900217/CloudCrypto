package cn.edu.buaa.crypto.application.llw15;

import cn.edu.buaa.crypto.application.llw15.generators.*;
import cn.edu.buaa.crypto.application.llw15.params.*;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/17.
 *
 * Liu-Liu-Wu EHR role-based access control engine.
 */
public class RBACLLW15Engine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW15-RBAC";

    private static RBACLLW15Engine engine;

    public static RBACLLW15Engine getInstance() {
        if (engine == null) {
            engine = new RBACLLW15Engine();
        }
        return engine;
    }

    private RBACLLW15Engine() {

    }


    /**
     * Setup algorithm
     * @param rBitLength Order of Z_r bit length
     * @param qBitLength Order of G/G_T bit length
     * @param maxRoleNumber maximal number of atom roles
     * @return public key / master secret key pairs
     */
    public AsymmetricCipherKeyPair Setup(int rBitLength, int qBitLength, int maxRoleNumber) {
        RBACLLW15KeyPairGenerator keyPairGenerator = new RBACLLW15KeyPairGenerator();
        keyPairGenerator.init(new RBACLLW15KeyPairGenerationParameters(rBitLength, qBitLength, maxRoleNumber));

        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Intermediate parameter generation lagorithm
     * @param publicKey public key
     * @return intermediate parameters
     */
    public CipherParameters IntermediateGen(CipherParameters publicKey) {
        if (!(publicKey instanceof RBACLLW15PublicKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RBACLLW15PublicKeyParameters.class.getName());
        }
        RBACLLW15IntermediateGenerator intermediateGenerator = new RBACLLW15IntermediateGenerator();
        intermediateGenerator.init(new RBACLLW15IntermediateGenParameters(publicKey));
        return intermediateGenerator.generateIntermadiateParameters();
    }

    /**
     * Patient access credential generation algorithm
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id patient's id
     * @return access credential for the patient associated with id
     */
    public CipherParameters ACGenP(CipherParameters publicKey, CipherParameters masterKey, String id) {
        isValidACGenParameters(publicKey, masterKey);
        RBACLLW15AccessCredentialPGenerator secretKeyGenerator = new RBACLLW15AccessCredentialPGenerator();
        secretKeyGenerator.init(new RBACLLW15AccessCredentialPGenParameters(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    /**
     * Patient access credential generation algorithm using intermediate parameters
     * @param publicKey public key
     * @param masterKey master secret key
     * @param intermediateParameters intermediate parameters
     * @param id patient's id
     * @return access credential for the patient associated with id
     */
    public CipherParameters ACGenP(CipherParameters publicKey, CipherParameters masterKey,
                                   CipherParameters intermediateParameters, String id) {
        isValidACGenParameters(publicKey, masterKey);
        RBACLLW15AccessCredentialPGenerator secretKeyGenerator = new RBACLLW15AccessCredentialPGenerator();
        secretKeyGenerator.init(new RBACLLW15AccessCredentialPGenParameters(
                publicKey, masterKey, intermediateParameters, id));

        return secretKeyGenerator.generateKey();
    }

    /**
     * Medical staff access credential generation algorithm
     * @param publicKey public key
     * @param masterKey master secret key
     * @param roles role vectors
     * @param time valid time
     * @return access credential for the medical staff associated with roles
     */
    public CipherParameters ACGenM(CipherParameters publicKey, CipherParameters masterKey, String[] roles, String time) {
        isValidACGenParameters(publicKey, masterKey);
        RBACLLW15AccessCredentialMGenerator secretKeyGenerator = new RBACLLW15AccessCredentialMGenerator();
        secretKeyGenerator.init(new RBACLLW15AccessCredentialMGenParameters(
                publicKey, masterKey, roles, time));

        return secretKeyGenerator.generateKey();
    }

    /**
     * Medical staff access credential generation algorithm using intermediate parameters
     * @param publicKey public key
     * @param masterKey master secret key
     * @param intermediateParameters intermediate parameters
     * @param roles role vectors
     * @param time valid time
     * @return access credential for the medical staff associated with roles
     */
    public CipherParameters ACGenM(CipherParameters publicKey, CipherParameters masterKey,
                                   CipherParameters intermediateParameters, String[] roles, String time) {
        isValidACGenParameters(publicKey, masterKey);
        RBACLLW15AccessCredentialMGenerator secretKeyGenerator = new RBACLLW15AccessCredentialMGenerator();
        secretKeyGenerator.init(new RBACLLW15AccessCredentialMGenParameters(
                publicKey, masterKey, intermediateParameters, roles, time));

        return secretKeyGenerator.generateKey();
    }

    private void isValidACGenParameters(CipherParameters publicKey, CipherParameters masterKey) {
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
    }

    /**
     * Medical staff access credential delegation algorithm
     * @param publicKey public key
     * @param accessCredentialM parent medical staff access credential
     * @param index delegated role index
     * @param role delegated role
     * @return access credential for the medical staff associated with delegated role
     */
    public CipherParameters ACDeleM(CipherParameters publicKey, CipherParameters accessCredentialM, int index, String role) {
        isValidACDeleMParameters(publicKey, accessCredentialM);
        RBACLLW15AccessCredentialMGenerator secretKeyGenerator = new RBACLLW15AccessCredentialMGenerator();
        secretKeyGenerator.init(new RBACLLW15AccessCredentialMDeleParameters(
                publicKey, accessCredentialM, index, role));

        return secretKeyGenerator.generateKey();
    }

    /**
     * Medical staff access credential delegation algorithm using intermediate parameters
     * @param publicKey public key
     * @param accessCredentialM parent medical staff access credential
     * @param intermediateParameters intermediate parameters
     * @param index delegated role index
     * @param role delegated role
     * @return access credential for the medical staff associated with delegated role
     */
    public CipherParameters ACDeleM(CipherParameters publicKey, CipherParameters accessCredentialM,
                                    CipherParameters intermediateParameters, int index, String role) {
        isValidACDeleMParameters(publicKey, accessCredentialM);
        RBACLLW15AccessCredentialMGenerator secretKeyGenerator = new RBACLLW15AccessCredentialMGenerator();
        secretKeyGenerator.init(new RBACLLW15AccessCredentialMDeleParameters(
                publicKey, accessCredentialM, intermediateParameters, index, role));

        return secretKeyGenerator.generateKey();
    }

    private void isValidACDeleMParameters(CipherParameters publicKey, CipherParameters accessCredentialM) {
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
    }

    /**
     * key encapsulation algorithm
     * @param publicKey public key
     * @param id patient's id
     * @param roles associated roles
     * @param time valid time
     * @return ciphertext / sesscion key pair
     */
    public PairingKeyEncapsulationPair EHREnc(CipherParameters publicKey, String id, String[] roles, String time) {
        isValidKeyEncapsulationParameters(publicKey);
        RBACLLW15KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new RBACLLW15KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new RBACLLW15EncapsulationGenParameters(
                publicKey, id, roles, time));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    /**
     * key encapsulation algorithm using intermediate parameters
     * @param publicKey public key
     * @param intermediateParameters intermediate parameters
     * @param id patient's id
     * @param roles associated roles
     * @param time valid time
     * @return ciphertext / session key pair
     */
    public PairingKeyEncapsulationPair EHREnc(CipherParameters publicKey, CipherParameters intermediateParameters,
                                              String id, String[] roles, String time) {
        isValidKeyEncapsulationParameters(publicKey);
        RBACLLW15KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new RBACLLW15KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new RBACLLW15EncapsulationGenParameters(
                publicKey, intermediateParameters, id, roles, time));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    private void isValidKeyEncapsulationParameters(CipherParameters publicKey) {
        if (!(publicKey instanceof RBACLLW15PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RBACLLW15PublicKeyParameters.class.getName());
        }
    }

    /**
     * EHR encapsulation audit algorithm
     * @param publicKey public key
     * @param id patient's id
     * @param roles associated roles
     * @param time valid time
     * @param encapsulation ciphertext
     * @return true if valid, false if invalid
     */
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

    /**
     * EHR medical staff decapsulation algorithm without encapsulation audit procedure
     * @param publicKey public key
     * @param id patient's id
     * @param roles associated roles
     * @param time valid time
     * @param encapsulation ciphertext
     * @param accessCredentialM medical staff access credential
     * @return decapsulated session key
     */
    public byte[] EHRDecM (
            CipherParameters publicKey, String id, String[] roles, String time,
            CipherParameters encapsulation, CipherParameters accessCredentialM) throws InvalidCipherTextException {
        isValidAccessCredentialMDecapsulationParameters(publicKey, encapsulation, accessCredentialM);
        RBACLLW15DecapsulationMGenerator keyDecapsulationGenerator = new RBACLLW15DecapsulationMGenerator();
        keyDecapsulationGenerator.init(new RBACLLW15DecapsulationMParameters(
                publicKey, accessCredentialM, id, roles, time, encapsulation));
        return keyDecapsulationGenerator.recoverKey();
    }

    /**
     * EHR medical staff decapsulation algorithm with encapsulation audit procedure
     * @param publicKey public key
     * @param id patient's id
     * @param roles associated roles
     * @param time valid time
     * @param encapsulation ciphertext
     * @param accessCredentialM medical staff access credential
     * @return decapsulated session key
     * @throws InvalidCipherTextException if EHR encapsulation is invalid
     */
    public byte[] EHRDecMWithAudit (
            CipherParameters publicKey, String id, String[] roles, String time,
            CipherParameters encapsulation, CipherParameters accessCredentialM) throws InvalidCipherTextException {
        isValidAccessCredentialMDecapsulationParameters(publicKey, encapsulation, accessCredentialM);
        if (!EHRAudit(publicKey, id, roles, time, encapsulation)) {
            throw new InvalidCipherTextException("Encapsulation is invalid due to EHRAudit");
        }
        return EHRDecM(publicKey, id, roles, time, encapsulation, accessCredentialM);
    }

    private void isValidAccessCredentialMDecapsulationParameters(
            CipherParameters publicKey, CipherParameters encapsulation, CipherParameters accessCredentialM) {
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
    }

    /**
     * EHR patient decapsulation algorithm without encapsulation audit procedure
     * @param publicKey public key
     * @param id patient's id
     * @param roles assocciated roles
     * @param time valid time
     * @param encapsulation ciphertext
     * @param accessCredentialP patient access credential
     * @return decapsulated session key
     * @throws InvalidCipherTextException
     */
    public byte[] EHRDecP (
            CipherParameters publicKey, String id, String[] roles, String time,
            CipherParameters encapsulation, CipherParameters accessCredentialP) throws InvalidCipherTextException {
        isValidAccessCredentialPDecapsulationParameters(publicKey, encapsulation, accessCredentialP);
        RBACLLW15DecapsulationPGenerator keyDecapsulationGenerator = new RBACLLW15DecapsulationPGenerator();
        keyDecapsulationGenerator.init(new RBACLLW15DecapsulationPParameters(
                publicKey, accessCredentialP, id, roles, time, encapsulation));
        return keyDecapsulationGenerator.recoverKey();
    }

    /**
     * EHR patient decapsulation algorithm with encapsulation audit procedure
     * @param publicKey public key
     * @param id patient's id
     * @param roles assocciated roles
     * @param time valid time
     * @param encapsulation ciphertext
     * @param accessCredentialP patient access credential
     * @return decapsulated session key
     * @throws InvalidCipherTextException
     */
    public byte[] EHRDecPWithAudit (
            CipherParameters publicKey, String id, String[] roles, String time,
            CipherParameters encapsulation, CipherParameters accessCredentialP) throws InvalidCipherTextException {
        isValidAccessCredentialPDecapsulationParameters(publicKey, encapsulation, accessCredentialP);
        if (!EHRAudit(publicKey, id, roles, time, encapsulation)) {
            throw new InvalidCipherTextException("Encapsulation is invalid due to EHRAudit");
        }
        return EHRDecP(publicKey, id, roles, time, encapsulation, accessCredentialP);
    }

    private void isValidAccessCredentialPDecapsulationParameters(
            CipherParameters publicKey, CipherParameters encapsulation, CipherParameters accessCredentialP) {
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
    }
}
