package cn.edu.buaa.crypto.encryption.hibbe.llw17.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams.HIBBELLW17DecapsulationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE session key decapsulation generator.
 */
public class HIBBELLW17DecapsulationGenerator implements PairingDecapsulationGenerator {
    private HIBBELLW17DecapsulationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBBELLW17DecapsulationParameter)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        Digest digest = this.params.getDigest();
        digest.reset();
        HIBBELLW17PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        HIBBELLW17SecretKeySerParameter secretKeyParameters = this.params.getSecretKeyParameters();
        HIBBELLW17CipherSerParameter ciphertextParameters = this.params.getCiphertextParameters();
        if (this.params.getIds().length != publicKeyParameters.getMaxUser()
                || secretKeyParameters.getIds().length != publicKeyParameters.getMaxUser()) {
            throw new IllegalArgumentException("Invalid identity vector / identity vector set length");
        }

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIdsCT = PairingUtils.MapStringArrayToGroup(pairing, this.params.getIds(), PairingUtils.PairingGroupType.Zr);

        for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
            if (secretKeyParameters.getIdAt(i) != null &&
                    !secretKeyParameters.getElementIdAt(i).equals(elementIdsCT[i])){
                throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector set");
            }
        }

        Element a0 = secretKeyParameters.getA0().getImmutable();
        Element C0 = ciphertextParameters.getC0().getImmutable();
        Element C1 = ciphertextParameters.getC1().getImmutable();
        Element a1 = secretKeyParameters.getA1().getImmutable();

        //ciphertext public verification.
        byte[] byteArrayC0 = C0.toBytes();
        digest.update(byteArrayC0, 0, byteArrayC0.length);
        byte[] byteArrayIDv = new byte[digest.getDigestSize()];
        digest.doFinal(byteArrayIDv, 0);
        Element elementIDv = PairingUtils.MapByteArrayToGroup(pairing, byteArrayIDv, PairingUtils.PairingGroupType.Zr).getImmutable();
        Element Z3_r = pairing.getZr().newRandomElement().getImmutable();
        Element Z3 = publicKeyParameters.getX3().powZn(Z3_r).getImmutable();
        Element Z3Prime_r = pairing.getZr().newRandomElement().getImmutable();
        Element Z3Prime = publicKeyParameters.getX3().powZn(Z3Prime_r).getImmutable();
        Element tempVerify = publicKeyParameters.getH();
        for (int i = 0; i < publicKeyParameters.getMaxUser(); i++) {
            if (params.getIdsAt(i) != null) {
                tempVerify = tempVerify.mul(publicKeyParameters.getUsAt(i).powZn(elementIdsCT[i]));
            }
        }
        tempVerify = tempVerify.mul(publicKeyParameters.getUv().powZn(elementIDv)).getImmutable();
        Element tempVerifyPairing1 = pairing.pairing(publicKeyParameters.getG().mul(Z3), C1).getImmutable();
        Element tempVerifyPairing2 = pairing.pairing(C0, tempVerify.mul(Z3Prime)).getImmutable();
        if (!tempVerifyPairing1.equals(tempVerifyPairing2)) {
            throw new InvalidCipherTextException("Invalid ciphertext.");
        }

        //decapsulation
        for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
            if (secretKeyParameters.getIdAt(i) == null && params.getIdsAt(i) != null) {
                a0 = a0.mul(secretKeyParameters.getBsAt(i).powZn(elementIdsCT[i])).getImmutable();
            }
        }
        a0 = a0.mul(secretKeyParameters.getBv().powZn(elementIDv)).getImmutable();
        Element temp0 = pairing.pairing(C0, a0).getImmutable();
        Element temp1 = pairing.pairing(a1, C1).getImmutable();
        Element sessionKey = temp0.div(temp1).getImmutable();
        return sessionKey.toBytes();
    }
}
