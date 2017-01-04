package cn.edu.buaa.crypto.encryption.re.llw16b.generators;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.re.genparams.REDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.generators.RELLW16aDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bSecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE decryption generator.
 */
public class RELLW16bDecryptionGenerator extends RELLW16aDecryptionGenerator {
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerParameter chameleonHashPublicKey;
    private RELLW16bPublicKeySerParameter publicKeyParameter;
    private RELLW16bHeaderSerParameter headerParameter;
    private byte[] chameleonHash;
    private byte[] r;
    private Element V;

    public void init(CipherParameters parameter) {
        REDecryptionGenerationParameter oriDecryptionGenerationParameter  = (REDecryptionGenerationParameter) parameter;
        this.chameleonHasher = oriDecryptionGenerationParameter.getChameleonHasher();
        this.publicKeyParameter = (RELLW16bPublicKeySerParameter) oriDecryptionGenerationParameter.getPublicKeyParameter();
        this.headerParameter = (RELLW16bHeaderSerParameter) oriDecryptionGenerationParameter.getCiphertextParameter();
        this.chameleonHashPublicKey = this.headerParameter.getChameleonHashPublicKey();
        this.chameleonHash = this.headerParameter.getChameleonHash();
        this.r = this.headerParameter.getR();

        Pairing pairing = PairingFactory.getPairing(oriDecryptionGenerationParameter.getPublicKeyParameter().getParameters());
        String[] ids = oriDecryptionGenerationParameter.getIds();
        Element[] mappedElementIds = PairingUtils.MapStringArrayToFirstHalfZr(pairing, ids);
        String[] mappedIds = PairingUtils.MapElementArrayToStringArray(mappedElementIds);
        REDecryptionGenerationParameter decryptionGenerationParameter
                = new REDecryptionGenerationParameter(
                oriDecryptionGenerationParameter.getPublicKeyParameter(),
                oriDecryptionGenerationParameter.getSecretKeyParameter(),
                mappedIds,
                oriDecryptionGenerationParameter.getCiphertextParameter());
        super.init(decryptionGenerationParameter);
    }

    private void verifyCiphertext() throws InvalidCipherTextException {
        Element C0 = headerParameter.getC0().getImmutable();
        Element C01 = headerParameter.getC01().getImmutable();
        Element C02 = headerParameter.getC02().getImmutable();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        //compute Xch
        try {
            chameleonHasher.init(false, chameleonHashPublicKey);
            byte[] byteArrayChPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
            chameleonHasher.update(byteArrayChPublicKey, 0, byteArrayChPublicKey.length);
            if (headerParameter instanceof RELLW16bCiphertextSerParameter) {
                Element C = ((RELLW16bCiphertextSerParameter)headerParameter).getC().getImmutable();
                byte[] byteArrayC = C.toBytes();
                chameleonHasher.update(byteArrayC, 0, byteArrayC.length);
            }
            byte[] byteArrayC0 = C0.toBytes();
            chameleonHasher.update(byteArrayC0, 0, byteArrayC0.length);
            byte[] byteArrayC01 = C01.toBytes();
            chameleonHasher.update(byteArrayC01, 0, byteArrayC01.length);
            String[] sortedIds = new String[this.parameter.getIds().length];
            System.arraycopy(this.parameter.getIds(), 0, sortedIds, 0, sortedIds.length);
            Arrays.sort(sortedIds);
            for (String id : sortedIds) {
                byte[] byteArrayId = id.getBytes();
                chameleonHasher.update(byteArrayId, 0, byteArrayId.length);
                byte[] byteArrayC1i = headerParameter.getC1sAt(id).toBytes();
                chameleonHasher.update(byteArrayC1i, 0, byteArrayC1i.length);
                byte[] byteArrayC2i = headerParameter.getC2sAt(id).toBytes();
                chameleonHasher.update(byteArrayC2i, 0, byteArrayC2i.length);
                byte[] byteArrayC3i = headerParameter.getC3sAt(id).toBytes();
                chameleonHasher.update(byteArrayC3i, 0, byteArrayC3i.length);
            }
            byte[][] chResult = chameleonHasher.computeHash(chameleonHash, r);
            Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
            String mappedStringV = tempV.toString();
            this.V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
            //verify ciphertext
            Element tau0 = pairing.getZr().newRandomElement().getImmutable();
            Element temp1 = C02.powZn(tau0).getImmutable();
            Element temp2 = C01.powZn(V.mulZn(tau0)).getImmutable();
            Element temp3 = C01.powZn(tau0).getImmutable();
            Element temp4 = C01.duplicate().getImmutable();
            for (String id : sortedIds) {
                Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingUtils.PairingGroupType.Zr);
                Element taui = pairing.getZr().newRandomElement().getImmutable();
                temp1 = temp1.mul(headerParameter.getC2sAt(id)
                        .mul(publicKeyParameter.getGb2().powZn(headerParameter.getC3sAt(id))).powZn(taui)).getImmutable();
                temp2 = temp2.mul(headerParameter.getC1sAt(id).powZn(elementId.mulZn(taui))).getImmutable();
                temp3 = temp3.mul(headerParameter.getC1sAt(id).powZn(taui)).getImmutable();
                temp4 = temp4.mul(headerParameter.getC1sAt(id)).getImmutable();
            }
            Element verifyResult1 = pairing.pairing(temp1, publicKeyParameter.getGb())
                    .div(pairing.pairing(temp2, publicKeyParameter.getGb2()))
                    .div(pairing.pairing(temp3, publicKeyParameter.getHb())).getImmutable();
            Element verifyResult2 = pairing.pairing(publicKeyParameter.getG(), temp4)
                    .div(pairing.pairing(C0, publicKeyParameter.getGb())).getImmutable();
            if (!verifyResult1.equals(pairing.getGT().newOneElement())
                    || !verifyResult2.equals(pairing.getGT().newOneElement())) {
                throw new InvalidCipherTextException("Illegal ciphertext, reject to decrypt.");
            }
        } catch (IOException e) {
            throw new InvalidCipherTextException("Illegal ciphertext, reject to decrypt.");
        } catch (CryptoException e) {
            throw new InvalidCipherTextException("Illegal ciphertext, reject to decrypt.");
        }
    }

    protected void computeDecapsulation() throws InvalidCipherTextException {
        RELLW16bSecretKeySerParameter secretKeyParameters = (RELLW16bSecretKeySerParameter)this.parameter.getSecretKeyParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        //remove repeated ids
        String[] ids = PairingUtils.removeDuplicates(this.parameter.getIds());

        Element C1 = headerParameter.getC01().powZn(secretKeyParameters.getElementId().sub(V).invert()).getImmutable();
        Element C2 = headerParameter.getC02().powZn(secretKeyParameters.getElementId().sub(V).invert()).getImmutable();

        for (String revokeId : ids) {
            Element elementId = PairingUtils.MapStringToGroup(pairing, revokeId, PairingUtils.PairingGroupType.Zr).getImmutable();
            if (PairingUtils.isEqualElement(secretKeyParameters.getElementId(), elementId)) {
                throw new InvalidCipherTextException("identity associated with the secret key is in the revocation list of the ciphertext");
            }
            C1 = C1.mul(headerParameter.getC1sAt(revokeId).powZn(secretKeyParameters.getElementId().sub(elementId).invert())).getImmutable();
            C2 = C2.mul(headerParameter.getC2sAt(revokeId).mul(publicKeyParameter.getGb2().powZn(headerParameter.getC3sAt(revokeId)))
                    .powZn(secretKeyParameters.getElementId().sub(elementId).invert())).getImmutable();
        }
        this.sessionKey = pairing.pairing(headerParameter.getC0(), secretKeyParameters.getD0())
                .div(pairing.pairing(secretKeyParameters.getD1(), C1)).div(pairing.pairing(secretKeyParameters.getD2(), C2)).getImmutable();
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        verifyCiphertext();
        computeDecapsulation();
        RELLW16bCiphertextSerParameter ciphertextParameter = (RELLW16bCiphertextSerParameter)this.headerParameter;
        return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        verifyCiphertext();
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}
