package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators;

import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13DecryptionGenerator;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 OO-CP-ABE decryption generator.
 */
public class CPABEHW14DecryptionGenerator extends CPABERW13DecryptionGenerator {
    public void init(CipherParameters params) {
        CPABEDecryptionGenerationParameter oriParameter = (CPABEDecryptionGenerationParameter)params;
        CPABEHW14PublicKeySerParameter oriPublicKeyParameter = (CPABEHW14PublicKeySerParameter)oriParameter.getPublicKeyParameter();
        CPABEHW14HeaderSerParameter oriHeaderParameter = (CPABEHW14HeaderSerParameter)oriParameter.getCiphertextParameter();

        Map<String, Element> oriC1s = oriHeaderParameter.getC1s();
        Map<String, Element> oriC2s = oriHeaderParameter.getC2s();
        Map<String, Element> oriC4s = oriHeaderParameter.getC4s();
        Map<String, Element> oriC5s = oriHeaderParameter.getC5s();
        Map<String, Element> newC1s = new HashMap<String, Element>();
        Map<String, Element> newC2s = new HashMap<String, Element>();
        for (String attribute : oriC1s.keySet()) {
            Element newC1 = oriC1s.get(attribute).mul(oriPublicKeyParameter.getW().powZn(oriC4s.get(attribute))).getImmutable();
            newC1s.put(attribute, newC1);
        }
        for (String attribute : oriC2s.keySet()) {
            Element newC2 = oriC2s.get(attribute).mul(oriPublicKeyParameter.getU().powZn(oriC5s.get(attribute))).getImmutable();
            newC2s.put(attribute, newC2);
        }
        if (oriHeaderParameter instanceof CPABEHW14CiphertextSerParameter) {
            CPABEHW14CiphertextSerParameter oriCiphertextParameter = (CPABEHW14CiphertextSerParameter)oriHeaderParameter;
            CPABEHW14CiphertextSerParameter newCiphertextParameter = new CPABEHW14CiphertextSerParameter(
                    oriCiphertextParameter.getParameters(),
                    oriCiphertextParameter.getC(),
                    oriCiphertextParameter.getC0(),
                    newC1s,
                    newC2s,
                    oriCiphertextParameter.getC3s(),
                    oriC4s,
                    oriC5s
            );
            CPABEDecryptionGenerationParameter resultParameter = new CPABEDecryptionGenerationParameter(
                    oriParameter.getAccessControlEngine(),
                    oriParameter.getPublicKeyParameter(),
                    oriParameter.getSecretKeyParameter(),
                    oriParameter.getAccessPolicy(),
                    oriParameter.getRhos(),
                    newCiphertextParameter);
            super.init(resultParameter);
        } else {
            CPABEHW14HeaderSerParameter newHeaderParameter = new CPABEHW14HeaderSerParameter(
                    oriHeaderParameter.getParameters(),
                    oriHeaderParameter.getC0(),
                    newC1s,
                    newC2s,
                    oriHeaderParameter.getC3s(),
                    oriC4s,
                    oriC5s
            );
            CPABEDecryptionGenerationParameter resultParameter = new CPABEDecryptionGenerationParameter(
                    oriParameter.getAccessControlEngine(),
                    oriParameter.getPublicKeyParameter(),
                    oriParameter.getSecretKeyParameter(),
                    oriParameter.getAccessPolicy(),
                    oriParameter.getRhos(),
                    newHeaderParameter);
            super.init(resultParameter);
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        CPABEHW14CiphertextSerParameter ciphertextParameter = (CPABEHW14CiphertextSerParameter) this.parameter.getCiphertextParameter();
        return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }
}
