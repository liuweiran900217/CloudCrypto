package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators;

import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13DecryptionGenerator;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE decryption generator.
 */
public class KPABEHW14DecryptionGenerator extends KPABERW13DecryptionGenerator {
    public void init(CipherParameters params) {
        KPABEDecryptionGenerationParameter oriParameter = (KPABEDecryptionGenerationParameter)params;
        KPABEHW14PublicKeySerParameter oriPublicKeyParameter = (KPABEHW14PublicKeySerParameter)oriParameter.getPublicKeyParameter();
        KPABEHW14HeaderSerParameter oriHeaderParameter = (KPABEHW14HeaderSerParameter)oriParameter.getCiphertextParameter();

        Map<String, Element> oriC2s = oriHeaderParameter.getC2s();
        Map<String, Element> oriC3s = oriHeaderParameter.getC3s();
        Map<String, Element> newC2s = new HashMap<String, Element>();
        for (String attribute : oriC2s.keySet()) {
            Element newC2 = oriC2s.get(attribute).mul(oriPublicKeyParameter.getU().powZn(oriC3s.get(attribute))).getImmutable();
            newC2s.put(attribute, newC2);
        }
        if (oriHeaderParameter instanceof KPABEHW14CiphertextSerParameter) {
            KPABEHW14CiphertextSerParameter oriCiphertextParameter = (KPABEHW14CiphertextSerParameter)oriHeaderParameter;
            KPABEHW14CiphertextSerParameter newCiphertextParameter = new KPABEHW14CiphertextSerParameter(
                    oriCiphertextParameter.getParameters(),
                    oriCiphertextParameter.getC(),
                    oriCiphertextParameter.getC0(),
                    oriCiphertextParameter.getC1s(),
                    newC2s,
                    oriC3s
            );
            KPABEDecryptionGenerationParameter resultParameter = new KPABEDecryptionGenerationParameter(
                    oriParameter.getAccessControlEngine(),
                    oriParameter.getPublicKeyParameter(),
                    oriParameter.getSecretKeyParameter(),
                    oriParameter.getAttributes(),
                    newCiphertextParameter);
            super.init(resultParameter);
        } else {
            KPABEHW14HeaderSerParameter newHeaderParameter = new KPABEHW14HeaderSerParameter(
                    oriHeaderParameter.getParameters(),
                    oriHeaderParameter.getC0(),
                    oriHeaderParameter.getC1s(),
                    newC2s,
                    oriC3s
            );
            KPABEDecryptionGenerationParameter resultParameter = new KPABEDecryptionGenerationParameter(
                    oriParameter.getAccessControlEngine(),
                    oriParameter.getPublicKeyParameter(),
                    oriParameter.getSecretKeyParameter(),
                    oriParameter.getAttributes(),
                    newHeaderParameter);
            super.init(resultParameter);
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        super.computeDecapsulation();
        KPABEHW14CiphertextSerParameter ciphertextParameter = (KPABEHW14CiphertextSerParameter)this.parameter.getCiphertextParameter();
        return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }
}
