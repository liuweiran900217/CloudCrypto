package cn.edu.buaa.crypto.encryption.re.llw16a.generators;

import cn.edu.buaa.crypto.encryption.re.genparams.REDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aDecryptionGenerator;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CPA-secure OO-RE decryption generator.
 */
public class RELLW16aDecryptionGenerator extends RELSW10aDecryptionGenerator {
    public void init(CipherParameters params) {
        REDecryptionGenerationParameter oriParameter = (REDecryptionGenerationParameter)params;
        RELLW16aPublicKeySerParameter oriPublicKeyParameter = (RELLW16aPublicKeySerParameter)oriParameter.getPublicKeyParameter();
        RELLW16aHeaderSerParameter oriHeaderParameter = (RELLW16aHeaderSerParameter)oriParameter.getCiphertextParameter();

        Map<String, Element> oriC2s = oriHeaderParameter.getC2s();
        Map<String, Element> oriC3s = oriHeaderParameter.getC3s();
        Map<String, Element> newC2s = new HashMap<String, Element>();
        for (String revokeId : oriC2s.keySet()) {
            Element newC2 = oriC2s.get(revokeId).mul(oriPublicKeyParameter.getGb2().powZn(oriC3s.get(revokeId))).getImmutable();
            newC2s.put(revokeId, newC2);
        }
        if (oriHeaderParameter instanceof RELLW16aCiphertextSerParameter) {
            RELLW16aCiphertextSerParameter oriCiphertextParameter = (RELLW16aCiphertextSerParameter)oriHeaderParameter;
            RELLW16aCiphertextSerParameter newCiphertextParameter = new RELLW16aCiphertextSerParameter(
                    oriCiphertextParameter.getParameters(),
                    oriCiphertextParameter.getC(),
                    oriCiphertextParameter.getC0(),
                    oriCiphertextParameter.getC1s(),
                    newC2s,
                    oriC3s
            );
            REDecryptionGenerationParameter resultParameter = new REDecryptionGenerationParameter(
                    oriParameter.getPublicKeyParameter(),
                    oriParameter.getSecretKeyParameter(),
                    oriParameter.getIds(),
                    newCiphertextParameter);
            super.init(resultParameter);
        } else {
            RELLW16aHeaderSerParameter newHeaderParameter = new RELLW16aHeaderSerParameter(
                    oriHeaderParameter.getParameters(),
                    oriHeaderParameter.getC0(),
                    oriHeaderParameter.getC1s(),
                    newC2s,
                    oriC3s
            );
            REDecryptionGenerationParameter resultParameter = new REDecryptionGenerationParameter(
                    oriParameter.getPublicKeyParameter(),
                    oriParameter.getSecretKeyParameter(),
                    oriParameter.getIds(),
                    newHeaderParameter);
            super.init(resultParameter);
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        super.computeDecapsulation();
        RELLW16aCiphertextSerParameter ciphertextParameter = (RELLW16aCiphertextSerParameter)this.parameter.getCiphertextParameter();
        return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }
}
