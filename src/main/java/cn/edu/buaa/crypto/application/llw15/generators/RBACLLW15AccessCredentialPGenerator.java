package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.application.llw15.params.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/6/19.
 */
public class RBACLLW15AccessCredentialPGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public CipherParameters generateKey() {
        RBACLLW15AccessCredentialPGenParameters parameters = (RBACLLW15AccessCredentialPGenParameters) params;

        RBACLLW15PublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();
        RBACLLW15MasterSecretKeyParameters masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementId = PairingUtils.MapToZr(pairing, parameters.getId());
        Element r = pairing.getZr().newRandomElement().getImmutable();

        Element a1 = publicKeyParameters.getG().powZn(r).getImmutable();
        Element a0 = publicKeyParameters.getG3().getImmutable();
        Element b0 = publicKeyParameters.getU0().powZn(r).getImmutable();
        Element bv = publicKeyParameters.getUv().powZn(r).getImmutable();
        Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];

        a0 = a0.mul(publicKeyParameters.getGh().powZn(elementId)).getImmutable();
        a0 = a0.powZn(r).mul(masterSecretKeyParameters.getG2Alpha()).getImmutable();
        for (int i = 0; i < publicKeyParameters.getMaxRoleNumber(); i++) {
            //Set h[i] to be h_i^r
            bs[i] = publicKeyParameters.getUsAt(i).powZn(r).getImmutable();
        }
        return new RBACLLW15AccessCredentialPParameters(publicKeyParameters.getParameters(),
                parameters.getId(), elementId, a0, a1, b0, bv, bs);
    }
}
