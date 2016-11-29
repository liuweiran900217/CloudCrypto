package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakia-Waters CP-ABE secret key generator.
 */
public class CPABERW13SecretKeyGenerator implements PairingKeyParameterGenerator {
    private CPABESecretKeyGenerationParameter parameter;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (CPABESecretKeyGenerationParameter)keyGenerationParameter;
    }

    public PairingKeySerParameter generateKey() {
        CPABERW13MasterSecretKeySerParameter masterSecretKeyParameter = (CPABERW13MasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        CPABERW13PublicKeySerParameter publicKeyParameter = (CPABERW13PublicKeySerParameter)parameter.getPublicKeyParameter();

        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Map<String, Element> K2s = new HashMap<String, Element>();
        Map<String, Element> K3s = new HashMap<String, Element>();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element K0 = publicKeyParameter.getG().powZn(masterSecretKeyParameter.getAlpha()).mul(publicKeyParameter.getW().powZn(r)).getImmutable();
        Element K1 = publicKeyParameter.getG().powZn(r).getImmutable();

        Element K3Temp = publicKeyParameter.getV().powZn(r.negate()).getImmutable();
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            K2s.put(attribute, publicKeyParameter.getG().powZn(ri).getImmutable());
            Element K3i = publicKeyParameter.getU().powZn(elementAttribute).mul(publicKeyParameter.getH()).powZn(ri).getImmutable();
            K3i = K3i.mul(K3Temp).getImmutable();
            K3s.put(attribute, K3i);
        }
        return new CPABERW13SecretKeySerParameter(publicKeyParameter.getParameters(), K0, K1, K2s, K3s);
    }
}
