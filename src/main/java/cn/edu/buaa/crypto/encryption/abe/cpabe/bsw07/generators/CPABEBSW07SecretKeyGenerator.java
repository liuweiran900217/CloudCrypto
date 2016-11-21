package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams.CPABEBSW07SecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE secret key generator.
 */
public class CPABEBSW07SecretKeyGenerator implements PairingKeyParameterGenerator {
    private CPABEBSW07SecretKeyGenerationParameter parameter;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (CPABEBSW07SecretKeyGenerationParameter)keyGenerationParameter;
    }

    public PairingKeySerParameter generateKey() {
        CPABEBSW07MasterSecretKeySerParameter masterSecretKeyParameter = (CPABEBSW07MasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        CPABEBSW07PublicKeySerParameter publicKeyParameter = (CPABEBSW07PublicKeySerParameter)parameter.getPublicKeyParameter();

        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Map<String, Element> elementAttributes = new HashMap<String, Element>();
        Map<String, Element> D1s = new HashMap<String, Element>();
        Map<String, Element> D2s = new HashMap<String, Element>();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element D = masterSecretKeyParameter.getGAlpha().mul(publicKeyParameter.getG().powZn(r)).powZn(masterSecretKeyParameter.getBeta().invert()).getImmutable();
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.G1);
            elementAttributes.put(attribute, elementAttribute);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            D1s.put(attribute, publicKeyParameter.getG().powZn(r).mul(elementAttribute.powZn(ri)).getImmutable());
            D2s.put(attribute, publicKeyParameter.getG().powZn(ri).getImmutable());
        }
            return new CPABEBSW07SecretKeySerParameter(publicKeyParameter.getParameters(), elementAttributes, D, D1s, D2s);
    }
}
