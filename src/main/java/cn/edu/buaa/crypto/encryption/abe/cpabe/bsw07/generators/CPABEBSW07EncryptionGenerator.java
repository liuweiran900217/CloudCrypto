package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams.CPABEBSW07EncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE encryption generator.
 */
public class CPABEBSW07EncryptionGenerator implements PairingEncryptionGenerator {

    private CPABEBSW07EncryptionGenerationParameter parameter;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEBSW07EncryptionGenerationParameter) parameter;
    }

    public PairingCipherSerParameter generateCiphertext() {
        CPABEBSW07PublicKeySerParameter publicKeyParameter = (CPABEBSW07PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        int[][] accessPolicy = this.parameter.getAccessPolicy();
        String[] rhos = this.parameter.getRhos();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element CPrime = publicKeyParameter.getEggAlpha().powZn(s).mul(this.parameter.getMessage()).getImmutable();
        Element C = publicKeyParameter.getH().powZn(s).getImmutable();
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);

        Map<String, Element> C1s = new HashMap<String, Element>();
        Map<String, Element> C2s = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            C1s.put(rho, publicKeyParameter.getG().powZn(lambdas.get(rho)).getImmutable());
            C2s.put(rho, PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.G1).powZn(lambdas.get(rho)).getImmutable());
        }
        return new CPABEBSW07CiphertextSerParameter(publicKeyParameter.getParameters(), CPrime, C, C1s, C2s);
    }
}