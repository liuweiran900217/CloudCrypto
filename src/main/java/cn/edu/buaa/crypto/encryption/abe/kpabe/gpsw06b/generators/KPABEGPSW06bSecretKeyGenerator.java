package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.genparams.KPABEGPSW06bSecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bSecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles secret key generator.
 */
public class KPABEGPSW06bSecretKeyGenerator implements PairingKeyParameterGenerator {
    private KPABEGPSW06bSecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (KPABEGPSW06bSecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        KPABEGPSW06bMasterSecretKeySerParameter masterSecretKeyParameter = (KPABEGPSW06bMasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        KPABEGPSW06bPublicKeySerParameter publicKeyParameter = (KPABEGPSW06bPublicKeySerParameter)parameters.getPublicKeyParameter();
        int[][] accessPolicy = this.parameters.getAccessPolicy();
        String[] stringRhos = this.parameters.getRhos();
        Map<String, Element> Ds = new HashMap<String, Element>();
        Map<String, Element> Rs = new HashMap<String, Element>();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            Element y = masterSecretKeyParameter.getY().getImmutable();
            AccessControlParameter accessControlParameter =
                    this.parameters.getAccessControlEngine().generateAccessControl(accessPolicy, stringRhos);
            Map<String, Element> lambdaElementsMap = this.parameters.getAccessControlEngine().secretSharing(pairing, y, accessControlParameter);
            for (String rho : lambdaElementsMap.keySet()) {
                Element ri = pairing.getZr().newRandomElement().getImmutable();
                Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.G1);
                Element D = publicKeyParameter.getG2().powZn(lambdaElementsMap.get(rho)).mul(elementRho.powZn(ri)).getImmutable();
                Ds.put(rho, D);
                Element R = publicKeyParameter.getG().powZn(ri).getImmutable();
                Rs.put(rho, R);
            }
            return new KPABEGPSW06bSecretKeySerParameter(publicKeyParameter.getParameters(), accessControlParameter, Ds, Rs);
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }
}
