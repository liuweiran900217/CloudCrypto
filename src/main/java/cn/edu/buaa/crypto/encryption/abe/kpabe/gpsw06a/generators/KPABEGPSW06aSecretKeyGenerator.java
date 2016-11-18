package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerParametersGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams.KPABEGPSW06aSecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.InvalidParameterException;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE secret key generator.
 */
public class KPABEGPSW06aSecretKeyGenerator implements AsymmetricKeySerParametersGenerator {
    private KPABEGPSW06aSecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (KPABEGPSW06aSecretKeyGenerationParameter)keyGenerationParameters;
    }

    public AsymmetricKeySerParameter generateKey() {
        KPABEGPSW06aMasterSecretKeySerParameter masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();
        KPABEGPSW06aPublicKeySerParameter publicKeyParameters = parameters.getPublicKeyParameters();

        int[][] accessPolicy = this.parameters.getAccessPolicy();
        String[] stringRhos = this.parameters.getRhos();
        Element[] Ds = new Element[publicKeyParameters.getMaxAttributesNum()];

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        try {
            Element y = masterSecretKeyParameters.getY().getImmutable();
            AccessControlParameter accessControlParameter =
                    this.parameters.getAccessControlEngine().generateAccessControl(accessPolicy, stringRhos);
            Map<String, Element> lambdaElementsMap = this.parameters.getAccessControlEngine().secretSharing(pairing, y, accessControlParameter);
            for (String rho : stringRhos) {
                int index = Integer.parseInt(rho);
                if (index >= publicKeyParameters.getMaxAttributesNum() || index < 0) {
                    throw new InvalidParameterException("Rho index greater than or equal to the max number of attributes supported");
                }
                Ds[index] = publicKeyParameters.getG().powZn(lambdaElementsMap.get(rho).div(masterSecretKeyParameters.getTsAt(index))).getImmutable();
            }
            return new KPABEGPSW06aSecretKeySerParameter(publicKeyParameters.getParameters(), accessControlParameter, stringRhos, Ds);
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }
}
