package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE encryption generator.
 */
public class CPABELLW14EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private CPABEEncryptionGenerationParameter parameter;

    private CPABELLW14PublicKeySerParameter publicKeyParameter;
    private AccessControlParameter accessControlParameter;
    private Element sessionKey;
    private Element C0;
    private Element s;
    private Map<String, Element> C1s;
    private Map<String, Element> C2s;
    private Map<String, Element> C3s;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEEncryptionGenerationParameter) parameter;
        this.publicKeyParameter = (CPABELLW14PublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        int[][] accessPolicy = this.parameter.getAccessPolicy();
        String[] rhos = this.parameter.getRhos();
        Element[] mappedElementRhos = PairingUtils.MapStringArrayToFirstHalfZr(pairing, rhos);
        String[] mappedStringRhos = PairingUtils.MapElementArrayToStringArray(mappedElementRhos);
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        this.accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, mappedStringRhos);

        this.s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
        this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();

        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        this.C3s = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element ti = pairing.getZr().newRandomElement().getImmutable();
            C1s.put(rho, publicKeyParameter.getW().powZn(lambdas.get(rho)).mul(publicKeyParameter.getV().powZn(ti)).getImmutable());
            C2s.put(rho, publicKeyParameter.getU().powZn(elementRho).mul(publicKeyParameter.getH()).powZn(ti.negate()).getImmutable());
            C3s.put(rho, publicKeyParameter.getG().powZn(ti).getImmutable());
        }
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        try {
            Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
            Element t0 = pairing.getZr().newRandomElement().getImmutable();
            Element C01 = publicKeyParameter.getW().powZn(s).mul(publicKeyParameter.getV().powZn(t0)).getImmutable();
            Element C03 = publicKeyParameter.getG().powZn(t0).getImmutable();
            ChameleonHasher chameleonHasher = this.parameter.getChameleonHasher();
            AsymmetricKeySerParameter chameleonHashPublicKey = publicKeyParameter.getChameleonHashPublicKey();
            chameleonHasher.init(false, chameleonHashPublicKey);
            byte[] byteArrayChPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
            chameleonHasher.update(byteArrayChPublicKey, 0, byteArrayChPublicKey.length);
            byte[] byteArrayAccessControlParameter = PairingUtils.SerCipherParameter(accessControlParameter);
            chameleonHasher.update(byteArrayAccessControlParameter, 0, byteArrayAccessControlParameter.length);
            byte[] byteArrayC0 = C0.toBytes();
            chameleonHasher.update(byteArrayC0, 0, byteArrayC0.length);
            byte[] byteArrayC01 = C01.toBytes();
            chameleonHasher.update(byteArrayC01, 0, byteArrayC01.length);
            byte[] byteArrayC03 = C03.toBytes();
            chameleonHasher.update(byteArrayC03, 0, byteArrayC03.length);
            for (String rho : accessControlParameter.getRhos()) {
                byte[] byteArrayC1i = C1s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC1i, 0, byteArrayC1i.length);
                byte[] byteArrayC2i = C2s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC2i, 0, byteArrayC2i.length);
                byte[] byteArrayC3i = C3s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC3i, 0, byteArrayC3i.length);
            }
            byte[][] chResult = chameleonHasher.computeHash();
            byte[] chameleonHash = chResult[0];
            byte[] r = chResult[1];
            Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
            String mappedStringV = tempV.toString();
            Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
            Element C02 = publicKeyParameter.getU().powZn(V).mul(publicKeyParameter.getH()).powZn(t0.negate()).getImmutable();
            return new PairingKeyEncapsulationSerPair(
                    this.sessionKey.toBytes(),
                    new CPABELLW14HeaderSerParameter(publicKeyParameter.getParameters(), chameleonHash, r, C01, C02, C03, C0, C1s, C2s, C3s)
            );
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize chk.");
        } catch (CryptoException e) {
            throw new RuntimeException("Cannot compute chameleon hash.");
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        try {
            Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
            Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
            Element t0 = pairing.getZr().newRandomElement().getImmutable();
            Element C01 = publicKeyParameter.getW().powZn(s).mul(publicKeyParameter.getV().powZn(t0)).getImmutable();
            Element C03 = publicKeyParameter.getG().powZn(t0).getImmutable();
            ChameleonHasher chameleonHasher = this.parameter.getChameleonHasher();
            AsymmetricKeySerParameter chameleonHashPublicKey = publicKeyParameter.getChameleonHashPublicKey();
            chameleonHasher.init(false, chameleonHashPublicKey);
            byte[] byteArrayChPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
            chameleonHasher.update(byteArrayChPublicKey, 0, byteArrayChPublicKey.length);
            byte[] byteArrayAccessControlParameter = PairingUtils.SerCipherParameter(accessControlParameter);
            chameleonHasher.update(byteArrayAccessControlParameter, 0, byteArrayAccessControlParameter.length);
            byte[] byteArrayC = C.toBytes();
            chameleonHasher.update(byteArrayC, 0, byteArrayC.length);
            byte[] byteArrayC0 = C0.toBytes();
            chameleonHasher.update(byteArrayC0, 0, byteArrayC0.length);
            byte[] byteArrayC01 = C01.toBytes();
            chameleonHasher.update(byteArrayC01, 0, byteArrayC01.length);
            byte[] byteArrayC03 = C03.toBytes();
            chameleonHasher.update(byteArrayC03, 0, byteArrayC03.length);
            for (String rho : accessControlParameter.getRhos()) {
                byte[] byteArrayC1i = C1s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC1i, 0, byteArrayC1i.length);
                byte[] byteArrayC2i = C2s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC2i, 0, byteArrayC2i.length);
                byte[] byteArrayC3i = C3s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC3i, 0, byteArrayC3i.length);
            }
            byte[][] chResult = chameleonHasher.computeHash();
            byte[] chameleonHash = chResult[0];
            byte[] r = chResult[1];
            Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
            String mappedStringV = tempV.toString();
            Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
            Element C02 = publicKeyParameter.getU().powZn(V).mul(publicKeyParameter.getH()).powZn(t0.negate()).getImmutable();
            return new CPABELLW14CiphertextSerParameter(
                    publicKeyParameter.getParameters(), chameleonHash, r, C01, C02, C03, C, C0, C1s, C2s, C3s);
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize chk.");
        } catch (CryptoException e) {
            throw new RuntimeException("Cannot compute chameleon hash.");
        }
    }
}
