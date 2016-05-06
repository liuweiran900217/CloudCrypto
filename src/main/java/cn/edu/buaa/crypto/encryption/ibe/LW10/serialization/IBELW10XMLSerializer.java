package cn.edu.buaa.crypto.encryption.ibe.LW10.serialization;

import cn.edu.buaa.crypto.SerializationUtils;
import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.encryption.ibe.LW10.IBELW10Engine;
import cn.edu.buaa.crypto.encryption.ibe.LW10.params.IBELW10CiphertextParameters;
import cn.edu.buaa.crypto.encryption.ibe.LW10.params.IBELW10MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.ibe.LW10.params.IBELW10PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.ibe.LW10.params.IBELW10SecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by liuweiran on 16/5/7.
 */
public class IBELW10XMLSerializer implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = IBELW10Engine.SCHEME_NAME;

    //Tags for public key
    private static final String TAG_PK_U = "U";
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_H = "H";
    private static final String TAG_PK_EggAlpha = "EggAlpha";

    //Tags for master secret key
    private static final String TAG_MSK_ALPHA = "alpha";
    private static final String TAG_MSK_G3Generator = "g3";

    //Tags for secret key
    private static final String TAG_SK_K1 = "k1";
    private static final String TAG_SK_K2 = "k2";
    private static final String TAG_SK_ID = "id";

    //Tags for ciphertext
    private static final String TAG_CT_C1 = "C1";
    private static final String TAG_CT_C2 = "C2";

    private static final IBELW10XMLSerializer INSTANCE = new IBELW10XMLSerializer();

    private IBELW10XMLSerializer() { }

    public static IBELW10XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof IBELW10PublicKeyParameters) {
            return getInstance().publicKeyParametersSerialization((IBELW10PublicKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof IBELW10MasterSecretKeyParameters) {
            return getInstance().masterSecretKeyParametersSerialization((IBELW10MasterSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof IBELW10SecretKeyParameters) {
            return getInstance().secretKeyParametersSerialization((IBELW10SecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof IBELW10CiphertextParameters) {
            return getInstance().ciphertextParametersSerialization((IBELW10CiphertextParameters) cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + TAG_SCHEME_NAME +
                    " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(IBELW10PublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(IBELW10XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, IBELW10XMLSerializer.TYPE_PK);
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set u
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_U, publicKeyParameters.getU());
            //Set g
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G, publicKeyParameters.getG());
            //Set h
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_H, publicKeyParameters.getH());
            //Set eggAlpha
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_EggAlpha, publicKeyParameters.getEggAlpha());
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(IBELW10MasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(IBELW10XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, IBELW10XMLSerializer.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set alpha
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_ALPHA, masterSecretKeyParameters.getAlpha());
            //Set g3Generator
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_G3Generator, masterSecretKeyParameters.getG3Generator());
            return masterSecretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document secretKeyParametersSerialization(IBELW10SecretKeyParameters secretKeyParameters){
        try {
            Document secretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = secretKeyDocument.createElement(IBELW10XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, IBELW10XMLSerializer.TYPE_SK);
            secretKeyDocument.appendChild(schemeElement);
            //Set id
            SerializationUtils.SetString(secretKeyDocument, schemeElement, TAG_SK_ID, secretKeyParameters.getId());
            //Set k1
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_K1, secretKeyParameters.getK1());
            //Set k2
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_K2, secretKeyParameters.getK2());
            return secretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document ciphertextParametersSerialization(IBELW10CiphertextParameters ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(IBELW10XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, IBELW10XMLSerializer.TYPE_CT);
            ciphertextDocument.appendChild(schemeElement);
            //Set C1
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C1, ciphertextParameters.getC1());
            //Set C2
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C2, ciphertextParameters.getC2());
            return ciphertextDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    public CipherParameters documentDeserialization(PairingParameters pairingParameters, Document document) {
        Element schemeElement = document.getDocumentElement();
        String cipherParameterType = schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_TYPE);
        if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_PK)){
            return getInstance().publicKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_MSK)){
            return getInstance().masterSecretKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_SK)) {
            return getInstance().secretKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_CT)) {
            return getInstance().ciphertextParametersDeserialization(pairingParameters, schemeElement);
        } else {
            throw new InvalidParameterException("Illegal " + TAG_SCHEME_NAME + " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element u = null;
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element h = null;
        it.unisa.dia.gas.jpbc.Element eggAlpha = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_U)) {
                //Set u
                String uString = node.getFirstChild().getNodeValue();
                u = pairing.getG1().newElementFromBytes(Hex.decode(uString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
                String gString = node.getFirstChild().getNodeValue();
                g = pairing.getG1().newElementFromBytes(Hex.decode(gString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_H)) {
                //Set h
                String hString = node.getFirstChild().getNodeValue();
                h = pairing.getG1().newElementFromBytes(Hex.decode(hString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_EggAlpha)) {
                //Set eggAlpha
                String eggAlphaString = node.getFirstChild().getNodeValue();
                eggAlpha = pairing.getGT().newElementFromBytes(Hex.decode(eggAlphaString)).getImmutable();
            }
        }
        return new IBELW10PublicKeyParameters(pairingParameters, u, g, h, eggAlpha);
    }

    private CipherParameters masterSecretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element alpha = null;
        it.unisa.dia.gas.jpbc.Element g3Generator = null;
        for (int i=0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_MSK_ALPHA)) {
                //Set alpha
                String alphaString = node.getFirstChild().getNodeValue();
                alpha = pairing.getZr().newElementFromBytes(Hex.decode(alphaString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_MSK_G3Generator)) {
                //Set g3Generator
                String g3GeneratorString = node.getFirstChild().getNodeValue();
                g3Generator = pairing.getG1().newElementFromBytes(Hex.decode(g3GeneratorString)).getImmutable();
            }
        }
        return new IBELW10MasterSecretKeyParameters(pairingParameters, alpha, g3Generator);
    }

    private CipherParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        String id = null;
        it.unisa.dia.gas.jpbc.Element elementId = null;
        it.unisa.dia.gas.jpbc.Element k1 = null;
        it.unisa.dia.gas.jpbc.Element k2 = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_K1)) {
                //Set k1
                String k1String = node.getFirstChild().getNodeValue();
                k1 = pairing.getG1().newElementFromBytes(Hex.decode(k1String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_SK_K2)) {
                //Set k2
                String k2String = node.getFirstChild().getNodeValue();
                k2 = pairing.getG1().newElementFromBytes(Hex.decode(k2String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_SK_ID)) {
                //Set Id
                id = node.getFirstChild().getNodeValue();
                elementId = Utils.MapToZr(pairing, id);
            }
        }
        return new IBELW10SecretKeyParameters(pairingParameters, id, elementId, k1, k2);
    }

    private CipherParameters ciphertextParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element C1 = null;
        it.unisa.dia.gas.jpbc.Element C2 = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_CT_C1)) {
                //Set C1
                String c1String = node.getFirstChild().getNodeValue();
                C1 = pairing.getG1().newElementFromBytes(Hex.decode(c1String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_CT_C2)) {
                //Set C2
                String c2String = node.getFirstChild().getNodeValue();
                C2 = pairing.getG1().newElementFromBytes(Hex.decode(c2String)).getImmutable();
            }
        }
        return new IBELW10CiphertextParameters(pairingParameters, C1, C2);
    }
}
