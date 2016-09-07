package cn.edu.buaa.crypto.encryption.hibe.bb04.serialization;

import cn.edu.buaa.crypto.SerializationUtils;
import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04SecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.*;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 15-10-2.
 *
 * XML Serializer for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04XMLSerializer implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = HIBEBB04Engine.SCHEME_NAME;

    //Tags for public key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_G1 = "G1";
    private static final String TAG_PK_G2 = "G2";
    private static final String TAG_PK_HS = "Hs";
    private static final String TAG_PK_HI = "Hi";

    //Tags for master secret key
    private static final String TAG_MSK_G2ALPHA = "G2Alpha";

    //Tags for secret key
    private static final String TAG_SK_D0 = "d0";
    private static final String TAG_SK_DS = "ds";
    private static final String TAG_SK_DI = "di";
    private static final String TAG_SK_IDS = "Ids";
    private static final String TAG_SK_IDI = "Idi";

    //Tags for ciphertexts
    private static final String TAG_CT_B = "B";
    private static final String TAG_CT_CS = "Cs";
    private static final String TAG_CT_CI = "Ci";

    private static final HIBEBB04XMLSerializer INSTANCE = new HIBEBB04XMLSerializer();

    private HIBEBB04XMLSerializer() { }

    public static HIBEBB04XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof HIBEBB04PublicKeyParameters) {
            return getInstance().publicKeyParametersSerialization((HIBEBB04PublicKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBEBB04MasterSecretKeyParameters) {
            return getInstance().masterSecretKeyParametersSerialization((HIBEBB04MasterSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBEBB04SecretKeyParameters) {
            return getInstance().secretKeyParametersSerialization((HIBEBB04SecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBEBB04CiphertextParameters) {
            return getInstance().ciphertextParametersSerialization((HIBEBB04CiphertextParameters) cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + TAG_SCHEME_NAME +
                    " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(HIBEBB04PublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(HIBEBB04XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, HIBEBB04XMLSerializer.TYPE_PK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(publicKeyParameters.getMaxLength()));
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G, publicKeyParameters.getG());
            //Set g1
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G1, publicKeyParameters.getG1());
            //Set g2
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G2, publicKeyParameters.getG2());
            //Set h
            SerializationUtils.SetElementArray(publicKeyParametersDocument, schemeElement, TAG_PK_HS, TAG_PK_HI, publicKeyParameters.getHs());
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(HIBEBB04MasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(HIBEBB04XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, HIBEBB04XMLSerializer.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set g2Alpha
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_G2ALPHA, masterSecretKeyParameters.getG2Alpha());
            return masterSecretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document secretKeyParametersSerialization(HIBEBB04SecretKeyParameters secretKeyParameters){
        try {
            Document secretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = secretKeyDocument.createElement(HIBEBB04XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, HIBEBB04XMLSerializer.TYPE_SK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(secretKeyParameters.getLength()));
            secretKeyDocument.appendChild(schemeElement);
            //Set Ids
            SerializationUtils.SetStringArray(secretKeyDocument, schemeElement, TAG_SK_IDS, TAG_SK_IDI, secretKeyParameters.getIds());
            //Set d0
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_D0, secretKeyParameters.getD0());
            //Set ds
            SerializationUtils.SetElementArray(secretKeyDocument, schemeElement, TAG_SK_DS, TAG_SK_DI, secretKeyParameters.getDs());
            return secretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document ciphertextParametersSerialization(HIBEBB04CiphertextParameters ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(HIBEBB04XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, HIBEBB04XMLSerializer.TYPE_CT);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(ciphertextParameters.getLength()));
            ciphertextDocument.appendChild(schemeElement);
            //Set B
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_B, ciphertextParameters.getB());
            //Set Cs
            SerializationUtils.SetElementArray(ciphertextDocument, schemeElement, TAG_CT_CS, TAG_CT_CI, ciphertextParameters.getCs());
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
        int maxLength = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element g1 = null;
        it.unisa.dia.gas.jpbc.Element g2 = null;
        it.unisa.dia.gas.jpbc.Element[] hs = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
                g = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_G1)) {
                //Set g1
                g1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_G2)) {
                //Set g2
                g2 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_HS)) {
                //Set hs
                hs = SerializationUtils.GetElementArray(pairing, node, TAG_PK_HI, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new HIBEBB04PublicKeyParameters(pairingParameters, g, g1, g2, hs);
    }

    private CipherParameters masterSecretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g2Alpha = null;
        for (int i=0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            //Set gaAlpha
            if (node.getNodeName().equals(TAG_MSK_G2ALPHA)) {
                g2Alpha = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new HIBEBB04MasterSecretKeyParameters(pairingParameters, g2Alpha);
    }

    private CipherParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        String[] ids = null;
        it.unisa.dia.gas.jpbc.Element d0 = null;
        it.unisa.dia.gas.jpbc.Element[] ds = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_D0)) {
                //Set d0
                d0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_SK_DS)) {
                //Set ds
                ds = SerializationUtils.GetElementArray(pairing, node, TAG_SK_DI, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_SK_IDS)) {
                //Set Ids
                ids = SerializationUtils.GetStringArray(node, TAG_SK_IDI);
            }
        }
        return new HIBEBB04SecretKeyParameters(pairingParameters, ids, PairingUtils.MapToZr(pairing, ids), d0, ds);
    }

    private CipherParameters ciphertextParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element B = null;
        it.unisa.dia.gas.jpbc.Element[] Cs = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_CT_B)) {
                //Set B
                B = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_CT_CS)) {
                //Set Cs
                Cs = SerializationUtils.GetElementArray(pairing, node, TAG_CT_CI, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new HIBEBB04CiphertextParameters(pairingParameters, length, B, Cs);
    }
}
