package cn.edu.buaa.crypto.encryption.hibbe.llw14.serialization;

import cn.edu.buaa.crypto.utils.SerializationUtils;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14SecretKeyParameters;
import cn.edu.buaa.crypto.algebra.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 16/5/17.
 */
public class HIBBELLW14XMLSerializer implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = HIBBELLW14Engine.SCHEME_NAME;

    //Tags for public key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_H = "H";
    private static final String TAG_PK_US = "Us";
    private static final String TAG_PK_UI = "Ui";
    private static final String TAG_PK_X3 = "X3";
    private static final String TAG_PK_EggAlpha = "EggAlpha";

    //Tags for master secret key
    private static final String TAG_MSK_GALPHA = "GAlpha";

    //Tags for secret key
    private static final String TAG_SK_A0 = "a0";
    private static final String TAG_SK_A1 = "a1";
    private static final String TAG_SK_BS = "bs";
    private static final String TAG_SK_BI = "bi";
    private static final String TAG_SK_IDS = "Ids";
    private static final String TAG_SK_IDI = "Idi";

    //Tags for ciphertexts
    private static final String TAG_CT_C0 = "C0";
    private static final String TAG_CT_C1 = "C1";

    private static final HIBBELLW14XMLSerializer INSTANCE = new HIBBELLW14XMLSerializer();

    private HIBBELLW14XMLSerializer() { }

    public static HIBBELLW14XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof HIBBELLW14PublicKeyParameters) {
            return getInstance().publicKeyParametersSerialization((HIBBELLW14PublicKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBBELLW14MasterSecretKeyParameters) {
            return getInstance().masterSecretKeyParametersSerialization((HIBBELLW14MasterSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBBELLW14SecretKeyParameters) {
            return getInstance().secretKeyParametersSerialization((HIBBELLW14SecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBBELLW14CiphertextParameters) {
            return getInstance().ciphertextParametersSerialization((HIBBELLW14CiphertextParameters) cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + HIBBELLW14Engine.SCHEME_NAME
                    + " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(HIBBELLW14PublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(HIBBELLW14XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_PK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_USER, Integer.toString(publicKeyParameters.getMaxUser()));
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G, publicKeyParameters.getG());
            //Set h
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_H, publicKeyParameters.getH());
            //Set X3
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_X3, publicKeyParameters.getX3());
            //Set eggAlpha
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_EggAlpha, publicKeyParameters.getEggAlpha());
            //Set u
            SerializationUtils.SetElementArray(publicKeyParametersDocument, schemeElement, TAG_PK_US, TAG_PK_UI, publicKeyParameters.getUs());
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(HIBBELLW14MasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(HIBBELLW14XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set gAlpha
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_GALPHA, masterSecretKeyParameters.getGAlpha());
            return masterSecretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document secretKeyParametersSerialization(HIBBELLW14SecretKeyParameters secretKeyParameters){
        try {
            Document secretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = secretKeyDocument.createElement(HIBBELLW14XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_SK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_USER, Integer.toString(secretKeyParameters.getBs().length));
            secretKeyDocument.appendChild(schemeElement);
            //Set Ids
            SerializationUtils.SetStringArray(secretKeyDocument, schemeElement, TAG_SK_IDS, TAG_SK_IDI, secretKeyParameters.getIds());
            //Set a0
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_A0, secretKeyParameters.getA0());
            //Set a1
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_A1, secretKeyParameters.getA1());
            //Set bs
            SerializationUtils.SetElementArray(secretKeyDocument, schemeElement, TAG_SK_BS, TAG_SK_BI, secretKeyParameters.getBs());
            return secretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document ciphertextParametersSerialization(HIBBELLW14CiphertextParameters ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(HIBBELLW14XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_CT);
            ciphertextDocument.appendChild(schemeElement);
            //Set C0
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C0, ciphertextParameters.getC0());
            //Set C1
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C1, ciphertextParameters.getC1());
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
            throw new InvalidParameterException("Illegal " + HIBBELLW14Engine.SCHEME_NAME +
                    " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element h = null;
        it.unisa.dia.gas.jpbc.Element X3 = null;
        it.unisa.dia.gas.jpbc.Element eggAlpha = null;
        it.unisa.dia.gas.jpbc.Element[] us = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
                g = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_H)) {
                //Set h
                h = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_X3)) {
                //Set X3
                X3 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_EggAlpha)) {
                //Set eggAlpha
                eggAlpha = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.GT);
            } else if (node.getNodeName().equals(TAG_PK_US)) {
                //Set us
                us = SerializationUtils.GetElementArray(pairing, node, TAG_PK_UI, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new HIBBELLW14PublicKeyParameters(pairingParameters, g, h, us, X3, eggAlpha);
    }

    private CipherParameters masterSecretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element gAlpha = null;
        for (int i=0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            //Set gAlpha
            if (node.getNodeName().equals(TAG_MSK_GALPHA)) {
                gAlpha = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new HIBBELLW14MasterSecretKeyParameters(pairingParameters, gAlpha);
    }

    private CipherParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        String[] ids = null;
        it.unisa.dia.gas.jpbc.Element[] elementIds;
        it.unisa.dia.gas.jpbc.Element a0 = null;
        it.unisa.dia.gas.jpbc.Element a1 = null;
        it.unisa.dia.gas.jpbc.Element[] bs = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_A0)) {
                //Set a0
                a0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_SK_A1)) {
                //Set a1
                a1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_SK_BS)) {
                //Set bs
                bs = SerializationUtils.GetElementArray(pairing, node, TAG_SK_BI, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_SK_IDS)) {
                //Set Ids
                ids = SerializationUtils.GetStringArray(node, TAG_SK_IDI);
            }
        }
        elementIds = PairingUtils.MapToZr(pairing, ids);
        return new HIBBELLW14SecretKeyParameters(pairingParameters, ids, elementIds, a0, a1, bs);
    }

    private CipherParameters ciphertextParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element C0 = null;
        it.unisa.dia.gas.jpbc.Element C1 = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_CT_C0)) {
                //Set C0
                C0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_CT_C1)) {
                //Set C1
                C1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new HIBBELLW14CiphertextParameters(pairingParameters, C0, C1);
    }
}