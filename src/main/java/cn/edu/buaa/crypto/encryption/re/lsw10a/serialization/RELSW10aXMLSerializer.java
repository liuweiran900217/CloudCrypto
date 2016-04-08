package cn.edu.buaa.crypto.encryption.re.lsw10a.serialization;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.encryption.re.lsw10a.RELSW10aEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aCiphertextParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aPublicKeyParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aSecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class RELSW10aXMLSerializer implements PairingParameterXMLSerializer {

    private static final String TAG_SCHEME_NAME = RELSW10aEngine.SCHEME_NAME;

    //Tags for public key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_Gb = "Gb";
    private static final String TAG_PK_Gb2 = "Gb2";
    private static final String TAG_PK_Hb = "Hb";
    private static final String TAG_PK_EggAlpha = "EggAlpha";

    //Tags for master secret key
    private static final String TAG_MSK_ALPHA = "Alpha";
    private static final String TAG_MSK_B = "b";
    private static final String TAG_MSK_H = "h";

    //Tags for secret key
    private static final String TAG_SK_ID = "id";
    private static final String TAG_SK_D0 = "d0";
    private static final String TAG_SK_D1 = "d1";
    private static final String TAG_SK_D2 = "d2";

    //Tags for ciphertexts
    private static final String TAG_CT_C0 = "C0";
    private static final String TAG_CT_C1S = "C1s";
    private static final String TAG_CT_C1I = "C1i";
    private static final String TAG_CT_C2S = "C2s";
    private static final String TAG_CT_C2I = "C2i";

    private static final RELSW10aXMLSerializer INSTANCE = new RELSW10aXMLSerializer();

    private RELSW10aXMLSerializer() { }

    public static RELSW10aXMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof RELSW10aPublicKeyParameters) {
            return getInstance().publicKeyParametersSerialization((RELSW10aPublicKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof RELSW10aMasterSecretKeyParameters) {
            return getInstance().masterSecretKeyParametersSerialization((RELSW10aMasterSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof RELSW10aSecretKeyParameters) {
            return getInstance().secretKeyParametersSerialization((RELSW10aSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof RELSW10aCiphertextParameters) {
            return getInstance().ciphertextParametersSerialization((RELSW10aCiphertextParameters) cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + RELSW10aEngine.SCHEME_NAME
                    + " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(RELSW10aPublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(RELSW10aXMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_PK);
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g
            Element gElement = publicKeyParametersDocument.createElement(TAG_PK_G);
            String gString = new String(Hex.encode(publicKeyParameters.getG().toBytes()));
            Text gText = publicKeyParametersDocument.createTextNode(gString);
            schemeElement.appendChild(gElement);
            gElement.appendChild(gText);
            //Set gb
            Element gbElement = publicKeyParametersDocument.createElement(TAG_PK_Gb);
            String gbString = new String(Hex.encode(publicKeyParameters.getGb().toBytes()));
            Text gbText = publicKeyParametersDocument.createTextNode(gbString);
            schemeElement.appendChild(gbElement);
            gbElement.appendChild(gbText);
            //Set gb2
            Element gb2Element = publicKeyParametersDocument.createElement(TAG_PK_Gb2);
            String gb2String = new String(Hex.encode(publicKeyParameters.getGb2().toBytes()));
            Text gb2Text = publicKeyParametersDocument.createTextNode(gb2String);
            schemeElement.appendChild(gb2Element);
            gb2Element.appendChild(gb2Text);
            //Set hb
            Element hbElement = publicKeyParametersDocument.createElement(TAG_PK_Hb);
            String hbString = new String(Hex.encode(publicKeyParameters.getHb().toBytes()));
            Text hbText = publicKeyParametersDocument.createTextNode(hbString);
            schemeElement.appendChild(hbElement);
            hbElement.appendChild(hbText);
            //Set eggAlpha
            Element eggAlphaElement = publicKeyParametersDocument.createElement(TAG_PK_EggAlpha);
            String eggAlphaString = new String(Hex.encode(publicKeyParameters.getEggAlpha().toBytes()));
            Text eggAlphaText = publicKeyParametersDocument.createTextNode(eggAlphaString);
            schemeElement.appendChild(eggAlphaElement);
            eggAlphaElement.appendChild(eggAlphaText);
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(RELSW10aMasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(RELSW10aXMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set alpha
            Element alphaElement = masterSecretKeyDocument.createElement(TAG_MSK_ALPHA);
            String alphaString = new String(Hex.encode(masterSecretKeyParameters.getAlpha().toBytes()));
            Text alphaText = masterSecretKeyDocument.createTextNode(alphaString);
            schemeElement.appendChild(alphaElement);
            alphaElement.appendChild(alphaText);
            //Set b
            Element bElement = masterSecretKeyDocument.createElement(TAG_MSK_B);
            String bString = new String(Hex.encode(masterSecretKeyParameters.getB().toBytes()));
            Text bText = masterSecretKeyDocument.createTextNode(bString);
            schemeElement.appendChild(bElement);
            bElement.appendChild(bText);
            //Set h
            Element hElement = masterSecretKeyDocument.createElement(TAG_MSK_H);
            String hString = new String(Hex.encode(masterSecretKeyParameters.getH().toBytes()));
            Text hText = masterSecretKeyDocument.createTextNode(hString);
            schemeElement.appendChild(hElement);
            hElement.appendChild(hText);
            return masterSecretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document secretKeyParametersSerialization(RELSW10aSecretKeyParameters secretKeyParameters){
        try {
            Document secretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = secretKeyDocument.createElement(RELSW10aXMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_SK);
            secretKeyDocument.appendChild(schemeElement);
            //Set id
            Element idElement = secretKeyDocument.createElement(TAG_SK_ID);
            Text idText = secretKeyDocument.createTextNode(secretKeyParameters.getId());
            schemeElement.appendChild(idElement);
            idElement.appendChild(idText);
            //Set d0
            Element d0Element = secretKeyDocument.createElement(RELSW10aXMLSerializer.TAG_SK_D0);
            String d0String = new String(Hex.encode(secretKeyParameters.getD0().toBytes()));
            Text d0Text = secretKeyDocument.createTextNode(d0String);
            schemeElement.appendChild(d0Element);
            d0Element.appendChild(d0Text);
            //Set d1
            Element d1Element = secretKeyDocument.createElement(RELSW10aXMLSerializer.TAG_SK_D1);
            String d1String = new String(Hex.encode(secretKeyParameters.getD1().toBytes()));
            Text d1Text = secretKeyDocument.createTextNode(d1String);
            schemeElement.appendChild(d1Element);
            d1Element.appendChild(d1Text);
            //Set d2
            Element d2Element = secretKeyDocument.createElement(RELSW10aXMLSerializer.TAG_SK_D2);
            String d2String = new String(Hex.encode(secretKeyParameters.getD2().toBytes()));
            Text d2Text = secretKeyDocument.createTextNode(d2String);
            schemeElement.appendChild(d2Element);
            d2Element.appendChild(d2Text);
            return secretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document ciphertextParametersSerialization(RELSW10aCiphertextParameters ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(RELSW10aXMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_CT);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(ciphertextParameters.getLength()));
            ciphertextDocument.appendChild(schemeElement);
            //Set C0
            Element c0Element = ciphertextDocument.createElement(RELSW10aXMLSerializer.TAG_CT_C0);
            String c0String = new String(Hex.encode(ciphertextParameters.getC0().toBytes()));
            Text c0Text = ciphertextDocument.createTextNode(c0String);
            schemeElement.appendChild(c0Element);
            c0Element.appendChild(c0Text);
            //Set C1s
            Element c1sElement = ciphertextDocument.createElement(TAG_CT_C1S);
            schemeElement.appendChild(c1sElement);
            for (int i=0; i<ciphertextParameters.getC1s().length; i++){
                Element c1iElement = ciphertextDocument.createElement(TAG_CT_C1I);
                c1iElement.setAttribute(PairingParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
                String c1iString = new String(Hex.encode(ciphertextParameters.getC1sAt(i).toBytes()));
                Text c1iText = ciphertextDocument.createTextNode(c1iString);
                c1sElement.appendChild(c1iElement);
                c1iElement.appendChild(c1iText);
            }
            //Set C2s
            Element c2sElement = ciphertextDocument.createElement(TAG_CT_C2S);
            schemeElement.appendChild(c2sElement);
            for (int i=0; i<ciphertextParameters.getC2s().length; i++){
                Element c2iElement = ciphertextDocument.createElement(TAG_CT_C2I);
                c2iElement.setAttribute(PairingParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
                String c2iString = new String(Hex.encode(ciphertextParameters.getC2sAt(i).toBytes()));
                Text c2iText = ciphertextDocument.createTextNode(c2iString);
                c2sElement.appendChild(c2iElement);
                c2iElement.appendChild(c2iText);
            }
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
            throw new InvalidParameterException("Illegal " + RELSW10aEngine.SCHEME_NAME +
                    " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element gb = null;
        it.unisa.dia.gas.jpbc.Element gb2 = null;
        it.unisa.dia.gas.jpbc.Element hb = null;
        it.unisa.dia.gas.jpbc.Element eggAlpha = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
                String gString = node.getFirstChild().getNodeValue();
                g = pairing.getG1().newElementFromBytes(Hex.decode(gString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_Gb)) {
                //Set gb
                String gbString = node.getFirstChild().getNodeValue();
                gb = pairing.getG1().newElementFromBytes(Hex.decode(gbString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_Gb2)) {
                //Set gb2
                String gb2String = node.getFirstChild().getNodeValue();
                gb2 = pairing.getG1().newElementFromBytes(Hex.decode(gb2String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_Hb)) {
                //Set hb
                String hbString = node.getFirstChild().getNodeValue();
                hb = pairing.getG1().newElementFromBytes(Hex.decode(hbString)).getImmutable();
            }else if (node.getNodeName().equals(TAG_PK_EggAlpha)) {
                //Set eggAlpha
                String eggAlphaString = node.getFirstChild().getNodeValue();
                eggAlpha = pairing.getG1().newElementFromBytes(Hex.decode(eggAlphaString)).getImmutable();
            }
        }
        return new RELSW10aPublicKeyParameters(pairingParameters, g, gb, gb2, hb, eggAlpha);
    }

    private CipherParameters masterSecretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element alpha = null;
        it.unisa.dia.gas.jpbc.Element b = null;
        it.unisa.dia.gas.jpbc.Element h = null;
        for (int i=0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            //Set alpha
            if (node.getNodeName().equals(TAG_MSK_ALPHA)) {
                String alphaString = node.getFirstChild().getNodeValue();
                alpha = pairing.getZr().newElementFromBytes(Hex.decode(alphaString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_MSK_B)) {
                String bString = node.getFirstChild().getNodeValue();
                b = pairing.getZr().newElementFromBytes(Hex.decode(bString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_MSK_H)) {
                String hString = node.getFirstChild().getNodeValue();
                h = pairing.getG1().newElementFromBytes(Hex.decode(hString)).getImmutable();
            }
        }
        return new RELSW10aMasterSecretKeyParameters(pairingParameters, alpha, b, h);
    }

    private CipherParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        String id = null;
        it.unisa.dia.gas.jpbc.Element elementId = null;
        it.unisa.dia.gas.jpbc.Element d0 = null;
        it.unisa.dia.gas.jpbc.Element d1 = null;
        it.unisa.dia.gas.jpbc.Element d2 = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_ID)) {
                id = node.getFirstChild().getNodeValue();
            } else if (node.getNodeName().equals(TAG_SK_D0)) {
                //Set d0
                String d0String = node.getFirstChild().getNodeValue();
                d0 = pairing.getG1().newElementFromBytes(Hex.decode(d0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_SK_D1)) {
                //Set d1
                String d1String = node.getFirstChild().getNodeValue();
                d1 = pairing.getG1().newElementFromBytes(Hex.decode(d1String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_SK_D2)) {
                //Set d2
                String d2String = node.getFirstChild().getNodeValue();
                d2 = pairing.getG1().newElementFromBytes(Hex.decode(d2String)).getImmutable();
            }
        }
        elementId = Utils.MapToZr(pairing, id);
        return new RELSW10aSecretKeyParameters(pairingParameters, id, elementId, d0, d1, d2);
    }

    private CipherParameters ciphertextParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element C0 = null;
        it.unisa.dia.gas.jpbc.Element[] C1s = new it.unisa.dia.gas.jpbc.Element[length];
        it.unisa.dia.gas.jpbc.Element[] C2s = new it.unisa.dia.gas.jpbc.Element[length];
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_CT_C0)) {
                //Set C0
                String c0String = node.getFirstChild().getNodeValue();
                C0 = pairing.getG1().newElementFromBytes(Hex.decode(c0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_CT_C1S)) {
                //Set C1s
                NodeList nodeHsList = ((Element) node).getElementsByTagName(TAG_CT_C1I);
                for (int j=0; j<nodeHsList.getLength(); j++) {
                    Element elementC1i = (Element) nodeHsList.item(j);
                    int index = Integer.valueOf(elementC1i.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    String c1iString = elementC1i.getFirstChild().getNodeValue();
                    C1s[index] = pairing.getG1().newElementFromBytes(Hex.decode(c1iString)).getImmutable();
                }
            } else if (node.getNodeName().equals(TAG_CT_C2S)) {
                //Set C2s
                NodeList nodeHsList = ((Element) node).getElementsByTagName(TAG_CT_C2I);
                for (int j=0; j<nodeHsList.getLength(); j++) {
                    Element elementC2i = (Element) nodeHsList.item(j);
                    int index = Integer.valueOf(elementC2i.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    String c2iString = elementC2i.getFirstChild().getNodeValue();
                    C2s[index] = pairing.getG1().newElementFromBytes(Hex.decode(c2iString)).getImmutable();
                }
            }
        }
        return new RELSW10aCiphertextParameters(pairingParameters,length, C0, C1s, C2s);
    }
}
