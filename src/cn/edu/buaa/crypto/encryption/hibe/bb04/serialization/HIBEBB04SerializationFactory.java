package cn.edu.buaa.crypto.encryption.hibe.bb04.serialization;

import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04SecretKeyParameters;
import cn.edu.buaa.crypto.serialization.CipherParameterSerializationFactory;
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
 * Created by Weiran Liu on 15-10-2.
 */
public class HIBEBB04SerializationFactory implements CipherParameterSerializationFactory {
    private static final String TAG_SCHEME = "HIBEBB04";

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
    private static final String TAG_SK_DS = "dd";
    private static final String TAG_CT_B = "B";
    private static final String TAG_CT_CS = "Cs";
    private static final String TAG_ID = "ID";

    private static final HIBEBB04SerializationFactory INSTANCE = new HIBEBB04SerializationFactory();

    private HIBEBB04SerializationFactory() { }

    public static HIBEBB04SerializationFactory getInstance(){
        return INSTANCE;
    }

    @Override
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
            throw new InvalidParameterException("Invalid CipherParameter Instance of HIBEBB04 Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(HIBEBB04PublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(HIBEBB04SerializationFactory.TAG_SCHEME);
            schemeElement.setAttribute(CipherParameterSerializationFactory.LABEL_TYPE, HIBEBB04SerializationFactory.TYPE_PK);
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g
            Element gElement = publicKeyParametersDocument.createElement(TAG_PK_G);
            String gString = new String(Hex.encode(publicKeyParameters.getG().toBytes()));
            Text gText = publicKeyParametersDocument.createTextNode(gString);
            schemeElement.appendChild(gElement);
            gElement.appendChild(gText);
            //Set g1
            Element g1Element = publicKeyParametersDocument.createElement(TAG_PK_G1);
            String g1String = new String(Hex.encode(publicKeyParameters.getG1().toBytes()));
            Text g1Text = publicKeyParametersDocument.createTextNode(g1String);
            schemeElement.appendChild(g1Element);
            g1Element.appendChild(g1Text);
            //Set g2
            Element g2Element = publicKeyParametersDocument.createElement(TAG_PK_G2);
            String g2String = new String(Hex.encode(publicKeyParameters.getG2().toBytes()));
            Text g2Text = publicKeyParametersDocument.createTextNode(g2String);
            schemeElement.appendChild(g2Element);
            g2Element.appendChild(g2Text);
            //Set h
            Element hsElement = publicKeyParametersDocument.createElement(TAG_PK_HS);
            schemeElement.appendChild(hsElement);
            for (int i=0; i<publicKeyParameters.getMaxLength(); i++){
                Element hiElement = publicKeyParametersDocument.createElement(TAG_PK_HI);
                hiElement.setAttribute(CipherParameterSerializationFactory.ATTRI_INDEX, Integer.toString(i));
                String hiString = new String(Hex.encode(publicKeyParameters.getHAt(i).toBytes()));
                Text hiText = publicKeyParametersDocument.createTextNode(hiString);
                hsElement.appendChild(hiElement);
                hiElement.appendChild(hiText);
            }
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(HIBEBB04MasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(HIBEBB04SerializationFactory.TAG_SCHEME);
            schemeElement.setAttribute(CipherParameterSerializationFactory.LABEL_TYPE, HIBEBB04SerializationFactory.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set g2Alpha
            Element g2AlphaElement = masterSecretKeyDocument.createElement(TAG_MSK_G2ALPHA);
            String g2AlphaString = new String(Hex.encode(masterSecretKeyParameters.getG2Alpha().toBytes()));
            Text g2AlphaText = masterSecretKeyDocument.createTextNode(g2AlphaString);
            schemeElement.appendChild(g2AlphaElement);
            g2AlphaElement.appendChild(g2AlphaText);

            return masterSecretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document secretKeyParametersSerialization(HIBEBB04SecretKeyParameters secretKeyParameters){
        return null;
    }

    private Document ciphertextParametersSerialization(HIBEBB04CiphertextParameters ciphertextParameters){
        return null;
    }

    @Override
    public CipherParameters documentDeserialization(PairingParameters pairingParameters, Document document) {
        Element schemeElement = document.getDocumentElement();
        String cipherParameterType = schemeElement.getAttribute(CipherParameterSerializationFactory.LABEL_TYPE);
        if (cipherParameterType.equals(CipherParameterSerializationFactory.TYPE_PK)){
            return publicKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(CipherParameterSerializationFactory.TYPE_MSK)){
            return masterSecretKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(CipherParameterSerializationFactory.TYPE_SK)) {
            return null;
        } else if (cipherParameterType.equals(CipherParameterSerializationFactory.TYPE_CT)) {
            return null;
        } else {
            throw new InvalidParameterException("Illegal HIBEBB04 Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element g1 = null;
        it.unisa.dia.gas.jpbc.Element g2 = null;
        it.unisa.dia.gas.jpbc.Element[] hs = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);

            if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
                String gString = node.getFirstChild().getNodeValue();
                g = pairing.getG1().newElementFromBytes(Hex.decode(gString));
            } else if (node.getNodeName().equals(TAG_PK_G1)) {
                //Set g1
                String g1String = node.getFirstChild().getNodeValue();
                g1 = pairing.getG1().newElementFromBytes(Hex.decode(g1String));
            } else if (node.getNodeName().equals(TAG_PK_G2)) {
                //Set g2
                String g2String = node.getFirstChild().getNodeValue();
                g2 = pairing.getG1().newElementFromBytes(Hex.decode(g2String));
            } else if (node.getNodeName().equals(TAG_PK_HS)) {
                //Set hs
                NodeList nodeHsList = node.getChildNodes();
                hs = new it.unisa.dia.gas.jpbc.Element[nodeHsList.getLength()];
                for (int j=0; j<nodeHsList.getLength(); j++) {
                    Element nodeHi = (Element)nodeHsList.item(j);
                    String hiString = nodeHi.getFirstChild().getNodeValue();
                    int index = Integer.valueOf(((Element) nodeHi).getAttribute(CipherParameterSerializationFactory.ATTRI_INDEX));
                    hs[index] = pairing.getG1().newElementFromBytes(Hex.decode(hiString));
                }
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
                String g2AlphaString = node.getFirstChild().getNodeValue();
                g2Alpha = pairing.getG1().newElementFromBytes(Hex.decode(g2AlphaString));
            }
        }
        return new HIBEBB04MasterSecretKeyParameters(pairingParameters, g2Alpha);
    }
}
