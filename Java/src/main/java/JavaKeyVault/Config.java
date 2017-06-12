package JavaKeyVault;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.File;

public class Config {

    Document configDocument;

    public Config() throws Exception{
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        configDocument = builder.parse(new File("Config.xml"));

    }

    private String getElement(String tagName) {
        try {
            XPath xPath = XPathFactory.newInstance().newXPath();
            String expression = String.format("/Config/%s/text()", tagName);
            Node node = (Node) xPath.evaluate(expression, configDocument, XPathConstants.NODE);
            return node.getNodeValue();
        }
        catch (Exception e) {
            return null;
        }

    }

    public String getPassword() {
        return getElement("Password");
    }
    public String getAppId() {
        return getElement("AppId");
    }
    public String getTenentId() {
        return getElement("TenentId");
    }
    public String getCertFilePath() {
        return getElement("CertFilePath");
    }
    public String getCertName() {
        return getElement("CertName");
    }
    public String getCertType() {
        return getElement("CertType");
    }
    public String getKeyVaultName() {
        return getElement("KeyVaultName");
    }
    public String getSecretName() {
        return getElement("SecretName");
    }
}
