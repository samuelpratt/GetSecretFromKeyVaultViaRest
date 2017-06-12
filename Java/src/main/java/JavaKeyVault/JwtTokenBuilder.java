package JavaKeyVault;

import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Base64;


import java.security.Signature;

public class JwtTokenBuilder {

    private Config Config;

    public JwtTokenBuilder(Config config) {
        this.Config = config;
    }

    public String buildJwtClientAuthToken() throws Exception
    {
        String header = getJwtHeader();
        String payload = getJwtPayload();

        byte[] signatureBytes = getJwtSignature(header, payload);

        String jwtToken = buildJwtToken(header, payload, signatureBytes);
        return jwtToken;
    }

    private String buildJwtToken(String header, String payload, byte[] signatureBytes) throws UnsupportedEncodingException {
        return new String(Base64.getEncoder().encode(header.getBytes("UTF-8")), "UTF-8")
                + "."
                + new String(Base64.getEncoder().encode(payload.getBytes("UTF-8")), "UTF-8")
                + "."
                + new String(Base64.getEncoder().encode(signatureBytes), "UTF-8");
    }

    private byte[] getJwtSignature(String header, String payload) throws Exception {
        ByteArrayOutputStream dataToSignStream = new ByteArrayOutputStream( );
        dataToSignStream.write(Base64.getEncoder().encode(header.getBytes("UTF-8")) );
        dataToSignStream.write( ".".getBytes("UTF-8") );
        dataToSignStream.write(Base64.getEncoder().encode(payload.getBytes("UTF-8")) );
        byte dataToSign[] = dataToSignStream.toByteArray( );

        PrivateKey privateKey = getPrivateKey();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(dataToSign);
        return signature.sign();
    }

    private String getJwtPayload() {
        return String.format("{" +
                "'aud': '%s', " +
                "'iss': '%s', " +
                "'sub': '%s', " +
                "'exp': '%s' " +
                "}", String.format("https://login.windows.net/%s/oauth2/token", Config.getTenentId()), Config.getAppId(), Config.getAppId(), getJwtExpTime());
    }

    private String getJwtHeader() throws Exception {
        return String.format("{ 'alg':  'RS256', 'x5t': '%s'}", getX5tString());
    }

    private long getJwtExpTime() {
        Date expDate = new Date();
        return (expDate.getTime()/1000) + 60;
    }

    private String getX5tString() throws Exception
    {
        KeyStore store = getKeystore();
        Certificate cert = store.getCertificate(Config.getCertName());
        byte[] der = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(der);
        byte[] digest = md.digest();

        return new String(Base64.getEncoder().encode(digest));
    }

    private PrivateKey getPrivateKey() throws Exception
    {
        KeyStore store = getKeystore();
        PrivateKey key = (PrivateKey)store.getKey(Config.getCertName(), Config.getPassword().toCharArray());
        return key;
    }

    private KeyStore getKeystore() throws Exception {
        File file = new File(Config.getCertFilePath());
        InputStream stream = new FileInputStream(file);
        KeyStore store = KeyStore.getInstance(Config.getCertType());
        store.load(stream, Config.getPassword().toCharArray());
        return store;
    }
}
