package JavaKeyVault;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

public class KeyVaultRestClient {

    private Config Config;

    public KeyVaultRestClient(Config config) {
        Config = config;
    }

    public String getBearerToken(String jwtClientAuthToken) throws Exception {

        String urlParameters = "resource=https%3A%2F%2Fvault.azure.net&client_id="
                + URLEncoder.encode(Config.getAppId())
                + "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&grant_type=client_credentials&client_assertion="
                + URLEncoder.encode(jwtClientAuthToken);

        URL url = new URL(String.format("https://login.windows.net/%s/oauth2/token", Config.getTenentId()));

        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Accept", "text/json");
        con.setDoOutput(true);

        DataOutputStream wr = new DataOutputStream(con.getOutputStream());
        wr.writeBytes(urlParameters);

        wr.flush();
        wr.close();

        int responseCode = con.getResponseCode();
        if(responseCode != 200) throw new Exception("Non 200 response code returned");

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String responseBody;
        StringBuffer response = new StringBuffer();

        while ((responseBody = in.readLine()) != null) {
            response.append(responseBody);
        }
        in.close();

        Pattern pattern = Pattern.compile("\"access_token\" *: *\"(.*?)\"");
        Matcher matcher = pattern.matcher(response.toString());
        if (matcher.find())
        {
            return matcher.group(1);
        }
        else {
            throw new Exception("Can't find access token in response");
        }
    }

    public String getSecretFromVault(String bearerToken, String secret) throws Exception{
        URL url = new URL(String.format("https://%s.vault.azure.net/secrets/%s/?api-version=2016-10-01", Config.getKeyVaultName(), secret));

        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("Accept", "text/json");
        con.setRequestProperty("Authorization", "Bearer " + bearerToken);
        con.setDoOutput(true);

        int responseCode = con.getResponseCode();
        if(responseCode != 200) throw new Exception("Non 200 response code returned");

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String responseBody;
        StringBuffer response = new StringBuffer();

        while ((responseBody = in.readLine()) != null) {
            response.append(responseBody);
        }
        in.close();

        Pattern pattern = Pattern.compile("\"value\" *: *\"(.*?)\"");
        Matcher matcher = pattern.matcher(response.toString());
        if (matcher.find())
        {
            return matcher.group(1);
        }
        else {
            throw new Exception("Can't find value in response");
        }
    }
}
