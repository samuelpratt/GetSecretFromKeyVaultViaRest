package JavaKeyVault;

public class App
{
    public static void main( String[] args ) throws Exception
    {
        Config config = new Config();
        JwtTokenBuilder jwtTokenBuilder = new JwtTokenBuilder(config);
        KeyVaultRestClient restClient = new KeyVaultRestClient(config);

        String jwtClientAuthToken = jwtTokenBuilder.buildJwtClientAuthToken();
        String bearerToken = restClient.getBearerToken(jwtClientAuthToken);
        String secret = restClient.getSecretFromVault(bearerToken, config.getSecretName());

        System.out.println(secret);
    }
}



