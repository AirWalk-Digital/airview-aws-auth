import axios from "axios";

jest.mock("axios");

import { CognitoAuthenticator, ApiGatewayAuthenticator } from "../src/";

const DATE = new Date("2017");
// @ts-ignore
global.Date = class extends Date {
  constructor() {
    super();
    return DATE;
  }
};

describe("private functions", () => {
  let authenticator;

  beforeEach(() => {
    authenticator = new CognitoAuthenticator({
      region: "us-east-1",
      userPoolId: "us-east-1_abcdef123",
      userPoolAppId: "123456789qwertyuiop987abcd",
      userPoolDomain: "my-cognito-domain.auth.us-east-1.amazoncognito.com",
      cookieExpirationDays: 365,
      disableCookieDomain: false,
      logLevel: "error",
    });
  });

  test("should fetch token", () => {
    axios.request = jest.fn().mockResolvedValue({ data: tokenData });

    return authenticator
      ._fetchTokensFromCode("htt://redirect", "AUTH_CODE")
      .then((res) => {
        expect(res).toEqual(tokenData);
      });
  });

  test("should throw if unable to fetch token", () => {
    axios.request = jest.fn().mockRejectedValue(new Error("Unexpected error"));
    return expect(() =>
      authenticator._fetchTokensFromCode("htt://redirect", "AUTH_CODE")
    ).rejects.toThrow();
  });

  test("should getRedirectResponse", async () => {
    const username = "toto";
    const domain = "example.com";
    const location = "/test";
    const cookiePath = "/myPath";
    jest.spyOn(authenticator._jwtVerifier, "verify");
    authenticator._jwtVerifier.verify.mockReturnValueOnce(
      Promise.resolve({ token_use: "id", "cognito:username": username })
    );

    const response = await authenticator._getRedirectResponse({
      tokens: tokenData,
      domain,
      location,
      cookiePath,
    });
    expect(response).toMatchObject({
      status: "302",
      headers: {
        location: [
          {
            key: "Location",
            value: location,
          },
        ],
      },
    });
    expect(response.headers["set-cookie"]).toEqual(
      expect.arrayContaining([
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${DATE}; Secure; Path=/myPath`,
        },
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${DATE}; Secure; Path=/myPath`,
        },
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone email profile openid aws.cognito.signin.user.admin; Domain=${domain}; Expires=${DATE}; Secure; Path=/myPath`,
        },
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${DATE}; Secure; Path=/myPath`,
        },
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${DATE}; Secure; Path=/myPath`,
        },
      ])
    );
    expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
  });

  test("should not return cookie domain", async () => {
    const authenticatorWithNoCookieDomain = new CognitoAuthenticator({
      region: "us-east-1",
      userPoolId: "us-east-1_abcdef123",
      userPoolAppId: "123456789qwertyuiop987abcd",
      userPoolDomain: "my-cognito-domain.auth.us-east-1.amazoncognito.com",
      cookieExpirationDays: 365,
      disableCookieDomain: true,
      logLevel: "error",
    });
    authenticatorWithNoCookieDomain._jwtVerifier.cacheJwks(jwksData);

    const username = "toto";
    const domain = "example.com";
    const path = "/test";
    const cookiePath = "/myPath";
    jest.spyOn(authenticatorWithNoCookieDomain._jwtVerifier, "verify");
    authenticatorWithNoCookieDomain._jwtVerifier.verify.mockReturnValueOnce(
      Promise.resolve({ token_use: "id", "cognito:username": username })
    );

    const response = await authenticatorWithNoCookieDomain._getRedirectResponse(
      {
        tokens: tokenData,
        domain,
        location: path,
        cookiePath,
      }
    );
    expect(response).toMatchObject({
      status: "302",
      headers: {
        location: [
          {
            key: "Location",
            value: path,
          },
        ],
      },
    });
    expect(response.headers["set-cookie"]).toEqual(
      expect.arrayContaining([
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Expires=${DATE}; Secure; Path=/myPath`,
        },
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Expires=${DATE}; Secure; Path=/myPath`,
        },
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone email profile openid aws.cognito.signin.user.admin; Expires=${DATE}; Secure; Path=/myPath`,
        },
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Expires=${DATE}; Secure; Path=/myPath`,
        },
        {
          key: "Set-Cookie",
          value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Expires=${DATE}; Secure; Path=/myPath`,
        },
      ])
    );
    expect(
      authenticatorWithNoCookieDomain._jwtVerifier.verify
    ).toHaveBeenCalled();
  });

  test("should getIdTokenFromCookie", () => {
    const appClientName = "toto,./;;..-_lol123";
    expect(
      authenticator._getTokenFromCookie(
        [
          {
            key: "Cookie",
            value: `CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.idToken=wrong; CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken=${tokenData.id_token}; CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken=${tokenData.id_token}; CognitoIdentityServiceProvider.5ukasw8840tap1g1i1617jh8pi.${appClientName}.idToken=wrong;`,
          },
        ],
        "idToken"
      )
    ).toBe(tokenData.id_token);

    expect(
      authenticator._getTokenFromCookie(
        [
          {
            key: "Cookie",
            value: `CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.accessToken=someValue; CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken=${tokenData.id_token}`,
          },
        ],
        "idToken"
      )
    ).toBe(tokenData.id_token);
  });

  test("should getRefreshTokenFromCookie", () => {
    const appClientName = "toto,./;;..-_lol123";
    expect(
      authenticator._getTokenFromCookie(
        [
          {
            key: "Cookie",
            value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.refreshToken=${tokenData.refresh_token}; CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken=${tokenData.id_token}; CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken=${tokenData.id_token}; CognitoIdentityServiceProvider.5ukasw8840tap1g1i1617jh8pi.${appClientName}.idToken=wrong;`,
          },
        ],
        "refreshToken"
      )
    ).toBe(tokenData.refresh_token);
  });

  test("should getIdTokenFromCookie throw on cookies", () => {
    expect(() =>
      authenticator._getTokenFromCookie(undefined, "idToken")
    ).toThrow("idToken");
    expect(() => authenticator._getTokenFromCookie("", "idToken")).toThrow(
      "idToken"
    );
    expect(() => authenticator._getTokenFromCookie([], "idToken")).toThrow(
      "idToken"
    );
  });
});

describe("createCognitoAuthenticator", () => {
  let params;

  beforeEach(() => {
    params = {
      region: "us-east-1",
      userPoolId: "us-east-1_abcdef123",
      userPoolAppId: "123456789qwertyuiop987abcd",
      userPoolDomain: "my-cognito-domain.auth.us-east-1.amazoncognito.com",
      cookieExpirationDays: 365,
      disableCookieDomain: true,
    };
  });

  test("should create authenticator", () => {
    expect(typeof new CognitoAuthenticator(params)).toBe("object");
  });

  test("should create authenticator without cookieExpirationDay", () => {
    delete params.cookieExpirationDays;
    expect(typeof new CognitoAuthenticator(params)).toBe("object");
  });

  test("should create authenticator without disableCookieDomain", () => {
    delete params.disableCookieDomain;
    expect(typeof new CognitoAuthenticator(params)).toBe("object");
  });

  test("should fail when creating authenticator without params", () => {
    // @ts-ignore
    // ts-ignore is used here to override typescript's type check in the constructor
    // this test is still useful when the library is imported to a js file
    expect(() => new CognitoAuthenticator()).toThrow("Expected params");
  });

  test("should fail when creating authenticator without region", () => {
    delete params.region;
    expect(() => new CognitoAuthenticator(params)).toThrow("region");
  });

  test("should fail when creating authenticator without userPoolId", () => {
    delete params.userPoolId;
    expect(() => new CognitoAuthenticator(params)).toThrow("userPoolId");
  });

  test("should fail when creating authenticator without userPoolAppId", () => {
    delete params.userPoolAppId;
    expect(() => new CognitoAuthenticator(params)).toThrow("userPoolAppId");
  });

  test("should fail when creating authenticator without userPoolDomain", () => {
    delete params.userPoolDomain;
    expect(() => new CognitoAuthenticator(params)).toThrow("userPoolDomain");
  });

  test("should fail when creating authenticator with invalid region", () => {
    params.region = 123;
    expect(() => new CognitoAuthenticator(params)).toThrow("region");
  });

  test("should fail when creating authenticator with invalid userPoolId", () => {
    params.userPoolId = 123;
    expect(() => new CognitoAuthenticator(params)).toThrow("userPoolId");
  });

  test("should fail when creating authenticator with invalid userPoolAppId", () => {
    params.userPoolAppId = 123;
    expect(() => new CognitoAuthenticator(params)).toThrow("userPoolAppId");
  });

  test("should fail when creating authenticator with invalid userPoolDomain", () => {
    params.userPoolDomain = 123;
    expect(() => new CognitoAuthenticator(params)).toThrow("userPoolDomain");
  });

  test("should fail when creating authenticator with invalid cookieExpirationDay", () => {
    params.cookieExpirationDays = "123";
    expect(() => new CognitoAuthenticator(params)).toThrow(
      "cookieExpirationDays"
    );
  });

  test("should fail when creating authenticator with invalid disableCookieDomain", () => {
    params.disableCookieDomain = "123";
    expect(() => new CognitoAuthenticator(params)).toThrow(
      "disableCookieDomain"
    );
  });
});

describe("handle", () => {
  let authenticator;

  beforeEach(() => {
    authenticator = new CognitoAuthenticator({
      region: "us-east-1",
      userPoolId: "us-east-1_abcdef123",
      userPoolAppId: "123456789qwertyuiop987abcd",
      userPoolDomain: "my-cognito-domain.auth.us-east-1.amazoncognito.com",
      cookieExpirationDays: 365,
      logLevel: "debug",
    });
    authenticator._jwtVerifier.cacheJwks(jwksData);
    jest.spyOn(authenticator, "_getTokenFromCookie");
    jest.spyOn(authenticator, "_fetchTokensFromCode");
    jest.spyOn(authenticator, "_fetchTokensFromRefresh");
    jest.spyOn(authenticator, "_getRedirectResponse");
    jest.spyOn(authenticator._jwtVerifier, "verify");
  });

  test("should forward request if authenticated", () => {
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({}));
    return expect(authenticator.handle(getCloudfrontRequest()))
      .resolves.toEqual(getCloudfrontRequest().Records[0].cf.request)
      .then(() => {
        expect(authenticator._getTokenFromCookie).toHaveBeenCalled();
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
      });
  });

  test("should fetch and set token if code is present", () => {
    authenticator._jwtVerifier.verify.mockImplementationOnce(async () => {
      throw new Error();
    });
    authenticator._fetchTokensFromRefresh.mockImplementationOnce(() => {
      throw new Error();
    });
    authenticator._fetchTokensFromCode.mockResolvedValueOnce(tokenData);
    authenticator._getRedirectResponse.mockReturnValueOnce({
      response: "toto",
    });
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.querystring = "code=54fe5f4e&state=/lol";
    return expect(authenticator.handle(request))
      .resolves.toEqual({ response: "toto" })
      .then(() => {
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticator._fetchTokensFromCode).toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).toHaveBeenCalledWith({
          tokens: tokenData,
          domain: "d111111abcdef8.cloudfront.net",
          location: "/lol",
        });
      });
  });

  test("should redirect to same if unauthenticated with valid refreshToken", () => {
    authenticator._jwtVerifier.verify
      .mockImplementationOnce(async () => {
        throw new Error();
      })
      .mockReturnValueOnce(
        Promise.resolve({ token_use: "id", "cognito:username": "toto" })
      );

    const { refresh_token, ...rest } = tokenData;
    axios.request = jest.fn().mockResolvedValue({ data: rest });

    return expect(authenticator.handle(getCloudfrontRequest()))
      .resolves.toEqual({
        status: "302",
        headers: {
          location: [
            {
              key: "Location",
              value: "/lol?param=1",
            },
          ],
          "cache-control": [
            {
              key: "Cache-Control",
              value: "no-cache, no-store, max-age=0, must-revalidate",
            },
          ],
          pragma: [
            {
              key: "Pragma",
              value: "no-cache",
            },
          ],
          "set-cookie": [
            {
              key: "Set-Cookie",
              value:
                "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.accessToken=eyJz9sdfsdfsdfsd; Domain=d111111abcdef8.cloudfront.net; Expires=Sun Jan 01 2017 00:00:00 GMT+0000 (Greenwich Mean Time); Secure; Path=/",
            },
            {
              key: "Set-Cookie",
              value:
                "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.idToken=dmcxd329ujdmkemkd349r; Domain=d111111abcdef8.cloudfront.net; Expires=Sun Jan 01 2017 00:00:00 GMT+0000 (Greenwich Mean Time); Secure; Path=/",
            },
            {
              key: "Set-Cookie",
              value:
                "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.tokenScopesString=phone email profile openid aws.cognito.signin.user.admin; Domain=d111111abcdef8.cloudfront.net; Expires=Sun Jan 01 2017 00:00:00 GMT+0000 (Greenwich Mean Time); Secure; Path=/",
            },
            {
              key: "Set-Cookie",
              value:
                "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=toto; Domain=d111111abcdef8.cloudfront.net; Expires=Sun Jan 01 2017 00:00:00 GMT+0000 (Greenwich Mean Time); Secure; Path=/",
            },
          ],
        },
      })
      .then(() => {
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
      });
  });

  test("should redirect to auth domain if unauthenticated and no code", () => {
    authenticator._jwtVerifier.verify.mockImplementationOnce(async () => {
      throw new Error();
    });
    authenticator._fetchTokensFromRefresh.mockImplementationOnce(() => {
      throw new Error();
    });
    return expect(authenticator.handle(getCloudfrontRequest()))
      .resolves.toEqual({
        status: "302",
        headers: {
          location: [
            {
              key: "Location",
              value:
                "https://my-cognito-domain.auth.us-east-1.amazoncognito.com/authorize?redirect_uri=https://d111111abcdef8.cloudfront.net&response_type=code&client_id=123456789qwertyuiop987abcd&state=/lol%3Fparam%3D1",
            },
          ],
          "cache-control": [
            {
              key: "Cache-Control",
              value: "no-cache, no-store, max-age=0, must-revalidate",
            },
          ],
          pragma: [
            {
              key: "Pragma",
              value: "no-cache",
            },
          ],
        },
      })
      .then(() => {
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
      });
  });
});

/* eslint-disable quotes, comma-dangle */

const jwksData = {
  keys: [
    {
      kid: "1234example=",
      alg: "RS256",
      kty: "RSA",
      e: "AQAB",
      n: "1234567890",
      use: "sig",
    },
    {
      kid: "5678example=",
      alg: "RS256",
      kty: "RSA",
      e: "AQAB",
      n: "987654321",
      use: "sig",
    },
  ],
};

const tokenData = {
  access_token: "eyJz9sdfsdfsdfsd",
  refresh_token: "dn43ud8uj32nk2je",
  id_token: "dmcxd329ujdmkemkd349r",
  token_type: "Bearer",
  expires_in: 3600,
};

const getCloudfrontRequest = () => ({
  Records: [
    {
      cf: {
        config: {
          distributionDomainName: "d123.cloudfront.net",
          distributionId: "EDFDVBD6EXAMPLE",
          eventType: "viewer-request",
          requestId: "MRVMF7KydIvxMWfJIglgwHQwZsbG2IhRJ07sn9AkKUFSHS9EXAMPLE==",
        },
        request: {
          body: {
            action: "read-only",
            data: "eyJ1c2VybmFtZSI6IkxhbWJkYUBFZGdlIiwiY29tbWVudCI6IlRoaXMgaXMgcmVxdWVzdCBib2R5In0=",
            encoding: "base64",
            inputTruncated: false,
          },
          clientIp: "2001:0db8:85a3:0:0:8a2e:0370:7334",
          querystring: "param=1",
          uri: "/lol",
          method: "GET",
          headers: {
            host: [
              {
                key: "Host",
                value: "d111111abcdef8.cloudfront.net",
              },
            ],
            "user-agent": [
              {
                key: "User-Agent",
                value: "curl/7.51.0",
              },
            ],
            cookie: [
              {
                key: "cookie",
                value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.idToken=${tokenData.access_token};`,
              },

              {
                key: "cookie",
                value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.refreshToken=${tokenData.refresh_token};`,
              },
            ],
          },
          origin: {
            custom: {
              customHeaders: {
                "my-origin-custom-header": [
                  {
                    key: "My-Origin-Custom-Header",
                    value: "Test",
                  },
                ],
              },
              domainName: "example.com",
              keepaliveTimeout: 5,
              path: "/custom_path",
              port: 443,
              protocol: "https",
              readTimeout: 5,
              sslProtocols: ["TLSv1", "TLSv1.1"],
            },
            s3: {
              authMethod: "origin-access-identity",
              customHeaders: {
                "my-origin-custom-header": [
                  {
                    key: "My-Origin-Custom-Header",
                    value: "Test",
                  },
                ],
              },
              domainName: "my-bucket.s3.amazonaws.com",
              path: "/s3_path",
              region: "us-east-1",
            },
          },
        },
      },
    },
  ],
});

describe("createApiGatewayAuthenticator", () => {
  let authenticator;

  beforeEach(() => {
    authenticator = new ApiGatewayAuthenticator({
      region: "us-east-1",
      userPoolId: "us-east-1_abcdef123",
      userPoolAppId: "123456789qwertyuiop987abcd",
      userPoolDomain: "my-cognito-domain.auth.us-east-1.amazoncognito.com",
    });

    jest.spyOn(authenticator._jwtVerifier, "verify");
  });

  test("should reject invalid id token", async () => {
    const event = {
      cookies: [
        "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.idToken=eyJz9sdfsdfsdfsd;",
        "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.refreshToken=aaabbccc;",
      ],
    };

    authenticator._jwtVerifier.verify.mockReturnValue(Promise.reject());

    return expect(authenticator.handle(event))
      .resolves.toStrictEqual({ isAuthorized: false })
      .then(() => {
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalledWith(
          "eyJz9sdfsdfsdfsd"
        );
      });
  });

  test("should reject missing id token", async () => {
    const event = {
      cookies: [
        "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.blahToken=eyJz9sdfsdfsdfsd;",
        "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.refreshToken=aaabbccc;",
      ],
    };

    authenticator._jwtVerifier.verify.mockReturnValue(Promise.resolve());

    return expect(authenticator.handle(event))
      .resolves.toStrictEqual({ isAuthorized: false })
      .then(() => {
        expect(authenticator._jwtVerifier.verify).toBeCalledTimes(0);
      });
  });

  test("should allow valid id token", async () => {
    const event = {
      cookies: [
        "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.idToken=eyJz9sdfsdfsdfsd;",
        "CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.refreshToken=aaabbccc;",
      ],
    };
    authenticator._jwtVerifier.verify.mockReturnValue(Promise.resolve());
    return expect(authenticator.handle(event))
      .resolves.toStrictEqual({ isAuthorized: true })
      .then(() => {
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalledWith(
          "eyJz9sdfsdfsdfsd"
        );
      });
  });
});
