import pino from "pino";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import {
  APIGatewayRequestAuthorizerEventV2,
  APIGatewaySimpleAuthorizerResult,
} from "aws-lambda";

interface ApiGatewayAuthenticatorParams {
  region: string;
  userPoolId: string;
  userPoolAppId: string;
  userPoolAppSecret?: string;
  userPoolDomain: string;
  logLevel?: "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent";
}

export class ApiGatewayAuthenticator {
  _region: string;
  _userPoolId: string;
  _userPoolAppId: string;
  _userPoolAppSecret: string;
  _userPoolDomain: string;
  _cookieBase: string;
  _logger;
  _jwtVerifier;

  constructor(params: ApiGatewayAuthenticatorParams) {
    this._verifyParams(params);
    this._region = params.region;
    this._userPoolId = params.userPoolId;
    this._userPoolAppId = params.userPoolAppId;
    this._userPoolAppSecret = params.userPoolAppSecret;
    this._userPoolDomain = params.userPoolDomain;
    this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
    this._logger = pino({
      level: params.logLevel || "silent", // Default to silent
      base: null, //Remove pid, hostname and name logging as not useful for Lambda
    });
    this._jwtVerifier = CognitoJwtVerifier.create({
      userPoolId: params.userPoolId,
      clientId: params.userPoolAppId,
      tokenUse: "id",
    });
  }

  /**
   * Verify that constructor parameters are corrects.
   * @param  {object} params constructor params
   * @return {void} throw an exception if params are incorrect
   */
  _verifyParams(params) {
    if (typeof params !== "object") {
      throw new Error("Expected params to be an object");
    }
    ["region", "userPoolId", "userPoolAppId", "userPoolDomain"].forEach(
      (param) => {
        if (typeof params[param] !== "string") {
          throw new Error(`Expected params.${param} to be a string`);
        }
      }
    );
  }

  /**
   * Extract value of the authentication token from the request cookies.
   * @param  {Array}  cookies Request cookies.
   * @return {String} Extracted access token. Throw if not found.
   */
  _getIdTokenFromCookie(cookies) {
    this._logger.debug({
      msg: "Extracting authentication token from request cookie",
      cookies,
    });
    // eslint-disable-next-line no-useless-escape
    const regex = new RegExp(
      `${this._userPoolAppId}\..+?\.idToken=(.*?)(?:;|$)`
    );
    if (cookies) {
      for (let i = 0; i < cookies.length; i++) {
        const matches = cookies[i].match(regex);
        if (matches && matches.length > 1) {
          this._logger.debug({
            msg: "  Found token in cookie",
            token: matches[1],
          });
          return matches[1];
        }
      }
    }
    this._logger.debug("  idToken wasn't present in request cookies");
    throw new Error("Id token isn't present in the request cookies");
  }

  /**
   * Handle auth event:
   *   * if authentication cookie is present and valid: forward the request
   *   * if ?code=<grant code> is present: set cookies with new tokens
   *   * else redirect to the Cognito UserPool to authenticate the user
   * @param  {Object}  event Lambda@Edge event.
   * @return {Promise} CloudFront response.
   */
  async handle(
    event: APIGatewayRequestAuthorizerEventV2
  ): Promise<APIGatewaySimpleAuthorizerResult> {
    this._logger.debug({ msg: "Handling event", event });
    try {
      const payload = await this._jwtVerifier.verify(
        this._getIdTokenFromCookie(event.cookies)
      );
      console.log("Token is valid. Payload:", payload);
      return {
        isAuthorized: true,
      };
    } catch {
      console.log("Token is not valid!");
      return {
        isAuthorized: false,
      };
    }
  }
}

