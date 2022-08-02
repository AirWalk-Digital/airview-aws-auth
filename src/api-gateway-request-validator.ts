import pino from 'pino';
import {CognitoJwtVerifier} from 'aws-jwt-verify';
import {
  APIGatewayRequestAuthorizerEventV2,
  APIGatewaySimpleAuthorizerResult,
} from 'aws-lambda';

interface ApiGatewayRequestValidatorParams {
  region: string;
  userPoolId: string;
  userPoolAppId: string;
  userPoolAppSecret?: string;
  userPoolDomain: string;
  logLevel?: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
}

export class ApiGatewayRequestValidator {
  _region: string;
  _userPoolId: string;
  _userPoolAppIdRaw: string;
  _userPoolAppId: Array<string>;
  _userPoolAppSecret: string;
  _userPoolDomain: string;
  _cookieBase: string;
  _logger;
  _jwtVerifier;

  constructor(params: ApiGatewayRequestValidatorParams) {
    this._verifyParams(params);
    this._region = params.region;
    this._userPoolId = params.userPoolId;
    this._userPoolAppIdRaw = params.userPoolAppId;
    this._userPoolAppId = params.userPoolAppId.split(';');
    this._userPoolAppSecret = params.userPoolAppSecret;
    this._userPoolDomain = params.userPoolDomain;
    this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
    this._logger = pino({
      level: params.logLevel || 'silent', // Default to silent
      base: null, //Remove pid, hostname and name logging as not useful for Lambda
    });

    this._jwtVerifier = CognitoJwtVerifier.create({
      userPoolId: this._userPoolId,
      clientId: this._userPoolAppId,
    });
  }

  /**
   * Verify that constructor parameters are corrects.
   * @param  {object} params constructor params
   * @return {void} throw an exception if params are incorrect
   */
  _verifyParams(params): void {
    if (typeof params !== 'object') {
      throw new Error('Expected params to be an object');
    }
    ['region', 'userPoolId', 'userPoolAppId', 'userPoolDomain'].forEach(
      (param) => {
        if (typeof params[param] !== 'string') {
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
  _getIdTokenFromCookie(cookies): string {
    this._logger.debug({
      msg: 'Extracting authentication token from request cookie',
      cookies,
    });
    // eslint-disable-next-line no-useless-escape
    const regex = new RegExp(
      `(?:${this._userPoolAppId.join('|')})\..+?\.idToken=(.*?)(?:;|$)`
    );
    if (cookies) {
      for (let i = 0; i < cookies.length; i++) {
        const matches = cookies[i].match(regex);
        if (matches && matches.length > 1) {
          this._logger.debug({
            msg: 'Found token in cookie',
            token: matches[1],
          });
          return matches[1];
        }
      }
    }
    this._logger.debug("idToken wasn't present in request cookies");
    throw new Error("Id token isn't present in the request cookies");
  }

  _getAccessTokenFromAuthHeader(headers): string {
    this._logger.debug({
      msg: 'Extracting Access Token from headers',
      headers,
    });
    if (headers && headers['authorization'] != undefined) {
      const authHeader = headers['authorization'];
      if (authHeader.startsWith('Bearer ')){
        return authHeader.substring(7, authHeader.length);
      } else {
        throw new Error('Unexpected Authorization Header Type');
      }
    } else {
      throw new Error("Access token isn't present in the request headers");
    }
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
    this._logger.debug({ msg: 'Handling event', event });
    let token = null;
    let tokenUse;

    // Check for token in cookie, then header.  If both present, header overrides
    try {
      token = this._getIdTokenFromCookie(event.cookies);
      tokenUse = 'id';
    } catch (e) { }

    try {
      token = this._getAccessTokenFromAuthHeader(event.headers);
      tokenUse = 'access';
    } catch (e) { }
    
    if (token == null) {
      this._logger.debug('Token is not present in any source!');
      return {
        isAuthorized: false,
      };
    }

    this._logger.debug(`Token Content: ${token}`);
    this._logger.debug(`Token Use: ${tokenUse}`);

    try {
      const payload = await this._jwtVerifier.verify(
        token,
        {tokenUse: tokenUse}
      );
      this._logger.debug('Token is valid. Payload:', payload);
      return {
        isAuthorized: true,
      };
    } catch(e) {
      this._logger.debug('Token is not valid!');
      if (e && e.message != undefined) {
        this._logger.debug(`Reason: ${e.message}`);
      }
      return {
        isAuthorized: false,
      };
    }
  }
}
