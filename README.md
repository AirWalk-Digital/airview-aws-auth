# airview-aws-auth

This module provides lambda-based **Cognito JWT** authenticators for use in Cloudfront and API Gateway workflows as part of Airview.

This module is based on the AWS [cognito-at-edge](https://github.com/awslabs/cognito-at-edge) module.

## Usage
### Cloudfront User Authentication

For cloudfront usage, the module provides JWT **validation and authentication using Cognito**.  If a request is 
unauthenticated, the user will be redirected via the Cognito Authentication flow.  In the case of expired tokens, a 
refresh token is used if present in the request cookies. 

You must create a [Lambda@Edge function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-at-the-edge.html) 
in the `us-east-1` region and associate it with the CloudFront distribution's *viewer request* events.

Within your function, you can import and use the `CloudFrontUserAuthenticator` class as shown here:

``` js
const { CloudFrontUserAuthenticator } = require('airview-aws-auth');

const authenticator = new CloudFrontUserAuthenticator({
  // Replace these parameter values with those of your own environment
  region: 'us-east-1', // user pool region
  userPoolId: 'us-east-1_tyo1a1FHH', // user pool ID
  userPoolAppId: '63gcbm2jmskokurt5ku9fhejc6', // user pool app client ID
  userPoolDomain: 'domain.auth.us-east-1.amazoncognito.com', // user pool domain
});

exports.handler = async (request) => authenticator.handle(request);
```

#### Reference

##### `CloudFrontUserAuthenticator(params)`

* `params` *Object* Authenticator parameters:
  * `region` *string* Cognito UserPool region (eg: `us-east-1`)
  * `userPoolId` *string* Cognito UserPool ID (eg: `us-east-1_tyo1a1FHH`)
  * `userPoolAppId` *string* Cognito UserPool Application ID (eg: `63gcbm2jmskokurt5ku9fhejc6`)
  * `userPoolAppSecret` *string* (Optional) Cognito UserPool Application Secret (eg: `oh470px2i0uvy4i2ha6sju0vxe4ata9ol3m63ufhs2t8yytwjn7p`)
  * `userPoolDomain` *string* Cognito UserPool domain (eg: `your-domain.auth.us-east-1.amazoncognito.com`)
  * `cookieExpirationDays` *number* (Optional) Number of day to set cookies expiration date, default to 365 days (eg: `365`)
  * `disableCookieDomain` *boolean* (Optional) Sets domain attribute in cookies, defaults to false (eg: `false`)
  * `logLevel` *string* (Optional) Logging level. Default: `'silent'`. One of `'fatal'`, `'error'`, `'warn'`, `'info'`, `'debug'`, `'trace'` or `'silent'`.

*This is the class constructor.*

##### `handle(request)`

* `request` *Object* Lambda@Edge request object
  * See AWS doc for details: [Lambda@Edge events](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html)

Use it as your Lambda Handler. It will authenticate each query.

```
const authenticator = new CloudFrontUserAuthenticator( ... );
exports.handler = async (request) => authenticator.handle(request);
```

### API Gateway Reqquest Validation

For API Gateway usage, the module provides **Cognito JWT Validation only**, i.e. it does not redirect via the Cognito 
Authentication flow.  API Gateway token valiation can come from two sources:

1. You can pass an **access token** in the `Authorization` header with a type of `Bearer`.
2. The request cookies can contain the cognito cookies as set via the _Cloudfront User Authentication_ workflow above.

To use the module, you must create an Api Gateway authenticator lambda and associate it with your desired routes.

Within your Lambda function, you can import and use the `ApiGatewayRequestValidator` class as shown here:

``` js
const { ApiGatewayRequestValidator } = require('airview-aws-auth');

const authenticator = new ApiGatewayRequestValidator({
  // Replace these parameter values with those of your own environment
  region: 'us-east-1', // user pool region
  userPoolId: 'us-east-1_tyo1a1FHH', // user pool ID
  userPoolAppId: '63gcbm2jmskokurt5ku9fhejc6', // user pool app client ID
  userPoolDomain: 'domain.auth.us-east-1.amazoncognito.com', // user pool domain
});

exports.handler = async (request) => authenticator.handle(request);
```

#### Reference - ApiGatewayRequestValidator Class

##### `ApiGatewayRequestValidator(params)`

* `params` *Object* Authenticator parameters:
  * `region` *string* Cognito UserPool region (eg: `us-east-1`)
  * `userPoolId` *string* Cognito UserPool ID (eg: `us-east-1_tyo1a1FHH`)
  * `userPoolAppId` *string* Cognito UserPool Application ID (eg: `63gcbm2jmskokurt5ku9fhejc6`).  Accepts multiple Application IDs, separated by `;` (e.g. `appid1;appid2`).  When multiple Application IDs are present, the token must be valid for at least one application.
  * `userPoolAppSecret` *string* (Optional) Cognito UserPool Application Secret (eg: `oh470px2i0uvy4i2ha6sju0vxe4ata9ol3m63ufhs2t8yytwjn7p`)
  * `userPoolDomain` *string* Cognito UserPool domain (eg: `your-domain.auth.us-east-1.amazoncognito.com`)
  * `logLevel` *string* (Optional) Logging level. Default: `'silent'`. One of `'fatal'`, `'error'`, `'warn'`, `'info'`, `'debug'`, `'trace'` or `'silent'`.

*This is the class constructor.*

##### `handle(request)`

* `request` *Object* Lambda@Edge request object
  * See AWS doc for details: [Lambda@Edge events](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html)

Use it as your Lambda Handler. It will authenticate each query.

```
const authenticator = new ApiGatewayRequestValidator( ... );
exports.handler = async (request) => authenticator.handle(request);
```
