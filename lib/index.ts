'use strict';

type OriginPattern = boolean | string | RegExp;

type OriginValue = OriginPattern | OriginPattern[];

type OriginCallback = (err: Error | null, origin?: OriginValue) => void;

type CustomOrigin = (requestOrigin: string | undefined, callback: OriginCallback) => void;

interface CorsOptions {
  origin?: OriginValue | CustomOrigin;
  methods?: string | string[];
  allowedHeaders?: string | string[];
  headers?: string | string[];
  exposedHeaders?: string | string[];
  credentials?: boolean;
  maxAge?: number;
  preflightContinue?: boolean;
  optionsSuccessStatus?: number;
}

type CorsOptionsDelegate = (
  req: CorsRequest,
  callback: (err: Error | null, options?: CorsOptions) => void
) => void;

interface CorsRequest {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
}

interface CorsResponse {
  statusCode?: number;
  getHeader(key: string): unknown;
  setHeader(key: string, value: string | number | string[]): unknown;
  end(): unknown;
}

type NextFunction = (err?: Error | null) => void;

type HeaderValue = string | number | string[] | false | undefined;

interface HeaderRecord {
  key: string;
  value: HeaderValue;
}

type HeaderNode = HeaderRecord | HeaderNode[] | null;

const assign: typeof Object.assign = require('object-assign');
const vary: (res: CorsResponse, field: string) => void = require('vary');

var defaults: CorsOptions = {
  origin: '*',
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  preflightContinue: false,
  optionsSuccessStatus: 204
};

function isString(s: unknown): boolean {
  return typeof s === 'string' || s instanceof String;
}

function isOriginAllowed(origin: string | string[] | undefined, allowedOrigin: OriginValue): boolean {
  if (Array.isArray(allowedOrigin)) {
    for (var i = 0; i < allowedOrigin.length; ++i) {
      if (isOriginAllowed(origin, allowedOrigin[i])) {
        return true;
      }
    }
    return false;
  } else if (isString(allowedOrigin)) {
    return origin === allowedOrigin;
  } else if (allowedOrigin instanceof RegExp) {
    return allowedOrigin.test(origin as string);
  } else {
    return !!allowedOrigin;
  }
}

function configureOrigin(options: CorsOptions, req: CorsRequest): HeaderNode[] {
  var requestOrigin = req.headers.origin,
    headers: HeaderNode[] = [],
    isAllowed;

  if (!options.origin || options.origin === '*') {
    // allow any origin
    headers.push([{
      key: 'Access-Control-Allow-Origin',
      value: '*'
    }]);
  } else if (isString(options.origin)) {
    // fixed origin
    headers.push([{
      key: 'Access-Control-Allow-Origin',
      value: options.origin as string
    }]);
    headers.push([{
      key: 'Vary',
      value: 'Origin'
    }]);
  } else {
    isAllowed = isOriginAllowed(requestOrigin, options.origin as OriginValue);
    // reflect origin
    headers.push([{
      key: 'Access-Control-Allow-Origin',
      value: isAllowed ? requestOrigin : false
    }]);
    headers.push([{
      key: 'Vary',
      value: 'Origin'
    }]);
  }

  return headers;
}

function configureMethods(options: CorsOptions): HeaderRecord {
  var methods = options.methods;
  if ((methods as string[]).join) {
    methods = (options.methods as string[]).join(','); // .methods is an array, so turn it into a string
  }
  return {
    key: 'Access-Control-Allow-Methods',
    value: methods
  };
}

function configureCredentials(options: CorsOptions): HeaderRecord | null {
  if (options.credentials === true) {
    return {
      key: 'Access-Control-Allow-Credentials',
      value: 'true'
    };
  }
  return null;
}

function configureAllowedHeaders(options: CorsOptions, req: CorsRequest): HeaderNode[] {
  var allowedHeaders = options.allowedHeaders || options.headers;
  var headers: HeaderNode[] = [];

  if (!allowedHeaders) {
    allowedHeaders = req.headers['access-control-request-headers']; // .headers wasn't specified, so reflect the request headers
    headers.push([{
      key: 'Vary',
      value: 'Access-Control-Request-Headers'
    }]);
  } else if ((allowedHeaders as string[]).join) {
    allowedHeaders = (allowedHeaders as string[]).join(','); // .headers is an array, so turn it into a string
  }
  if (allowedHeaders && allowedHeaders.length) {
    headers.push([{
      key: 'Access-Control-Allow-Headers',
      value: allowedHeaders
    }]);
  }

  return headers;
}

function configureExposedHeaders(options: CorsOptions): HeaderRecord | null {
  var headers = options.exposedHeaders;
  if (!headers) {
    return null;
  } else if ((headers as string[]).join) {
    headers = (headers as string[]).join(','); // .headers is an array, so turn it into a string
  }
  if (headers && headers.length) {
    return {
      key: 'Access-Control-Expose-Headers',
      value: headers
    };
  }
  return null;
}

function configureMaxAge(options: CorsOptions): HeaderRecord | null {
  var maxAge = (typeof options.maxAge === 'number' || options.maxAge) && (options.maxAge as number).toString()
  if (maxAge && maxAge.length) {
    return {
      key: 'Access-Control-Max-Age',
      value: maxAge
    };
  }
  return null;
}

function applyHeaders(headers: HeaderNode[], res: CorsResponse): void {
  for (var i = 0, n = headers.length; i < n; i++) {
    var header = headers[i];
    if (header) {
      if (Array.isArray(header)) {
        applyHeaders(header, res);
      } else if (header.key === 'Vary' && header.value) {
        vary(res, header.value as string);
      } else if (header.value) {
        res.setHeader(header.key, header.value);
      }
    }
  }
}

function cors(options: CorsOptions, req: CorsRequest, res: CorsResponse, next: NextFunction): void {
  var headers: HeaderNode[] = [],
    method = req.method && req.method.toUpperCase && req.method.toUpperCase();

  if (method === 'OPTIONS') {
    // preflight
    headers.push(configureOrigin(options, req));
    headers.push(configureCredentials(options))
    headers.push(configureMethods(options))
    headers.push(configureAllowedHeaders(options, req));
    headers.push(configureMaxAge(options))
    headers.push(configureExposedHeaders(options))
    applyHeaders(headers, res);

    if (options.preflightContinue) {
      next();
    } else {
      // Safari (and potentially other browsers) need content-length 0,
      //   for 204 or they just hang waiting for a body
      res.statusCode = options.optionsSuccessStatus;
      res.setHeader('Content-Length', '0');
      res.end();
    }
  } else {
    // actual response
    headers.push(configureOrigin(options, req));
    headers.push(configureCredentials(options))
    headers.push(configureExposedHeaders(options))
    applyHeaders(headers, res);
    next();
  }
}

function middlewareWrapper(o?: CorsOptions | CorsOptionsDelegate) {
  // if options are static (either via defaults or custom options passed in), wrap in a function
  var optionsCallback: CorsOptionsDelegate | null = null;
  if (typeof o === 'function') {
    optionsCallback = o as CorsOptionsDelegate;
  } else {
    optionsCallback = function (req, cb) {
      cb(null, o as CorsOptions);
    };
  }

  return function corsMiddleware(req: CorsRequest, res: CorsResponse, next: NextFunction): void {
    (optionsCallback as CorsOptionsDelegate)(req, function (err, options) {
      if (err) {
        next(err);
      } else {
        var corsOptions: CorsOptions = assign({}, defaults, options);
        var originCallback: CustomOrigin | null = null;
        if (corsOptions.origin && typeof corsOptions.origin === 'function') {
          originCallback = corsOptions.origin as CustomOrigin;
        } else if (corsOptions.origin) {
          originCallback = function (origin, cb) {
            cb(null, corsOptions.origin as OriginValue);
          };
        }

        if (originCallback) {
          originCallback(req.headers.origin as string | undefined, function (err2, origin) {
            if (err2 || !origin) {
              next(err2);
            } else {
              corsOptions.origin = origin;
              cors(corsOptions, req, res, next);
            }
          });
        } else {
          next();
        }
      }
    });
  };
}

// can pass either an options hash, an options delegate, or nothing
declare namespace middlewareWrapper {
  export {
    CorsOptions,
    CorsOptionsDelegate,
    CorsRequest,
    CorsResponse,
    CustomOrigin,
    OriginCallback,
    OriginValue
  };
}

export = middlewareWrapper;
