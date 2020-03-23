var crypto = require('crypto');
var oauth_sign = require('oauth-sign');
var querystring = require('querystring');
var request = require('request');

module.exports = exports = function(options)
{
    // Options
    // {
    //      "useSandbox" : true | false, // default is true
    //      "key" : key,
    //      "secret" : secret
    // }

    if (arguments.length != 1 || typeof options != "object")
        throw Error("The etrade module requires an options block object parameter");
    if (!options.hasOwnProperty("key"))
        throw Error("The etrade module requires specification of an API key");
    if (!options.hasOwnProperty("secret"))
        throw Error("The etrade module requires specification of an API secret");
    if (!options.hasOwnProperty("useSandbox"))
        options.useSandbox = true;

    var configurations =
    {
            "base" : {
                "multi_user": false,
                "oauth" : {
                    "host" : "api.etrade.com",
                    "token" : "",
                    "secret" : "",
                    "code" : "",
                    "request_token" : "",
                    "access_token" : "",
                    "access_token_secret" : ""
                },
                "authorize" : {
                    "host" : "api.etrade.com",
                    "path" : "/oauth/request_token",
                    "login": "/home",
                },
                "pushURL" : "https://etwspushsb.etrade.com/apistream/cometd/oauth/",
                "getHostname" : function(module) {
                    return module == "oauth" ? this.oauth.host : this.host;
                }
            },
            "production" : {
                "host" : "api.etrade.com",
                "buildPath" : function(module,action) {
                    //return "/" + module + (module == "oauth" ? "/" : "/rest/") + action;
                    //return "/v1/" + module + (module == "oauth" ? "/" : "/") + action;
                    return (module == "oauth" ? "/" : "/v1/") + module + "/" + action;
                }
            },
            "sandbox" : {
                "host" : "apisb.etrade.com",
                "buildPath" : function(module,action) {
                    //return "/v1/" + module + (module == "oauth" ? "/" : "/") + action;
                    //return "/" + module + (module == "oauth" ? "/" : "/sandbox/rest/") + action;
                    return (module == "oauth" ? "/" : "/v1/") + module + "/" + action;
                }
            },
    };

    this.configuration = configurations.base;

    if (options.useSandbox)
    {
        for (var attrname in configurations.sandbox)
        {
            this.configuration[attrname] = configurations.sandbox[attrname];
        }
    }
    else
    {
        for (var attrname in configurations.production)
        {
            this.configuration[attrname] = configurations.production[attrname];
        }
    }

    this.configuration.multi_user = options.multiUser || false;
    this.configuration.key = options.key;
    this.configuration.secret = options.secret;
    this.authorized = false;

    this.crypto = crypto;
    this.oauth_sign = oauth_sign;
    this.querystring = querystring;
    this.request = request;
};

// Import module functions (these make up the public API of the E*TRADE client)

//Etrade modules
var modules = [require('./authorization.js'),
               require('./accounts.js'),
               require('./market.js'),
               require('./order.js')]; // List of E*TRADE modules
for (var moduleIndex = 0; moduleIndex < modules.length; ++moduleIndex)
    for (var funcName in modules[moduleIndex])
        exports.prototype[funcName] = modules[moduleIndex][funcName];

exports.prototype._getRequestOptions = function(method, timeStamp, module, action, useJSON)
{
    return {
        url : "https://" + this.configuration.getHostname(module) +
              this.configuration.buildPath(module,action) +
              (useJSON ? ".json" : ""),
        method : method,
        qs : {
            oauth_consumer_key : this.configuration.key,
            oauth_nonce : this._generateNonceFor(timeStamp),
            oauth_signature_method : "HMAC-SHA1",
            oauth_timestamp : Math.floor(timeStamp.getTime()/1000),
            oauth_version : "1.0" // Yes, needs to be a string (otherwise gets truncated)
        },
        headers : {},
    };
};

exports.prototype._generateNonceFor = function(timeStamp)
{
    var msSinceEpoch = timeStamp.getTime();

    var secondsSinceEpoch = Math.floor(msSinceEpoch / 1000.0);
    var msSinceSecond = (msSinceEpoch - (secondsSinceEpoch*1000)) / 1000.0;

    var maxRand = 2147483647.0;  // This constant comes from PHP, IIRC
    var rand = Math.round(Math.random() * maxRand);

    var microtimeString = "" + msSinceSecond + "00000 " + secondsSinceEpoch;
    var nonce = microtimeString + rand;

    var md5Hash = crypto.createHash('md5');
    md5Hash.update(nonce);
    return md5Hash.digest('hex');
};

exports.prototype._parseBody = function(contentType,body)
{
    var contentTypes = {
            "application/x-www-form-urlencoded" : function(body)
            {
                return querystring.parse(body);
            },
            "application/json" : function(body)
            {
                return JSON.parse(body);
            },
            "text/html" : function(body)
            {
                return body; // Ugh.  Remove this content type after debugging...
            },
            "application/xml" : function(body)
            {
                return body;
            }
    };
    contentType = contentType.split(";")[0];

    if (typeof(contentTypes[contentType]) == 'function')
    {
        return contentTypes[contentType](body);
    }
    else
    {
        throw "Unrecognized content type: " + contentType + "\nbody:" + body;
    }
};

exports.prototype._buildParamsDescriptor = function(paramsDescriptorArray)
{
    var paramsDescriptor = [];
    for (var index = 0; index < paramsDescriptorArray.length;)
    {
        var name = paramsDescriptorArray[index];
        var required = paramsDescriptorArray[index+1];
        var validator = paramsDescriptorArray[index+2];

        if (typeof(name) != "string") throw "Invalid 'name' in ParamsDescriptor!";
        else if (typeof(required) != "boolean" && typeof(required) != "function")
            throw "Invalid 'required' in ParamsDescriptor!";
        else if (typeof(validator) != "function")
            throw "Invalid 'validator' in ParamsDescriptor!";

        index += 3;

        paramsDescriptor.push({ name:name, required:required, validator:validator });
    }

    return paramsDescriptor;
};

exports.prototype._validateAsString = function(val)
{
    return { valid:true, value:String(val)};
};

exports.prototype._validateAsBool = function(val)
{
    return { valid:(typeof(val) == "Boolean"), value:Boolean(val) };
};

exports.prototype._validateAsInt = function(val)
{
    var newVal = parseInt(val);
    return { valid:!isNaN(newVal), value:newVal};
};

exports.prototype._validateAsFloat = function(val)
{
    var newVal = parseFloat(val);
    return { valid:!isNaN(newVal), value:val };
};

exports.prototype._validateAsMMDDYYYYDate = function(val)
{
    var regex = /^[01][0-9][0123][0-9][0-9]{4}$/; // Not a true date validation, but gets close
    return { valid:regex.test(val), value:val };
};

exports.prototype._validateAsOneOf = function(val,permittedValues)
{
    if (arguments.length < 2) // Simplifies usage of this validator
        return function(v) { return this._validateAsOneOf(v,val); }.bind(this);

    var valid = false;
    for (var index = 0; index < permittedValues.length && !valid; ++index)
        valid = (val == permittedValues[index]);
    return { valid:valid, value:val };
};

exports.prototype._validateAsComplex = function(paramsDescriptor)
{
    return function(params)
    {
    	// Is this right?  Why does this depart from the { valid:bool, value:val } paradigm everywhere else?
        var validationResult = this._validateParams(paramsDescriptor,params);
        if (validationResult.length) return "Complex Validation Failure: " + validationResult;
        else return "";
    }.bind(this);
};

exports.prototype._validateParams = function(paramsDescriptor,params)
{
    for (var paramDescriptor in paramsDescriptor)
    {
        var name = paramDescriptor.name;
        var isParamRequired = typeof paramDescriptor == "function" ?
                                 paramDescriptor.required(params) :
                                 paramDescriptor.required;
        var isParamPresent = name in params;
        if (isParamRequired && !isParamPresent)
        {
            return "Request parameter '" + name + "' not provided by user";
        }
        else if (isParamPresent)
        {
            var validationResult = paramDescriptor.validator(params[name]);
            if (validationResult.valid)
            {
                params[name] = validationResult.value;
            }
            else
            {
                return "Request parameter '" + name + "' failed client-side validation check";
            }
        }
    }

    return "";
};

exports.prototype._getAuthorizationHeaderFor = function(requestOptions, oauth_access_token_secret)
{
    // Sign the request
    var oauth_signature = this.oauth_sign.hmacsign(requestOptions.method,requestOptions.url,
                                                    requestOptions.qs,
                                                    this.configuration.secret,
                                                    oauth_access_token_secret);
    // From: http://tools.ietf.org/html/rfc5849
    // Authorization: OAuth realm="Example",
    //                oauth_consumer_key="9djdj82h48djs9d2",
    //                oauth_token="kkk9d7dh3k39sjv7",
    //                oauth_signature_method="HMAC-SHA1",
    //                oauth_timestamp="137131201",
    //                oauth_nonce="7d8f3e4a",
    //                oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
    //
    // Sample from: http://oauth.googlecode.com/svn/code/javascript/example/signature.html
    // OAuth realm="",oauth_version="1.0",oauth_consumer_key="abcd",oauth_token="ijkl",oauth_timestamp="1396481619",oauth_nonce="2HL9hcG4R2r",oauth_signature_method="HMAC-SHA1",oauth_signature="uIDIOWJapuMFBXluGCGHcjePIcM%3D"
    return "OAuth realm=\"\"," +
            "oauth_version=\"" + encodeURIComponent(requestOptions.qs.oauth_version) + "\"," +
            "oauth_consumer_key=\"" + encodeURIComponent(requestOptions.qs.oauth_consumer_key) +"\"," +
            "oauth_token=\"" + encodeURIComponent(requestOptions.qs.oauth_token) + "\"," +
            "oauth_timestamp=\"" + encodeURIComponent(requestOptions.qs.oauth_timestamp) + "\"," +
            "oauth_nonce=\"" + encodeURIComponent(requestOptions.qs.oauth_nonce) + "\"," +
            "oauth_signature_method=\"" + encodeURIComponent(requestOptions.qs.oauth_signature_method) + "\"," +
            "oauth_signature=\"" + encodeURIComponent(oauth_signature) + "\"";
};

exports.prototype._run = function(actionDescriptor, params, token, callback)
{
    //console.log('Running E*Trade For:', actionDescriptor, params, token)
    if (typeof(params) === "function") {
        callback = params;
        params = {};
        token = '';
    }

    if (typeof(token) === "function") {
        callback = token;
        token = '';
    }

    if (typeof(token) === "function" && typeof(params) === "string") {
        callback = token;
        token = params;
        params = {};
    }

    if (typeof(token) !== "string") {
        throw "Token must be a string";
    }

    if (typeof(callback) != "function")
        throw "callback is not a function!";

    if (!(this.authorized || token))
        return callback("Please authorize or pass in an access token!");

    //console.log('******ETRADE TOKEN NOW', token)
    const tokenArr = token.split(':');
    token = tokenArr[0];
    var secret = tokenArr[1];
    //console.log('******ETRADE TOKEN:', token, 'SECRET', secret)

    // Generate the options for the request module
    var requestOptions = this._getRequestOptions(actionDescriptor.method,
                                                  new Date(),
                                                  actionDescriptor.module,
                                                  actionDescriptor.action,
                                                  actionDescriptor.useJSON);
                                          
    // Add our token
    //requestOptions.qs.oauth_token = this.configuration.oauth.access_token || token;

    requestOptions.qs.oauth_token = token
    if (actionDescriptor.method == "GET")
    {
        // Add this call's query parameters
        for (var paramName in params)
            requestOptions.qs[paramName] = params[paramName];

        //console.log('------------------------------------')
        //console.log('Request options and secret for E*Trade Header:', requestOptions, secret)
        requestOptions.headers["Authorization"] = this._getAuthorizationHeaderFor(requestOptions, secret);
        //console.log('Authorization E*Trade Header:', requestOptions.headers["Authorization"])
        // Override query string with just the query params
        requestOptions.qs = params;
        //console.log('Request Options now E*Trade:', params)
    }
    else if (actionDescriptor.method == "POST" || actionDescriptor.method == "DELETE")
    {
        // Specify the content type for POST requests
        if (actionDescriptor.method == "POST") {
            if (actionDescriptor.useXML) {
                requestOptions.headers["Content-Type"] = "application/xml";
            } else {
                requestOptions.headers["Content-Type"] = actionDescriptor.useJSON ?
                                                            "application/json" :
                                                            "application/x-www-form-urlencoded";
            }
        }

        requestOptions.headers["Authorization"] = this._getAuthorizationHeaderFor(requestOptions, secret);

        //console.log("Authorization: " + requestOptions.headers["Authorization"]);

        requestOptions.qs = {}; // Clear query string (we don't use it in POST requests)

        if (actionDescriptor.method == "POST") {
            if (actionDescriptor.useXML) {
                requestOptions.body = params
            } else {
                requestOptions.body = actionDescriptor.useJSON ?
                                        JSON.stringify(params) :
                                        querystring.stringify(params);
            }
        }
    }

    // Make the request
    var qs = querystring.stringify(requestOptions.qs);
    console.log("Request: [" + requestOptions.method + "]: " + requestOptions.url + (qs.length ? "?" + qs : ""));
    this.request(requestOptions,function(error,message,body)
    {
        if (error)
        {
            console.error("Error received in etrade::_run(): " + error);
            callback(error);
        }
        else if (message.statusCode != 200)
        {
            var msg = { body:body, httpVersion:message.httpVersion,
                        headers:message.headers, statusCode:message.statusCode };

            callback("E*TRADE responded with a non-OK HTTP status code: " + JSON.stringify(msg, null, 2));
        }
        else
        {
            var response = this._parseBody(message.headers["content-type"],body);
            callback(null, response);
        }
    }.bind(this));
};
