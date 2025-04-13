"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function handleToken(res, secret, name, t, verify, buildErr) {
  if (t.error) {
    res.status(401).end(t.error);
    return Promise.resolve({ error: t.error, end: true });
  }
  else {
    return verify(t.token, secret)
      .then(function (payload) {
      res.locals[name] = payload;
      return Promise.resolve({ payload: payload, token: t.token });
    })
      .catch(function (err) {
      var _a = buildErr(err), status = _a.status, body = _a.body;
      res.status(status).end(body);
      return Promise.resolve({ token: t.token, error: t.error, end: true });
    });
  }
}
exports.handleToken = handleToken;
function fromCookies(req, name) {
  if (!req.cookies) {
    return { token: "", error: "Require cookies" };
  }
  else {
    var token = req.cookies[name];
    if (!token) {
      return { token: "", error: "Require '" + name + "' in cookies" };
    }
    else {
      return { token: token };
    }
  }
}
exports.fromCookies = fromCookies;
function fromAuthorization(req, prefix) {
  var data = req.headers["authorization"];
  if (data) {
    if (!data.startsWith(prefix)) {
      return { token: "", error: "Authorization must start with '" + prefix.trim() + "'" };
    }
    else {
      var token = data.substring(prefix.length);
      return { token: token };
    }
  }
  else {
    return { token: "", error: "Require 'Authorization' in header" };
  }
}
exports.fromAuthorization = fromAuthorization;
var LocalsToken = (function () {
  function LocalsToken(token) {
    this.token = token ? token : "token";
    this.getToken = this.getToken.bind(this);
  }
  LocalsToken.prototype.getToken = function (req, res) {
    var payload = res.locals[this.token];
    return Promise.resolve({ payload: payload });
  };
  return LocalsToken;
}());
exports.LocalsToken = LocalsToken;
var CookiesToken = (function () {
  function CookiesToken(secret, verify, buildErr, payload, token) {
    this.secret = secret;
    this.verify = verify;
    this.token = token ? token : "token";
    this.payload = payload ? payload : "token";
    this.buildError = buildErr ? buildErr : buildError;
    this.getToken = this.getToken.bind(this);
  }
  CookiesToken.prototype.getToken = function (req, res) {
    var t = fromCookies(req, this.token);
    return handleToken(res, this.secret, this.payload, t, this.verify, this.buildError);
  };
  return CookiesToken;
}());
exports.CookiesToken = CookiesToken;
var AuthorizationToken = (function () {
  function AuthorizationToken(secret, verify, buildErr, payload, prefix) {
    this.secret = secret;
    this.verify = verify;
    this.prefix = prefix ? prefix : "Bearer ";
    this.payload = payload ? payload : "token";
    this.buildError = buildErr ? buildErr : buildError;
    this.getToken = this.getToken.bind(this);
  }
  AuthorizationToken.prototype.getToken = function (req, res) {
    var t = fromAuthorization(req, this.prefix);
    return handleToken(res, this.secret, this.payload, t, this.verify, this.buildError);
  };
  return AuthorizationToken;
}());
exports.AuthorizationToken = AuthorizationToken;
var TokenService = (function () {
  function TokenService(secret, verify, buildErr, payload, token, prefix) {
    this.secret = secret;
    this.verify = verify;
    this.prefix = prefix ? prefix : "Bearer ";
    this.token = token ? token : "token";
    this.payload = payload ? payload : "token";
    this.buildError = buildErr ? buildErr : buildError;
    this.getToken = this.getToken.bind(this);
  }
  TokenService.prototype.getToken = function (req, res) {
    var t = fromCookies(req, this.token);
    if (t.error) {
      t = fromAuthorization(req, this.prefix);
    }
    return handleToken(res, this.secret, this.payload, t, this.verify, this.buildError);
  };
  return TokenService;
}());
exports.TokenService = TokenService;
function useToken(secret, verify, buildErr, cookie, payload, token, prefix) {
  if (cookie === true) {
    return new CookiesToken(secret, verify, buildErr, payload, token).getToken;
  }
  else if (cookie === false) {
    return new AuthorizationToken(secret, verify, buildErr, payload, prefix).getToken;
  }
  else {
    return new TokenService(secret, verify, buildErr, payload, token, prefix).getToken;
  }
}
exports.useToken = useToken;
exports.getToken = useToken;
var Handler = (function () {
  function Handler(secret, verify, prefix, token, payload) {
    this.secret = secret;
    this.verify = verify;
    this.prefix = prefix ? prefix : "Bearer ";
    this.token = token ? token : "token";
    this.payload = payload ? payload : "token";
    this.handle = this.handle.bind(this);
  }
  Handler.prototype.handle = function () {
    var _this = this;
    return function (req, res, next) {
      var t = fromCookies(req, _this.token);
      if (t.error) {
        t = fromAuthorization(req, _this.prefix);
      }
      if (t.error) {
        next();
      }
      else {
        _this.verify(t.token, _this.secret)
          .then(function (payload) {
          res.locals[_this.payload] = payload;
          next();
        })
          .catch(function (err) {
          next();
        });
      }
    };
  };
  return Handler;
}());
exports.Handler = Handler;
exports.AuthorizationHandler = Handler;
var AuthorizationChecker = (function () {
  function AuthorizationChecker(gt) {
    this.getToken = gt;
    this.check = this.check.bind(this);
    this.require = this.require.bind(this);
  }
  AuthorizationChecker.prototype.require = function () {
    var _this = this;
    return function (req, res, next) {
      _this.getToken(req, res).then(function (t) {
        if (!t.end) {
          next();
        }
      });
    };
  };
  AuthorizationChecker.prototype.check = function () {
    return this.require();
  };
  return AuthorizationChecker;
}());
exports.AuthorizationChecker = AuthorizationChecker;
function exist(obj, arr) {
  if (Array.isArray(obj)) {
    for (var _i = 0, obj_1 = obj; _i < obj_1.length; _i++) {
      var o = obj_1[_i];
      for (var _a = 0, arr_1 = arr; _a < arr_1.length; _a++) {
        var v = arr_1[_a];
        if (o == v) {
          return true;
        }
      }
    }
  }
  else {
    for (var _b = 0, arr_2 = arr; _b < arr_2.length; _b++) {
      var v = arr_2[_b];
      if (obj == v) {
        return true;
      }
    }
  }
  return false;
}
exports.exist = exist;
var Checker = (function () {
  function Checker(gt, key) {
    this.getToken = gt;
    this.key = key ? key : "id";
    this.check = this.check.bind(this);
  }
  Checker.prototype.check = function (v) {
    var _this = this;
    return function (req, res, next) {
      _this.getToken(req, res).then(function (t) {
        if (!t.end) {
          if (t.payload) {
            var obj = t.payload[_this.key];
            if (!obj) {
              res.status(403).end("Payload must contain " + _this.key);
            }
            else {
              if (exist(obj, v)) {
                next();
              }
              else {
                res.status(403).end("invalid " + _this.key);
              }
            }
          }
          else {
            res.status(403).end("Payload cannot be undefined");
          }
        }
      });
    };
  };
  return Checker;
}());
exports.Checker = Checker;
var Authorizer = (function () {
  function Authorizer(gt, privilege, buildErr, exact, payloadId, userId, permissions) {
    this.privilege = privilege;
    this.getToken = gt;
    this.buildError = buildErr ? buildErr : buildError;
    this.payloadId = payloadId ? payloadId : "id";
    this.userId = userId ? userId : "userId";
    this.permissions = permissions ? permissions : "permissions";
    this.exact = exact !== undefined ? exact : true;
    this.authorize = this.authorize.bind(this);
  }
  Authorizer.prototype.authorize = function (privilege, action) {
    var _this = this;
    return function (req, res, next) {
      _this.getToken(req, res).then(function (t) {
        if (!t.end) {
          var payload = t.payload;
          if (payload === undefined) {
            res.status(401).end("Payload cannot be undefined");
          }
          else {
            var userId_1 = payload[_this.payloadId];
            if (!userId_1) {
              res.status(403).end("Payload must contain " + _this.payloadId);
            }
            else {
              _this.privilege(userId_1, privilege)
                .then(function (p) {
                if (p === exports.none) {
                  res.status(403).end("no permission for " + userId_1);
                }
                else {
                  res.locals[_this.userId] = userId_1;
                  res.locals[_this.permissions] = p;
                  if (!action) {
                    next();
                  }
                  else {
                    if (_this.exact) {
                      var sum = action & p;
                      if (sum === action) {
                        return next();
                      }
                      else {
                        res.status(403).end("no permission");
                      }
                    }
                    else {
                      if (p >= action) {
                        return next();
                      }
                      else {
                        res.status(403).end("no permission");
                      }
                    }
                  }
                }
              })
                .catch(function (err) {
                var _a = _this.buildError(err), status = _a.status, body = _a.body;
                res.status(status).end(body);
              });
            }
          }
        }
      });
    };
  };
  return Authorizer;
}());
exports.Authorizer = Authorizer;
exports.none = 0;
exports.read = 1;
exports.write = 2;
exports.approve = 4;
exports.all = 2147483647;
var PrivilegeLoader = (function () {
  function PrivilegeLoader(sql, query) {
    this.sql = sql;
    this.query = query;
    this.privilege = this.privilege.bind(this);
  }
  PrivilegeLoader.prototype.privilege = function (userId, privilegeId) {
    return this.query(this.sql, [userId, privilegeId]).then(function (v) {
      if (!v || v.length === 0) {
        return exports.none;
      }
      var keys = Object.keys(v[0]);
      if (keys.length === 0) {
        return exports.all;
      }
      var k = keys[0];
      var permissions = 0;
      var ok = false;
      for (var _i = 0, v_1 = v; _i < v_1.length; _i++) {
        var p = v_1[_i];
        var x = p[k];
        if (typeof x === "number") {
          permissions = permissions | x;
          ok = true;
        }
      }
      return ok ? permissions : exports.all;
    });
  };
  return PrivilegeLoader;
}());
exports.PrivilegeLoader = PrivilegeLoader;
function buildError(err) {
  return { status: 401, body: "Invalid token: " + toString(err) };
}
exports.buildError = buildError;
function toString(err) {
  return typeof err === "string" ? err : JSON.stringify(err);
}
exports.toString = toString;
function get(app, path, authorize, handle, secure) {
  if (secure) {
    app.get(path, authorize, handle);
  }
  else {
    app.get(path, handle);
  }
}
exports.get = get;
function post(app, path, authorize, handle, secure) {
  if (secure) {
    app.post(path, authorize, handle);
  }
  else {
    app.post(path, handle);
  }
}
exports.post = post;
function put(app, path, authorize, handle, secure) {
  if (secure) {
    app.put(path, authorize, handle);
  }
  else {
    app.put(path, handle);
  }
}
exports.put = put;
function patch(app, path, authorize, handle, secure) {
  if (secure) {
    app.patch(path, authorize, handle);
  }
  else {
    app.patch(path, handle);
  }
}
exports.patch = patch;
function del(app, path, authorize, handle, secure) {
  if (secure) {
    app.delete(path, authorize, handle);
  }
  else {
    app.delete(path, handle);
  }
}
exports.del = del;
