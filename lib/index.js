"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Handler = (function () {
  function Handler(secret, verify, buildErr, prefix, token) {
    this.secret = secret;
    this.verify = verify;
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.token = (token ? token : 'token');
    this.handle = this.handle.bind(this);
  }
  Handler.prototype.handle = function () {
    var _this = this;
    return function (req, res, next) {
      var data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(_this.prefix)) {
          res.status(401).end("Authorization must start with '" + _this.prefix.trim() + "'");
        }
        else {
          var token = data.substr(_this.prefix.length);
          _this.verify(token, _this.secret).then(function (payload) {
            res.locals[_this.token] = payload;
            next();
          }).catch(function (err) {
            var _a = _this.buildError(err), status = _a.status, body = _a.body;
            res.status(status).end(body);
          });
        }
      }
      else {
        next();
      }
    };
  };
  return Handler;
}());
exports.Handler = Handler;
exports.AuthorizationHandler = Handler;
var AuthorizationChecker = (function () {
  function AuthorizationChecker(secret, verify, buildErr, prefix, token) {
    this.secret = secret;
    this.verify = verify;
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.token = (token ? token : 'token');
    this.check = this.check.bind(this);
    this.require = this.require.bind(this);
  }
  AuthorizationChecker.prototype.require = function () {
    var _this = this;
    return function (req, res, next) {
      var data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(_this.prefix)) {
          res.status(401).end("Authorization must start with '" + _this.prefix.trim() + "'");
        }
        else {
          var token = data.substr(_this.prefix.length);
          _this.verify(token, _this.secret).then(function (payload) {
            res.locals[_this.token] = payload;
            next();
          }).catch(function (err) {
            var _a = _this.buildError(err), status = _a.status, body = _a.body;
            res.status(status).end(body);
          });
        }
      }
      else {
        res.status(401).end("Require 'Authorization' in header");
      }
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
var QuickChecker = (function () {
  function QuickChecker(key, buildErr, token) {
    this.buildError = (buildErr ? buildErr : buildError);
    this.key = (key ? key : 'userId');
    this.token = (token ? token : 'token');
    this.check = this.check.bind(this);
  }
  QuickChecker.prototype.check = function (v) {
    var _this = this;
    return function (req, res, next) {
      var payload = res.locals[_this.token];
      if (!payload) {
        res.status(401).end('Payload cannot be undefined');
      }
      else {
        var obj = payload[_this.key];
        if (!obj) {
          res.status(403).end('Payload must contain ' + _this.key);
        }
        else {
          if (exist(obj, v)) {
            next();
          }
          else {
            res.status(403).end('invalid ' + _this.key);
          }
        }
      }
    };
  };
  return QuickChecker;
}());
exports.QuickChecker = QuickChecker;
var Checker = (function () {
  function Checker(secret, verify, buildErr, key, prefix, token) {
    this.secret = secret;
    this.verify = verify;
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.key = (key ? key : 'userId');
    this.token = (token ? token : 'token');
    this.check = this.check.bind(this);
  }
  Checker.prototype.check = function (v) {
    var _this = this;
    return function (req, res, next) {
      var data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(_this.prefix)) {
          res.status(401).end("Authorization must start with '" + _this.prefix.trim() + "'");
        }
        else {
          var token = data.substr(_this.prefix.length);
          _this.verify(token, _this.secret).then(function (payload) {
            if (payload === undefined) {
              res.status(401).end('Payload cannot be undefined');
            }
            else {
              res.locals[_this.token] = payload;
              var obj = payload[_this.key];
              if (!obj) {
                res.status(403).end('Payload must contain ' + _this.key);
              }
              else {
                if (exist(obj, v)) {
                  next();
                }
                else {
                  res.status(403).end('invalid ' + _this.key);
                }
              }
            }
          }).catch(function (err) {
            var _a = _this.buildError(err), status = _a.status, body = _a.body;
            res.status(status).end(body);
          });
        }
      }
      else {
        res.status(401).end("Require 'Authorization' in header");
      }
    };
  };
  return Checker;
}());
exports.Checker = Checker;
var MultiAuthorizer = (function () {
  function MultiAuthorizer(secret, verify, privilege, buildErr, key, exact, user, prefix, token) {
    this.secret = secret;
    this.verify = verify;
    this.privilege = privilege;
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.user = (user ? user : 'userId');
    this.key = (key ? key : 'userType');
    this.token = (token ? token : 'token');
    this.exact = (exact !== undefined ? exact : true);
    this.authorize = this.authorize.bind(this);
  }
  MultiAuthorizer.prototype.authorize = function (v, privilege, action) {
    var _this = this;
    return function (req, res, next) {
      var data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(_this.prefix)) {
          res.status(401).end("Authorization must start with '" + _this.prefix.trim() + "'");
        }
        else {
          var token = data.substr(_this.prefix.length);
          _this.verify(token, _this.secret).then(function (payload) {
            if (payload === undefined) {
              res.status(401).end('Payload cannot be undefined');
            }
            else {
              res.locals[_this.token] = payload;
              var obj = payload[_this.key];
              if (!obj) {
                res.status(403).end('Payload must contain ' + _this.key);
              }
              else {
                if (!exist(obj, v)) {
                  res.status(403).end('invalid ' + _this.key);
                }
                else {
                  var userId_1 = payload[_this.user];
                  if (!userId_1) {
                    res.status(403).end('Payload must contain ' + _this.user);
                  }
                  else {
                    _this.privilege(userId_1, privilege).then(function (p) {
                      if (p === exports.none) {
                        res.status(403).end('no permission for ' + userId_1);
                      }
                      else {
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
                              res.status(403).end('no permission');
                            }
                          }
                          else {
                            if (p >= action) {
                              return next();
                            }
                            else {
                              res.status(403).end('no permission');
                            }
                          }
                        }
                      }
                    }).catch(function (err) {
                      var _a = _this.buildError(err), status = _a.status, body = _a.body;
                      res.status(status).end(body);
                    });
                  }
                }
              }
            }
          }).catch(function (err) {
            var _a = _this.buildError(err), status = _a.status, body = _a.body;
            res.status(status).end(body);
          });
        }
      }
      else {
        res.status(401).end("Require 'Authorization' in header");
      }
    };
  };
  return MultiAuthorizer;
}());
exports.MultiAuthorizer = MultiAuthorizer;
var Authorizer = (function () {
  function Authorizer(secret, verify, privilege, buildErr, exact, key, prefix, token) {
    this.secret = secret;
    this.verify = verify;
    this.privilege = privilege;
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.key = (key ? key : 'userId');
    this.token = (token ? token : 'token');
    this.exact = (exact !== undefined ? exact : true);
    this.authorize = this.authorize.bind(this);
  }
  Authorizer.prototype.authorize = function (privilege, action) {
    var _this = this;
    return function (req, res, next) {
      var data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(_this.prefix)) {
          res.status(401).end("Authorization must start with '" + _this.prefix.trim() + "'");
        }
        else {
          var token = data.substr(_this.prefix.length);
          _this.verify(token, _this.secret).then(function (payload) {
            if (payload === undefined) {
              res.status(401).end('Payload cannot be undefined');
            }
            else {
              res.locals[_this.token] = payload;
              var userId_2 = payload[_this.key];
              if (!userId_2) {
                res.status(403).end('Payload must contain ' + _this.key);
              }
              else {
                _this.privilege(userId_2, privilege).then(function (p) {
                  if (p === exports.none) {
                    res.status(403).end('no permission for ' + userId_2);
                  }
                  else {
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
                          res.status(403).end('no permission');
                        }
                      }
                      else {
                        if (p >= action) {
                          return next();
                        }
                        else {
                          res.status(403).end('no permission');
                        }
                      }
                    }
                  }
                }).catch(function (err) {
                  var _a = _this.buildError(err), status = _a.status, body = _a.body;
                  res.status(status).end(body);
                });
              }
            }
          }).catch(function (err) {
            var _a = _this.buildError(err), status = _a.status, body = _a.body;
            res.status(status).end(body);
          });
        }
      }
      else {
        res.status(401).end("Require 'Authorization' in header");
      }
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
        if (typeof x === 'number') {
          permissions = permissions | x;
          ok = true;
        }
      }
      return (ok ? permissions : exports.all);
    });
  };
  return PrivilegeLoader;
}());
exports.PrivilegeLoader = PrivilegeLoader;
function buildError(err) {
  return { status: 401, body: 'Invalid token: ' + toString(err) };
}
exports.buildError = buildError;
function toString(err) {
  return (typeof err === 'string' ? err : JSON.stringify(err));
}
exports.toString = toString;
