import { NextFunction, Request, Response } from 'express';

export type Handle = (req: Request, res: Response, next: NextFunction) => void;
export type Authorize = (privilege: string, action?: number) => Handle;
export type MultiAuthorize<T> = (v: T[], privilege: string, action?: number) => Handle;
export type Authorizes<T> = (v: T[], privilege: string, action?: number) => Handle;
export type Check<T> = (v: T[]) => Handle;
export interface Token {
  secret: string;
  expires: number;
}
export interface TokenConfig {
  secret: string;
  expires: number;
}
export interface StatusError {
  status: number;
  body: string;
}
export class Handler<P> {
  buildError: (err: any) => StatusError;
  prefix: string;
  token: string;
  constructor(public secret: string, public verify: (token: string, secret: string) => Promise<P>, buildErr?: (err: any) => StatusError, prefix?: string, token?: string) {
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.token = (token ? token : 'token');
    this.handle = this.handle.bind(this);
  }
  handle(): (req: Request, res: Response, next: NextFunction) => void {
    return (req: Request, res: Response, next: NextFunction) => {
      const data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(this.prefix)) {
          res.status(401).end(`Authorization must start with '${this.prefix.trim()}'`);
        } else {
          const token = data.substr(this.prefix.length);
          this.verify(token, this.secret).then(payload => {
            res.locals[this.token] = payload;
            next();
          }).catch(err => {
            const { status, body } = this.buildError(err);
            res.status(status).end(body);
          });
        }
      } else {
        next();
      }
    };
  }
}
export const AuthorizationHandler = Handler;
// tslint:disable-next-line:max-classes-per-file
export class AuthorizationChecker<P> {
  buildError: (err: any) => StatusError;
  prefix: string;
  token: string;
  constructor(public secret: string, public verify: (token: string, secret: string) => Promise<P>, buildErr?: (err: any) => StatusError, prefix?: string, token?: string) {
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.token = (token ? token : 'token');
    this.check = this.check.bind(this);
    this.require = this.require.bind(this);
  }
  require(): Handle {
    return (req: Request, res: Response, next: NextFunction) => {
      const data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(this.prefix)) {
          res.status(401).end(`Authorization must start with '${this.prefix.trim()}'`);
        } else {
          const token = data.substr(this.prefix.length);
          this.verify(token, this.secret).then(payload => {
            res.locals[this.token] = payload;
            next();
          }).catch(err => {
            const { status, body } = this.buildError(err);
            res.status(status).end(body);
          });
        }
      } else {
        res.status(401).end(`Require 'Authorization' in header`);
      }
    };
  }
  check(): Handle {
    return this.require();
  }
}
export function exist<T>(obj: T | T[], arr: T[]): boolean {
  if (Array.isArray(obj)) {
    for (const o of obj) {
      for (const v of arr) {
        // tslint:disable-next-line:triple-equals
        if (o == v) {
          return true;
        }
      }
    }
  } else {
    for (const v of arr) {
      // tslint:disable-next-line:triple-equals
      if (obj == v) {
        return true;
      }
    }
  }
  return false;
}
// tslint:disable-next-line:max-classes-per-file
export class QuickChecker<T> {
  buildError: (err: any) => StatusError;
  key: string;
  token: string;
  constructor(key?: string, buildErr?: (err: any) => StatusError, token?: string) {
    this.buildError = (buildErr ? buildErr : buildError);
    this.key = (key ? key : 'userId');
    this.token = (token ? token : 'token');
    this.check = this.check.bind(this);
  }
  check(v: T[]): Handle {
    return (req: Request, res: Response, next: NextFunction) => {
      const payload: any = res.locals[this.token];
      if (!payload) {
        res.status(401).end('Payload cannot be undefined');
      } else {
        const obj = (payload as any)[this.key];
        if (!obj) {
          res.status(403).end('Payload must contain ' + this.key);
        } else {
          if (exist<T>(obj as any, v)) {
            next();
          } else {
            res.status(403).end('invalid ' + this.key);
          }
        }
      }
    };
  }
}
// tslint:disable-next-line:max-classes-per-file
export class Checker<T, P> {
  buildError: (err: any) => StatusError;
  key: string;
  prefix: string;
  token: string;
  constructor(public secret: string, public verify: (token: string, secret: string) => Promise<P>, buildErr?: (err: any) => StatusError, key?: string, prefix?: string, token?: string) {
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.key = (key ? key : 'userId');
    this.token = (token ? token : 'token');
    this.check = this.check.bind(this);
  }
  check(v: T[]): Handle {
    return (req: Request, res: Response, next: NextFunction) => {
      const data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(this.prefix)) {
          res.status(401).end(`Authorization must start with '${this.prefix.trim()}'`);
        } else {
          const token = data.substr(this.prefix.length);
          this.verify(token, this.secret).then(payload => {
            if (payload === undefined) {
              res.status(401).end('Payload cannot be undefined');
            } else {
              res.locals[this.token] = payload;
              const obj = (payload as any)[this.key];
              if (!obj) {
                res.status(403).end('Payload must contain ' + this.key);
              } else {
                if (exist<T>(obj as any, v)) {
                  next();
                } else {
                  res.status(403).end('invalid ' + this.key);
                }
              }
            }
          }).catch(err => {
            const { status, body } = this.buildError(err);
            res.status(status).end(body);
          });
        }
      } else {
        res.status(401).end(`Require 'Authorization' in header`);
      }
    };
  }
}
// tslint:disable-next-line:max-classes-per-file
export class MultiAuthorizer<T, P> {
  buildError: (err: any) => StatusError;
  user: string;
  key: string;
  prefix: string;
  exact: boolean;
  token: string;
  constructor(public secret: string, public verify: (token: string, secret: string) => Promise<P>, public privilege: (userId: string, privilegeId: string) => Promise<number>, buildErr?: (err: any) => StatusError, key?: string, exact?: boolean, user?: string, prefix?: string, token?: string) {
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.user = (user ? user : 'userId');
    this.key = (key ? key : 'userType');
    this.token = (token ? token : 'token');
    this.exact = (exact !== undefined ? exact : true);
    this.authorize = this.authorize.bind(this);
  }
  authorize(v: T[], privilege: string, action?: number): Handle {
    return (req: Request, res: Response, next: NextFunction) => {
      const data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(this.prefix)) {
          res.status(401).end(`Authorization must start with '${this.prefix.trim()}'`);
        } else {
          const token = data.substr(this.prefix.length);
          this.verify(token, this.secret).then(payload => {
            if (payload === undefined) {
              res.status(401).end('Payload cannot be undefined');
            } else {
              res.locals[this.token] = payload;
              const obj = (payload as any)[this.key];
              if (!obj) {
                res.status(403).end('Payload must contain ' + this.key);
              } else {
                if (!exist<T>(obj as any, v)) {
                  res.status(403).end('invalid ' + this.key);
                } else {
                  const userId = (payload as any)[this.user];
                  if (!userId) {
                    res.status(403).end('Payload must contain ' + this.user);
                  } else {
                    this.privilege(userId, privilege).then(p => {
                      if (p === none) {
                        res.status(403).end('no permission for ' + userId);
                      } else {
                        if (!action) {
                          next();
                        } else {
                          if (this.exact) {
                            // tslint:disable-next-line:no-bitwise
                            const sum = action & p;
                            if (sum === action) {
                              return next();
                            } else {
                              res.status(403).end('no permission');
                            }
                          } else {
                            if (p >= action) {
                              return next();
                            } else {
                              res.status(403).end('no permission');
                            }
                          }
                        }
                      }
                    }).catch(err => {
                      const { status, body } = this.buildError(err);
                      res.status(status).end(body);
                    });
                  }
                }
              }
            }
          }).catch(err => {
            const { status, body } = this.buildError(err);
            res.status(status).end(body);
          });
        }
      } else {
        res.status(401).end(`Require 'Authorization' in header`);
      }
    };
  }
}
// tslint:disable-next-line:max-classes-per-file
export class Authorizer<P> {
  buildError: (err: any) => StatusError;
  key: string;
  prefix: string;
  exact: boolean;
  token: string;
  constructor(public secret: string, public verify: (token: string, secret: string) => Promise<P>, public privilege: (userId: string, privilegeId: string) => Promise<number>, buildErr?: (err: any) => StatusError, exact?: boolean, key?: string, prefix?: string, token?: string) {
    this.buildError = (buildErr ? buildErr : buildError);
    this.prefix = (prefix ? prefix : 'Bearer ');
    this.key = (key ? key : 'userId');
    this.token = (token ? token : 'token');
    this.exact = (exact !== undefined ? exact : true);
    this.authorize = this.authorize.bind(this);
  }
  authorize(privilege: string, action?: number): Handle {
    return (req: Request, res: Response, next: NextFunction) => {
      const data = req.headers['authorization'];
      if (data) {
        if (!data.startsWith(this.prefix)) {
          res.status(401).end(`Authorization must start with '${this.prefix.trim()}'`);
        } else {
          const token = data.substr(this.prefix.length);
          this.verify(token, this.secret).then(payload => {
            if (payload === undefined) {
              res.status(401).end('Payload cannot be undefined');
            } else {
              res.locals[this.token] = payload;
              const userId = (payload as any)[this.key];
              if (!userId) {
                res.status(403).end('Payload must contain ' + this.key);
              } else {
                this.privilege(userId, privilege).then(p => {
                  if (p === none) {
                    res.status(403).end('no permission for ' + userId);
                  } else {
                    if (!action) {
                      next();
                    } else {
                      if (this.exact) {
                        // tslint:disable-next-line:no-bitwise
                        const sum = action & p;
                        if (sum === action) {
                          return next();
                        } else {
                          res.status(403).end('no permission');
                        }
                      } else {
                        if (p >= action) {
                          return next();
                        } else {
                          res.status(403).end('no permission');
                        }
                      }
                    }
                  }
                }).catch(err => {
                  const { status, body } = this.buildError(err);
                  res.status(status).end(body);
                });
              }
            }
          }).catch(err => {
            const { status, body } = this.buildError(err);
            res.status(status).end(body);
          });
        }
      } else {
        res.status(401).end(`Require 'Authorization' in header`);
      }
    };
  }
}
export const none = 0;
export const read = 1;
export const write = 2;
export const approve = 4;
export const all = 2147483647;
// tslint:disable-next-line:max-classes-per-file
export class PrivilegeLoader {
  constructor(public sql: string, public query: <T>(sql: string, args?: any[]) => Promise<T[]>) {
    this.privilege = this.privilege.bind(this);
  }
  privilege(userId: string, privilegeId: string): Promise<number> {
    return this.query<any>(this.sql, [userId, privilegeId]).then(v => {
      if (!v || v.length === 0) {
        return none;
      }
      const keys = Object.keys(v[0]);
      if (keys.length === 0) {
        return all;
      }
      const k: string = keys[0];
      let permissions = 0;
      let ok = false;
      for (const p of v) {
        const x = p[k];
        if (typeof x === 'number') {
          // tslint:disable-next-line:no-bitwise
          permissions = permissions | x;
          ok = true;
        }
      }
      return (ok ? permissions : all);
    });
  }
}
export function buildError(err: any): StatusError {
  return { status: 401, body: 'Invalid token: ' + toString(err) };
}
export function toString(err: any): string {
  return (typeof err === 'string' ? err : JSON.stringify(err));
}
