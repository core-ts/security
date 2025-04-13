import { Application, NextFunction, Request, Response } from "express"

export type Handle = (req: Request, res: Response, next: NextFunction) => void
export type Authorize = (privilege: string, action?: number) => Handle
export type MultiAuthorize<T> = (v: T[], privilege: string, action?: number) => Handle
export type Authorizes<T> = (v: T[], privilege: string, action?: number) => Handle
export type Check<T> = (v: T[]) => Handle
export interface Token {
  secret: string
  expires: number
}
export type TokenConfig = Token
export type TokenConf = Token
export interface StatusError {
  status: number
  body: string
}
export type GetToken<P> = (req: Request, res: Response) => Promise<PayloadToken<P>>
export interface StringToken {
  token: string
  error?: string
}
export interface PayloadToken<P> {
  payload?: P
  token?: string
  error?: string
  end?: boolean
}
export function handleToken<P>(
  res: Response,
  secret: string,
  name: string,
  t: StringToken,
  verify: (token: string, secret: string) => Promise<P>,
  buildErr: (err: any) => StatusError,
): Promise<PayloadToken<P>> {
  if (t.error) {
    res.status(401).end(t.error)
    return Promise.resolve({ error: t.error, end: true })
  } else {
    return verify(t.token, secret)
      .then((payload) => {
        res.locals[name] = payload
        return Promise.resolve({ payload, token: t.token })
      })
      .catch((err) => {
        const { status, body } = buildErr(err)
        res.status(status).end(body)
        return Promise.resolve({ token: t.token, error: t.error, end: true })
      })
  }
}
export function fromCookies(req: Request, name: string): StringToken {
  if (!req.cookies) {
    return { token: "", error: `Require cookies` }
  } else {
    const token = req.cookies[name]
    if (!token) {
      return { token: "", error: `Require '${name}' in cookies` }
    } else {
      return { token }
    }
  }
}
export function fromAuthorization(req: Request, prefix: string): StringToken {
  const data = req.headers["authorization"]
  if (data) {
    if (!data.startsWith(prefix)) {
      return { token: "", error: `Authorization must start with '${prefix.trim()}'` }
    } else {
      const token = data.substr(prefix.length)
      return { token }
    }
  } else {
    return { token: "", error: `Require 'Authorization' in header` }
  }
}
export interface TokenHandler<P> {
  getToken(req: Request, res: Response): Promise<PayloadToken<P>>
}
export class LocalsToken<P> implements TokenHandler<P> {
  token: string
  constructor(token?: string) {
    this.token = token ? token : "token"
    this.getToken = this.getToken.bind(this)
  }
  getToken(req: Request, res: Response): Promise<PayloadToken<P>> {
    const payload = res.locals[this.token]
    return Promise.resolve({ payload })
  }
}
// tslint:disable-next-line:max-classes-per-file
export class CookiesToken<P> implements TokenHandler<P> {
  token: string
  payload: string
  buildError: (err: any) => StatusError
  constructor(
    public secret: string,
    public verify: (token: string, secret: string) => Promise<P>,
    buildErr?: (err: any) => StatusError,
    payload?: string,
    token?: string,
  ) {
    this.token = token ? token : "token"
    this.payload = payload ? payload : "token"
    this.buildError = buildErr ? buildErr : buildError
    this.getToken = this.getToken.bind(this)
  }
  getToken(req: Request, res: Response): Promise<PayloadToken<P>> {
    const t = fromCookies(req, this.token)
    return handleToken<P>(res, this.secret, this.payload, t, this.verify, this.buildError)
  }
}
// tslint:disable-next-line:max-classes-per-file
export class AuthorizationToken<P> implements TokenHandler<P> {
  prefix: string
  payload: string
  buildError: (err: any) => StatusError
  constructor(
    public secret: string,
    public verify: (token: string, secret: string) => Promise<P>,
    buildErr?: (err: any) => StatusError,
    payload?: string,
    prefix?: string,
  ) {
    this.prefix = prefix ? prefix : "Bearer "
    this.payload = payload ? payload : "token"
    this.buildError = buildErr ? buildErr : buildError
    this.getToken = this.getToken.bind(this)
  }
  getToken(req: Request, res: Response): Promise<PayloadToken<P>> {
    const t = fromAuthorization(req, this.prefix)
    return handleToken<P>(res, this.secret, this.payload, t, this.verify, this.buildError)
  }
}
// tslint:disable-next-line:max-classes-per-file
export class TokenService<P> implements TokenHandler<P> {
  prefix: string
  token: string
  payload: string
  buildError: (err: any) => StatusError
  constructor(
    public secret: string,
    public verify: (token: string, secret: string) => Promise<P>,
    buildErr?: (err: any) => StatusError,
    payload?: string,
    token?: string,
    prefix?: string,
  ) {
    this.prefix = prefix ? prefix : "Bearer "
    this.token = token ? token : "token"
    this.payload = payload ? payload : "token"
    this.buildError = buildErr ? buildErr : buildError
    this.getToken = this.getToken.bind(this)
  }
  getToken(req: Request, res: Response): Promise<PayloadToken<P>> {
    let t = fromCookies(req, this.token)
    if (t.error) {
      t = fromAuthorization(req, this.prefix)
    }
    return handleToken<P>(res, this.secret, this.payload, t, this.verify, this.buildError)
  }
}
export function useToken<P>(
  secret: string,
  verify: (token: string, secret: string) => Promise<P>,
  buildErr?: (err: any) => StatusError,
  cookie?: boolean,
  payload?: string,
  token?: string,
  prefix?: string,
): GetToken<P> {
  if (cookie === true) {
    return new CookiesToken(secret, verify, buildErr, payload, token).getToken
  } else if (cookie === false) {
    return new AuthorizationToken(secret, verify, buildErr, payload, prefix).getToken
  } else {
    return new TokenService(secret, verify, buildErr, payload, token, prefix).getToken
  }
}
export const getToken = useToken
// tslint:disable-next-line:max-classes-per-file
export class Handler<P> {
  prefix: string
  token: string
  payload: string
  constructor(public secret: string, public verify: (token: string, secret: string) => Promise<P>, prefix?: string, token?: string, payload?: string) {
    this.prefix = prefix ? prefix : "Bearer "
    this.token = token ? token : "token"
    this.payload = payload ? payload : "token"
    this.handle = this.handle.bind(this)
  }
  handle(): (req: Request, res: Response, next: NextFunction) => void {
    return (req: Request, res: Response, next: NextFunction) => {
      let t = fromCookies(req, this.token)
      if (t.error) {
        t = fromAuthorization(req, this.prefix)
      }
      if (t.error) {
        next()
      } else {
        this.verify(t.token, this.secret)
          .then((payload) => {
            res.locals[this.payload] = payload
            next()
          })
          .catch((err) => {
            next()
          })
      }
    }
  }
}
export const AuthorizationHandler = Handler
// tslint:disable-next-line:max-classes-per-file
export class AuthorizationChecker<P> {
  getToken: GetToken<P>
  constructor(gt: GetToken<P>) {
    this.getToken = gt
    this.check = this.check.bind(this)
    this.require = this.require.bind(this)
  }
  require(): Handle {
    return (req: Request, res: Response, next: NextFunction) => {
      this.getToken(req, res).then((t) => {
        if (!t.end) {
          next()
        }
      })
    }
  }
  check(): Handle {
    return this.require()
  }
}
export function exist<T>(obj: T | T[], arr: T[]): boolean {
  if (Array.isArray(obj)) {
    for (const o of obj) {
      for (const v of arr) {
        // tslint:disable-next-line:triple-equals
        if (o == v) {
          return true
        }
      }
    }
  } else {
    for (const v of arr) {
      // tslint:disable-next-line:triple-equals
      if (obj == v) {
        return true
      }
    }
  }
  return false
}
// tslint:disable-next-line:max-classes-per-file
export class Checker<T, P> {
  key: string
  getToken: GetToken<P>
  constructor(gt: GetToken<P>, key?: string) {
    this.getToken = gt
    this.key = key ? key : "id"
    this.check = this.check.bind(this)
  }
  check(v: T[]): Handle {
    return (req: Request, res: Response, next: NextFunction) => {
      this.getToken(req, res).then((t) => {
        if (!t.end) {
          if (t.payload) {
            const obj = (t.payload as any)[this.key]
            if (!obj) {
              res.status(403).end("Payload must contain " + this.key)
            } else {
              if (exist<T>(obj as any, v)) {
                next()
              } else {
                res.status(403).end("invalid " + this.key)
              }
            }
          } else {
            res.status(403).end("Payload cannot be undefined")
          }
        }
      })
    }
  }
}
// tslint:disable-next-line:max-classes-per-file
export class MultiAuthorizer<T, P> {
  user: string
  key: string
  exact: boolean
  getToken: GetToken<P>
  buildError: (err: any) => StatusError
  constructor(
    gt: GetToken<P>,
    public privilege: (userId: string, privilegeId: string) => Promise<number>,
    buildErr?: (err: any) => StatusError,
    key?: string,
    user?: string,
    exact?: boolean,
  ) {
    this.getToken = gt
    this.buildError = buildErr ? buildErr : buildError
    this.user = user ? user : "id"
    this.key = key ? key : "userType"
    this.exact = exact !== undefined ? exact : true
    this.authorize = this.authorize.bind(this)
  }
  authorize(v: T[], privilege: string, action?: number): Handle {
    return (req: Request, res: Response, next: NextFunction) => {
      this.getToken(req, res).then((t) => {
        if (!t.end) {
          if (t.payload) {
            const obj = (t.payload as any)[this.key]
            if (!obj) {
              res.status(403).end("Payload must contain " + this.key)
            } else {
              if (exist<T>(obj as any, v)) {
                const userId = (t.payload as any)[this.user]
                if (!userId) {
                  res.status(403).end("Payload must contain " + this.user)
                } else {
                  this.privilege(userId, privilege)
                    .then((p) => {
                      if (p === none) {
                        res.status(403).end("no permission for " + userId)
                      } else {
                        if (!action) {
                          next()
                        } else {
                          if (this.exact) {
                            // tslint:disable-next-line:no-bitwise
                            const sum = action & p
                            if (sum === action) {
                              return next()
                            } else {
                              res.status(403).end("no permission")
                            }
                          } else {
                            if (p >= action) {
                              return next()
                            } else {
                              res.status(403).end("no permission")
                            }
                          }
                        }
                      }
                    })
                    .catch((err) => {
                      const { status, body } = this.buildError(err)
                      res.status(status).end(body)
                    })
                }
              } else {
                res.status(403).end("invalid " + this.key)
              }
            }
          } else {
            res.status(401).end("Payload cannot be undefined")
          }
        }
      })
    }
  }
}
// tslint:disable-next-line:max-classes-per-file
export class Authorizer<P> {
  key: string
  exact: boolean
  getToken: GetToken<P>
  buildError: (err: any) => StatusError
  constructor(
    gt: GetToken<P>,
    public privilege: (userId: string, privilegeId: string) => Promise<number>,
    buildErr?: (err: any) => StatusError,
    exact?: boolean,
    key?: string,
  ) {
    this.getToken = gt
    this.buildError = buildErr ? buildErr : buildError
    this.key = key ? key : "id"
    this.exact = exact !== undefined ? exact : true
    this.authorize = this.authorize.bind(this)
  }
  authorize(privilege: string, action?: number): Handle {
    return (req: Request, res: Response, next: NextFunction) => {
      this.getToken(req, res).then((t) => {
        if (!t.end) {
          const payload = t.payload
          if (payload === undefined) {
            res.status(401).end("Payload cannot be undefined")
          } else {
            const userId = (payload as any)[this.key]
            if (!userId) {
              res.status(403).end("Payload must contain " + this.key)
            } else {
              this.privilege(userId, privilege)
                .then((p) => {
                  if (p === none) {
                    res.status(403).end("no permission for " + userId)
                  } else {
                    if (!action) {
                      next()
                    } else {
                      if (this.exact) {
                        // tslint:disable-next-line:no-bitwise
                        const sum = action & p
                        if (sum === action) {
                          return next()
                        } else {
                          res.status(403).end("no permission")
                        }
                      } else {
                        if (p >= action) {
                          return next()
                        } else {
                          res.status(403).end("no permission")
                        }
                      }
                    }
                  }
                })
                .catch((err) => {
                  const { status, body } = this.buildError(err)
                  res.status(status).end(body)
                })
            }
          }
        }
      })
    }
  }
}
export const none = 0
export const read = 1
export const write = 2
export const approve = 4
export const all = 2147483647
// tslint:disable-next-line:max-classes-per-file
export class PrivilegeLoader {
  constructor(public sql: string, public query: <T>(sql: string, args?: any[]) => Promise<T[]>) {
    this.privilege = this.privilege.bind(this)
  }
  privilege(userId: string, privilegeId: string): Promise<number> {
    return this.query<any>(this.sql, [userId, privilegeId]).then((v) => {
      if (!v || v.length === 0) {
        return none
      }
      const keys = Object.keys(v[0])
      if (keys.length === 0) {
        return all
      }
      const k: string = keys[0]
      let permissions = 0
      let ok = false
      for (const p of v) {
        const x = p[k]
        if (typeof x === "number") {
          // tslint:disable-next-line:no-bitwise
          permissions = permissions | x
          ok = true
        }
      }
      return ok ? permissions : all
    })
  }
}
export function buildError(err: any): StatusError {
  return { status: 401, body: "Invalid token: " + toString(err) }
}
export function toString(err: any): string {
  return typeof err === "string" ? err : JSON.stringify(err)
}

export function get(app: Application, path: string, authorize: Handle, handle: Handle, secure?: boolean): void {
  if (secure) {
    app.get(path, authorize, handle)
  } else {
    app.get(path, handle)
  }
}
export function post(app: Application, path: string, authorize: Handle, handle: Handle, secure?: boolean): void {
  if (secure) {
    app.post(path, authorize, handle)
  } else {
    app.post(path, handle)
  }
}
export function put(app: Application, path: string, authorize: Handle, handle: Handle, secure?: boolean): void {
  if (secure) {
    app.put(path, authorize, handle)
  } else {
    app.put(path, handle)
  }
}
export function patch(app: Application, path: string, authorize: Handle, handle: Handle, secure?: boolean): void {
  if (secure) {
    app.patch(path, authorize, handle)
  } else {
    app.patch(path, handle)
  }
}
export function del(app: Application, path: string, authorize: Handle, handle: Handle, secure?: boolean): void {
  if (secure) {
    app.delete(path, authorize, handle)
  } else {
    app.delete(path, handle)
  }
}
