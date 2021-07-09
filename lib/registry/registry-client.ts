
import { format } from 'util';
import * as querystring from 'querystring';
import * as restifyErrors from 'restify-errors';
import * as mod_url from 'url';

import * as parsers from './parsers';
import * as djc from  './docker-json-client';

import assert = require('assert');

// Globals

export const MEDIATYPE_MANIFEST_V2
    = 'application/vnd.docker.distribution.manifest.v2+json';
export const MEDIATYPE_MANIFEST_LIST_V2
    = 'application/vnd.docker.distribution.manifest.list.v2+json';
export const DEFAULT_USERAGENT = 'balena-multibuild';

export type RegistryClientOptions = {
    name: string;
    username?: string;
    password?: string;
    userAgent?: string;
    bearerToken?: string;
    scope?: string;
    authType?: "basic" | "bearer" | "none"
}

export interface RegistryRepo {
    indexUrl?: string,
    remoteName?: string,
    localName?: string,
    canonicalName?: string
}

export type DockerImageManifestPlatform = {
    architecture: string;
    os: string;
};

export type DockerImageManifestComponentObject = {
    digest: string;
    platform?: DockerImageManifestPlatform;
};

export type DockerImageManifest = {
    mediaType: string;
    schemaVersion: number;
    name: string;
    tag: string;
    architecture: string;
    config: unknown;
    fsLayers?: unknown[];
    layers?: unknown[];
    history?: unknown[];
    signatures?: unknown[];
    manifests?: DockerImageManifestComponentObject[];
};


interface RegistryLoginAuthInfo {
    type?: "basic" | "bearer" | "none",
    token?: string,
    username?: string,
    password?: string,
}

interface RegistryLoginConfiguration {
    type?: "basic" | "bearer" | "none"
    scope?: string;
    username?: string;
    password?: string;
    bearerAuthToken?: string;
}

interface RegistryConnectionConfiguration {
    userAgent?: string;
}

type HttpHeaders = {
    [key: string]: string|string[];
};

type BearerTokenBody = {
    token: string | undefined;
};

export class RegistryClient {

    private repo: parsers.ParsedRepo;
    private loginConfig: RegistryLoginConfiguration = {};
    private connectionConfig: RegistryConnectionConfiguration = {};
    private currentAuth?: RegistryLoginAuthInfo;

    public constructor(opts: RegistryClientOptions) {
        assert.ok(opts.name);

        this.repo = parsers.parseRepo(opts.name);

        this.loginConfig.bearerAuthToken = opts.bearerToken;
        this.loginConfig.username = opts.username;
        this.loginConfig.password = opts.password;
        this.loginConfig.scope = opts.scope;
        this.loginConfig.type = opts.authType;

        this.connectionConfig.userAgent = opts.userAgent;
    }

    private createDockerJsonClient(
        url: string
    ): djc.DockerJsonClient {
        return djc.createClient({
            url: url,
            rejectUnauthorized: this.loginConfig.type != 'none',
            userAgent: this.connectionConfig.userAgent || DEFAULT_USERAGENT
        });
    }

    private formatBasicAuthHeader(username: string, password?: string) {
        const buffer = Buffer.from(username + ':' + (password ?? ''), 'utf8');
        return 'Basic ' + buffer.toString('base64');
    }

    private makeHttpHeaders(
        authInfo?: RegistryLoginAuthInfo
    ) : HttpHeaders {
        if (authInfo) {
            switch(authInfo.type) {
            case undefined:
                if (!authInfo.username) {
                    return {};
                } else {
                    return { 
                        authorization: this.formatBasicAuthHeader(
                            authInfo.username,
                            authInfo.password
                        )};
                }
            case 'basic':
                assert.ok(authInfo.username);
                return { 
                    authorization: this.formatBasicAuthHeader(
                        authInfo.username,
                        authInfo.password
                    )};
            case 'bearer':
                return { 
                    authorization: 'Bearer ' + authInfo.token 
                };
            }
        }
        return {};
    }

    private getRegistryErrorMessage(err: djc.HttpError) {
        if (err.body && Array.isArray(err.body.errors) && err.body.errors[0]) {
            return err.body.errors[0].message;
        } else if (err.body && err.body.details) {
            return err.body.details;
        } else if (Array.isArray(err.errors) && err.errors[0].message) {
            return err.errors[0].message;
        } else if (err.message) {
            return err.message;
        }
        return err.toString();
    }

    private makeAuthScope(resource: string, name: string, actions: string[]) {
        return format('%s:%s:%s', resource, name, actions.join(','));
    }

    private parseWWWAuthenticate(header: string) : parsers.ParsedChallenge{
        try {
            const parsed = parsers.ParseAuthenticateChallenge(header);
            if (!parsed.scheme) {
                throw new Error('could not parse WWW-Authenticate header');
            }
            return parsed;
        } catch (err) {
            throw new Error('could not parse WWW-Authenticate header "' + header + '": ' + err);
        }
    }

    private getRegistryAuthToken(
        realm: string,
        service: string,
        scope: string,
        callback: (err?: unknown, token?: string) => void
    ) {

        assert.ok(realm, 'realm');
        assert.ok(realm, 'service');
        assert.ok(this.repo.remoteName, 'repo.remoteName');

        // - add https:// prefix (or http) if none on 'realm'
        let tokenUrl = realm;
        const match = /^(\w+):\/\//.exec(tokenUrl);
        if (!match) {
            tokenUrl = 'https://' + tokenUrl;
        } else if (['http', 'https'].indexOf(match[1]) === -1) {
            return callback(new Error(format('unsupported scheme for ' +
                'WWW-Authenticate realm "%s": "%s"', realm, match[1])));
        } 
    
        // - GET $realm
        //      ?service=$service
        //      (&scope=$scope)*
        //      (&account=$username)
        //   Authorization: Basic ...

        const query = {
            service: service,
            scope: [scope]
        } as {
            service?: string,
            scope?: string[],
            account?: string,
        };
    
        if (this.loginConfig.username) {
            query.account = this.loginConfig.username;
        }

        if (Object.keys(query).length) {
            tokenUrl += '?' + querystring.stringify(query);
        }
    
        const parsedUrl = mod_url.parse(tokenUrl);
        const client = this.createDockerJsonClient(parsedUrl.protocol + '//' + parsedUrl.host);
        client.get({
            path: parsedUrl.path,
            headers: this.makeHttpHeaders({
                username: this.loginConfig.username,
                password: this.loginConfig.password
            })
        }, (err: djc.HttpError, _req, _res, body: BearerTokenBody) => {
            client.close();
            if (!body.token) {
                return callback(new restifyErrors.UnauthorizedError('authorization ' +
                    'server did not include a token in the response'));
            }
            callback(null, body.token);
        });
    }
            
    private getChallengeHeader(res: djc.HttpResponse) {
        assert.ok(res);        
        assert.ok(res.headers);

        let chalHeader = res.headers['www-authenticate'];
            
        // hack for quay.io
        if (!chalHeader && this.repo.indexUrl!.indexOf('quay.io') >= 0) {
            chalHeader = 'Bearer realm="https://quay.io/v2/auth",service="quay.io"';
        }

        return chalHeader;
    }

    private rawPing(
        headers: HttpHeaders,
        callback: (req: djc.HttpRequest, res: djc.HttpResponse, err: unknown) => void
    ) {
        assert.ok(this.repo.indexUrl, 'repo.indexUrl');
        const client = this.createDockerJsonClient(this.repo.indexUrl);
    
        client.get({
            path: '/v2/',
            // Ping should be fast. We don't want 15s of retrying.
            retry: false,
            connectTimeout: 10000
        }, (err: djc.HttpError, _, res: djc.HttpResponse, req: djc.HttpRequest) => {
            callback(req, res, err);
            client.close();
        });
    }

    /*
        Checks connectivity to the registry.  This means that if logged in, will check 
        that the registry would work using the current auth info.  If not logged in, 
        checks to see if it is possible to determine the auth scheme and log in
     */
    public ping(): Promise<boolean> {

        return new Promise<boolean>((resolve) => {
            this.rawPing(this.makeHttpHeaders(this.currentAuth), (req: djc.HttpRequest, res: djc.HttpResponse, err: djc.HttpError) => {
                if (this.currentAuth) {
                    resolve(!err);
                } else {
                    // success = no error or else 401 with challenge header
                    resolve(
                        !err || (res.statusCode === 401 && !!this.getChallengeHeader(res))
                    );
                }
            }); 
        });
    }

    public async login(
        forceReset = false,         // if we already have auth info, forceReset makes us do it anyway
        forceValidate = false       // if we have auth info (configured or obtained), still do a ping to validate it
    ): Promise<boolean> {

        assert.ok(this.repo);
        assert.ok(this.repo.remoteName, "repo not parsed");

        if (forceReset) {
            this.currentAuth = undefined;
        }
        if (!this.currentAuth) { 

            switch(this.loginConfig.type) {
            case 'basic':
                this.currentAuth = {
                    type: 'basic',
                    username: this.loginConfig.username,
                    password: this.loginConfig.password
                };
                break;
            case 'bearer':
                this.currentAuth = {
                    type: 'bearer',
                    token: this.loginConfig.bearerAuthToken
                };
                break;
            case 'none':
                this.currentAuth = {
                    type: 'none',
                };
                break;
            case undefined:
                // allow the method to go through the process to login, do the challenge, get a token, etc
                break;
            }

            if (this.currentAuth && !forceValidate) {
                return true;
            }
        }

        let challengeHeader: string;

        // Do a raw ping and process challenge header if necessary
        const pingSucceeded = await new Promise<boolean>((resolve, reject) => {
            this.rawPing(this.makeHttpHeaders(this.currentAuth), (req: djc.HttpRequest, res:djc.HttpResponse, err: djc.HttpError) => {
                if (this.currentAuth) {
                    // if we have auth info and there was an error, this call will
                    // just communicate the failure. Otherwise, if err
                    // is undefined, then the auth info is still good. Either way,
                    // we want to just got to next out at this point.
                    return resolve(!err);
                }

                // if we got here, we do _not_ have existing auth info
                if (!err) {

                    // success out of the gate!  No auth required.
                    this.currentAuth = { type: 'none' };
                    return resolve(true);

                } else if (res.statusCode === 401) {

                    // No auth, which is expected in most cases.  use the response to
                    // figure out how to handle auth for reals.

                    challengeHeader = this.getChallengeHeader(res);

                    if (!challengeHeader) {
                        return reject(new restifyErrors.UnauthorizedError(
                            'missing WWW-Authenticate header in 401 ' +
                            'response to "GET /v2/" (see ' +
                            'https://docs.docker.com/registry/spec/api/#api-version-check)'));
                    }

                    return resolve(true);

                } else {
                    // some other error occured in the ping. 
                    return resolve(false);
                }
            });
        });

        if (!pingSucceeded) {
            return false;
        }
        if (this.currentAuth) {
            return true;
        }

        // parse auth challenge
        let authChallenge: parsers.ParsedChallenge;
        
        try {
            authChallenge = this.parseWWWAuthenticate(challengeHeader!);
        } catch {
            return false;
        }

        switch(authChallenge?.scheme?.toLowerCase()) {
        case 'basic':
            this.currentAuth = {
                type: 'basic',
                username: this.loginConfig.username,
                password: this.loginConfig.password
            };
            return true;
        case 'bearer':
            assert.ok(authChallenge?.params, "Auth challenge parameters are undefined");
            
            return await new Promise<boolean>((resolve) => {
                this.getRegistryAuthToken(
                    authChallenge.params!.realm,  
                    authChallenge.params!.service,  
                    this.loginConfig.scope ?? this.makeAuthScope('repository', this.repo.remoteName!, ['pull']),
                    (err, token) => {
                        if (err) {
                            return resolve(false);
                        }
                        this.currentAuth = {
                            type: 'bearer',
                            token: token,
                        };
                        return resolve(true); 
                    });
                });
        default:
            return false;
        }
    }

    public async getManifest(
        tag = "latest",
        maxSchemaVersion = 2,
        acceptManifestLists = true,
    ) : Promise<DockerImageManifest | number | undefined>{
    
        assert.ok(this.repo, "repo");
        assert.ok(this.repo.indexUrl, "repo.indexUrl");
        assert.ok(this.repo.remoteName, "repo.remoteName");

        const loginSucceeded = await this.login();
        if (!loginSucceeded) {
            return 401;
        }

        const headers = this.makeHttpHeaders(this.currentAuth);
        if (maxSchemaVersion === 2) {
            const accept: string[] = [];
            accept.push(MEDIATYPE_MANIFEST_V2);
            if (acceptManifestLists) {
                accept.push(MEDIATYPE_MANIFEST_LIST_V2);
            }
            headers.accept = accept;
        }
        const client = this.createDockerJsonClient(this.repo.indexUrl!);
        
        try {
            return await new Promise<DockerImageManifest>((resolve, reject) => {
                client.get({
                    path: `/v2/${encodeURI(this.repo.remoteName!)}/manifests/${encodeURI(tag)}`,
                    headers: headers
                }, (err: djc.HttpError, _, res, parsedBody: DockerImageManifest) => {
                    if (err) {
                        if (err.statusCode === 401) {
                            // Convert into a 404 error.
                            // If we get an Unauthorized error here, it actually
                            // means the repo does not exist, otherwise we should
                            // have received an unauthorized error during the
                            // doLogin step and this code path would not be taken.
                            const errMsg = this.getRegistryErrorMessage(err);
                            return reject(restifyErrors.makeErrFromCode(404, {message: errMsg}));
                        }

                        return reject(err);
                    }

                    if (parsedBody.schemaVersion > maxSchemaVersion) {
                        throw new restifyErrors.InvalidContentError(format(
                            'unsupported schema version %s in %s:%s manifest',
                            parsedBody.schemaVersion, this.repo.localName,
                            tag));
                    }

                    resolve(parsedBody);
                });
            });
        } catch (err) {
            const statusCode = (err as djc.HttpError).statusCode;
            if (statusCode) {
                return statusCode;
            } else {
                return;
            }
        }
    }    
}
