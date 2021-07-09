/*
 * Adapted from code found in https://github.com/joyent/node-docker-registry-client
 * 
 * We are inheriting from a JS prototype based class, so we hide the ugliness here.
*/

'use strict';

import * as crypto from 'crypto';
import * as restifyClients from 'restify-clients';
import * as restifyErrors from 'restify-errors';
import * as util from 'util';
import * as zlib from 'zlib';
import * as bunyan from 'bunyan';

const StringClient = restifyClients.StringClient;


// --- API

function DockerJsonClientInternal(options) {

    options.accept = 'application/json';
    options.name = options.userAgent;
    options.contentType = 'application/json';
    options.log = bunyan.createLogger({
        name: 'registry',
        serializers: restifyClients.bunyan.serializers
    });

    StringClient.call(this, options);

    this._super = StringClient.prototype;
}
util.inherits(DockerJsonClientInternal, StringClient);

DockerJsonClientInternal.prototype.parse = function (req: restifyClients.HttpRequest, callback:DockerJsonClientCallback) {
    const parseResponse = (err: restifyClients.HttpError, res: restifyClients.HttpResponse) => {
        const chunks: Buffer[] = []; // gunzipped response chunks
        let len = 0; // accumulated count of chunk lengths
        let contentMd5Hash;
        let gz;
        let resErr = err;

        const finish = () => {
            const body = Buffer.concat(chunks, len);

            // Content-Length check
            const contentLength = Number(res.headers['content-length']);
            if (!isNaN(contentLength) && len !== contentLength) {
                resErr = new restifyErrors.InvalidContentError(util.format(
                    'Incomplete content: Content-Length:%s but got %s bytes',
                    contentLength, len));
                callback(resErr, req, res);
                return;
            }

            // Content-MD5 check.
            if (contentMd5Hash &&
                contentMd5 !== contentMd5Hash.digest('base64'))
            {
                resErr = new restifyErrors.BadDigestError('Content-MD5');
                callback(resErr, req, res);
                return;
            }

            // Parse the body as JSON, if we can.
            // Note: This regex-based trim works on a buffer. `trim()` doesn't.
            let obj;
            const bodyStr = body.toString();
            if (len && !/^\s*$/.test(bodyStr)) {  // Skip all-whitespace body.
                try {
                    obj = JSON.parse(bodyStr);
                } catch (jsonErr) {
                    if (!resErr) {
                        resErr = new restifyErrors.InvalidContentError(
                            'Invalid JSON in response');
                    }
                }
            }

            // Special error handling.
            if (resErr) {
                resErr.message = body.toString('utf8');
            }
            if (res && res.statusCode >= 400) {
                // Upcast error to a RestError if possible
                if (obj && (obj.code || (obj.error && obj.error.code))) {
                    const _c = obj.code ||
                        (obj.error ? obj.error.code : '') ||
                        '';
                    const _m = obj.message ||
                        (obj.error ? obj.error.message : '') ||
                        '';

                    resErr = new restifyErrors.RestError({
                        message: _m,
                        restCode: _c,
                        statusCode: res.statusCode
                    });
                    resErr.name = resErr.restCode;

                    if (!/Error$/.test(resErr.name)) {
                        resErr.name += 'Error';
                    }
                } else if (!resErr) {
                    resErr = restifyErrors.makeErrFromCode(res.statusCode,
                        obj.message || '', body);
                }
            }
            if (resErr && obj) {
                resErr.body = obj;
            }

            callback(resErr, req, res, obj, body);
        }

        if (!res) {
            // Early out if we didn't even get a response.
            callback(resErr, req);
            return;
        }

        // Content-MD5 setup.
        const contentMd5:string = res.headers['content-md5'];
        if (contentMd5 && req.method !== 'HEAD' && res.statusCode !== 206) {
            contentMd5Hash = crypto.createHash('md5');
        }

        if (res.headers['content-encoding'] === 'gzip') {
            gz = zlib.createGunzip();
            gz.on('data', (chunk: Buffer) => {
                chunks.push(chunk);
                len += chunk.length;
            });
            gz.once('end', finish);
            res.once('end', gz.end.bind(gz));
        } else {
            res.once('end', finish);
        }

        res.on('data', (chunk: Buffer) => {
            if (contentMd5Hash) {
                contentMd5Hash.update(chunk.toString('utf8'));
            }

            if (gz) {
                gz.write(chunk);
            } else {
                chunks.push(chunk);
                len += chunk.length;
            }
        });
    }

    return (parseResponse);
};

// --- Exports

export type HttpErrorMessageObject = {
    message?: string;
};

export type HttpError = {
    body?: {
        errors?: HttpErrorMessageObject[];
        details: string;
    },
    errors?: HttpErrorMessageObject[];
    message?: string;
    statusCode?: number;
};

export type HttpResponse = { 
    headers: { [key: string]: string };
    statusCode: number;
};

export type HttpRequest = {
    _headers: { host: string };
};

export type DockerJsonClientCallback = (err?: HttpError, req?: HttpRequest, res?: HttpResponse, body?: unknown, bodyString?: string | Buffer) => void;

export interface DockerJsonClient {
    get(
        options: unknown,
        callback: DockerJsonClientCallback
    ): void;

    close(): void;
}

export function createClient(options: unknown): DockerJsonClient {
    return new DockerJsonClientInternal(options);
}

