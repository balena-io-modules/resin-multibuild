/*
 * Guided by code at https://github.com/joyent/node-docker-registry-client
*/

// --- globals

const DEFAULT_INDEX_NAME = 'docker.io';
//const DEFAULT_INDEX_URL = 'https://index.docker.io';
const DEFAULT_V2_REGISTRY = 'https://registry-1.docker.io';
const DEFAULT_LOGIN_SERVERNAME = 'https://index.docker.io/v1/';

const VALID_NS = /^[a-z0-9._-]*$/;
const VALID_REPO = /^[a-z0-9_/.-]*$/;

const ParseAuth = /(\w+)\s+(.*)/; // -> scheme, params
const Separators = /([",=])/;

// --- exports

export type ParsedIndex = {
    name: string;
    official: boolean;
    scheme: string;
};

export type ParsedRepo = {
    localName: string;
    canonicalName: string;
    remoteName: string;
    indexUrl: string;
};

export type HeaderParams = {
    [key: string]: string;
};

export type ParsedChallenge = {
    scheme?: string;
    params?: HeaderParams
}

enum ParamParseState {
    Token,
    ExpectEquals,
    ExpectValue,
    HandleQuotedString,
    EndQuotedString,
    ExpectComma
}

function splitStrOnce(str: string, separator: string) {
    const index = str.indexOf(separator);
    if (index < 0) {
        return str;
    }
    return [str.substring(0, index), str.substring(index + 1)];
}

/**
 * Parse a docker index name or index URL.
 *
 * Examples:
 *      docker.io               (no scheme implies 'https')
 *      index.docker.io         (normalized to docker.io)
 *      https://docker.io
 *      http://localhost:5000
 *      https://index.docker.io/v1/  (special case)
 *
 */
function parseIndex(arg: string|undefined): ParsedIndex {

    const index: Partial<ParsedIndex> = {};

    if (!arg || arg === DEFAULT_LOGIN_SERVERNAME) {
        // Default index.
        index.name = DEFAULT_INDEX_NAME;
        index.official = true;
        index.scheme = 'https';
    } else {
        // Optional protocol/scheme.
        let indexName;

        const protoSepIdx = arg.indexOf('://');
        if (protoSepIdx !== -1) {
            const scheme = arg.slice(0, protoSepIdx);
            if (['http', 'https'].indexOf(scheme) === -1) {
                throw new Error('invalid index scheme, must be ' +
                    '"http" or "https": ' + arg);
            }
            index.scheme = scheme;
            indexName = arg.slice(protoSepIdx + 3);
        } else {
            indexName = arg;
        }

        if (!indexName) {
            throw new Error('invalid index, empty host: ' + arg);
        } else if (indexName.indexOf('.') === -1 &&
            indexName.indexOf(':') === -1 &&
            indexName !== 'localhost')
        {
            throw new Error(`invalid index, "${indexName}" does not look like a valid host: ${arg}`);
        } else {
            // Allow a trailing '/' as from some URL builder functions that
            // add a default '/' path to a URL, e.g. 'https://docker.io/'.
            if (indexName[indexName.length - 1] === '/') {
                indexName = indexName.slice(0, indexName.length - 1);
            }

            // Ensure no trailing repo.
            if (indexName.indexOf('/') !== -1) {
                throw new Error('invalid index, trailing repo: ' + arg);
            }
        }

        // Per docker.git's `ValidateIndexName`.
        if (indexName === 'index.' + DEFAULT_INDEX_NAME) {
            indexName = DEFAULT_INDEX_NAME;
        }

        index.name = indexName;
        index.official = Boolean(indexName === DEFAULT_INDEX_NAME);

        // Disallow official and 'http'.
        if (index.official && index.scheme === 'http') {
            throw new Error('invalid index, HTTP to official index is disallowed: ' + arg);
        }
    }

    return index as ParsedIndex;
}


/**
 * Parse a docker repo and tag string: [INDEX/]REPO[:TAG|@DIGEST]
 *
 * Examples:
 *    busybox
 *    google/python
 *    docker.io/ubuntu
 *    localhost:5000/blarg
 *    http://localhost:5000/blarg
 *
 */
export function parseRepo(arg: string) : ParsedRepo {

    const info: Partial<ParsedRepo> = {};

    // Strip off optional leading `INDEX/`, parse it to `info.index` and
    // leave the rest in `remoteName`.
    let remoteName;
    const protoSepIdx = arg.indexOf('://');
    let index: ParsedIndex;

    if (protoSepIdx !== -1) {
        // (A) repo with a protocol, e.g. 'https://host/repo'.
        const slashIdx = arg.indexOf('/', protoSepIdx + 3);
        if (slashIdx === -1) {
            throw new Error('invalid repository name, no "/REPO" after ' +
                'hostame: ' + arg);
        }
        const indexName = arg.slice(0, slashIdx);
        remoteName = arg.slice(slashIdx + 1);
        index = parseIndex(indexName);
    } else {
        const parts = splitStrOnce(arg, '/');
        if (parts.length === 1 || (
            /* or if parts[0] doesn't look like a hostname or IP */
            parts[0].indexOf('.') === -1 &&
            parts[0].indexOf(':') === -1 &&
            parts[0] !== 'localhost'))
        {
            // (B) repo without leading 'INDEX/'.
            index = parseIndex(undefined);
            remoteName = arg;
        } else {
            // (C) repo with leading 'INDEX/' (without protocol).
            index = parseIndex(parts[0]);
            remoteName = parts[1];
        }
    }

    // Validate remoteName (docker `validateRemoteName`).
    const nameParts = splitStrOnce(remoteName, '/');
    let ns, name;
    if (nameParts.length === 2) {
        name = nameParts[1];

        // Validate ns.
        ns = nameParts[0];
        if (ns.length < 2 || ns.length > 255) {
            throw new Error('invalid repository namespace, must be between ' +
                '2 and 255 characters: ' + ns);
        }
        if (! VALID_NS.test(ns)) {
            throw new Error('invalid repository namespace, may only contain ' +
                '[a-z0-9._-] characters: ' + ns);
        }
        if (ns[0] === '-' && ns[ns.length - 1] === '-') {
            throw new Error('invalid repository namespace, cannot start or ' +
                'end with a hypen: ' + ns);
        }
        if (ns.indexOf('--') !== -1) {
            throw new Error('invalid repository namespace, cannot contain ' +
                'consecutive hyphens: ' + ns);
        }
    } else {
        name = remoteName;
        if (index.official) {
            ns = 'library';
        }
    }

    // Validate name.
    if (! VALID_REPO.test(name)) {
        throw new Error('invalid repository name, may only contain ' +
            '[a-z0-9_/.-] characters: ' + name);
    }


    if (index.official) {
        info.remoteName = ns + '/' + name;
        if (ns === 'library') {
            info.localName = name;
        } else {
            info.localName = info.remoteName;
        }
        info.canonicalName = DEFAULT_INDEX_NAME + '/' + info.localName;
        info.indexUrl = DEFAULT_V2_REGISTRY;
    } else {
        if (ns) {
            info.remoteName = ns + '/' + name;
        } else {
            info.remoteName = name;
        }
        info.localName = index.name + '/' + info.remoteName;
        info.canonicalName = info.localName;
        info.indexUrl = `${index.scheme || 'https'}://${index.name}`;
    }

    return info as ParsedRepo;
}

function parseParams(header: string): HeaderParams {
    let token, key, value;
    let state: ParamParseState = ParamParseState.Token;
    const splitHeader = header.split(Separators);
    const params: HeaderParams = {};

    for (let i = 0, len = splitHeader.length; i < len; i++) {
        token = splitHeader[i];
        if (!token.length) { 
            continue;
        }
        switch (state) {
        case ParamParseState.Token:
            key = token.trim();
            state = ParamParseState.ExpectEquals;
            continue;
        case ParamParseState.ExpectEquals:
            if (token !== "=") { 
                throw "Equal sign was expected after " + key;
            }
            state = ParamParseState.ExpectValue;
            continue;
        case ParamParseState.ExpectValue:
            if ('"' == token) {
                value = "";
                state = ParamParseState.HandleQuotedString; 
                continue;
            } else {
                params[key] = value = token.trim();
                state = ParamParseState.ExpectComma;
                continue;
            }
        case ParamParseState.HandleQuotedString: 
            if ('"' == token) {
                state = ParamParseState.EndQuotedString;
                continue;
            } else {
                value += token;
                state = ParamParseState.HandleQuotedString; // continue accumulating quoted string
                continue;
            }
        case ParamParseState.EndQuotedString: 
            if ('"' == token) {
                // double quoted
                value += '"';
                state = ParamParseState.HandleQuotedString; // back to quoted string
                continue;
            }
            if ("," == token) {
                params[key] = value;
                state = ParamParseState.Token;
                continue;
            } else {
                throw "Unexpected token (" + token + ") after " + value + '"';
            }
        case ParamParseState.ExpectComma: 
            if ("," != token) {
                throw "Comma expected after " + value;
            }
            state = ParamParseState.Token;
            continue;
        }
    }

    switch (state) { // terminal state
    case ParamParseState.Token: // Empty or ignoring terminal comma
    case ParamParseState.ExpectComma: // Expecting comma or end of header
        break;
    case ParamParseState.EndQuotedString: // Last token was end quote
        params[key] = value;
        break;
    default:
        throw "Unexpected end of www-authenticate value.";
    }

    return params;
}

export function ParseAuthenticateChallenge(toParse: string): ParsedChallenge {
    const parsed = toParse.match(ParseAuth);
    if (!parsed) {
        return {};
    }
    return {
        scheme: parsed[1],
        params: parseParams(parsed[2])
    }
}
