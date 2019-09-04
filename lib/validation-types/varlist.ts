import * as t from 'io-ts';
import * as _ from 'lodash';

type AcceptedVarList = VarList | string[];

export interface VarList {
	[key: string]: string;
}

const stringRegex = /([^\s=]+?)=(.+)/;

const validate = (value: unknown): value is VarList => {
	if (_.isArray(value)) {
		return validateStringArray(value);
	} else if (_.isObject(value)) {
		return _.every(value as Dictionary<unknown>, (v, k) => {
			return _.isString(v) && _.isString(k);
		});
	}
	return false;
};

const convert = (value: unknown): VarList | undefined => {
	if (!validate(value)) {
		return;
	}
	if (_.isArray(value)) {
		const varList: VarList = {};
		_.each(value as string[], str => {
			const match = str.match(stringRegex);
			if (match == null) {
				return;
			}
			varList[match[1]] = match[2];
		});
		return varList;
	} else {
		return value;
	}
};

export const PermissiveVarList = new t.Type<VarList, AcceptedVarList, unknown>(
	'VarList',
	validate,
	(u, ctx) => {
		const value = convert(u);
		if (value != null) {
			return t.success(value);
		}
		return t.failure('Invalid variable list', ctx);
	},
	() => {
		throw new Error('Encode not implemented for type VarList');
	},
);

function validateStringArray(arr: unknown[]): boolean {
	if (!_.every(arr, a => _.isString(a))) {
		return false;
	}

	// Perform a regex on every value to make sure it's in the
	// correct format
	return _.every(arr as string[], a => stringRegex.test(a));
}
