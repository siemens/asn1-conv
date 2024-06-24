"""!
@file asn1Conv.py
@author Daniel Starke
@copyright (C) Copyright Siemens Mobility GmbH, 2024. All rights reserved.
@version $Id$

Converts an ASN.1 schema (X.680) to a different format.
Note that only a subset of ASN.1 is supported.
Requires Python 3.10 or newer.
Tested with asn1tools 0.166.0.

Note that JS refers to JSON Schema in this context.
"""
# SPDX-License-Identifier: MIT

import locale
import argparse
import re
import sys
import json
import yaml
import asn1tools

## JSON Schema prefix for type definitions.
jsDefs = '#/$defs/'
flavor = 'json'

def prettify(value, level = 0, indent = 2):
	"""! Debug helper to convert a Python structure into an indented string.
	@param value - Python value to convert
	@param level - current indention level
	@param indent - space characters per indention level
	@return string representation of `value`
	"""
	preN = '\n' + (' ' * (indent * level))
	preN1 = preN + (' ' * indent)
	if isinstance(value, dict):
		items = [
			preN1 + repr(key) + ': ' + prettify(value[key], level + 1, indent)
			for key in value
		]
		return '{' + (','.join(items) + preN) + '}'
	if isinstance(value, list):
		items = [
			preN1 + prettify(item, level + 1, indent)
			for item in value
		]
		return '[' + (','.join(items) + preN) + ']'
	if isinstance(value, set):
		items = [
			preN1 + prettify(item, level + 1, indent)
			for item in value
		]
		return '{' + (','.join(items) + preN) + '}'
	if isinstance(value, tuple):
		items = [
			preN1 + prettify(item, level + 1, indent)
			for item in value
		]
		return '(' + (','.join(items) + preN) + ')'
	if isinstance(value, asn1tools.parser.ParseResults):
		items = [
			preN1 + prettify(item, level + 1, indent)
			for item in value
		]
		return 'ParseResults(' + (','.join(items) + preN) + ')'
	return repr(value)

def jsTypeFromAsn1(name, val, types):
	"""! Return JSON type from ASN.1 type.
	@param name - JSON Schema element name
	@param val - ASN.1 type string
	@param types - ASN.1 description of all available types (see `asn1tools/parser.py`)
	@return JSON type string
	"""
	res = None
	match val:
		# string types
		case 'BMPString'|'DATE'|'DATE-TIME'|'DURATION'|'GeneralizedTime'|'GeneralString'|'GraphicString'|\
		     'IA5String'|'ISO646String'|'NumericString'|'PrintableString'|'T61String'|'TeletexString'|\
		     'TIME'|'TIME-OF-DAY'|'UniversalString'|'UTCTime'|'UTF8String'|'VideotexString'|'VisibleString':
			res = 'string'
		# binary types
		case 'BIT STRING'|'CHARACTER STRING'|'OCTET STRING':
			res = 'string'
		# numeric types
		case 'INTEGER':
			res = 'integer'
		case 'REAL':
			res = 'number'
		# other primitive types
		case 'ENUMERATED':
			res = 'string'
		case 'NULL':
			res = 'null'
		case 'BOOLEAN':
			res = 'boolean'
		# list types
		case 'SET'|'SET OF':
			res = 'array'
		# property types
		case 'CHOICE'|'SEQUENCE'|'SEQUENCE OF':
			res = 'object'
	if res:
		return res
	if not val in types:
		raise SyntaxError(f'Undefined type {val} used for {name}.')
	return jsDefs + val

def jsEnumFromAsn1(obj):
	"""! JSON enumeration from ASN.1 enumeration.
	@param obj - ASN.1 value enumeration
	@return JSON enumeration value list
	"""
	res = []
	for k, _ in obj:
		res.append(k)
	return res

def regexClassChar(val):
	"""! Converts the given character into a valid regex character class string.
	@param val - input character
	@return regex character class string
	"""
	oVal = ord(val)
	if oVal < 32:
		return '\\x' + '{0:02X}'.format(oVal)
	if oVal > 255:
		return '\\u' + '{0:04X}'.format(oVal)
	if val == '\\':
		return '\\\\'
	if val == ']':
		return '\\]'
	return val

def regexClassFromSet(val = None):
	"""! Creates a regex character class from the given character set.
	@param val - character set or `None` for all characters
	@return regex character class
	"""
	if not isinstance(val, set):
		return '.'
	if len(val) == 1 and '^' in val:
		return '\\^'
	res = '['
	first = None
	last = None
	for c in sorted(val):
		if c in ['-', '^']:
			continue # added at the end
		if last:
			if ord(last) + 1 != ord(c):
				# end of range
				if first == last: # single character
					res = res + regexClassChar(first)
				else: # character range
					res = res + regexClassChar(first) + '-' + regexClassChar(last)
				first = c
		else:
			first = c
		last = c
	if last and last:
		# add remaining
		if first == last: # single character
			res = res + regexClassChar(first)
		else: # character range
			res = res + regexClassChar(first) + '-' + regexClassChar(last)
	if '^' in val:
		res = res + '^'
	if '-' in val:
		res = res + '-'
	return res + ']'

def charSet(first, last):
	"""! Creates a set of characters from the given start and end character.
	@param first - first character in range (inclusive)
	@param last - last character in range (inclusive)
	@return set with the characters of the defined range
	"""
	return set().union([chr(c) for c in range(ord(first), ord(last) + 1)])

def charSetFromAsn1From(obj, subset = None):
	"""! Creates a set of characters from the given ASN.1 `FROM` field.
	@param obj - ASN.1 `FROM` field
	@param subset - optional set of characters to intersect with
	@return resulting set of characters
	"""
	chars = set()
	# collect possible character values
	for r in obj:
		s = charSet(r[0], r[1])
		if s:
			chars.update(s)
	if isinstance(subset, set):
		chars.intersection_update(subset)
	# create reduced regex class
	return regexClassFromSet(chars)

def charC0Set():
	"""! ECMA-35, Table 1 and Figure 5 C0 character set.
	@return C0 character set
	"""
	return charSet(chr(0), chr(31))

def charC1Set():
	"""! ECMA-35, Table 1 and Figure 5 C1 character set.
	@return C1 character set
	"""
	return charC0Set().union(charSet(chr(128), chr(159)))

def charG0Set():
	"""! ECMA-35, Table 1 and Figure 5 G0 character set.
	@return G0 character set
	"""
	return charSet(chr(32), chr(127))

def charG1Set():
	"""! ECMA-35, Table 1 and Figure 5 G1 character set.
	@return G1 character set
	"""
	return charG0Set().union(charSet(chr(161), chr(255)))

def rangeFromAsn1Str(val):
	"""! Returns a set of valid characters from a given ASN.1 type string.
	@param val - ASN.1 type string
	@return `None` if unrestricted of a set of valid characters
	"""
	# X.680 Table 8
	res = set()
	match val:
		case 'BMPString'|'CHARACTER STRING'|'DATE'|'DATE-TIME'|'DURATION'|'TIME-OF-DAY'|'TIME'|'UniversalString'|'UTF8String':
			res = None # all
		case 'BIT STRING'|'OCTET STRING':
			res = None # all
		case 'GeneralString':
			res.update(charC1Set())
			res.update(charG1Set())
			res.add(' ')
			res.add(chr(127)) # DELETE
		case 'GraphicString':
			res.update(charG1Set())
		case 'IA5String': # X.680 Ch. 43.8
			res.update(charSet(chr(0), chr(127)))
		case 'NumericString': # X.680 Ch. 43.5
			res.update(charSet('0', '9'))
			res.add(' ')
		case 'PrintableString': # X.680 Ch. 43.6
			res.update([' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?', chr(6), chr(127)])
			res.update(charSet('0', '9'))
			res.update(charSet('a', 'z'))
			res.update(charSet('A', 'Z'))
		case 'T61String'|'TeletexString':
			res.update([chr(c) for c in [6, 32, 87, 102, 103, 106, 107, 126, 127, 144, 150, 153, 156, 164, 165, 168]])
		case 'VideotexString':
			res.update([chr(c) for c in [1, 13, 32, 72, 73, 87, 89, 102, 108, 126, 127, 128, 129, 144, 150, 153, 164, 165, 168]])
		case 'GeneralizedTime'|'ISO646String'|'UTCTime'|'VisibleString': # X.680 Ch. 43.7, 47.3
			res.update(charSet(chr(32), chr(126)))
	return res

def regexFromRawStr(val):
	"""! Escapes a string for its use in a regular expression.
	@param val - string to escape
	@return escaped string
	@remarks Spaces are also escaped. See https://stackoverflow.com/a/32419915
	"""
	return '^' + re.escape(val) + '$'

# pylint: disable=too-many-branches,too-many-statements
def regexFromAsn1Pattern(val, anyClass = None):
	"""! Creates a regular expression from the given ASN.1 pattern string (X.680 Ch. A.2.1).
	@param val - ASN.1 pattern string
	@param anyClass - optional character class restriction applied on `.`
	@return regular expression (see ECMAScript)
	"""
	# pylint: disable=invalid-name,too-few-public-methods
	class RegexParseState:
		"""! Possible states for the regular expression parser used here. """
		IDLE       = 0
		ESCAPE     = 1
		CODEPOINT0 = 2
		CODEPOINT1 = 3
		CODEPOINT2 = 4
		CODEPOINT3 = 5
		RANGE      = 6
		RANGE_NUM  = 7
		RANGE_MIN  = 8
		RANGE_MAX  = 9
	def escStr(x):
		return x.translate(str.maketrans({
			'\t': r'\t',
			'\n': r'\n',
			'\f': r'\f',
			'\r': r'\r'
		}))
	res = ''
	st = RegexParseState.IDLE
	cp = 0
	num = 0
	hasNum = False
	escCh = ''
	for i, c in enumerate(val):
		match st:
			case RegexParseState.IDLE:
				if c == '\\':
					st = RegexParseState.ESCAPE
				elif c == '{' and escCh == '':
					st = RegexParseState.CODEPOINT0
					cp = 0
					num = 0
					continue
				elif c == '#':
					st = RegexParseState.RANGE
					continue
				elif c == '.' and anyClass:
					res = res + anyClass
					continue
				escCh = ''
			case RegexParseState.ESCAPE:
				st = RegexParseState.IDLE
				if c == 'N': # named Unicode character
					c = 'p'
				escCh = c
			case RegexParseState.CODEPOINT0:
				if c == ',':
					st = RegexParseState.CODEPOINT1
					cp = (cp * 256) + num
					num = 0
				elif c.isdigit():
					num = (num * 10) + ord(c) - ord('0')
					if num > 255:
						raise SyntaxError(f'Codepoint entry number overflow in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				else:
					raise SyntaxError(f'Unexpected character for codepoint in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				continue
			case RegexParseState.CODEPOINT1:
				if c == ',':
					st = RegexParseState.CODEPOINT2
					cp = (cp * 256) + num
					num = 0
				elif c.isdigit():
					num = (num * 10) + ord(c) - ord('0')
					if num > 255:
						raise SyntaxError(f'Codepoint entry number overflow in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				else:
					raise SyntaxError(f'Unexpected character for codepoint in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				continue
			case RegexParseState.CODEPOINT2:
				if c == ',':
					st = RegexParseState.CODEPOINT3
					cp = (cp * 256) + num
					num = 0
				elif c.isdigit():
					num = (num * 10) + ord(c) - ord('0')
					if num > 255:
						raise SyntaxError(f'Codepoint entry number overflow in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				else:
					raise SyntaxError(f'Unexpected character for codepoint in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				continue
			case RegexParseState.CODEPOINT3:
				if c == '}':
					st = RegexParseState.IDLE
					cp = (cp * 256) + num
					res = '\\u' + '{0:04X}'.format(cp)
				elif c.isdigit():
					num = (num * 10) + ord(c) - ord('0')
					if num > 255:
						raise SyntaxError(f'Codepoint entry number overflow in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				else:
					raise SyntaxError(f'Unexpected character for codepoint in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				continue
			case RegexParseState.RANGE:
				if c == '(':
					st = RegexParseState.RANGE_MIN
					num = 0
					hasNum = False
					continue
				if c.isdigit():
					st = RegexParseState.RANGE_NUM
					num = ord(c) - ord('0')
					hasNum = True
					continue
				st = RegexParseState.IDLE
			case RegexParseState.RANGE_NUM:
				if c.isdigit():
					num = (num * 10) + ord(c) - ord('0')
					hasNum = True
					continue
				if hasNum:
					st = RegexParseState.IDLE
					res = res + '{' + str(num) + '}'
				else:
					st = RegexParseState.IDLE
			case RegexParseState.RANGE_MIN:
				if c == ',':
					st = RegexParseState.RANGE_MAX
					if hasNum:
						res = res + '{' + str(num) + ','
					else:
						res = res + '{,'
					num = 0
					hasNum = False
				elif c == ')':
					st = RegexParseState.IDLE
					if hasNum:
						res = res + '{' + str(num) + '}'
					else:
						res = res + '{}'
				elif c.isdigit():
					num = (num * 10) + ord(c) - ord('0')
					hasNum = True
				else:
					raise SyntaxError(f'Unexpected character for range start in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				continue
			case RegexParseState.RANGE_MAX:
				if c == ')':
					st = RegexParseState.IDLE
					if hasNum:
						res = res + str(num) + '}'
					else:
						res = res + '}'
				elif c.isdigit():
					num = (num * 10) + ord(c) - ord('0')
					hasNum = True
				else:
					raise SyntaxError(f'Unexpected character for range end in PATTERN.\n{escStr(val[:i+1])}<<<HERE<<<{escStr(val[i+1:])}\n')
				continue
		res = res + c
	if st == RegexParseState.ESCAPE:
		raise SyntaxError(f'Incomplete escape sequence at the end of PATTERN:\n{escStr(val)}\n')
	if st in [RegexParseState.CODEPOINT0, RegexParseState.CODEPOINT1, RegexParseState.CODEPOINT2, RegexParseState.CODEPOINT3]:
		raise SyntaxError(f'Incomplete codepoint definition ath the end of PATTERN:\n{escStr(val)}\n')
	if st in [RegexParseState.RANGE_MIN, RegexParseState.RANGE_MAX]:
		raise SyntaxError(f'Incomplete range at the end of PATTERN:\n{escStr(val)}\n')
	if st == RegexParseState.RANGE_NUM and hasNum:
		res = res + '{' + str(num) + '}'
	try:
		re.compile(res.replace('\\p', '')) # handle limited Unicode support accordingly
	except re.error as err:
		raise SyntaxError(f'Invalid regular expression from PATTERN.\nASN.1: {escStr(val)}\nRegex: {escStr(res)}\n{err}\n') from err
	return '^' + res + '$' # X.680 Ch. A.2.1 Note 3

def jsObjectFromAsn1(members, types):
	"""! Converts an ASN.1 `asn1tools` internal `members` object to JSON Schema `properties`.
	@param members - ASN.1 `asn1tools` internal `members` object
	@param types - ASN.1 description of all available types (see `asn1tools/parser.py`)
	@return JSON Schema `properties` field
	"""
	res = {}
	for m in members:
		if not 'name' in m:
			continue
		o = convertAsn1Type(m['name'], m, types)
		del o['title']
		res[m['name']] = o
	return res

def jsRangeFromAsn1(size, minN, maxN, useConst = False):
	"""! Converts an ASN.1 `SIZE` constraint to JSON Schema constraint.
	@param size - `asn1tools` internal `size` or `restricted-to` array
	@param minN - target JSON Schema field name for the minimum
	@param maxN - target JSON Schema field name for the maximum
	@param useConst - set `True` to use `const` instant of value range, else `False`
	@return `dict` of the JSON Schema constraint
	"""
	res = []
	for s in size:
		if s is None:
			continue
		e = {}
		if isinstance(s, tuple) and len(s) == 2:
			if s[0] != 'MIN':
				e[minN] = s[0]
			if s[1] != 'MAX':
				e[maxN] = s[1]
			if e:
				res.append(e)
		elif useConst:
			e['const'] = s
			res.append(e)
		else:
			e[minN] = s
			e[maxN] = s
			res.append(e)
	if res:
		if len(res) == 1:
			return res[0]
		return {'oneOf': res}
	return {}

def resolveComponentsOf(name, members, types):
	"""! Resolves all COMPONENT OF fields in the given member list.
	@param name - JSON Schema element name
	@param desc - ASN.1 type description (see `asn1tools/parser.py`)
	@param types - ASN.1 description of all available types (see `asn1tools/parser.py`)
	@return Complete ASN.1 type member list
	"""
	res = []
	for m in members:
		if 'name' in m:
			res.append(m)
		elif 'components-of' in m:
			t = m['components-of']
			if not t in types:
				raise SyntaxError(f'Undefined type {t} used in COMPONENTS OF within {name}.')
			subType = types[t]['type']
			if not subType in ['SET', 'SEQUENCE']:
				raise SyntaxError(f'Invalid referenced type {t} used in COMPONENTS OF within {name}. Only SET and SEQUENCE are allowed.')
			res.extend(resolveComponentsOf(subType, types[t]['members'], types))
	return res

def hasAsn1Constraint(members):
	"""! Checks if an ASN.1 member list from `asn1tools` has an constraint parameter.
	@param member - ASN.1 member description (see `asn1tools/parser.py`)
	@return True if a constraint was found, else False
	"""
	for member in members:
		for constraint in ['size', 'values', 'from', 'pattern', 'restricted-to', 'optional', 'default']:
			if constraint in member:
				return True
	return False

def convertAsn1MemberSet(members, types):
	"""! Converts an ASN.1 member list from `asn1tools` to a JSON Schema member list.
	@param member - ASN.1 member description (see `asn1tools/parser.py`)
	@param types - ASN.1 description of all available types (see `asn1tools/parser.py`)
	@return JSON Schema element
	"""
	obj = {}
	obj['additionalProperties'] = False
	obj['properties'] = jsObjectFromAsn1(members, types)
	r = []
	for m in members:
		if not 'name' in m:
			continue
		if not 'default' in m and (not 'optional' in m or not m['optional']):
			r.append(m['name'])
	if r:
		obj['required'] = r
	return obj

# pylint: disable=too-many-locals,too-many-nested-blocks
def convertAsn1Type(name, desc, types):
	"""! Converts an ASN.1 type from `asn1tools` to a JSON Schema element.
	@param name - JSON Schema element name
	@param desc - ASN.1 type description (see `asn1tools/parser.py`)
	@param types - ASN.1 description of all available types (see `asn1tools/parser.py`)
	@return JSON Schema element
	"""
	obj = {'title': name}
	asn1Type = desc['type']
	asn1Base = asn1Type
	jsType = jsTypeFromAsn1(name, asn1Type, types)
	if jsType.startswith(jsDefs):
		if 'with-components' in desc:
			# use base type to apply WITH COMPONENTS constraint
			newDesc = types[asn1Type].copy()
			newDesc['with-components'] = desc['with-components']
			return convertAsn1Type(name, newDesc, types)
		obj['$ref'] = jsType
	elif jsType != 'object':
		obj['type'] = jsType
	# resolve base type
	while jsType.startswith(jsDefs):
		asn1Base = types[jsType.lstrip(jsDefs)]['type']
		jsType = jsTypeFromAsn1(name, asn1Base, types)
	if jsType == 'string' and asn1Base != 'ENUMERATED':
		# note that sets of valid sizes are not supported by JSON Schema
		if 'from' in desc:
			ch = charSetFromAsn1From(desc['from'], rangeFromAsn1Str(asn1Base))
		else:
			ch = regexClassFromSet(rangeFromAsn1Str(asn1Base))
		# X.680 Ch. 51.5
		if 'size' in desc:
			s = desc['size']
			p = ''
			for r in s:
				if len(p) > 0:
					p = p + '|^'
				else:
					p = '^'
				if isinstance(r, tuple) and len(r) == 2:
					# range
					if r[0] == 'MIN' and r[1] == 'MAX':
						p = p + ch + '*'
					else:
						p = p + ch + '{'
						if r[0] != 'MIN' and r[0] != 0:
							p = p + str(r[0])
						else:
							p = p + '0'
						p = p + ','
						if r[1] != 'MAX':
							p = p + str(r[1])
						p = p + '}$'
				else:
					# single
					p = p + ch + '{' + str(r) + '}$'
			obj['pattern'] = p
		else:
			obj['pattern'] = '^' + ch + '*$'
		if obj['pattern'] == '^.*$': # unrestricted
			del obj['pattern']
	if jsType == 'string':
		if 'restricted-to' in desc:
			# this overwrites the pattern field
			p = ''
			for s in desc['restricted-to']:
				if len(p) > 0:
					p = p + '|'
				if isinstance(s, dict) and 'PATTERN' in s:
					p = p + '|'.join(regexFromAsn1Pattern(x) for x in s['PATTERN'])
				else:
					p = p + regexFromRawStr(str(s))
			if 'pattern' in obj:
				oldP = obj['pattern']
				del obj['pattern']
				obj['allOf'] = [
					{'pattern': oldP},
					{'pattern': p}
				]
			else:
				obj['pattern'] = p
	match asn1Base:
		# numeric types
		case 'INTEGER'|'REAL':
			# note that PLUS-INFINITY, MINUS-INFINITY and NOT-A-NUMBER are not possible in JSON
			if 'restricted-to' in desc:
				# X.680 Ch. 51.4
				obj.update(jsRangeFromAsn1(desc['restricted-to'], 'minimum', 'maximum', True))
		# other primitive types
		case 'ENUMERATED':
			if 'values' in desc:
				obj['enum'] = jsEnumFromAsn1(desc['values'])
		case 'BOOLEAN':
			if 'restricted-to' in desc:
				r = desc['restricted-to']
				if len(r) == 1:
					obj['const'] = r[0].lower() == 'true'
	# RFC3339, ISO8601 syntax elements
	reHour = '([01][0-9]|2[0-3])'
	reMin = '[0-5][0-9]'
	reSec = '([0-5][0-9]|60)'
	reDate = '[0-9]{4}-(0[0-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[12])'
	reTime = f'{reHour}:{reMin}:{reSec}'
	reTimeFrac = '[.,][0-9]+'
	reTimeOff = f'(Z|[+-]{reHour}:{reMin})'
	reOptMin = f'(-|{reMin}:)'
	reOptHour = f'(-|{reHour}:)'
	reSpecHour = f'{reHour}(:{reMin}(:{reSec})?)?'
	reSpecMin = f'{reOptHour}{reOptMin}(:{reSec})?'
	reSpecSec = f'-{reOptMin}{reSec}'
	reSpecBase = f'({reSpecHour}|{reSpecMin}|{reSpecSec})'
	match asn1Type:
		# string type
		case 'DATE': # X.680 Ch. 38.4.1, RFC 3339, ISO8601
			obj['pattern'] = f'^{reDate}$'
		case 'DATE-TIME': # X.680 Ch. 38.4.3, RFC 3339, ISO8601
			obj['pattern'] = f'^{reDate}T{reTime}{reTimeOff}?$'
		case 'DURATION': # X.680 Ch. 38.4.4, RFC 3339, ISO8601
			reDurSec = '[0-9]+S'
			reDurMin = f'[0-9]M({reDurSec})?'
			reDurHour = f'[0-9]H({reDurMin})?'
			reDurDay = '[0-9]+D'
			reDurWeek = '[0-9]+W'
			reDurMon = f'[0-9]+M({reDurDay})?'
			reDurYear = f'[0-9]+Y({reDurMon})?'
			reDurTime = f'T({reDurHour}|{reDurMin}|{reDurSec})'
			reDurDate = f'({reDurDay}|{reDurMon}|{reDurYear})({reDurTime})?'
			obj['pattern'] = f'^P({reDurDate}|{reDurTime}|{reDurWeek})$'
		case 'GeneralizedTime': # X.680 Ch. 46
			obj['pattern'] = '^([0-9]{2}){4,7}([.,][0-9]*)?(Z|[-+][0-9]{4})?$'
		case 'TIME-OF-DAY': # X.680 Ch. 38.4.2, RFC 3339, ISO8601
			obj['pattern'] = f'^{reTime}$'
		case 'TIME': # X.680 Ch. 38.1.1, RFC 3339, ISO8601
			obj['pattern'] = f'^{reSpecBase}({reTimeFrac})?({reTimeOff})?$'
		case 'UTCTime': # X.680 Ch. 47
			obj['pattern'] = f'^{reHour}{reMin}({reSec})?(Z|[-+]{reHour}{reMin})$'
		# binary types
		case 'BIT STRING': # X.697 Ch. 24, hex encoded
			obj['pattern'] = '^[0-9a-fA-F]*$'
		case 'OCTET STRING': # X.697 Ch. 25, BASE64 encoded
			obj['pattern'] = '^(?:[0-9a-zA-Z+/]{4})*(?:[0-9a-zA-Z+/]{2}==|[0-9a-zA-Z+/]{3}=)?$'
		# structure types
		case 'CHOICE':
			if 'members' in desc:
				obj['type'] = 'object'
				oneOf = []
				memberNames = {m['name'] for m in desc['members']}
				if 'with-components' in desc:
					# subtyping by partial selection of choices
					selected = set()
					for specification in desc['with-components']:
						for member in specification:
							if len(member) > 1:
								raise SyntaxError(f'WITH COMPONENTS of {name} with invalid constraint.')
							m = member['name']
							if not m in memberNames:
								raise SyntaxError(f'WITH COMPONENTS field {m} is not part of {name}.')
							selected.update([m])
					memberNames = selected
				for m in desc['members']:
					if not m['name'] in memberNames:
						continue
					oneOf.append({
						'additionalProperties': False,
						'properties': jsObjectFromAsn1([m], types)
					})
				obj['oneOf'] = oneOf
		case 'SET'|'SEQUENCE':
			if 'members' in desc:
				members = resolveComponentsOf(name, desc['members'], types)
				obj['type'] = 'object'
				base = convertAsn1MemberSet(members, types)
				memberMap = {m['name']: m for m in members}
				optMemberNames = {m['name'] for m in members if 'optional' in m or 'default' in m}
				if 'with-components' in desc:
					# X.680 Ch. 51.8
					oneOf = []
					for specification in desc['with-components']:
						isPartial = False
						if specification[0] == asn1tools.parser.EXTENSION_MARKER:
							# partial specification: specify optional fields and use all members with additional constraints
							isPartial = True
							del specification[0]
						else:
							# full specification: use member list with additional constraints
							pass
						additional = []
						constrainted = set()
						present = set()
						absent = set()
						for member in specification:
							m = member['name']
							if not m in memberMap:
								raise SyntaxError(f'WITH COMPONENTS field {m} is not part of {name}.')
							if m in constrainted or m in absent:
								raise SyntaxError(f'WITH COMPONENTS field {m} of {name} can only be constrained once.')
							isPresent = True
							if 'present' in member:
								forced = member['present']
								if not m in optMemberNames:
									token = 'PRESENT' if forced else 'ABSENT'
									raise SyntaxError(f'WITH COMPONENTS field {m} of {name} with invalid {token} constraint.')
								if forced:
									present.update([m])
								else:
									absent.update([m])
									isPresent = False
								del member['present']
							if isPresent:
								constrainted.update([m])
								baseMember = memberMap[m]
								member['type'] = baseMember['type']
								if 'values' in baseMember:
									member['values'] = baseMember['values']
								additional.append(member)
						# build base variant from present members (may be a subset)
						variant = []
						for member in members:
							v = member.copy()
							m = member['name']
							if m in present:
								del v['optional']
								variant.append(v)
							elif not m in absent and (isPartial or m in constrainted):
								variant.append(v)
						if isPartial and len(constrainted) > 0:
							# members missing in partial specification remain in their original form
							for m, member in memberMap.items():
								if not m in constrainted and not m in absent:
									item = member.copy()
									item.update({'optional': m in optMemberNames})
									additional.append(item)
						# convert to JSON Schema
						hasVariantConstraint = hasAsn1Constraint(variant)
						variant = convertAsn1MemberSet(variant, types)
						if len(additional) > 0:
							additional = convertAsn1MemberSet(additional, types)
							if hasVariantConstraint:
								oneOf.append({'allOf': [variant, additional]})
							else:
								oneOf.append(additional)
						elif isPartial:
							oneOf.append(variant)
						else:
							raise SyntaxError(f'WITH COMPONENTS with missing fields in {name}.')
					obj['oneOf'] = oneOf
				else:
					obj.update(base)
		case 'SEQUENCE OF'|'SET OF':
			if 'element' in desc:
				e = desc['element']
				obj['type'] = 'array'
				if 'type' in e:
					t = jsTypeFromAsn1(name, e['type'], types)
					if t.startswith(jsDefs):
						obj['items'] = {'$ref': t}
					else:
						obj['items'] = {'type': t}
				if 'size' in desc:
					obj.update(jsRangeFromAsn1(desc['size'], 'minItems', 'maxItems'))
	if 'default' in desc:
		if asn1Base == 'BOOLEAN':
			if desc['default'] == 'TRUE':
				obj['default'] = True
			elif desc['default'] == 'FALSE':
				obj['default'] = False
		else:
			obj['default'] = desc['default']
	if '$ref' in obj and hasAsn1Constraint(desc):
		# aid schema validators by using inheritance for placing additional constraints on referenced types
		obj['allOf'] = [{'$ref': obj['$ref']}]
		del obj['$ref']
	return obj

# pylint: disable=invalid-name
def asn1tools_parser_convert_inner_type_constraints(_s, _l, tokens):
	"""! Patches asn1tools/parser.py to support ASN.1 `WITH COMPONENTS` inner subtypes. """
	tokens = tokens.asList()
	components = []

	if tokens[0] == 'WITH COMPONENTS':
		hasExtensionMarker = False
		if len(tokens[2]) > 0 and tokens[2][0] == '...':
			hasExtensionMarker = True
			tokens[2] = tokens[2][1:]
		for item_tokens in tokens[2]:
			l = len(item_tokens)
			if l == 0:
				continue
			if l == 1:
				components.append({'name': item_tokens[0]})
			else:
				item = {'name': item_tokens[0]}
				item.update(asn1tools_parser_convert_type([{}, item_tokens[1:]], {}))
				components.append(item)
		if hasExtensionMarker:
			components.insert(0, asn1tools.parser.EXTENSION_MARKER)
		return {'with-components': components}
	return {}

# pylint: disable=invalid-name
def asn1tools_parser_convert_type(tokens, parameters):
	"""! Patches asn1tools/parser.py to support ASN.1 `WITH COMPONENTS` and `PATTERN`. """
	converted_type, constraints = tokens
	restricted_to = []

	for constraint_tokens in constraints:
		if isinstance(constraint_tokens, asn1tools.parser.ParseResults):
			constraint_tokens = constraint_tokens.asList()

		if constraint_tokens == '...':
			if restricted_to:
				restricted_to.append(asn1tools.parser.EXTENSION_MARKER)

			if 'size' in converted_type:
				converted_type['size'].append(None)
		elif constraint_tokens == 'ABSENT':
			# add ABSENT support within WITH COMPONENTS
			converted_type.update({'present': False})
		elif constraint_tokens == 'PRESENT':
			# add PRESENT support within WITH COMPONENTS
			converted_type.update({'present': True})
		elif len(constraint_tokens) == 1:
			token = constraint_tokens[0]
			if not isinstance(token, dict):
				restricted_to.append(asn1tools.parser.convert_number(constraint_tokens[0]))
			elif 'size' in token:
				# merge multiple SIZE constraints
				converted_type.setdefault('size', []).extend(token['size'])
			elif 'from' in token:
				# merge multiple FROM constraints
				converted_type.setdefault('from', []).extend(token['from'])
			elif 'with-components' in token:
				# adds WITH COMPONENTS support
				if not 'with-components' in converted_type:
					converted_type['with-components'] = []
				sub_constraints = token['with-components']
				converted_type['with-components'].append(sub_constraints)
		elif isinstance(constraint_tokens, list) and len(constraint_tokens) == 2:
			# adds PATTERN support
			restricted_to.append({'PATTERN': constraint_tokens[1]})

	if isinstance(parameters, dict):
		converted_type.update(parameters)

	if '{' in restricted_to:
		restricted_to = []

	if restricted_to:
		converted_type['restricted-to'] = restricted_to

	if 'type' in converted_type:
		types = [
			'BIT STRING',
			'OCTET STRING',
			'IA5String',
			'BMPString',
			'VisibleString',
			'UTF8String',
			'NumericString',
			'PrintableString'
		]

		if converted_type['type'] in types:
			size = asn1tools.parser.convert_size(constraints)

			if size:
				converted_type['size'] = size

		if '&' in converted_type['type']:
			raise SyntaxError('Table constraints are unsupported.')

	return converted_type

def main():
	"""! Main application. """
	global jsDefs, flavor # pylint: disable=global-statement
	# patch asn1tools
	asn1tools.parser.convert_inner_type_constraints = asn1tools_parser_convert_inner_type_constraints
	asn1tools.parser.convert_type = asn1tools_parser_convert_type
	try:
		locale.setlocale(locale.LC_TIME, 'C')
	except locale.Error:
		pass
	# check dependency versions
	if asn1tools.__version__ != '0.166.0':
		print(f'asn1tools package version {asn1tools.__version__} may be incompatible. Continue [y/n]?')
		checkedVersion = False
		while not checkedVersion:
			answer = input()
			if answer in ['y', 'Y']:
				checkedVersion = True
			elif answer in ['n', 'N']:
				sys.exit(1)
	# command-line parser
	cmdLine = argparse.ArgumentParser(
		formatter_class = argparse.RawTextHelpFormatter,
		description = 'Converts an ASN.1 Schema to a given output format.\nOutput is written to standard out.'
	)
	cmdLine.add_argument('-f', '--flavor', default = 'json', choices = ['json', 'openapi'],
		help = '''sets the output format flavor (default: %(default)s)
json - JSON schema
openapi - OpenAPI schema''')
	cmdLine.add_argument('-t', '--target', default = 'json', choices = ['json', 'yaml'],
		help = '''sets the target format (default: %(default)s)
json - JSON
yaml - YAML''')
	cmdLine.add_argument('-e', '--export', action = 'store_true', help = 'bring all types to global scope')
	cmdLine.add_argument('schema', nargs = 1)
	args = cmdLine.parse_args()
	# conversion routine
	try:
		if args.flavor == 'openapi':
			if args.export:
				raise SyntaxError('The -e/--export command-line switch is not supported for OpenAPI flavor.')
			jsDefs = '#/components/schemas/'
		flavor = args.flavor
		schema = asn1tools.parse_files(args.schema[0])
		#print(prettify(schema)) # print asn1tools internal schema representation
		res = {}
		schemaId = ''
		for k, s in schema.items():
			schemaId = k
			defs = {}
			exports = []
			asn1Types = s['types']
			for n, t in asn1Types.items():
				obj = convertAsn1Type(n, t, asn1Types)
				title = obj['title']
				del obj['title']
				defs.update({title: obj})
				exports.append({
					'additionalProperties': False,
					'properties': {
						title: {'$ref': jsDefs + title}
					}
				})
			break # use only first schema
		match args.flavor:
			case 'json':
				res = {
					'$id': schemaId,
					'$schema': 'https://json-schema.org/draft/2020-12/schema',
					'$defs': defs
				}
				if exports and args.export:
					res['type'] = 'object'
					res['minProperties'] = 1
					res['maxProperties'] = 1
					res['oneOf'] = exports
			case 'openapi':
				res = {
					'openapi': '3.1.0',
					'info': {
						'title': schemaId,
						'version': 'tbd'
					},
					'components': {
						'schemas': defs
					}
				}
		match args.target:
			case 'json':
				print(json.dumps(res, indent = 2))
			case 'yaml':
				print(yaml.safe_dump(res, allow_unicode = False, default_flow_style = False, width = 8192, sort_keys = False))
	except asn1tools.parser.ParseError as err:
		print(err, file = sys.stderr)
	except SyntaxError as err:
		print(err, file = sys.stderr)

# main entry point
if __name__ == '__main__':
	main()
