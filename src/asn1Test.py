"""!
@file asn1Test.py
@author Daniel Starke
@copyright (C) Copyright Siemens Mobility GmbH, 2024. All rights reserved.
@version $Id$

Test whether a given JSON file conforms to an ASN.1 schema.
Tested with asn1tools 0.166.0.
"""
# SPDX-License-Identifier: MIT

import json
import locale
import argparse
import asn1tools

# pylint: disable=invalid-name,too-many-branches
def asn1tools_parser_convert_type(tokens, parameters):
	"""! Patches asn1tools/parser.py to support constraint unions ASN.1. """
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
		elif len(constraint_tokens) == 1:
			token = constraint_tokens[0]
			if not isinstance(token, dict):
				token = asn1tools.parser.convert_number(constraint_tokens[0])
				if isinstance(token, tuple):
					restricted_to.append(token)
			elif 'size' in token:
				# merge multiple SIZE constraints
				converted_type.setdefault('size', []).extend(token['size'])
			elif 'from' in token:
				# merge multiple FROM constraints
				converted_type.setdefault('from', []).extend(token['from'])

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
	# patch asn1tools
	asn1tools.parser.convert_type = asn1tools_parser_convert_type
	try:
		locale.setlocale(locale.LC_TIME, 'C')
	except locale.Error:
		pass
	cmdLine = argparse.ArgumentParser(description = 'Test whether a given JSON file conforms to an ASN.1 schema.')
	cmdLine.add_argument('-s', '--schema', nargs = 1, required = False, default = 'schema.asn', dest = 'schema',
		help = 'Path to the used ASN.1 schema file. Defaults to "schema.asn".')
	cmdLine.add_argument('-e', '--element', nargs = 1, required = True, dest = 'element',
		help = 'The ASN.1 element name the input is based on.')
	cmdLine.add_argument('file', nargs = '+')
	args = cmdLine.parse_args()
	try:
		schema = asn1tools.compile_files(args.schema[0], codec = "jer")
		for file in args.file:
			print(file + '(' + args.element[0] + '):')
			with open(file, encoding = 'utf-8') as f:
				content = f.read()
			try:
				internalRepr = schema.decode(args.element[0], bytearray(content, 'utf-8'), True)
				externalRepr = schema.encode(args.element[0], internalRepr)
				print(json.dumps(json.loads(externalRepr), indent = 2))
			except asn1tools.codecs.ConstraintsError as err:
				print(err)
	except asn1tools.parser.ParseError as err:
		print(err)

if __name__ == '__main__':
	main()
