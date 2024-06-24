ASN.1 Converter
===============

Collection of tools and information for ASN.1 schema conversion.

The main application is the conversion from ASN.1 schema to JSON schema and/or OpenAPI schema.

References
==========

ASN.1
-----

- Quick Reference (https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference.html)
- Standard Introduction (https://www.itu.int/en/ITU-T/asn1/Pages/introduction.aspx)
- ECMA-35 Character Encoding (https://ecma-international.org/publications-and-standards/standards/ecma-35/)
- T.50 IA5 Character Encoding (https://www.itu.int/rec/T-REC-T.50-199209-I/en)
- X.680 Basic Notation Specification (https://www.itu.int/rec/T-REC-X.680-202102-I/en)
- X.681 Information Object Specification (https://www.itu.int/rec/T-REC-X.681-202102-I/en)
- X.682 Constraint Specification (https://www.itu.int/rec/T-REC-X.682-202102-I/en)
- X.683 Parameterization Specification (https://www.itu.int/rec/T-REC-X.683-202102-I/en)
- X.697 JSON Encoding Rules (https://www.itu.int/rec/T-REC-X.697-202102-I/en)

JSON
----

- ECMA-404 JSON Specification (https://ecma-international.org/publications-and-standards/standards/ecma-404/)
- OpenAPI 3.1.0 (https://spec.openapis.org/oas/v3.1.0)
- JSON Schema 2020-12 Core Specification (https://json-schema.org/draft/2020-12/json-schema-core)
- JSON Schema 2020-12 Validation Specification (https://json-schema.org/draft/2020-12/json-schema-validation)
- YAML 1.2.2 (https://yaml.org/spec/1.2.2/)

Tools
=====

The following dependencies are given:  
- Python 3.10 or newer (https://www.python.org/)
- asn1tools 0.166.0 (https://github.com/eerimoq/asn1tools)
- pyyaml (https://github.com/yaml/pyyaml)

Additionally, pylint can be used for code review:
```sh
pylint src/*.py
```

asn1Conv.py
-----------

Converts an ASN.1 schema to a different format.
Note that only a subset of ASN.1 is supported.

Execution examples:
```sh
python src/asn1Conv.py --target json etc/schema.asn
python src/asn1Conv.py --target yaml etc/schema.asn
```

It is also possible to create an output in OpenAPI flavor:
```sh
python src/asn1Conv.py --flavor openapi --target yaml etc/schema.asn
```

### Known Limitations

- The `CLASS` keyword (X.681) and its friends are not supported.
- Parameterization (X.683) is not supported.
- The `EMBEDDED PDV` type is not supported.
- The `ANY` and `ANY DEFINED BY` types are not supported. They were removed from the ASN.1 standard 1994.
- The `DURATION` type is not supported.
- The `INTERSECTION` and `UNION` keywords are not handled distinct. It is treated like `UNION` for same elements and `INTERSETION` for others.
- The keywords `PLUS-INFINITY`, `MINUS-INFINITY` and `NOT-A-NUMBER` cannot be mapped to JSON Schema, hence, are unsupported.
- `WITH COMPONENTS` for `SEQUENCE OF` and `SET OF` is not supported.
- Extensions and extension groups are not supported.
- Only closed value ranges are supported. Not open value ranges.
- Table constraints are not supported.
- Extension markers are not supported.
- The `ALL EXCEPT` constraint is not supported.
- The `IMPORTS` keyword is not supported.
- The `SETTINGS` keyword is not supported.
- XML notation is not supported.

asn1Test.py
-----------

Test whether a given JSON file conforms to an ASN.1 schema.

Execution examples:
```sh
python src/asn1Test.py --schema etc/schema.asn --element OBSessionOpenData etc/OBSessionOpenData_err.json
python src/asn1Test.py --schema etc/schema.asn --element OBSessionOpenData etc/OBSessionOpenData_ok.json
```

### Known Limitations

- The `CLASS` keyword (X.681) and its friends are not supported.
- Parameterization (X.683) is not supported.
- The `EMBEDDED PDV` type is not supported.
- The `ANY` and `ANY DEFINED BY` types are not supported. They were removed from the ASN.1 standard 1994.
- The date and time related types are not supported.
- The `INTERSECTION` and `UNION` keywords are not handled distinct. It is treated like `UNION` for same elements and `INTERSETION` for others.
- The keywords `PLUS-INFINITY`, `MINUS-INFINITY` and `NOT-A-NUMBER` cannot be mapped to JSON Schema, hence, are unsupported.
- `WITH COMPONENTS` is not supported.
- Extensions and extension groups are not supported.
- Only closed value ranges are supported. Not open value ranges.
- Table constraints are not supported.
- Extension markers are not supported.
- The `ALL EXCEPT` constraint is not supported.
- The `PATTERN` constraint is not supported.
- The `IMPORTS` keyword is not supported.
- The `SETTINGS` keyword is not supported.
- XML notation is not supported.

Other Resources
---------------

- asn1editor (https://github.com/Futsch1/asn1editor)
- ASN.1 for Rust (https://github.com/librasn/compiler)
- JSON Schema Validator (https://jsoneditoronline.org/indepth/validate/json-schema-validator/)
- JSON Schema Linter (https://www.json-schema-linter.com/)
- schemalint for JSON schema (https://github.com/giantswarm/schemalint)
- OpenAPI of 3GPP Services (https://forge.3gpp.org/rep/all/5G_APIs)
- IBM OpenAPI Linter (https://github.com/IBM/openapi-validator)

# License

This project is licensed under the [MIT](LICENSE) license.
