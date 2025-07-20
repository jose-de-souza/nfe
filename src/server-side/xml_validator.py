import argparse
import json
import sys
from lxml import etree
from pathlib import Path

class NFeValidator:
    def __init__(self, schema_dir=None):
        """
        Initialize the NFe validator with the directory containing XSD schemas.
        
        Args:
            schema_dir (str or Path, optional): Path to the directory containing XSD files.
                                               Defaults to the script's directory.
        """
        if schema_dir is None:
            schema_dir = Path(__file__).parent
        self.schema_dir = Path(schema_dir)
        self.schemas = {
            "enviNFe": self._load_schema("leiauteNFe_v4.00.xsd"),
            "consStatServ": self._load_schema("leiauteConsStatServ_v4.00.xsd")
        }

    def _load_schema(self, schema_file):
        """
        Load an XSD schema and resolve dependencies.
        
        Args:
            schema_file (str): Name of the XSD file.
        
        Returns:
            etree.XMLSchema: The loaded XML schema object.
        
        Raises:
            FileNotFoundError: If schema file is missing.
            etree.XMLSchemaParseError: If schema parsing fails.
        """
        schema_path = self.schema_dir / schema_file
        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")

        try:
            schema_doc = etree.parse(str(schema_path))
            schema_doc.set_base_url(str(self.schema_dir))
            schema = etree.XMLSchema(schema_doc)
            return schema
        except etree.XMLSchemaParseError as e:
            raise etree.XMLSchemaParseError(f"Failed to parse schema {schema_file}: {e}")

    def validate_xml(self, xml_content):
        """
        Validate XML content against the appropriate NFe schema.
        
        Args:
            xml_content (str or bytes): The XML content to validate.
        
        Returns:
            dict: Validation result with status and optional error messages.
        """
        result = {"status": "success", "errors": []}

        try:
            # Parse XML content
            if isinstance(xml_content, str):
                xml_content = xml_content.encode('utf-8')
            xml_doc = etree.fromstring(xml_content)

            # Determine schema based on root element
            root_tag = xml_doc.tag.split('}')[-1] if '}' in xml_doc.tag else xml_doc.tag
            schema = self.schemas.get(root_tag)
            if not schema:
                result["status"] = "error"
                result["errors"].append(f"No schema defined for root element: {root_tag}")
                return result

            # Validate against schema
            schema.assertValid(xml_doc)
            return result
        except etree.XMLSyntaxError as e:
            result["status"] = "error"
            result["errors"].append(f"XML syntax error: {str(e)}")
            return result
        except etree.DocumentInvalid as e:
            result["status"] = "error"
            result["errors"].extend([str(error) for error in schema.error_log])
            return result
        except Exception as e:
            result["status"] = "error"
            result["errors"].append(f"Unexpected error during validation: {str(e)}")
            return result

def main():
    parser = argparse.ArgumentParser(description="Validate NFe XML against SEFAZ schemas.")
    parser.add_argument("--xml", help="XML content to validate (or pass via stdin)")
    args = parser.parse_args()

    # Get XML content from argument or stdin
    if args.xml:
        xml_content = args.xml
    else:
        xml_content = sys.stdin.read().strip()

    if not xml_content:
        result = {"status": "error", "errors": ["No XML content provided"]}
        print(json.dumps(result))
        sys.stdout.flush()
        sys.exit(1)

    # Initialize validator
    try:
        validator = NFeValidator()
        result = validator.validate_xml(xml_content)
        print(json.dumps(result))
        sys.stdout.flush()
    except FileNotFoundError as e:
        result = {"status": "error", "errors": [f"Schema error: {str(e)}"]}
        print(json.dumps(result))
        sys.stdout.flush()
        sys.exit(1)
    except etree.XMLSchemaParseError as e:
        result = {"status": "error", "errors": [f"Schema error: {str(e)}"]}
        print(json.dumps(result))
        sys.stdout.flush()
        sys.exit(1)
    except Exception as e:
        result = {"status": "error", "errors": [f"Unexpected error: {str(e)}"]}
        print(json.dumps(result))
        sys.stdout.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()