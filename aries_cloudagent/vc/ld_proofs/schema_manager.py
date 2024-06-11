"""Manage schemas for validating VCs.

Caches schemas which have been fetched in memory.
"""
import json
import string
from jsonschema import Draft201909Validator, ValidationError
import jsonschema
import requests
from aries_cloudagent.vc.vc_ld.models.credential import VerifiableCredential


import logging
from typing import Dict, List, Optional
from ...version import __version__
import urllib.parse as urllib_parse

logger = logging.getLogger(__name__)

class VcSchemaManagerError(Exception):
    """Generic VcSchemaManager Error."""

class VcSchemaValidatorError(Exception):
    """Generic VcSchemaValidator Error."""

class VcSchemaValidator:
    """Verifiable Credential Schema Validator."""
    def __init__(
        self,
        schema_manager: Optional["VcSchemaManager"] = None):
        """TODO."""
        self.schema_manager = schema_manager or VcSchemaManager()

    def validate(self, vc: VerifiableCredential):
        """Validates a given VerifiableCredential against its credentialSchema.

        :param vc: the Verifiable Credential to validate
        :raises VcSchemaValidatorError: errors for invalid Credential
        :return: True if Verifiable Credential is valid
        """
        if not vc.credential_schema:
                raise VcSchemaValidatorError("Credential schema is required")
        vc_schemas = vc.credential_schema

        validation_errors = []

        for vc_schema in vc_schemas:
            schema_type = vc_schema.get('type')
            schema_id = vc_schema.get('id')
            
            validator = self.schema_manager.get_validator(schema_type, schema_id)
            vc_json = json.loads(vc.to_json())

            validation_errors.extend(validator.iter_errors(vc_json))
        
        if len(validation_errors) > 0:
            formatted  = self.format_validation_errors(validation_errors)
            raise VcSchemaValidatorError(formatted)

        return True
    
    def format_validation_errors(self, errors:List[ValidationError]):
        """Formats a list of errors from validating the VC.

        :param errors: the errors to format
        """

        by_relevance = sorted(errors, key=jsonschema.exceptions.relevance)

        error_details = []

        def traverse_errors(errors):
            for error in errors:
                if error.context is not None:
                    traverse_errors(error.context)

                details = {
                    "reason": str(error.message),
                    "credential_path": str('$.' + '.'.join([str(item) for item in error.relative_path])),
                    "schema_path": [str(item) for item in error.relative_schema_path]
                }
                error_details.append(details)

        traverse_errors(by_relevance)

        prefix = "Credential does not conform to Schema"

        error = {
            "message": prefix,
            "details": error_details
        }
        return json.dumps(error)





class VcSchemaManager:
    """Manages the enumeration and retrieval of VC Credential Schema."""
    def __init__(
        self,
        schema_downloader: Optional["VcSchemaDownloader"] = None):
        self.schema_downloader = schema_downloader or VcSchemaDownloader()
        self.cache = {} 
    
    """Gets the validator object depending on the schema type"""
    def get_validator(self, schema_type:str, schema_id:Optional[str]):
        """Gets the appropriate supported validator.

        :param schema_type: the type of 
        :param schema_id: the URL $id of the schema
        
        :return: validator class object

        """

        if schema_type == '1EdTechJsonSchemaValidator2019':
            schema = self.load(schema_id, {"TLS_1_3": True})
            validator = Draft201909Validator(schema['document'], format_checker=Draft201909Validator.FORMAT_CHECKER,

)
            validator.check_schema(schema['document'])
            return validator
                    
        else:
            raise VcSchemaManagerError(
                'The schema type provided',
                    schema_type,
                'is unsupported')

    def load(self, url: str,  options: Optional[Dict] = None):
        """Load a schema document from URL.

        Prioritize local static cache before attempting to download from the URL.
        """
        cached = self.cache.get(url)

        if cached is not None:
            logger.info("Cache hit for context: %s", url)
            return cached

        logger.debug("Schema %s not in static cache, resolving from URL.", url)
        return self._live_load(url, options)
    
    def _live_load(self, url: str, options: Optional[Dict] = None):
        doc = self.schema_downloader.download(url, options)
        self.cache[url] = doc
        return doc


class VcSchemaDownloader:
    """Verifiable Credential Schema Downloader."""
    def download(self, url: str, options: Optional[Dict], **kwargs):
        """Retrieves a schema JSON document from the given URL.

        :param url: the URL of the schema to download
        :param options: _description_
        :return: _description_
        """
        options = options or {}

        try:
            # validate URL
            pieces = urllib_parse.urlparse(url)
            if (
                not all([pieces.scheme, pieces.netloc])
                or pieces.scheme not in ["http", "https"]
                or set(pieces.netloc)
                > set(string.ascii_letters + string.digits + "-.:")
            ):
                raise VcSchemaManagerError(
                    'URL could not be dereferenced; only "http" and "https" '             
                    "URLs are supported.", 
                    {"url": url})

        except Exception as cause:
            raise VcSchemaManagerError(cause)
        headers = options.get("headers")
        if headers is None:
            headers = {"Accept": "application/json"}
        headers["User-Agent"] = f"AriesCloudAgent/{__version__}"

        if options.get("TLS_1_3"):
            pass # TODO
        else:
            pass
        
        response = requests.get(url, headers=headers, **kwargs)

        content_type = response.headers.get("content-type")
        if not content_type:
            content_type = "application/octet-stream"
        doc = {
            "contentType": content_type,
            "documentUrl": response.url,
            "document": response.json(),
        }
        return doc


