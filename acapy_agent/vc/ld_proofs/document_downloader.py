"""Quick and dirty fix to use as alternative to pyld downloader.

Allows keeping some context in local filesystem.
"""

import logging
import re
import string
import urllib.parse as urllib_parse
from importlib import resources
from typing import Dict, Optional

import requests
from pyld import jsonld
from pyld.jsonld import LINK_HEADER_REL, JsonLdError, parse_link_header

from ...version import __version__

logger = logging.getLogger(__name__)


def _load_jsonld_file(
    original_url, filename: str, resource_path: str = f"{__package__}.resources"
):
    """Load context from package.

    Given a URL and filename,
    load a context in the format used by pyld document loader.
    """
    return {
        "contentType": "application/ld+json",
        "contextUrl": None,
        "documentUrl": original_url,
        "document": (resources.files(resource_path) / filename).read_text(),
    }


class StaticCacheJsonLdDownloader:
    """Context downloader with filesystem static cache for common contexts."""

    CONTEXT_FILE_MAPPING = {
        "https://www.w3.org/2018/credentials/v1": "credentials_context.jsonld",
        "https://www.w3.org/ns/credentials/v2": "credentials_v2_context.jsonld",
        "https://w3id.org/vc/status-list/2021/v1": "status_list_context.jsonld",
        "https://www.w3.org/ns/did/v1": "did_documents_context.jsonld",
        "https://w3id.org/security/v1": "security-v1-context.jsonld",
        "https://w3id.org/security/v2": "security-v2-context.jsonld",
        "https://w3id.org/security/suites/ed25519-2020/v1": "ed25519-2020-context.jsonld",
        "https://w3id.org/security/bbs/v1": "bbs-v1-context.jsonld",
        "https://identity.foundation/presentation-exchange/submission/v1": (
            "dif-presentation-exchange-submission-v1.jsonld"
        ),
    }

    def __init__(
        self,
        document_downloader: Optional["JsonLdDocumentDownloader"] = None,
        document_parser: Optional["JsonLdDocumentParser"] = None,
    ):
        """Load static document on initialization."""
        self.documents_downloader = document_downloader or JsonLdDocumentDownloader()
        self.document_parser = document_parser or JsonLdDocumentParser()

        self.cache = {
            url: self.document_parser.parse(_load_jsonld_file(url, filename), None)
            for url, filename in StaticCacheJsonLdDownloader.CONTEXT_FILE_MAPPING.items()
        }

    def load(self, url: str, options: Optional[Dict] = None):
        """Load a jsonld document from URL.

        Prioritize local static cache before attempting to download from the URL.
        """
        cached = self.cache.get(url)

        if cached is not None:
            logger.info("Local cache hit for context: %s", url)
            return cached

        logger.debug("Context %s not in static cache, resolving from URL.", url)
        return self._live_load(url, options)

    def _live_load(self, url: str, options: Optional[Dict] = None):
        doc, link_header = self.documents_downloader.download(url, options)
        return self.document_parser.parse(doc, link_header)


class JsonLdDocumentDownloader:
    """JsonLd documents downloader."""

    def download(self, url: str, options: Optional[Dict], **kwargs):
        """Retrieves JSON-LD at the given URL.

        This was lifted from pyld.documentloader.requests.

        :param url: the URL to retrieve.
        :param options:

        :return: the RemoteDocument.

        """
        options = options or {}

        try:
            # validate URL
            pieces = urllib_parse.urlparse(url)
            if (
                not all([pieces.scheme, pieces.netloc])
                or pieces.scheme not in ["http", "https"]
                or set(pieces.netloc) > set(string.ascii_letters + string.digits + "-.:")
            ):
                raise JsonLdError(
                    'URL could not be dereferenced; only "http" and "https" '
                    "URLs are supported.",
                    "jsonld.InvalidUrl",
                    {"url": url},
                    code="loading document failed",
                )
            if options.get("secure") and pieces.scheme != "https":
                raise JsonLdError(
                    "URL could not be dereferenced; secure mode enabled and "
                    'the URL\'s scheme is not "https".',
                    "jsonld.InvalidUrl",
                    {"url": url},
                    code="loading document failed",
                )
            headers = options.get("headers")
            if headers is None:
                headers = {"Accept": "application/ld+json, application/json"}
            headers["User-Agent"] = f"AriesCloudAgent/{__version__}"
            response = requests.get(url, headers=headers, **kwargs)

            content_type = response.headers.get("content-type")
            if not content_type:
                content_type = "application/octet-stream"
            doc = {
                "contentType": content_type,
                "contextUrl": None,
                "documentUrl": response.url,
                "document": response.json(),
            }

            return doc, response.headers.get("link")
        except Exception as cause:
            raise JsonLdError(
                "Could not retrieve a JSON-LD document from the URL.",
                "jsonld.LoadDocumentError",
                code="loading document failed",
                cause=cause,
            )


class JsonLdDocumentParser:
    """JsonLd documents parser."""

    def parse(self, doc: Dict, link_header: Optional[str]):
        """Parse a jsonld document after retrieval.

        This was lifted from pyld.documentloader.requests.
        """
        try:
            if link_header:
                linked_context = parse_link_header(link_header).get(LINK_HEADER_REL)
                # only 1 related link header permitted
                if linked_context and doc["content_type"] != "application/ld+json":
                    if isinstance(linked_context, list):
                        raise JsonLdError(
                            "URL could not be dereferenced, "
                            "it has more than one "
                            "associated HTTP Link Header.",
                            "jsonld.LoadDocumentError",
                            {"url": doc["url"]},
                            code="multiple context link headers",
                        )
                    doc["contextUrl"] = linked_context["target"]
                linked_alternate = parse_link_header(link_header).get("alternate")
                # if not JSON-LD, alternate may point there
                if (
                    linked_alternate
                    and linked_alternate.get("type") == "application/ld+json"
                    and not re.match(r"^application\/(\w*\+)?json$", doc["content_type"])
                ):
                    doc["contentType"] = "application/ld+json"
                    doc["documentUrl"] = jsonld.prepend_base(
                        doc["url"], linked_alternate["target"]
                    )
            return doc
        except JsonLdError as e:
            raise e
        except Exception as cause:
            raise JsonLdError(
                "Could not retrieve a JSON-LD document from the URL.",
                "jsonld.LoadDocumentError",
                code="loading document failed",
                cause=cause,
            )
