"""A minimal S3-backed MCP document server for the controlled AWS lab.

Only loopback HTTP; remote connections must go through a secure SSM tunnel.
AWS credentials are supplied by the EC2 IAM instance role, never by this app.
"""
from __future__ import annotations

import os
import re

import boto3
from botocore.exceptions import ClientError
from mcp.server.fastmcp import FastMCP

BUCKET = os.environ["MCP_DOCUMENTS_BUCKET"]
REGION = os.environ.get("AWS_REGION", "eu-west-3")
MAX_BYTES = 32 * 1024
FILE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}\.txt\Z")
READ_KEY = re.compile(r"(?:demo/)?[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}\.txt\Z")

mcp = FastMCP(
    "MCP Document Server",
    host="127.0.0.1",
    port=8000,
    stateless_http=True,
    json_response=True,
)


def _s3():
    return boto3.client("s3", region_name=REGION)


def _validate_read_key(key: str) -> str:
    if not isinstance(key, str) or not READ_KEY.fullmatch(key) or ".." in key:
        raise ValueError("Invalid document key.")
    return key


def _validate_demo_filename(filename: str) -> str:
    if not isinstance(filename, str) or not FILE_NAME.fullmatch(filename) or ".." in filename:
        raise ValueError("Only simple .txt filenames are allowed.")
    return "demo/" + filename


def _raise_clean_s3_error(exc: ClientError) -> None:
    code = str(exc.response.get("Error", {}).get("Code", ""))
    if code in {"AccessDenied", "403"}:
        raise PermissionError("AWS IAM denied this S3 operation.") from None
    if code in {"NoSuchKey", "NotFound", "404"}:
        raise FileNotFoundError("Document not found.") from None
    if code in {"PreconditionFailed", "412"}:
        raise ValueError("A document with this filename already exists.") from None
    raise RuntimeError("S3 operation failed.") from None


@mcp.tool()
def list_documents() -> list[str]:
    """List text documents in the company's approved S3 document bucket."""
    try:
        pages = _s3().get_paginator("list_objects_v2").paginate(
            Bucket=BUCKET, PaginationConfig={"MaxItems": 1000}
        )
        return sorted(
            entry["Key"]
            for page in pages
            for entry in page.get("Contents", ())
            if entry["Key"].endswith(".txt")
        )
    except ClientError as exc:
        _raise_clean_s3_error(exc)


@mcp.tool()
def read_document(key: str) -> str:
    """Read an approved UTF-8 .txt document by its key in the document bucket."""
    key = _validate_read_key(key)
    try:
        response = _s3().get_object(Bucket=BUCKET, Key=key)
        body = response["Body"]
        try:
            data = body.read(MAX_BYTES + 1)
        finally:
            body.close()
        if len(data) > MAX_BYTES:
            raise ValueError("Document is too large for this demo.")
        return data.decode("utf-8")
    except ClientError as exc:
        _raise_clean_s3_error(exc)
    except UnicodeDecodeError:
        raise ValueError("Document must be UTF-8 text.") from None


@mcp.tool()
def upload_document(filename: str, content: str) -> str:
    """Upload a new UTF-8 text document under the restricted demo/ prefix."""
    key = _validate_demo_filename(filename)
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Document content must be UTF-8 text under 32 KiB.")
    try:
        _s3().put_object(
            Bucket=BUCKET, Key=key, Body=content.encode("utf-8"),
            ContentType="text/plain; charset=utf-8",
            ServerSideEncryption="AES256", IfNoneMatch="*",
        )
        return f"Created {key}"
    except ClientError as exc:
        _raise_clean_s3_error(exc)


@mcp.tool()
def delete_document(filename: str) -> str:
    """Delete a test document only under the restricted demo/ prefix."""
    key = _validate_demo_filename(filename)
    try:
        _s3().delete_object(Bucket=BUCKET, Key=key)
        return f"Deleted {key}"
    except ClientError as exc:
        _raise_clean_s3_error(exc)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
