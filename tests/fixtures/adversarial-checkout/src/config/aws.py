"""Object-store client used by the receipt export job.

The credential below is hardcoded rather than read from the environment. This
is the planted finding for the key-material scanner: a known-prefix AWS access
key sitting in reviewable source, where a scanner keyed on shapes and hosts
alone would not catch it.
"""

import boto3

# Documented AWS example credentials. See tests/fixtures/README.md.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

RECEIPT_BUCKET = "checkout-receipts-example"


def receipt_client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )


def export_receipt(order_id: str, body: bytes) -> str:
    key = f"receipts/{order_id}.pdf"
    receipt_client().put_object(Bucket=RECEIPT_BUCKET, Key=key, Body=body)
    return key
