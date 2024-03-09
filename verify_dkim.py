import traceback

import dkim
import sys


def verify_dkim_signature(eml_file_path):
    with open(eml_file_path, 'rb') as file:
        email_data = file.read()
    dkim_signature_exists = b"DKIM-Signature" in email_data

    if not dkim_signature_exists:
        return False, "No DKIM-Signature found in the email."

    try:
        # dkim_header = dkim.signature.Signature.from_email(email_data)
        dnsfunc = dkim.dnsplug.get_txt
        verified = dkim.verify(email_data, dnsfunc=dnsfunc)
    except Exception as e:
        # print stack trace
        traceback.print_exc()
        return False, str(e)

    return verified, "DKIM Signature valid." if verified else "Invalid DKIM Signature."


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python verify_dkim.py <eml_file_path>")
        sys.exit(1)

    eml_file_path = sys.argv[1]
    result, message = verify_dkim_signature(eml_file_path)
    print(message)
