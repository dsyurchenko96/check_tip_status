import os
import hashlib
import json
import sys
import http.client
import logging
import ssl
from urllib.parse import quote
import subprocess
import platform

error_dict = {
    400: "Request not processed: incorrect query.",
    401: "Request not processed: user authentication failed.",
    403: "Request not processed: quota or request limit exceeded.",
    404: "Request not processed: requested object lookup results not found.",
    413: "Request not processed: file size exceeds a size limit.",
}


def main():
    """Main function to process files and interact with TIP API."""
    if len(sys.argv) < 3:
        print(
            "Usage: python check_tip_status.py <token_file_path> <file_path1> [<file_path2> ...]"
        )
        logger.error("Insufficient arguments provided")
        sys.exit(1)

    token_file_path = os.path.abspath(sys.argv[1])
    file_paths = [os.path.abspath(file_path) for file_path in sys.argv[2:]]
    cert_name = "cert_chain.pem"

    if not os.path.isfile(cert_name):
        fetch_certificate_chain(cert_name)

    context = create_ssl_context(cert_name)
    token = read_token(token_file_path)
    results = []

    for file_path in file_paths:
        result = process_file(file_path, token, context)
        results.append(result)

    print(json.dumps(results, indent=4))
    logger.info("Processing complete")


def fetch_certificate_chain(cert_name: str) -> None:
    """
    Fetches the certificate chain from the server and saves it to a file. It uses a subprocess to execute
    the command to download the certificate chain. The command uses the `openssl` command to download the
    certificate chain and save it to a file. The `2>/dev/null` and `</dev/null` redirections are used to, first,
    remove the default stderr cluttering output from the command, and, second, not expect any further input
    from the user so that the command execution doesn't hang.

    :param cert_name: the path to the certificate chain
    :return: None
    """
    logger.info("Downloading certificate chain")
    command = f"openssl s_client -connect opentip.kaspersky.com:443 -showcerts 2>/dev/null </dev/null > {cert_name}"
    if platform.system() == "Windows":
        command = "winpty " + command
    subprocess.run(command, shell=True, check=True)
    logger.info(f"Certificate chain saved to {cert_name}")


def create_ssl_context(cert_name: str) -> ssl.SSLContext:
    """
    Creates an SSL context using the specified certificate chain. Then, it attempts to connect to the server
    using the context which is supposed to contain the full chain. If the connection isn't successful, try to
    update the certificates installed on your system and try again or remove the verification.

    :param cert_name: the path to the certificate chain
    :return: the SSL context used to connect to TIP
    """
    context = ssl.create_default_context(cafile=cert_name)
    try:
        http.client.HTTPSConnection("opentip.kaspersky.com", context=context).connect()
        logger.info("Certificate loaded successfully")
    except ssl.SSLCertVerificationError as e:
        # alternatively, you can uncomment the line below and comment the rest of the block to remove the verification
        # ssl._create_default_https_context = ssl._create_unverified_context

        print(
            f"Certificate verification failed. Please check {cert_name} and update your certificates."
        )
        logger.error(f"Certificate verification failed, error:\n{e}")
        exit(1)
    return context


def process_file(file_path: str, token: str, context: ssl.SSLContext) -> dict:
    """
    Processes a single file, checking its hash and possibly uploading it to TIP.

    :param file_path: the path of the file to be processed
    :param token: the user's API token
    :param context: the SSL context used to connect to TIP
    :return: a dictionary containing the file path and the response from TIP (either successful or an error message)
    """
    if not os.path.isfile(file_path):
        error = f"Invalid or non-existent file path: {file_path}"
        logger.error(error)
        return {"file_path": file_path, "error": error}

    md5_hash = calculate_md5(file_path)
    if md5_hash is None:
        error = f"Error calculating MD5 hash for file: {file_path}"
        logger.error(error)
        return {"file_path": file_path, "error": error}

    status, response = check_hash(md5_hash, token, context)

    if status == 404:
        logger.info(
            f"File {file_path} not found in TIP. Uploading for basic file analysis..."
        )
        status, response = upload_file(file_path, token, context)
    if status == 200:
        return {"file_path": file_path, "response": response}

    error = error_dict[status]
    logger.error(error)
    return {"file_path": file_path, "error": error}


def read_token(token_file_path: str) -> str:
    """
    Reads the API token from a file if it exists.

    :param token_file_path: the path to the token file
    :return: the token read from the file
    """
    try:
        with open(token_file_path, "r") as file:
            token = file.readline().strip()
        logger.info(f"Token read successfully from {token_file_path}")
        return token
    except FileNotFoundError:
        error = f"File not found at {token_file_path}"
        print(error)
        logger.error(error)
        sys.exit(1)


def calculate_md5(file_path: str) -> str | None:
    """
    Calculates the MD5 hash of a file by reading its contents
    a set number of bytes at a time and updating the hash.

    :param file_path: the path to the file to be hashed
    :return: the MD5 hash of the file (or None if an error occurred)
    """
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_md5.update(chunk)
        md5_hash = hash_md5.hexdigest()
        logger.debug(f"MD5 hash for file {file_path} is {md5_hash}")
        return md5_hash
    except FileNotFoundError:
        logger.error(f"File not found at {file_path}")
        return None


def http_get(
    host: str, path: str, headers: dict, context: ssl.SSLContext = None
) -> tuple[int, str]:
    """
    Attempts to perform a GET request.

    :param host: the host name of the TIP server
    :param path: the path of the request
    :param headers: the headers of the request
    :param context: the SSL context used to connect to TIP
    :return: the response from TIP as a tuple of (status code, response body)
    """
    try:
        connection = http.client.HTTPSConnection(host, context=context)
        logger.debug(f"GET request to {path} started")
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        logger.info(f"GET request to {path} returned status {response.status}")
        return response.status, data.decode()
    except ValueError as e:
        logger.error(f"Invalid value, error:\n{e}")
        print(f"Invalid value(s) in the request data.")
        exit(1)


def http_post(
    host: str, path: str, headers: dict, body: bytes, context: ssl.SSLContext = None
) -> tuple[int, str]:
    """
    Attempts to perform a POST request.

    :param host: the host name of the TIP server
    :param path: the path of the request
    :param headers: the headers of the request
    :param body: the body of the request in byte form, specifically the uploaded file contents (POST data)
    :param context: the SSL context used to connect to TIP
    :return: the response from TIP as a tuple of (status code, response body)
    """
    try:
        connection = http.client.HTTPSConnection(host, context=context)
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        logger.info(f"POST request to {path} returned status {response.status}")
        return response.status, data.decode()
    except ValueError as e:
        logger.error(f"Invalid value, error:\n{e}")
        print(f"Invalid value(s) in the request data.")
        exit(1)


def check_hash(
    md5_hash: str, token: str, context: ssl.SSLContext = None
) -> tuple[int, str | None]:
    """
    Checks whether TIP contains a record of the specified file using the API.

    :param md5_hash: the MD5 hash of the file
    :param token: the user's API token
    :param context: the SSL context used to connect to TIP
    :return: the response from TIP as a tuple of (status code, response body)
    """
    host = "opentip.kaspersky.com"
    path = f"/api/v1/search/hash?request={quote(md5_hash)}"
    headers = {"x-api-key": token}
    status, response = http_get(host, path, headers, context=context)
    logger.info(f"Checked hash {md5_hash}, status: {status}")
    if status != 200:
        return status, None
    return status, json.loads(response)


def upload_file(
    file_path: str, token: str, context: ssl.SSLContext = None
) -> tuple[int, str | None]:
    """
    Uploads a file to TIP for analysis using the API.

    :param file_path: the path to the file to be uploaded
    :param token: the user's API token
    :param context: the SSL context used to connect to TIP
    :return: the response from TIP as a tuple of (status code, response body)
    """
    host = "opentip.kaspersky.com"
    filename = os.path.basename(file_path)
    path = f"/api/v1/scan/file?filename={quote(filename)}"
    headers = {"x-api-key": token, "Content-Type": "application/octet-stream"}
    with open(file_path, "rb") as file:
        file_content = file.read()
    status, response = http_post(host, path, headers, file_content, context)
    logger.info(f"Uploaded file {file_path} for analysis, status: {status}")
    if status != 200:
        return status, None
    return status, json.loads(response)


def init_logger(level: int = logging.INFO) -> logging.Logger:
    """
    Initializes and formats the logger.

    :param level: the logging level (default: logging.INFO)
    :return: the configured logger object
    """
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)7s | %(funcName)15s:%(lineno)3s | %(message)s",
        filename="check_tip_status.log",
    )
    with open("check_tip_status.log", "a") as f:
        f.write(f"{'_' * 100}\n")
    return logging.getLogger()


if __name__ == "__main__":
    logger = init_logger()
    main()
