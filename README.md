## Check TIP Status

This script checks the status of files uploaded to the Kaspersky Threat Intelligence Portal (TIP).
Such files can be checked for whether they're safe or malware, ransomware, etc.
For each file path provided, it calculates its MD5 hash and checks the TIP for an existing
record. If a record is found, the script outputs the result. Otherwise, the script uploads
the file for a basic analysis and outputs the result.

To run the script, you need to provide an API token and a list of file paths.
You can request an API token from the Threat Intelligence Portal if you sign up.
For more information about the API and getting a token, follow [this link](https://opentip.kaspersky.com/Help/Doc_data/WorkingWithAPI.htm).

### Example usage
``` bash
python check_tip_status.py token_file_path file_path_1 [file_path_2 ...]
```

Arguments:
- ```token_file_path```: Path to the file containing a valid API token.
- ```file_paths```: List of file paths to check or upload to TIP.