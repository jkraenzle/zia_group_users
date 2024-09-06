# Overview

This script is designed to place a set of users defined by a regular expression match into an existing group.
Optionally, the script can remove any users that currently exist in the group.

# Prerequisites
The script requires installation of the Python requests library in a Python 3.10 installation.
This can be done using the command:
pip install requests

# Execution
To execute the script, use the command:

```
python group_users.py --cloud <Zscaler Cloud> 
     --username <user@domain> [--password <>] --api_key <Zscaler API Key>
     --group_name <Existing User Group>
     --action <test, add, or overwrite>
     --user_regex <"regular expression match"> [--user_field email]
     [--ssl_verify <True|False>]
```

The password argument is optional and will be requested during the script if not entered in the command line.
The user_field argument defaults to 'email'.

# Limitations

The script is limited in current implementation to tenants with less than 10,000 users. The function get_users would need to be modified to pageinate and iterate over multiple requests to support larger numbers.
