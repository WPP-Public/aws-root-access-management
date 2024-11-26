import subprocess
import json
import sys
import os
import argparse


def execute_command(command, environment=None, dry_run=False):
    """
    Helper function to execute AWS CLI commands.
    """
    if dry_run:
        print("[DRY RUN] Would execute command:", " ".join(command))
        return None

    if environment is None:
        environment = os.environ.copy()
    environment["PATH"] = "/usr/local/bin:" + environment.get("PATH", "")
    print("Executing command:", " ".join(command))
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, env=environment)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e.stderr}")
        return None


def enable_centralized_root_access():
    """
    Enables centralized root access for member accounts.
    """
    print("Enabling centralized root access...")

    # Step 1: Enable trusted access for IAM in AWS Organizations
    print("Step 1: Enabling trusted access for IAM in AWS Organizations...")
    execute_command([
        "aws", "organizations", "enable-aws-service-access",
        "--service-principal", "iam.amazonaws.com"
    ])

    # Step 2: Enable centralized management of root user credentials
    print("Step 2: Enabling centralized management of root user credentials...")
    execute_command(["aws", "iam", "enable-organizations-root-credentials-management"])

    # Step 3: Enable centralized root sessions
    print("Step 3: Enabling centralized root sessions...")
    execute_command(["aws", "iam", "enable-organizations-root-sessions"])

    print("Centralized root access enabled successfully.\n")


def assume_root_account(account_id):
    """
    Assumes the root role for a specific AWS account.
    """
    print(f"Assuming root role for account: {account_id}")
    command = [
        "aws", "sts", "assume-root",
        "--target-principal", account_id,
        "--task-policy-arn", "arn=arn:aws:iam::aws:policy/root-task/IAMDeleteRootUserCredentials",
        "--duration-seconds", "900"  # Valid for 15 minutes
    ]
    output = execute_command(command)
    if output:
        credentials = json.loads(output)
        return credentials['Credentials']
    return None


def delete_root_user_credentials(credentials, skip_login_profile, skip_access_keys, skip_signing_certificates, skip_mfa_devices, dry_run):
    """
    Deletes the root user credentials using temporary credentials.
    """
    environment = {
        "AWS_ACCESS_KEY_ID": credentials['AccessKeyId'],
        "AWS_SECRET_ACCESS_KEY": credentials['SecretAccessKey'],
        "AWS_SESSION_TOKEN": credentials['SessionToken'],
    }

    # Delete login profile
    if skip_login_profile:
        print("Skipping login profile deletion as per the --skip-login-profile flag.")
    else:
        print("Checking if root login profile exists...")
        login_profile_exists = execute_command(["aws", "iam", "get-login-profile"], environment)
        if login_profile_exists:
            print("Login profile exists. Attempting to delete it...")
            execute_command(["aws", "iam", "delete-login-profile"], environment, dry_run=dry_run)
        else:
            print("No login profile found.")

    # List and delete access keys
    if skip_access_keys:
        print("Skipping access key deletion as per the --skip-access-keys flag.")
    else:
        print("Listing and deleting access keys...")
        access_keys_output = execute_command(["aws", "iam", "list-access-keys"], environment)
        if access_keys_output:
            try:
                access_keys = json.loads(access_keys_output).get('AccessKeyMetadata', [])
                for key in access_keys:
                    execute_command(["aws", "iam", "delete-access-key", "--access-key-id", key['AccessKeyId']], environment, dry_run=dry_run)
            except json.JSONDecodeError:
                print("Failed to decode access keys JSON. Skipping...")
        else:
            print("Access denied or no access keys found.")

    # List and delete signing certificates
    if skip_signing_certificates:
        print("Skipping signing certificate deletion as per the --skip-signing-certificates flag.")
    else:
        print("Listing and deleting signing certificates...")
        certs_output = execute_command(["aws", "iam", "list-signing-certificates"], environment)
        if certs_output:
            try:
                certs = json.loads(certs_output).get('Certificates', [])
                for cert in certs:
                    execute_command(["aws", "iam", "delete-signing-certificate", "--certificate-id", cert['CertificateId']], environment, dry_run=dry_run)
            except json.JSONDecodeError:
                print("Failed to decode signing certificates JSON. Skipping...")
        else:
            print("Access denied or no signing certificates found.")

    # List and delete MFA devices
    if skip_mfa_devices:
        print("Skipping MFA device deletion as per the --skip-mfa-devices flag.")
    else:
        print("Listing and deleting MFA devices...")
        mfa_output = execute_command(["aws", "iam", "list-mfa-devices"], environment)
        if mfa_output:
            try:
                mfa_devices = json.loads(mfa_output).get('MFADevices', [])
                for mfa_device in mfa_devices:
                    serial_number = mfa_device['SerialNumber']
                    print(f"Deactivating MFA device: {serial_number}")
                    execute_command(["aws", "iam", "deactivate-mfa-device", "--serial-number", serial_number], environment, dry_run=dry_run)
            except json.JSONDecodeError:
                print("Failed to decode MFA devices JSON. Skipping...")
        else:
            print("Access denied or no MFA devices found.")


def list_accounts():
    """
    Lists all accounts in the AWS Organization.
    """
    print("Retrieving accounts from AWS Organizations...")
    command = ["aws", "organizations", "list-accounts"]
    output = execute_command(command)
    if output:
        accounts = json.loads(output).get('Accounts', [])
        return [account['Id'] for account in accounts]
    return []


def main():
    """
    Main execution flow.
    """
    parser = argparse.ArgumentParser(description="Script to delete root user credentials from AWS accounts.")
    parser.add_argument("--skip-login-profile", action="store_true", help="Skip deleting login profile.")
    parser.add_argument("--skip-access-keys", action="store_true", help="Skip deleting access keys.")
    parser.add_argument("--skip-signing-certificates", action="store_true", help="Skip deleting signing certificates.")
    parser.add_argument("--skip-mfa-devices", action="store_true", help="Skip deleting MFA devices.")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without performing them.")
    args = parser.parse_args()

    skip_login_profile = args.skip_login_profile
    skip_access_keys = args.skip_access_keys
    skip_signing_certificates = args.skip_signing_certificates
    skip_mfa_devices = args.skip_mfa_devices
    dry_run = args.dry_run

    # Enable centralized root access
    enable_centralized_root_access()

    accounts = list_accounts()
    if not accounts:
        print("No accounts found or unable to retrieve accounts.")
        return

    print(f"Found {len(accounts)} accounts. Starting process...\n")
    for account_id in accounts:
        print(f"\nProcessing account: {account_id}")
        credentials = assume_root_account(account_id)
        if credentials:
            delete_root_user_credentials(credentials, skip_login_profile, skip_access_keys, skip_signing_certificates, skip_mfa_devices, dry_run)
        else:
            print(f"Failed to assume root role for account: {account_id}")


if __name__ == "__main__":
    main()
