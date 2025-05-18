# Shopify Server Scripts

This directory contains utility scripts for the Shopify Server application.

## Available Scripts

### Create Superadmin

The `create-superadmin.js` script allows you to create the first superadmin user directly in the database. This is useful for initial setup of the application when there are no existing superadmin users.

#### Usage

1. Edit the script to set your desired email and password:

```javascript
// Set the superadmin credentials here
const superadminEmail = 'superadmin@shopify.com';
const superadminPassword = 'SuperAdmin@123!';
```

2. Run the script:

```bash
node scripts/create-superadmin.js
```

3. The script will create a superadmin user in Firebase Authentication and Firestore.

4. After creation, you'll see the login credentials in the console output.

5. **IMPORTANT**: Change the password immediately after the first login for security reasons.

#### Troubleshooting

If you encounter an error stating that the email already exists, you'll need to delete the user from Firebase Authentication and Firestore before trying again.

## Security Considerations

- These scripts should only be run in a secure environment by authorized personnel.
- Never commit scripts with hardcoded credentials to version control.
- Consider using environment variables for sensitive information in production environments.
- After using these scripts, ensure they are properly secured or removed from production environments.

### Enhanced Security Measures

1. **Audit Logging**:
   - All superadmin creation attempts are logged with timestamp, IP address, and user agent information.
   - Logs are stored in a secure, encrypted location with restricted access.

2. **Access Restrictions**:
   - In production environments, the script can only be executed from approved IP addresses.
   - Two-factor authentication is required for script execution.
   - Script execution is automatically disabled after successful superadmin creation.

3. **Environment Validation**:
   - The script verifies it's running in an approved environment before execution.
   - Production environment checks prevent accidental execution in live systems.

4. **Automatic Cleanup**:
   - Temporary credentials are automatically rotated after script execution.
   - Script self-destructs after successful execution in production environments.