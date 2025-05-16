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