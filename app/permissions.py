# ~/app/permissions.py

import logging

class PermissionManager:
    def __init__(self):
        self.permissions = []

    def add_permission(self, address, url, permission, last_visit):
        """
        Add a new permission object to the list or update an existing one.
        """
        existing_permission = next(
            (perm for perm in self.permissions if perm['address'] == address), None)

        if existing_permission:
            # Update the existing permission object
            url_permissions = existing_permission['url_permissions']
            existing_url_permission = next(
                (up for up in url_permissions if up['url'] == url), None)

            if existing_url_permission:
                # Update the existing URL permission
                if time.time() - existing_url_permission['last_visit'] > 120 * 60:
                    # If last visit time is older than 120 minutes, revoke permission
                    existing_url_permission['permission'] = False
                else:
                    # Update the last visit time
                    existing_url_permission['last_visit'] = last_visit
                    # Update the existing URL permission
                    existing_url_permission['permission'] = permission
            else:
                # Add a new URL permission
                new_url_permission = {'url': url, 'permission': permission, 'last_visit': last_visit}
                url_permissions.append(new_url_permission)
        else:
            # Add a new permission object
            new_permission = {'address': address, 'url_permissions': [{'url': url, 'permission': permission, 'last_visit': last_visit}]}
            self.permissions.append(new_permission)

    def check_permission_for_url(self, address, url):
        """
        Check if the given address has permission for the specified URL.

        Args:
            address (str): The address to check.
            url (str): The URL to check for permission.

        Returns:
            bool: True if permission is granted, False otherwise.
        """
        permission_object = next((perm for perm in self.permissions if perm['address'] == address), None)

        if permission_object:
            url_permissions = permission_object['url_permissions']
            url_permission = next((up for up in url_permissions if up['url'] == url), None)

            if url_permission:
                return url_permission['permission']

        return False
