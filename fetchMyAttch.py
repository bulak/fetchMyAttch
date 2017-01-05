#!/usr/bin/env python
"""Fetches and saves attachments from queries of your Gmail""" 

# Parts of this script are either directly copied or modified from
# Google Gmail API example codes available at
# https://developers.google.com/gmail/api/v1/reference


from __future__ import print_function
import httplib2
import os
import time
import base64
import json
from collections import defaultdict

from apiclient import discovery, errors
from oauth2client import client, tools
from oauth2client.file import Storage

try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'Gmail API Quickstart'


def get_credentials():
    """Gets valid user credentials from storage.

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.

    Returns:
        Credentials, the obtained credential.
    """
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir,
                                   'gmail-quickstart.json')

    store = Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        if flags:
            credentials = tools.run_flow(flow, store, flags)
        else:  # Needed only for compatability with Python 2.6
            credentials = tools.run(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials


def get_messages(service, user_id='me', query=''):
    """List all Messages of the user's mailbox matching the query.

    Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    query: String used to filter messages returned.
    Eg.- 'from:user@some_domain.com' for Messages from a particular sender.

    Returns:
    List of Messages that match the criteria of the query. Note that the
    returned list contains Message IDs, you must use get with the
    appropriate ID to get the details of a Message.
    """
    try:
        response = service.users().messages().list(
            userId=user_id, q=query).execute()
        messages = []
        if 'messages' in response:
            messages.extend(response['messages'])
        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().messages().list(
                userId=user_id, q=query, pageToken=page_token).execute()
            messages.extend(response['messages'])
        return messages
    except errors.HttpError, error:
        return error


def get_files_attached(message):
    attchs = []
    parts = message['payload'].get('parts', [])
    for part in parts:
        if not part['filename'] == "" and 'attachmentId' in part['body']:
            attchs.append({'filename': part['filename'],
                           'attchId': part['body']['attachmentId'],
                           'mimeType': part['mimeType']})
    return attchs


def get_attachment_types(message, start_point=1):
    attch_types = []
    parts = message['payload'].get('parts', [])
    for part in parts:
        if float(part.get('partId', 0.0)) >= start_point:
            attch_types.append(part['mimeType'])
    return attch_types


def get_message_attr(message, attr='Subject'):
    headers = message['payload'].get('headers', [])
    for header in headers:
        if header['name'] == attr:
            return header['value']


def get_attachment(service, msg_id, attch_id, user_id='me'):
    try:
        response = service.users().messages().attachments().get(
            userId=user_id, messageId=msg_id, id=attch_id).execute()
        return unicode(response['data']).encode("utf-8")
    except errors.HttpError, error:
        return error


def get_message_date(message):
    return time.strftime('%Y-%m-%d_%H:%M:%S',
                         time.localtime(float(message['internalDate'])/1000))


def main():
    """Fetches and saves attachments from emails using Gmail API.

    Creates a Gmail API service object and applies custom query,
    then fetches all attachments and saves them along message metadata into
    seperate folders.
    """
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)
    messages = get_messages(service, query='from:nihan has:attachment')
    if not messages:
        print('No messages with current criteria were found.')
    else:
        print('Found {} messages. Now fetching attachments'.format(
            len(messages)))
        msg_counts = defaultdict(int)
        for message in messages:
            cur_message_id = message['id']
            cur_message = service.users().messages().get(
                userId='me', id=cur_message_id).execute()
            cur_message_date = get_message_date(cur_message)
            cur_message_attchs = get_files_attached(cur_message)
            if cur_message_attchs:
                msg_counts[cur_message_date] += 1
                msg_dir = "{}_{:03d}".format(
                    cur_message_date, msg_counts[cur_message_date])
                msg_path = "{}/message.json".format(msg_dir)
                try:
                    os.mkdir(msg_dir)
                except OSError:
                    print("Found '{}', using it!".format(msg_dir))
                if not os.path.isfile(msg_path):
                    with open(msg_path, 'w') as f:
                        json.dump(cur_message, f, indent=3,
                                  separators=(',', ': '))
                else:
                    print("Found a message in {}, skipping it".format(msg_dir))
                for attch in cur_message_attchs:
                    file_name = "{}/{}".format(
                        msg_dir, unicode(attch['filename']).encode("utf-8"))
                    if not os.path.isfile(file_name):
                        with open(file_name, 'w') as f:
                            file_data = base64.urlsafe_b64decode(
                                get_attachment(service, cur_message_id,
                                               attch['attchId']))
                            f.write(file_data)
                    else:
                        print("Found attachment '{}', skipping it".format(
                            file_name))


if __name__ == '__main__':
    main()
