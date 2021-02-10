#!/usr/bin/env python
"""
Make pull requests to Quansight Repos with CODE-OF-CONDUCT.md.

This script is licensed MIT:

The MIT License (MIT)

Copyright (c) 2021 Quansight

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""
import os
import json
import datetime
import time
import webbrowser
import argparse
import tempfile
import subprocess
import shlex

import requests

# ========================= START GITHUB API STUFF ==========================


# The GitHub API code here was taken from doctr, whose license is reproduced below:
#
# The MIT License (MIT)
#
# Copyright (c) 2016 Aaron Meurer, Gil Forsyth
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

def bold(text):
    return "\033[1m%s\033[0m" % text

class AuthenticationFailed(Exception):
    pass

def GitHub_login(client_id, *, headers=None, scope='repo'):
    """
    Login to GitHub.

    This uses the device authorization flow. client_id should be the client id
    for your GitHub application. See
    https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps#device-flow.

    'scope' should be the scope for the access token ('repo' by default). See https://docs.github.com/en/free-pro-team@latest/developers/apps/scopes-for-oauth-apps#available-scopes.
[<8;72;11m[<8;71;11m
    Returns an access token.

    """
    _headers = headers or {}
    headers = {"accept":  "application/json", **_headers}

    r = requests.post("https://github.com/login/device/code",
                      {"client_id": client_id, "scope": scope},
                      headers=headers)
    GitHub_raise_for_status(r)
    result = r.json()
    device_code = result['device_code']
    user_code = result['user_code']
    verification_uri = result['verification_uri']
    expires_in = result['expires_in']
    interval = result['interval']
    request_time = time.time()

    print("Go to", verification_uri, "and enter this code:")
    print()
    print(bold(user_code))
    print()
    input("Press Enter to open a webbrowser to " + verification_uri)
    webbrowser.open(verification_uri)
    while True:
        time.sleep(interval)
        now = time.time()
        if now - request_time > expires_in:
            print("Did not receive a response in time. Please try again.")
            return GitHub_login(client_id=client_id, headers=headers, scope=scope)
        # Try once before opening in case the user already did it
        r = requests.post("https://github.com/login/oauth/access_token",
                          {"client_id": client_id,
                           "device_code": device_code,
                           "grant_type": "urn:ietf:params:oauth:grant-type:device_code"},
                          headers=headers)
        GitHub_raise_for_status(r)
        result = r.json()
        if "error" in result:
            # https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps#error-codes-for-the-device-flow
            error = result['error']
            if error == "authorization_pending":
                if 0:
                    print("No response from GitHub yet: trying again")
                continue
            elif error == "slow_down":
                # We are polling too fast somehow. This adds 5 seconds to the
                # poll interval, which we increase by 6 just to be sure it
                # doesn't happen again.
                interval += 6
                continue
            elif error == "expired_token":
                print("GitHub token expired. Trying again...")
                return GitHub_login(client_id=client_id, headers=headers, scope=scope)
            elif error == "access_denied":
                raise AuthenticationFailed("User canceled authorization")
            else:
                # The remaining errors, "unsupported_grant_type",
                # "incorrect_client_credentials", and "incorrect_device_code"
                # mean the above request was incorrect somehow, which
                # indicates a bug. Or GitHub added a new error type, in which
                # case this code needs to be updated.
                raise AuthenticationFailed("Unexpected error when authorizing with GitHub:", error)
        else:
            return result['access_token']


class GitHubError(RuntimeError):
    pass

def GitHub_raise_for_status(r):
    """
    Call instead of r.raise_for_status() for GitHub requests

    Checks for common GitHub response issues and prints messages for them.
    """
    # This will happen if the doctr session has been running too long and the
    # OTP code gathered from GitHub_login has expired.

    # TODO: Refactor the code to re-request the OTP without exiting.
    if r.status_code == 401 and r.headers.get('X-GitHub-OTP'):
        raise GitHubError("The two-factor authentication code has expired. Please run doctr configure again.")
    if r.status_code == 403 and r.headers.get('X-RateLimit-Remaining') == '0':
        reset = int(r.headers['X-RateLimit-Reset'])
        limit = int(r.headers['X-RateLimit-Limit'])
        reset_datetime = datetime.datetime.fromtimestamp(reset, datetime.timezone.utc)
        relative_reset_datetime = reset_datetime - datetime.datetime.now(datetime.timezone.utc)
        # Based on datetime.timedelta.__str__
        mm, ss = divmod(relative_reset_datetime.seconds, 60)
        hh, mm = divmod(mm, 60)
        def plural(n):
            return n, abs(n) != 1 and "s" or ""

        s = "%d minute%s" % plural(mm)
        if hh:
            s = "%d hour%s, " % plural(hh) + s
        if relative_reset_datetime.days:
            s = ("%d day%s, " % plural(relative_reset_datetime.days)) + s
        authenticated = limit >= 100
        message = """\
Your GitHub API rate limit has been hit. GitHub allows {limit} {un}authenticated
requests per hour. See {documentation_url}
for more information.
""".format(limit=limit, un="" if authenticated else "un", documentation_url=r.json()["documentation_url"])
        if authenticated:
            message += """
Note that GitHub's API limits are shared across all oauth applications. A
common cause of hitting the rate limit is the Travis "sync account" button.
"""
        else:
            message += """
You can get a higher API limit by authenticating. Try running doctr configure
again without the --no-upload-key flag.
"""
        message += """
Your rate limits will reset in {s}.\
""".format(s=s)
        raise GitHubError(message)
    r.raise_for_status()

def get_headers(token):
    return {'Authorization': "token {}".format(token),
            "Accept": "application/vnd.github.v3+json"}

def GitHub_post(url, data, *, token, headers=None):
    """
    POST the data ``data`` to GitHub.

    Returns the json response from the server, or raises on error status.

    """
    headers = get_headers(token)
    headers.update(headers or {})
    r = requests.post(url, headers=headers, data=json.dumps(data))
    GitHub_raise_for_status(r)
    return r.json()

def GitHub_get(url, params=None, *, token, headers=None):
    """
    GET the url from GitHub.

    Returns the json response from the server, or raises on error status.

    """
    headers = get_headers(token)
    headers.update(headers or {})
    # print("GET", url)
    r = requests.get(url, params=params, headers=headers)
    GitHub_raise_for_status(r)
    return r.json()

# ========================== END GITHUB API STUFF ===========================

CLIENT_ID = '1cee0ea4bab32a58132b'

CODE_OF_CONDUCT = """\
This repository is governed by the Quansight Repository Code of Conduct. It
can be found here:
https://github.com/Quansight/.github/blob/master/CODE_OF_CONDUCT.md.
"""

def get_repos(token, org):
    repos = []
    i = 1
    while True:
        res = GitHub_get(f'https://api.github.com/orgs/{org}/repos',
                       dict(type='public', per_page=100, page=i), token=token)
        if not res:
            break
        repos += [r for r in res if not r['fork'] and not r['name'] == '.github']
        i += 1

    return repos

def main():
    parser = argparse.ArgumentParser(description='add code of conduct to Quansight repos')

    parser.add_argument('-l', '--list-repos', action='store_true',
                        help="""List open source repos that would be updated""")
    parser.add_argument('--org', default='Quansight', help="""The org to work
    on. The default is 'Quansight'.""")
    parser.add_argument('--repos', default=["ALL"], nargs='+', help="""The repos to update.
    The default is 'ALL', which updates all public repos in the org.""")
    parser.add_argument('--dry-run', default=True, help="""Don't actually push anything to GitHub""")
    args = parser.parse_args()

    token = GitHub_login(CLIENT_ID)

    all_repos = get_repos(token, args.org)
    if args.list_repos:
        for r in all_repos:
            print(args.org + '/' + r['name'])
        return

    if args.repos == ['ALL']:
        repos = all_repos
    else:
        repos = []
        for repo in args.repos:
            for r in all_repos:
                if r['name'].lower() == repo.lower():
                    repos.append(r)
                    break
            else:
                raise RuntimeError(f"Did not find repo {repo}")

    for repo in repos:
        add_coc(args.org, repo['name'], push=not args.dry_run)
        if not args.dry_run:
            make_pr(args.org, repo['name'],
                    default_branch=repo['default_branch'], token=token)
def run(cmd, *args, **kwargs):
    kwargs.setdefault('check', True)
    print(' '.join(map(shlex.quote, cmd)))
    return subprocess.run(cmd, *args, **kwargs)

BRANCH_NAME = 'add-code-of-conduct'

def add_coc(org, repo, push=True):
    print(f"Adding CODE_OF_CONDUCT.md to {org}/{repo}")
    # with tempfile.TemporaryDirectory() as tmpdirname:
    tmpdirname = tempfile.mkdtemp()
    print("Cloning into", tmpdirname)
    run(['git', 'clone', f'git@github.com:{org}/{repo}.git'],
        cwd=tmpdirname)
    clone = os.path.join(tmpdirname, repo)
    run(['git', 'checkout', '-b', BRANCH_NAME], cwd=clone)
    with open(os.path.join(clone, 'CODE_OF_CONDUCT.md'), 'w') as f:
        f.write(CODE_OF_CONDUCT)

    run(['git', 'add', 'CODE_OF_CONDUCT.md'], cwd=clone)
    run(['git', 'commit', '-m', 'Add CODE_OF_CONDUCT.md, linking to the Quansight Code of Conduct'], cwd=clone)
    if push:
        run(['git', 'push', 'origin', BRANCH_NAME], cwd=clone)


PR_TITLE = "Add CODE_OF_CONDUCT.md"

PR_BODY = """\
This adds CODE_OF_CONDUCT.md. The contents of this file point back to the
actual Quansight Code of Conduct at
https://github.com/Quansight/.github/blob/master/CODE_OF_CONDUCT.md.

See https://github.com/Quansight/.github/issues/8 for more information.
"""

def make_pr(org, repo, *, default_branch, token):
    data = dict(
        head=BRANCH_NAME,
        base=default_branch,
        title=PR_TITLE,
        body=PR_BODY,
        maintainer_can_modify=True,
    )

    r = GitHub_post(f'https://api.github.com/repos/{org}/{repo}/pulls', data, token=token)
    return r

if __name__ == '__main__':
    main()
