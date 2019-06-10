#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import sys
import datetime
import argparse
import uuid
import hashlib
import os
import re
import json
import tempfile
from git import Repo
from git import NULL_TREE
from truffleHogRegexes.regexChecks import regexes
from truffleHog.utils import BColors, str2bool, get_rules, get_path_inclusions
from truffleHog.utils import shannon_entropy, clone_git_repo, del_rw


def main():
    args = get_args()
    rules = get_rules(args)
    do_entropy = str2bool(args.do_entropy)
    path_inclusions, path_exclusions = get_path_inclusions(args)

    # main logic
    output = find_strings(
        args.git_url, args.since_commit, args.max_depth,
        args.output_json, args.do_regex, do_entropy, surpress_output=False,
        path_inclusions=path_inclusions, path_exclusions=path_exclusions)
    project_path = output["project_path"]
    shutil.rmtree(project_path, onerror=del_rw)
    if output["foundIssues"]:
        sys.exit(1)
    else:
        sys.exit(0)


def get_args():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument(
        '--json', dest="output_json", action="store_true",
        help="Output in JSON")
    parser.add_argument(
        "--regex", dest="do_regex", action="store_true",
        help="Enable high signal regex checks")
    parser.add_argument(
        "--rules", dest="rules",
        help="Ignore default regexes and source from json list file")
    parser.add_argument(
        "--entropy", dest="do_entropy",
        help="Enable entropy checks")
    parser.add_argument(
        "--since_commit", dest="since_commit",
        help="Only scan from a given commit hash")
    parser.add_argument(
        "--max_depth", dest="max_depth",
        help="The max commit depth to go back when searching for secrets")
    parser.add_argument(
        '-i', '--include_paths', type=argparse.FileType('r'), metavar='INCLUDE_PATHS_FILE',
        help='File with regular expressions (one per line), at least one of which must match a Git '
             'object path in order for it to be scanned; lines starting with "#" are treated as '
             'comments and are ignored. If empty or not provided (default), all Git object paths '
             'are included unless otherwise excluded via the --exclude_paths option.')
    parser.add_argument(
        '-x', '--exclude_paths', type=argparse.FileType('r'), metavar='EXCLUDE_PATHS_FILE',
        help='File with regular expressions (one per line), none of which may match a Git object '
             'path in order for it to be scanned; lines starting with "#" are treated as comments '
             'and are ignored. If empty or not provided (default), no Git object paths are '
             'excluded unless  effectively excluded via the --include_paths option.')
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    parser.set_defaults(regex=False)
    parser.set_defaults(rules={})
    parser.set_defaults(max_depth=1000000)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(entropy=True)
    return parser.parse_args()


def path_included(blob, include_patterns=None, exclude_patterns=None):
    path = blob.b_path if blob.b_path else blob.a_path
    if include_patterns and not any(p.match(path) for p in include_patterns):
        return False
    if exclude_patterns and any(p.match(path) for p in exclude_patterns):
        return False
    return True


def is_line_disabled(line):
    """find a comment like # pylint: disable=no-member
    not-a-secret
    and send true if exist."""
    return re.search(r"\s*not-a-secret", line)


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings


def print_results(printJson, issue):
    commit_time = issue['date']
    branch_name = issue['branch']
    prev_commit = issue['commit']
    printableDiff = issue['printDiff']
    commit_hash = issue['commit_hash']
    reason = issue['reason']
    path = issue['path']

    if printJson:
        print(json.dumps(issue, sort_keys=True))
    else:
        print("~~~~~~~~~~~~~~~~~~~~~")
        reason = "{}Reason: {}{}".format(BColors.OKGREEN, reason, BColors.ENDC)
        print(reason)
        dateStr = "{}Date: {}{}".format(BColors.OKGREEN, commit_time, BColors.ENDC)
        print(dateStr)
        hashStr = "{}Hash: {}{}".format(BColors.OKGREEN, commit_hash, BColors.ENDC)
        print(hashStr)
        filePath = "{}Filepath: {}{}".format(BColors.OKGREEN, path, BColors.ENDC)
        print(filePath)

        if sys.version_info >= (3, 0):
            branchStr = "{}Branch: {}{}".format(BColors.OKGREEN, branch_name, BColors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(BColors.OKGREEN, prev_commit, BColors.ENDC)
            print(commitStr)
            print(printableDiff)
        else:
            branchStr = "{}Branch: {}{}".format(BColors.OKGREEN, branch_name.encode('utf-8'), BColors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(BColors.OKGREEN, prev_commit.encode('utf-8'), BColors.ENDC)
            print(commitStr)
            print(printableDiff.encode('utf-8'))
        print("~~~~~~~~~~~~~~~~~~~~~")


def find_base64_shannon_entropy(printableDiff, word):
    l_strings_found = []
    l_printable_diff = printableDiff
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    base64_strings = get_strings_of_set(word, BASE64_CHARS)
    for string in base64_strings:
        b64_entropy = shannon_entropy(string, BASE64_CHARS)
        if b64_entropy > 4.5:
            l_strings_found.append(string)
            l_printable_diff = printableDiff.replace(
                string, BColors.WARNING + string + BColors.ENDC)
    return (l_strings_found, l_printable_diff)

def find_hex_shannon_entropy(printableDiff, word):
    l_strings_found = []
    l_printable_diff = printableDiff
    HEX_CHARS = "1234567890abcdefABCDEF"
    hex_strings = get_strings_of_set(word, HEX_CHARS)
    for string in hex_strings:
        hex_entropy = shannon_entropy(string, HEX_CHARS)
        if hex_entropy > 3:
            l_strings_found.append(string)
            l_printable_diff = printableDiff.replace(
                string, BColors.WARNING + string + BColors.ENDC)
    return (l_strings_found, l_printable_diff)

def find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commit_hash):
    stringsFound = []
    lines = printableDiff.split("\n")
    for line in lines:
        if is_line_disabled(line):
            continue
        for word in line.split():
            strings_found, printableDiff = find_base64_shannon_entropy(printableDiff, word)
            stringsFound = stringsFound + strings_found
            strings_found, printableDiff = find_hex_shannon_entropy(printableDiff, word)
            stringsFound = stringsFound + strings_found

    entropic_diff = None
    if len(stringsFound) > 0:
        entropic_diff = {}
        entropic_diff['date'] = commit_time
        entropic_diff['path'] = blob.b_path if blob.b_path else blob.a_path
        entropic_diff['branch'] = branch_name
        entropic_diff['commit'] = prev_commit.message
        entropic_diff['diff'] = blob.diff.decode('utf-8', errors='replace')
        entropic_diff['stringsFound'] = stringsFound
        entropic_diff['printDiff'] = printableDiff
        entropic_diff['commit_hash'] = commit_hash
        entropic_diff['reason'] = "High Entropy"
    return entropic_diff


def regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commit_hash, custom_regexes={}):
    if custom_regexes:
        secret_regexes = custom_regexes
    else:
        secret_regexes = regexes
    regex_matches = []
    for key in secret_regexes:
        found_strings = secret_regexes[key].findall(printableDiff)
        for found_string in found_strings:
            found_diff = printableDiff.replace(printableDiff, BColors.WARNING + found_string + BColors.ENDC)
        if found_strings:
            foundRegex = {}
            foundRegex['date'] = commit_time
            foundRegex['path'] = blob.b_path if blob.b_path else blob.a_path
            foundRegex['branch'] = branch_name
            foundRegex['commit'] = prev_commit.message
            foundRegex['diff'] = blob.diff.decode('utf-8', errors='replace')
            foundRegex['stringsFound'] = found_strings
            foundRegex['printDiff'] = found_diff
            foundRegex['reason'] = key
            foundRegex['commit_hash'] = commit_hash
            regex_matches.append(foundRegex)
    return regex_matches


def diff_worker(diff, curr_commit, prev_commit, branch_name, commit_hash,
                custom_regexes, do_entropy, do_regex, printJson,
                surpress_output, path_inclusions=None, path_exclusions=None):
    issues = []
    for blob in diff:
        printableDiff = blob.diff.decode('utf-8', errors='replace')
        if printableDiff.startswith("Binary files"):
            continue
        if not path_included(blob, path_inclusions, path_exclusions):
            continue
        commit_time = datetime.datetime.fromtimestamp(prev_commit.committed_date) \
            .strftime('%Y-%m-%d %H:%M:%S')
        foundIssues = []
        if do_entropy:
            entropic_diff = find_entropy(
                printableDiff, commit_time, branch_name, prev_commit,
                blob, commit_hash)
            if entropic_diff:
                foundIssues.append(entropic_diff)
        if do_regex:
            found_regexes = regex_check(
                printableDiff, commit_time, branch_name, prev_commit, blob,
                commit_hash, custom_regexes)
            foundIssues += found_regexes
        if not surpress_output:
            for foundIssue in foundIssues:
                print_results(printJson, foundIssue)
        issues += foundIssues
    return issues


def handle_results(output, output_dir, foundIssues):
    for foundIssue in foundIssues:
        result_path = os.path.join(output_dir, str(uuid.uuid4()))
        with open(result_path, "w+") as result_file:
            result_file.write(json.dumps(foundIssue))
        output["foundIssues"].append(result_path)
    return output


def find_strings(git_url, since_commit=None, max_depth=1000000, printJson=False,
                 do_regex=False, do_entropy=True, surpress_output=True,
                 custom_regexes={}, path_inclusions=None, path_exclusions=None):
    output = {"foundIssues": []}
    project_path = clone_git_repo(git_url)
    repo = Repo(project_path)
    already_searched = set()
    output_dir = tempfile.mkdtemp()

    for remote_branch in repo.remotes.origin.fetch():
        since_commit_reached = False
        branch_name = remote_branch.name
        prev_commit = None
        for curr_commit in repo.iter_commits(branch_name, max_count=max_depth):
            commit_hash = curr_commit.hexsha
            if commit_hash == since_commit:
                since_commit_reached = True
            if since_commit and since_commit_reached:
                prev_commit = curr_commit
                continue
            # if not prev_commit, then curr_commit is the newest commit. And we
            # have nothing to diff with. But we will diff the first commit with
            # NULL_TREE here to check the oldest code.
            # In this way, no commit will be missed.
            diff_hash = hashlib.md5((str(prev_commit) + str(curr_commit)).encode('utf-8')).digest()
            if not prev_commit:
                prev_commit = curr_commit
                continue
            elif diff_hash in already_searched:
                prev_commit = curr_commit
                continue
            else:
                diff = prev_commit.diff(curr_commit, create_patch=True)
            # avoid searching the same diffs
            already_searched.add(diff_hash)
            foundIssues = diff_worker(
                diff, curr_commit, prev_commit,
                branch_name, commit_hash, custom_regexes, do_entropy, do_regex,
                printJson, surpress_output, path_inclusions, path_exclusions)
            output = handle_results(output, output_dir, foundIssues)
            prev_commit = curr_commit

        # Handling the first commit
        diff = curr_commit.diff(NULL_TREE, create_patch=True)
        foundIssues = diff_worker(
            diff, curr_commit, prev_commit, branch_name,
            commit_hash, custom_regexes, do_entropy, do_regex, printJson,
            surpress_output, path_inclusions, path_exclusions)
        output = handle_results(output, output_dir, foundIssues)

    output["project_path"] = project_path
    output["clone_uri"] = git_url
    return output


if __name__ == "__main__":
    main()
