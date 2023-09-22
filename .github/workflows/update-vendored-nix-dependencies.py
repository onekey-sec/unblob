#!/usr/bin/env nix-shell
#! nix-shell -i python3 -p "python3.withPackages (ps: with ps; [ PyGithub ])" nvfetcher
# pyright: reportMissingImports=false
import subprocess
from os import environ as env
from pathlib import Path
from tempfile import NamedTemporaryFile

from github import Github
from github.GithubException import GithubException
from github.Repository import Repository

API_TOKEN = env["GITHUB_TOKEN"]
REPOSITORY = env["GITHUB_REPOSITORY"]
BASE_BRANCH = env.get("GITHUB_BASE_BRANCH", "main")
DRY_RUN = bool(env.get("GITHUB_DRY_RUN", False))

USER_NAME = "github-actions[bot]"
USER_EMAIL = "github-actions[bot]@users.noreply.github.com"


def create_pr(
    repo: Repository,
    pr_branch_name: str,
    pr_title: str,
    pr_body: str,
):
    try:
        repo.get_branch(pr_branch_name)
        print(f"Branch '{pr_branch_name}' already exist. Skipping update.")
    except GithubException as ex:
        if ex.status != 404:
            raise
    else:
        return

    subprocess.run(["git", "add", "."], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"{pr_title}\n\n{pr_body}"],
        check=True,
        env={
            "GIT_AUTHOR_NAME": USER_NAME,
            "GIT_COMMITTER_NAME": USER_NAME,
            "GIT_AUTHOR_EMAIL": USER_EMAIL,
            "GIT_COMMITTER_EMAIL": USER_EMAIL,
        },
    )
    subprocess.run(["git", "push", "origin", f"+HEAD:{pr_branch_name}"], check=True)
    pr = repo.create_pull(
        title=pr_title, body=pr_body, head=pr_branch_name, base=BASE_BRANCH
    )
    pr.add_to_labels("automated", "dependencies")


def update_dependencies():
    with NamedTemporaryFile() as log:
        subprocess.run(
            ["nvfetcher", "--build-dir", "nix/_sources", "--changelog", log.name],
            check=True,
        )
        return Path(log.name).read_text()


def main():
    github = Github(API_TOKEN)

    repo = github.get_repo(REPOSITORY)

    changes = update_dependencies()
    if not changes:
        print("-- Everything is up-to date")
        return

    title = "chore(deps): Updating vendored nix dependencies"

    body = f"""\
### Changes in dependencies:

{changes}
"""

    print(f"-- Creating PR\nTitle: {title}\nBody:\n{body}")
    if DRY_RUN:
        print("DRY-RUN: NOT creating PR...")
        return

    pr_branch_name = "refs/heads/update/nix-vendored-dependencies"
    create_pr(
        repo,
        pr_branch_name,
        title,
        body,
    )


if __name__ == "__main__":
    main()
