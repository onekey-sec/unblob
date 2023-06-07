#!/usr/bin/env nix-shell
#! nix-shell -i python3 -p "python3.withPackages (ps: with ps; [ PyGithub ])" "writeShellScriptBin ''update-python-libraries'' ''${pkgs.update-python-libraries} "$@"''"
# pyright: reportMissingImports=false
import subprocess
from difflib import unified_diff
from os import environ as env
from pathlib import Path
from typing import cast

from github import Github
from github.ContentFile import ContentFile
from github.GithubException import GithubException
from github.Repository import Repository

API_TOKEN = env["GITHUB_TOKEN"]
REPOSITORY = env["GITHUB_REPOSITORY"]
BASE_BRANCH = env.get("GITHUB_BASE_BRANCH", "main")
DRY_RUN = bool(env.get("GITHUB_DRY_RUN", False))


def files_to_update():
    return (p for p in Path(".").glob("nix/*/default.nix") if p.parent.name != "unblob")


def create_pr(
    repo: Repository,
    pr_branch_name: str,
    head: str,
    file: ContentFile,
    updated_content: str,
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

    pr_branch = repo.create_git_ref(pr_branch_name, head)
    repo.update_file(
        file.path,
        f"{pr_title}\n\n{pr_body}",
        updated_content,
        file.sha,
        branch=pr_branch_name,
    )
    repo.create_pull(title=pr_title, body=pr_body, head=pr_branch.ref, base=BASE_BRANCH)


def update_dependencies():
    subprocess.run(["update-python-libraries", *files_to_update()])


def main():
    github = Github(API_TOKEN)

    repo = github.get_repo(REPOSITORY)
    head = repo.get_branch(BASE_BRANCH).commit.sha

    update_dependencies()
    for path in files_to_update():
        content = cast(ContentFile, repo.get_contents(path.as_posix(), ref=BASE_BRANCH))
        updated = path.read_text()
        diff = "".join(
            unified_diff(
                content.decoded_content.decode().splitlines(keepends=True),
                updated.splitlines(keepends=True),
            )
        )
        if not diff:
            print(f"{path} is up-to date")
            continue

        title = f"chore(deps): Updating {path}"

        body = f"""\
### Changes for {path}

```diff
{diff}
```
"""

        print(f"[{path}] - Creating PR\nTitle: {title}\nBody:\n{body}")
        if DRY_RUN:
            print("DRY-RUN: NOT creating PR...")
            continue

        pr_branch_name = f"refs/heads/update/deps-{path.as_posix().replace('/', '-')}"
        create_pr(
            repo,
            pr_branch_name,
            head,
            content,
            updated,
            title,
            body,
        )


if __name__ == "__main__":
    main()
